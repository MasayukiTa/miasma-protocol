//! The send queue that survives a restart: one encrypted record per file that
//! is waiting to be sent, taken out when the transfer ends (done, cancelled,
//! failed for good).
//!
//! The log (`state_crypto`, label `PushOutbox`) holds `Put` records, each the
//! whole current state of one job, and `Del` records. On start the log is
//! folded into the set of jobs still wanted and rewritten when it holds mostly
//! dead records. File names and paths are inside the encrypted records only.
//!
//! Memory: one small record per queued job (the queue is capped by the
//! service); nothing else is held.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::state_crypto::{self, Label, LogReader, LogRewrite, LogWriter, StateKeys};

/// One file queued for a contact, as it is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutJob {
    /// The transfer id shown to the person (kept across a restart).
    pub id: String,
    pub contact_id: String,
    /// Absolute path of the source file.
    pub path: String,
    /// File name as sent.
    pub name: String,
    /// Size when queued.
    pub size: u64,
    /// Modification time when queued (ms since the Unix epoch); `0` if the
    /// platform does not tell.
    pub mtime_ms: u64,
    /// BLAKE3 of the whole file (hex), once computed.
    #[serde(default)]
    pub hash: Option<String>,
    /// Bytes the receiver had confirmed when the last attempt ended.
    #[serde(default)]
    pub offset: u64,
    /// Failed attempts in a row at that moment.
    #[serde(default)]
    pub attempt: u32,
    pub created_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Rec {
    Put { job: OutJob },
    Del { id: String },
}

struct Inner {
    jobs: HashMap<String, OutJob>,
    writer: Option<LogWriter>,
    /// Records in the log that no longer matter.
    garbage: usize,
}

pub struct Outbox {
    path: PathBuf,
    /// `None` when the state key is unavailable: nothing is stored.
    keys: Option<StateKeys>,
    inner: Mutex<Inner>,
}

impl Outbox {
    /// A queue that stores nothing (the state key is unavailable).
    pub fn disabled() -> Self {
        Self {
            path: PathBuf::new(),
            keys: None,
            inner: Mutex::new(Inner {
                jobs: HashMap::new(),
                writer: None,
                garbage: 0,
            }),
        }
    }

    /// Open (or start) the queue of the daemon that owns `data_dir`.
    pub fn open(data_dir: &Path) -> Self {
        let keys = match StateKeys::open_or_init(data_dir) {
            Ok(k) => k,
            Err(e) => {
                warn!("the send queue stays closed: {e}");
                return Self::disabled();
            }
        };
        let path = crate::paths::PUSH_OUTBOX.in_dir(data_dir);
        let mut jobs: HashMap<String, OutJob> = HashMap::new();
        let mut garbage = 0usize;
        let mut damaged = false;
        match LogReader::open(&keys, Label::PushOutbox, &path) {
            Ok(Some(mut r)) => loop {
                match r.next_record() {
                    Ok(Some(rec)) => match serde_json::from_slice::<Rec>(&rec) {
                        Ok(Rec::Put { job }) => {
                            if jobs.insert(job.id.clone(), job).is_some() {
                                garbage += 1;
                            }
                        }
                        Ok(Rec::Del { id }) => {
                            garbage += 1 + usize::from(jobs.remove(&id).is_some());
                        }
                        Err(_) => garbage += 1,
                    },
                    Ok(None) => break,
                    Err(_) => {
                        damaged = true;
                        break;
                    }
                }
            },
            Ok(None) => {}
            Err(_) => damaged = true,
        }
        if damaged {
            let tmp = crate::paths::PUSH_OUTBOX_TMP.in_dir(path.parent().unwrap_or(Path::new("")));
            if state_crypto::adopt_staged_log(&keys, Label::PushOutbox, &tmp, &path) {
                // A rewrite died after overwriting the old file and before the
                // rename: the staged copy holds the live jobs.
                return Self::open(data_dir);
            }
            match state_crypto::set_aside(&path) {
                Ok(p) => warn!("the send queue cannot be opened; it was moved to {p:?}"),
                Err(e) => warn!("the send queue cannot be opened: {e}"),
            }
            jobs.clear();
            garbage = 0;
        }
        let ob = Self {
            path,
            keys: Some(keys),
            inner: Mutex::new(Inner {
                jobs,
                writer: None,
                garbage,
            }),
        };
        ob.compact_if_needed(true);
        ob
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every job still wanted, oldest first.
    pub fn jobs(&self) -> Vec<OutJob> {
        let mut v: Vec<OutJob> = self.inner.lock().unwrap().jobs.values().cloned().collect();
        v.sort_by(|a, b| a.created_at_ms.cmp(&b.created_at_ms).then(a.id.cmp(&b.id)));
        v
    }

    pub fn get(&self, id: &str) -> Option<OutJob> {
        self.inner.lock().unwrap().jobs.get(id).cloned()
    }

    /// Store `job` (new, or replacing its earlier state). Durable before it
    /// returns when `durable`.
    pub fn put(&self, job: &OutJob, durable: bool) {
        let Some(keys) = &self.keys else { return };
        let Ok(rec) = serde_json::to_vec(&Rec::Put { job: job.clone() }) else {
            return;
        };
        let mut g = self.inner.lock().unwrap();
        if self.append(keys, &mut g, &rec, durable) {
            if g.jobs.insert(job.id.clone(), job.clone()).is_some() {
                g.garbage += 1;
            }
        } else {
            // Not written: keep it in memory so a compaction does not drop it.
            g.jobs.insert(job.id.clone(), job.clone());
        }
        drop(g);
        self.compact_if_needed(false);
    }

    /// Change a stored job in place (progress, hash) and store the result.
    pub fn update(&self, id: &str, f: impl FnOnce(&mut OutJob)) {
        let Some(mut job) = self.get(id) else { return };
        f(&mut job);
        self.put(&job, false);
    }

    /// Forget a job (the transfer ended).
    pub fn remove(&self, id: &str) {
        let Some(keys) = &self.keys else { return };
        let mut g = self.inner.lock().unwrap();
        if g.jobs.remove(id).is_none() {
            return;
        }
        if let Ok(rec) = serde_json::to_vec(&Rec::Del { id: id.to_owned() }) {
            self.append(keys, &mut g, &rec, false);
        }
        g.garbage += 2;
        drop(g);
        self.compact_if_needed(false);
    }

    /// Rewrite the log now with only the live jobs, overwriting the old file, so
    /// the names and paths of jobs that ended no longer sit in dead records.
    /// Jobs still wanted (queued, running, waiting) are kept as they are.
    pub fn shred_dead(&self) -> Result<(), String> {
        let Some(keys) = &self.keys else {
            return Ok(());
        };
        let mut g = self.inner.lock().unwrap();
        if g.garbage == 0 && !self.path.exists() {
            return Ok(());
        }
        g.writer = None;
        if self.rewrite_live(keys, &g.jobs) {
            g.garbage = 0;
            Ok(())
        } else {
            Err("the send queue could not be rewritten".into())
        }
    }

    fn rewrite_live(&self, keys: &StateKeys, jobs: &HashMap<String, OutJob>) -> bool {
        let tmp = crate::paths::PUSH_OUTBOX_TMP.in_dir(self.path.parent().unwrap_or(Path::new("")));
        let Ok(mut out) = LogRewrite::begin(keys, Label::PushOutbox, &self.path, &tmp) else {
            return false;
        };
        for job in jobs.values() {
            let Ok(rec) = serde_json::to_vec(&Rec::Put { job: job.clone() }) else {
                continue;
            };
            if out.append(&rec).is_err() {
                return false;
            }
        }
        out.commit_shredding().is_ok()
    }

    fn append(&self, keys: &StateKeys, g: &mut Inner, rec: &[u8], durable: bool) -> bool {
        if g.writer.is_none() {
            match LogWriter::open_append(keys, Label::PushOutbox, &self.path) {
                Ok(w) => g.writer = Some(w),
                Err(e) => {
                    warn!("cannot write the send queue: {e}");
                    return false;
                }
            }
        }
        let w = g.writer.as_mut().expect("just set");
        let r = if durable {
            w.append_durable(rec)
        } else {
            w.append(rec)
        };
        if r.is_err() {
            g.writer = None;
            return false;
        }
        true
    }

    /// Rewrite the log with only the live jobs when it has grown mostly out of
    /// dead records.
    fn compact_if_needed(&self, when_any_garbage: bool) {
        let Some(keys) = &self.keys else { return };
        let mut g = self.inner.lock().unwrap();
        let limit = g.jobs.len() * 2 + 256;
        if !(g.garbage > limit || (when_any_garbage && g.garbage > 0)) {
            return;
        }
        g.writer = None;
        if self.rewrite_live(keys, &g.jobs) {
            g.garbage = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(i: usize) -> OutJob {
        OutJob {
            id: format!("{i:04}"),
            contact_id: "c1".into(),
            path: format!("C:/files/報告書{i}.pdf"),
            name: format!("報告書{i}.pdf"),
            size: 1000 + i as u64,
            mtime_ms: 5,
            hash: None,
            offset: 0,
            attempt: 0,
            created_at_ms: i as u64,
        }
    }

    #[test]
    fn jobs_survive_a_reopen_and_removed_ones_do_not() {
        let dir = tempfile::tempdir().unwrap();
        {
            let ob = Outbox::open(dir.path());
            for i in 0..5 {
                ob.put(&job(i), true);
            }
            ob.update("0002", |j| {
                j.offset = 777;
                j.hash = Some("ab".repeat(32));
            });
            ob.remove("0003");
        }
        let ob = Outbox::open(dir.path());
        let ids: Vec<String> = ob.jobs().into_iter().map(|j| j.id).collect();
        assert_eq!(ids, vec!["0000", "0001", "0002", "0004"]);
        let j = ob.get("0002").unwrap();
        assert_eq!(j.offset, 777);
        assert_eq!(j.hash.as_deref(), Some("ab".repeat(32).as_str()));
    }

    #[test]
    fn nothing_readable_is_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        {
            let ob = Outbox::open(dir.path());
            ob.put(&job(1), true);
        }
        let raw = std::fs::read(crate::paths::PUSH_OUTBOX.in_dir(dir.path())).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains("files"), "the path is in the clear");
        assert!(!text.contains("pdf"), "the name is in the clear");
        assert!(!raw.windows(3).any(|w| w == "報".as_bytes()));
    }

    #[test]
    fn log_is_compacted_and_a_torn_tail_is_survived() {
        let dir = tempfile::tempdir().unwrap();
        let p = crate::paths::PUSH_OUTBOX.in_dir(dir.path());
        {
            let ob = Outbox::open(dir.path());
            for round in 0..40 {
                for i in 0..20 {
                    ob.put(&job(i + round * 100), false);
                }
                for i in 0..20 {
                    ob.remove(&format!("{:04}", i + round * 100));
                }
            }
            ob.put(&job(9999), true);
        }
        let big = std::fs::metadata(&p).unwrap().len();
        let ob = Outbox::open(dir.path());
        assert_eq!(ob.len(), 1);
        let small = std::fs::metadata(&p).unwrap().len();
        assert!(small < big, "{small} !< {big}");
        drop(ob);
        let len = std::fs::metadata(&p).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(len - 3)
            .unwrap();
        // The only record is torn: the queue opens (empty) rather than failing.
        let ob = Outbox::open(dir.path());
        assert!(ob.len() <= 1);
    }
}
