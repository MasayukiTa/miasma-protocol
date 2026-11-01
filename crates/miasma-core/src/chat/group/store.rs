//! Files of the group chat: one state document and one message log per group,
//! named by a keyed hash of the group ID so the names say nothing.
//!
//! In ephemeral mode (`history_save = false`) the messages are kept only in a
//! bounded in-memory ring and never written; the state documents are still
//! written (encrypted) so that a restart keeps membership, counters and
//! undelivered messages.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use tracing::warn;

use super::state::GroupState;
use crate::{
    chat::{
        crypto::{file_stem, Rd},
        proto::MAX_TEXT_BYTES,
        store::{StoreError, StoreSettings},
    },
    state_crypto::{self, doc, Label, LogReader, LogRewrite, LogWriter, StateError, StateKeys},
};

const WRITER_CACHE: usize = 8;
const ENTRY_OVERHEAD: usize = 160;

/// One group message as stored and shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMsg {
    /// Position in this device's log (grows with every recorded message).
    pub ord: u64,
    pub outgoing: bool,
    pub sender: [u8; 32],
    /// The sender's counter in this group.
    pub counter: u64,
    pub id: [u8; 16],
    pub sent_ms: u64,
    /// When this device recorded it.
    pub at_ms: u64,
    pub epoch: u32,
    pub text: String,
    /// When another member handed this past message over (ADR-012), the member
    /// who shared it. `None` for a message this device received or sent live.
    /// The outer seal authenticated the sharer, not the original `sender`, so
    /// the UI shows it as a claim by this person.
    pub shared_by: Option<[u8; 32]>,
}

impl GroupMsg {
    fn cost(&self) -> usize {
        self.text.len() + ENTRY_OVERHEAD
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(100 + self.text.len());
        // Version 2 appends the optional "shared by" key; a version-1 record is
        // still read (shared_by defaults to None).
        v.push(2);
        v.extend_from_slice(&self.ord.to_be_bytes());
        v.push(u8::from(self.outgoing));
        v.extend_from_slice(&self.sender);
        v.extend_from_slice(&self.counter.to_be_bytes());
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.sent_ms.to_be_bytes());
        v.extend_from_slice(&self.at_ms.to_be_bytes());
        v.extend_from_slice(&self.epoch.to_be_bytes());
        v.extend_from_slice(&(self.text.len() as u16).to_be_bytes());
        v.extend_from_slice(self.text.as_bytes());
        match self.shared_by {
            Some(by) => {
                v.push(1);
                v.extend_from_slice(&by);
            }
            None => v.push(0),
        }
        v
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Rd::new(b);
        let version = r.u8().ok()?;
        if version != 1 && version != 2 {
            return None;
        }
        let ord = r.u64().ok()?;
        let outgoing = r.u8().ok()? != 0;
        let sender = r.arr::<32>().ok()?;
        let counter = r.u64().ok()?;
        let id = r.arr::<16>().ok()?;
        let sent_ms = r.u64().ok()?;
        let at_ms = r.u64().ok()?;
        let epoch = r.u32().ok()?;
        let n = r.u16().ok()? as usize;
        if n > MAX_TEXT_BYTES {
            return None;
        }
        let text = std::str::from_utf8(r.bytes(n).ok()?).ok()?.to_owned();
        let shared_by = if version >= 2 {
            match r.u8().ok()? {
                0 => None,
                1 => Some(r.arr::<32>().ok()?),
                _ => return None,
            }
        } else {
            None
        };
        if !r.done() {
            return None;
        }
        Some(Self {
            ord,
            outgoing,
            sender,
            counter,
            id,
            sent_ms,
            at_ms,
            epoch,
            text,
            shared_by,
        })
    }
}

struct Inner {
    writers: Vec<([u8; 16], LogWriter, u64)>,
    ring: VecDeque<([u8; 16], GroupMsg)>,
    ring_bytes: usize,
    tick: u64,
}

pub struct GroupStore {
    dir: PathBuf,
    keys: Arc<StateKeys>,
    own_id: [u8; 32],
    settings: StoreSettings,
    inner: Mutex<Inner>,
}

impl GroupStore {
    pub fn open(
        dir: &Path,
        keys: Arc<StateKeys>,
        own_id: [u8; 32],
        settings: StoreSettings,
    ) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir).map_err(StateError::Io)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            keys,
            own_id,
            settings,
            inner: Mutex::new(Inner {
                writers: Vec::new(),
                ring: VecDeque::new(),
                ring_bytes: 0,
                tick: 0,
            }),
        })
    }

    pub fn settings(&self) -> &StoreSettings {
        &self.settings
    }

    fn stem(&self, gid: &[u8; 16]) -> String {
        let mut padded = [0u8; 32];
        padded[..16].copy_from_slice(gid);
        file_stem(&self.own_id, &padded)
    }

    fn state_path(&self, gid: &[u8; 16]) -> PathBuf {
        crate::paths::chat_group_file(&self.dir, &self.stem(gid))
    }

    fn history_path(&self, gid: &[u8; 16]) -> PathBuf {
        crate::paths::chat_group_history_file(&self.dir, &self.stem(gid))
    }

    // ── State documents ──────────────────────────────────────────────────────

    /// Every group on disk. A document that cannot be read is set aside.
    pub fn load_all(&self) -> Vec<GroupState> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        let mut paths: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| crate::paths::is_chat_group_file(p))
            .collect();
        paths.sort();
        for path in paths {
            match doc::read_document(&self.keys, Label::ChatGroups, &path) {
                Ok(bytes) => match GroupState::decode(&bytes) {
                    // The file name must be the one this group maps to.
                    Some(s) if self.state_path(&s.gid()) == path => out.push(s),
                    _ => {
                        warn!("a chat group file is damaged; it was set aside");
                        let _ = state_crypto::set_aside(&path);
                    }
                },
                Err(e) => {
                    warn!("a chat group file cannot be read ({e}); it was set aside");
                    let _ = state_crypto::set_aside(&path);
                }
            }
        }
        out
    }

    pub fn write_state(&self, s: &GroupState) -> Result<(), StoreError> {
        if self.settings.defer_flush {
            return Ok(());
        }
        doc::write_document(
            &self.keys,
            Label::ChatGroups,
            &self.state_path(&s.gid()),
            &s.encode(),
        )?;
        Ok(())
    }

    /// Write regardless of `defer_flush` (tests and shutdown).
    pub fn write_state_now(&self, s: &GroupState) -> Result<(), StoreError> {
        doc::write_document(
            &self.keys,
            Label::ChatGroups,
            &self.state_path(&s.gid()),
            &s.encode(),
        )?;
        Ok(())
    }

    /// Remove every file of a group and forget its messages.
    pub fn delete_group(&self, gid: &[u8; 16]) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        g.writers.retain(|(k, _, _)| k != gid);
        let freed: usize = g
            .ring
            .iter()
            .filter(|(k, _)| k == gid)
            .map(|(_, m)| m.cost())
            .sum();
        g.ring.retain(|(k, _)| k != gid);
        g.ring_bytes = g.ring_bytes.saturating_sub(freed);
        for p in [self.state_path(gid), self.history_path(gid)] {
            if p.exists() {
                state_crypto::overwrite_and_remove(&p).map_err(StateError::Io)?;
            }
        }
        Ok(())
    }

    // ── Messages ─────────────────────────────────────────────────────────────

    fn scan(&self, gid: &[u8; 16], mut f: impl FnMut(GroupMsg)) {
        let path = self.history_path(gid);
        let Ok(Some(mut r)) = LogReader::open(&self.keys, Label::ChatGroupHistory, &path) else {
            return;
        };
        while let Ok(Some(rec)) = r.next_record() {
            if let Some(m) = GroupMsg::decode(&rec) {
                f(m);
            }
        }
    }

    /// The largest `ord` in the saved log (0 when there is none).
    pub fn max_ord(&self, gid: &[u8; 16]) -> (u64, u64) {
        let g = self.inner.lock().unwrap();
        let (mut max, mut n) = (0u64, 0u64);
        if self.settings.history_save {
            self.scan(gid, |m| {
                max = max.max(m.ord);
                n += 1;
            });
        } else {
            for (_, m) in g.ring.iter().filter(|(k, _)| k == gid) {
                max = max.max(m.ord);
                n += 1;
            }
        }
        (max, n)
    }

    /// Append a message to the log of `gid` (or the ring).
    pub fn record(
        &self,
        gid: &[u8; 16],
        m: GroupMsg,
        durable: bool,
        count_after: u64,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        if !self.settings.history_save {
            g.ring_bytes += m.cost();
            g.ring.push_back((*gid, m));
            while g.ring_bytes > self.settings.ephemeral_bytes {
                match g.ring.pop_front() {
                    Some((_, old)) => g.ring_bytes = g.ring_bytes.saturating_sub(old.cost()),
                    None => break,
                }
            }
            return Ok(());
        }
        let rec = m.encode();
        g.tick += 1;
        let tick = g.tick;
        let idx = match g.writers.iter().position(|(k, _, _)| k == gid) {
            Some(i) => i,
            None => {
                if g.writers.len() >= WRITER_CACHE {
                    if let Some(oldest) = g
                        .writers
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, (_, _, used))| *used)
                        .map(|(i, _)| i)
                    {
                        g.writers.remove(oldest);
                    }
                }
                let w = LogWriter::open_append(
                    &self.keys,
                    Label::ChatGroupHistory,
                    &self.history_path(gid),
                )?;
                g.writers.push((*gid, w, tick));
                g.writers.len() - 1
            }
        };
        let entry = &mut g.writers[idx];
        entry.2 = tick;
        let res = if durable && !self.settings.defer_flush {
            entry.1.append_durable(&rec)
        } else {
            entry.1.append(&rec)
        };
        if let Err(e) = res {
            g.writers.remove(idx);
            return Err(e.into());
        }
        let cap = self.settings.max_messages_per_conversation;
        if count_after as usize > cap + cap / 10 {
            let newest = m.ord;
            self.rewrite_locked(&mut g, gid, |x| x.ord + cap as u64 > newest)?;
        }
        Ok(())
    }

    fn rewrite_locked(
        &self,
        g: &mut Inner,
        gid: &[u8; 16],
        mut keep: impl FnMut(&GroupMsg) -> bool,
    ) -> Result<u64, StoreError> {
        g.writers.retain(|(k, _, _)| k != gid);
        let path = self.history_path(gid);
        let tmp = path.with_extension("gmsgs.tmp");
        let Some(mut reader) = LogReader::open(&self.keys, Label::ChatGroupHistory, &path)? else {
            return Ok(0);
        };
        let mut out = LogRewrite::begin(&self.keys, Label::ChatGroupHistory, &path, &tmp)?;
        let mut kept = 0u64;
        while let Some(rec) = reader.next_record()? {
            if let Some(m) = GroupMsg::decode(&rec) {
                if keep(&m) {
                    out.append(&rec)?;
                    kept += 1;
                }
            }
        }
        drop(reader);
        out.commit()?;
        Ok(kept)
    }

    /// Keep only the messages `keep` accepts; returns how many remain.
    pub fn retain(
        &self,
        gid: &[u8; 16],
        mut keep: impl FnMut(&GroupMsg) -> bool,
    ) -> Result<u64, StoreError> {
        let mut g = self.inner.lock().unwrap();
        if !self.settings.history_save {
            let mut freed = 0usize;
            let mut kept = 0u64;
            g.ring.retain(|(k, m)| {
                if k != gid {
                    return true;
                }
                let k = keep(m);
                if k {
                    kept += 1;
                } else {
                    freed += m.cost();
                }
                k
            });
            g.ring_bytes = g.ring_bytes.saturating_sub(freed);
            return Ok(kept);
        }
        self.rewrite_locked(&mut g, gid, keep)
    }

    /// All saved messages of `gid` with `ord < before`, the newest `limit`
    /// of them, oldest first by `ord`.
    pub fn page(&self, gid: &[u8; 16], before: Option<u64>, limit: usize) -> Vec<GroupMsg> {
        let upper = before.unwrap_or(u64::MAX);
        let mut win: Vec<GroupMsg> = Vec::with_capacity(limit.min(64));
        let mut take = |m: GroupMsg| {
            if m.ord >= upper {
                return;
            }
            if win.len() == limit && m.ord < win[0].ord {
                return;
            }
            let at = win.partition_point(|x| x.ord < m.ord);
            if win.get(at).is_some_and(|x| x.ord == m.ord) {
                return;
            }
            win.insert(at, m);
            if win.len() > limit {
                win.remove(0);
            }
        };
        let g = self.inner.lock().unwrap();
        if self.settings.history_save {
            self.scan(gid, &mut take);
        } else {
            for (_, m) in g.ring.iter().filter(|(k, _)| k == gid) {
                take(m.clone());
            }
        }
        win
    }

    pub fn ring_bytes(&self) -> usize {
        self.inner.lock().unwrap().ring_bytes
    }

    pub fn history_file_exists(&self, gid: &[u8; 16]) -> bool {
        self.history_path(gid).exists()
    }

    pub fn close(&self) {
        self.inner.lock().unwrap().writers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path, save: bool) -> GroupStore {
        let keys = Arc::new(StateKeys::from_master_key(&[7; 32]).unwrap());
        GroupStore::open(
            dir,
            keys,
            [1; 32],
            StoreSettings {
                history_save: save,
                ..StoreSettings::default()
            },
        )
        .unwrap()
    }

    fn msg(ord: u64, text: &str) -> GroupMsg {
        GroupMsg {
            ord,
            outgoing: ord % 2 == 0,
            sender: [9; 32],
            counter: ord,
            id: [ord as u8; 16],
            sent_ms: 100 + ord,
            at_ms: 200 + ord,
            epoch: 2,
            text: text.to_owned(),
            shared_by: None,
        }
    }

    #[test]
    fn group_msg_keeps_shared_by_and_still_reads_version_one() {
        // A shared message round-trips with the member who handed it over.
        let mut m = msg(4, "from the past");
        m.shared_by = Some([5; 32]);
        assert_eq!(GroupMsg::decode(&m.encode()).unwrap(), m);
        // A plain message round-trips with shared_by None.
        let plain = msg(5, "live");
        assert_eq!(GroupMsg::decode(&plain.encode()).unwrap(), plain);
        // A version-1 record (no shared-by byte) still decodes to None. Build
        // one by hand: a version-2 encode of a plain message, with the trailing
        // "0" byte removed and the version stamped back to 1.
        let mut v1 = plain.encode();
        assert_eq!(*v1.last().unwrap(), 0, "plain message ends with a 0 marker");
        v1.truncate(v1.len() - 1);
        v1[0] = 1;
        let back = GroupMsg::decode(&v1).expect("a version 1 record");
        assert_eq!(back.shared_by, None);
        assert_eq!(back.text, "live");
    }

    #[test]
    fn messages_round_trip_and_reject_damage() {
        let m = msg(3, "こんにちは");
        let b = m.encode();
        assert_eq!(GroupMsg::decode(&b), Some(m));
        for n in 0..b.len() {
            assert!(GroupMsg::decode(&b[..n]).is_none(), "prefix {n}");
        }
    }

    #[test]
    fn history_pages_newest_first_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let gid = [5u8; 16];
        {
            let s = store(dir.path(), true);
            for i in 1..=30 {
                s.record(&gid, msg(i, &format!("m{i}")), true, i).unwrap();
            }
            s.close();
        }
        let s = store(dir.path(), true);
        let page = s.page(&gid, None, 10);
        let ords: Vec<u64> = page.iter().map(|m| m.ord).collect();
        assert_eq!(ords, (21..=30).collect::<Vec<_>>());
        let older = s.page(&gid, Some(21), 5);
        assert_eq!(older.first().unwrap().ord, 16);
        assert_eq!(s.max_ord(&gid), (30, 30));
    }

    #[test]
    fn stored_bytes_do_not_contain_the_text() {
        let dir = tempfile::tempdir().unwrap();
        let gid = [6u8; 16];
        let s = store(dir.path(), true);
        s.record(&gid, msg(1, "SECRET-GROUP-TEXT-12345"), true, 1)
            .unwrap();
        s.close();
        for e in std::fs::read_dir(dir.path()).unwrap().flatten() {
            let bytes = std::fs::read(e.path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("SECRET-GROUP-TEXT"));
        }
    }

    #[test]
    fn ephemeral_mode_writes_no_message_file_and_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let gid = [8u8; 16];
        let keys = Arc::new(StateKeys::from_master_key(&[7; 32]).unwrap());
        let s = GroupStore::open(
            dir.path(),
            keys,
            [1; 32],
            StoreSettings {
                history_save: false,
                ephemeral_bytes: 4096,
                ..StoreSettings::default()
            },
        )
        .unwrap();
        for i in 1..=200 {
            s.record(&gid, msg(i, &"x".repeat(100)), false, i).unwrap();
        }
        assert!(!s.history_file_exists(&gid));
        assert!(s.ring_bytes() <= 4096);
        assert!(!s.page(&gid, None, 50).is_empty());
    }

    #[test]
    fn retain_and_delete_group() {
        let dir = tempfile::tempdir().unwrap();
        let gid = [4u8; 16];
        let s = store(dir.path(), true);
        for i in 1..=10 {
            s.record(&gid, msg(i, "t"), true, i).unwrap();
        }
        assert_eq!(s.retain(&gid, |m| m.ord > 5).unwrap(), 5);
        assert_eq!(s.page(&gid, None, 50).len(), 5);
        s.delete_group(&gid).unwrap();
        assert!(!s.history_file_exists(&gid));
        assert!(s.page(&gid, None, 50).is_empty());
    }
}
