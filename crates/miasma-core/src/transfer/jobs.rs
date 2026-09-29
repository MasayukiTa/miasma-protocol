//! Transfer jobs that outlive the request that started them.
//!
//! A receive runs as a background task inside the daemon, so a CLI that
//! disconnects — or is killed — does not stop it; that is the torrent-client
//! behaviour. Anything can read its progress by id, cancel it, or list all
//! transfers, including ones that were paused by an earlier daemon process and
//! exist only as a journal on disk.
//!
//! One registry per data directory, found through [`registry_for`], so the
//! daemon's request handler needs no new parameter and two daemons in one test
//! process never share jobs.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use zeroize::Zeroizing;

use super::{
    journal::ReceiveJournal,
    progress::{Phase, TransferProgress, TransferState, TransferStatus},
};
use crate::{crypto::hash::ContentId, network::MiasmaCoordinator};

pub struct TransferRegistry {
    data_dir: PathBuf,
    jobs: Mutex<HashMap<String, Arc<TransferProgress>>>,
}

static REGISTRIES: OnceLock<Mutex<HashMap<PathBuf, Arc<TransferRegistry>>>> = OnceLock::new();

/// The registry for the daemon that owns `data_dir`.
pub fn registry_for(data_dir: &Path) -> Arc<TransferRegistry> {
    let all = REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()));
    all.lock()
        .unwrap()
        .entry(data_dir.to_path_buf())
        .or_insert_with(|| {
            Arc::new(TransferRegistry {
                data_dir: data_dir.to_path_buf(),
                jobs: Mutex::new(HashMap::new()),
            })
        })
        .clone()
}

impl TransferRegistry {
    /// Where receive journals live.
    pub fn journal_dir(&self) -> PathBuf {
        self.data_dir.join("transfers")
    }

    /// Start (or resume) receiving `mid` into `output_path` in the background.
    ///
    /// Idempotent while a transfer for the same MID is running: it returns the
    /// same id and starts nothing. A finished, failed, paused or cancelled job
    /// is replaced by the new run — which resumes from its journal unless
    /// `restart` is set.
    pub fn start_receive(
        &self,
        coord: Arc<MiasmaCoordinator>,
        mid: ContentId,
        output_path: PathBuf,
        password: Option<Zeroizing<String>>,
        restart: bool,
    ) -> String {
        let id = mid.to_string();
        let progress = {
            let mut jobs = self.jobs.lock().unwrap();
            if let Some(existing) = jobs.get(&id) {
                if existing.snapshot().state == TransferState::Running {
                    return id;
                }
            }
            let p = TransferProgress::new(id.clone());
            jobs.insert(id.clone(), p.clone());
            p
        };

        let journal_dir = self.journal_dir();
        let watched = progress.clone();
        let task = tokio::spawn(async move {
            // The outcome is recorded in `progress` by the engine itself.
            let _ = coord
                .receive_file(
                    &mid,
                    &output_path,
                    password,
                    &journal_dir,
                    restart,
                    progress,
                )
                .await;
        });
        // If the task panics the progress cell would say Running forever.
        tokio::spawn(async move {
            if let Err(e) = task.await {
                watched.set_state(
                    TransferState::Failed,
                    Some(format!("transfer task ended abnormally: {e}")),
                    true,
                );
            }
        });
        id
    }

    /// Current status of one transfer: the live job if there is one, otherwise
    /// a paused transfer known only from its journal.
    pub fn status(&self, id: &str) -> Option<TransferStatus> {
        if let Some(p) = self.jobs.lock().unwrap().get(id) {
            return Some(p.snapshot());
        }
        self.journal_statuses().into_iter().find(|s| s.mid == id)
    }

    /// Every transfer: live jobs first, then journals with no live job.
    pub fn list(&self) -> Vec<TransferStatus> {
        let mut out: Vec<TransferStatus> = self
            .jobs
            .lock()
            .unwrap()
            .values()
            .map(|p| p.snapshot())
            .collect();
        let live: std::collections::HashSet<String> = out.iter().map(|s| s.mid.clone()).collect();
        out.extend(
            self.journal_statuses()
                .into_iter()
                .filter(|s| !live.contains(&s.mid)),
        );
        out.sort_by(|a, b| a.mid.cmp(&b.mid));
        out
    }

    /// Ask a running transfer to stop at its next safe point. Its partial file
    /// and journal are kept. Returns `false` if there is no such live job.
    pub fn cancel(&self, id: &str) -> bool {
        match self.jobs.lock().unwrap().get(id) {
            Some(p) if p.snapshot().state == TransferState::Running => {
                p.cancel();
                true
            }
            _ => false,
        }
    }

    /// Transfers that exist only as journals (left by an earlier process).
    fn journal_statuses(&self) -> Vec<TransferStatus> {
        let Ok(entries) = std::fs::read_dir(self.journal_dir()) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("recv-") && n.ends_with(".json")
            })
            .filter_map(|e| ReceiveJournal::load(&e.path()))
            .map(|j| status_from_journal(&j))
            .collect()
    }
}

/// What a journal alone can tell you: how far it got, and that it can resume.
pub fn status_from_journal(j: &ReceiveJournal) -> TransferStatus {
    TransferStatus {
        mid: j.mid.clone(),
        phase: Phase::Transferring,
        state: TransferState::Paused,
        segments_done: j.next_segment,
        segments_total: j.segment_count,
        bytes_done: j.bytes_done,
        bytes_total: j.total_bytes,
        rate_bps: 0.0,
        eta_secs: None,
        elapsed_secs: 0.0,
        fetch_ms: 0,
        decode_ms: 0,
        write_ms: 0,
        pieces_fetched: 0,
        pieces_rejected: 0,
        segment_retries: 0,
        resumed_from_segment: j.next_segment,
        last_error: j.last_error.clone(),
        resumable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::journal::{journal_path, JOURNAL_VERSION};

    fn journal(mid: &ContentId, next: u32) -> ReceiveJournal {
        ReceiveJournal {
            version: JOURNAL_VERSION,
            mid: mid.to_string(),
            output_path: "out.bin".into(),
            part_path: "out.bin.part".into(),
            data_shards: 4,
            total_shards: 6,
            segment_count: 10,
            total_bytes: 10_000,
            manifest_hash: None,
            next_segment: next,
            bytes_done: next as u64 * 1000,
            started_at: 1,
            updated_at: 2,
            last_error: Some("holder went away".into()),
        }
    }

    #[test]
    fn one_registry_per_data_directory() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        assert!(Arc::ptr_eq(
            &registry_for(a.path()),
            &registry_for(a.path())
        ));
        assert!(!Arc::ptr_eq(
            &registry_for(a.path()),
            &registry_for(b.path())
        ));
    }

    #[test]
    fn a_journal_left_by_an_earlier_process_is_listed_as_paused_and_resumable() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry_for(dir.path());
        let mid = ContentId::compute(b"left behind", b"p");
        journal(&mid, 4)
            .save(&journal_path(&reg.journal_dir(), &mid))
            .unwrap();

        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        let s = &listed[0];
        assert_eq!(s.mid, mid.to_string());
        assert_eq!(s.state, TransferState::Paused);
        assert!(s.resumable);
        assert_eq!((s.segments_done, s.segments_total), (4, 10));
        assert_eq!((s.bytes_done, s.bytes_total), (4_000, 10_000));
        assert_eq!(s.last_error.as_deref(), Some("holder went away"));

        // And it can be looked up by id even though no job is live.
        assert_eq!(reg.status(&mid.to_string()).unwrap().segments_done, 4);
    }

    #[test]
    fn an_unknown_id_has_no_status_and_cannot_be_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry_for(dir.path());
        assert!(reg.status("miasma:nope").is_none());
        assert!(!reg.cancel("miasma:nope"));
        assert!(reg.list().is_empty());
    }

    #[test]
    fn corrupt_journals_are_ignored_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry_for(dir.path());
        std::fs::create_dir_all(reg.journal_dir()).unwrap();
        std::fs::write(reg.journal_dir().join("recv-garbage.json"), b"{ nope").unwrap();
        assert!(reg.list().is_empty());
    }
}
