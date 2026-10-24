//! The send journal: an append-only log of what a publish has finished.
//!
//! A publish of a big file takes long enough that it must survive being stopped.
//! Each completed segment appends **one record** (an encrypted JSON line, see
//! `state_crypto`) — never a rewrite of the whole file, which would cost
//! O(segments) per segment. A record that was only half written when the
//! process died is simply ignored on load. The key comes from the
//! `master.key` found above the folder the journal lives in.
//!
//! It records where the publish got to, never the password. It is also never
//! trusted by itself: on resume the source file is re-read and every completed
//! segment re-checked against its recorded hash, and the shares are checked to
//! still be in the local store.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{manifest::SegmentEntry, protection::Protection};
use crate::{
    network::types::ShardLocation,
    state_crypto::{self, Label, LogReader, LogWriter, StateKeys},
    MiasmaError,
};

pub const PUBLISH_JOURNAL_VERSION: u8 = 2;

/// First line: what is being published, and how.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishHeader {
    pub version: u8,
    /// The source path as the publish was started with.
    pub path: String,
    pub file_len: u64,
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
    pub data_shards: u8,
    pub total_shards: u8,
    pub segment_size: u32,
    /// `miasma:<base58>`. Recorded so a resume need not hash the file again.
    pub mid: String,
    /// Public parameters only (Argon2 cost, salt, wrong-password check).
    pub protection: Protection,
    pub started_at: u64,
    /// The object suite this publish writes. 0 (the serde default) means a
    /// journal written before this field existed, which is always Suite1. A
    /// resumed publish keeps the suite it started with.
    #[serde(default)]
    pub suite: u16,
}

/// One line per completed segment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishSegmentRecord {
    pub entry: SegmentEntry,
    /// Pieces another peer accepted, with the address *that peer* announced.
    /// The publisher's own copies are not recorded: their announced addresses
    /// can change when the daemon restarts, so they are rebuilt from the current
    /// ones on resume.
    pub remote: Vec<ShardLocation>,
}

#[derive(Debug, Clone)]
pub struct PublishJournal {
    pub header: PublishHeader,
    pub segments: Vec<PublishSegmentRecord>,
}

/// Where the journal for the file at `source` lives inside `dir`.
pub fn publish_journal_path(dir: &Path, source: &Path) -> PathBuf {
    let h = blake3::hash(source.to_string_lossy().as_bytes());
    dir.join(crate::paths::send_journal_name(
        &hex::encode(h.as_bytes())[..32],
    ))
}

fn to_record<T: Serialize>(v: &T) -> Result<Vec<u8>, MiasmaError> {
    serde_json::to_vec(v).map_err(|e| MiasmaError::Serialization(e.to_string()))
}

impl PublishJournal {
    /// Start a new journal, replacing any previous one.
    pub fn create(path: &Path, header: &PublishHeader) -> Result<(), MiasmaError> {
        let keys = StateKeys::for_state_file(path)?;
        let mut w = LogWriter::create_file(&keys, Label::TransferJournal, path)?;
        w.append_durable(&to_record(header)?)?;
        Ok(())
    }

    /// Record one finished segment. One record, made durable.
    pub fn append(path: &Path, record: &PublishSegmentRecord) -> Result<(), MiasmaError> {
        if !path.exists() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
        }
        let keys = StateKeys::for_state_file(path)?;
        let mut w = LogWriter::open_append(&keys, Label::TransferJournal, path)?;
        w.append_durable(&to_record(record)?)?;
        Ok(())
    }

    /// Read a journal. Returns `None` if there is no usable header. A damaged or
    /// half-written *trailing* record is dropped; nothing after a bad record is
    /// used, because segments must be contiguous from 0.
    pub fn load(path: &Path) -> Option<Self> {
        let keys = StateKeys::for_state_file(path).ok()?;
        // A journal written in plaintext by an earlier version is converted here.
        let _ = state_crypto::migrate::migrate_log(&keys, Label::TransferJournal, path);
        let mut reader = LogReader::open(&keys, Label::TransferJournal, path).ok()??;
        let header: PublishHeader = serde_json::from_slice(&reader.next_record().ok()??).ok()?;
        if header.version != PUBLISH_JOURNAL_VERSION {
            return None;
        }
        let mut segments: Vec<PublishSegmentRecord> = Vec::new();
        while let Ok(Some(rec)) = reader.next_record() {
            let Ok(rec) = serde_json::from_slice::<PublishSegmentRecord>(&rec) else {
                break;
            };
            if rec.entry.index as usize != segments.len() {
                break;
            }
            segments.push(rec);
        }
        Some(Self { header, segments })
    }

    /// Keep only the first `keep` segments (used when a resume finds that later
    /// ones no longer check out). Rewrites the file.
    pub fn truncate_to(&self, path: &Path, keep: usize) -> Result<(), MiasmaError> {
        let keys = StateKeys::for_state_file(path)?;
        let mut w = LogWriter::create_file(&keys, Label::TransferJournal, path)?;
        w.append(&to_record(&self.header)?)?;
        for rec in self.segments.iter().take(keep) {
            w.append(&to_record(rec)?)?;
        }
        w.sync()?;
        Ok(())
    }

    /// Overwrite and delete the journal (it names the file being published).
    pub fn remove(path: &Path) {
        if state_crypto::overwrite_and_remove(path).is_err() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A data directory with a master key, so the journal can be encrypted.
    fn test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        crate::state_crypto::provision_master_key(dir.path()).unwrap();
        dir
    }

    fn header() -> PublishHeader {
        PublishHeader {
            version: PUBLISH_JOURNAL_VERSION,
            path: "C:/data/big.bin".into(),
            file_len: 100 * 1024 * 1024 * 1024,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 123,
            data_shards: 10,
            total_shards: 12,
            segment_size: 64 * 1024 * 1024,
            mid: "miasma:abc".into(),
            protection: Protection::None,
            started_at: 1,
            suite: 1,
        }
    }

    fn record(i: u32) -> PublishSegmentRecord {
        PublishSegmentRecord {
            entry: SegmentEntry {
                index: i,
                plaintext_len: 64,
                plain_hash: [i as u8; 32],
                piece_ids: vec![[i as u8; 32]; 12],
            },
            remote: vec![],
        }
    }

    #[test]
    fn a_journal_round_trips_header_and_segments_in_order() {
        let dir = test_dir();
        let p = dir.path().join("j.jsonl");
        PublishJournal::create(&p, &header()).unwrap();
        for i in 0..5 {
            PublishJournal::append(&p, &record(i)).unwrap();
        }
        let j = PublishJournal::load(&p).unwrap();
        assert_eq!(j.header, header());
        assert_eq!(j.segments.len(), 5);
        assert_eq!(j.segments[3], record(3));
    }

    #[test]
    fn a_half_written_last_record_is_ignored_not_fatal() {
        let dir = test_dir();
        let p = dir.path().join("j.jsonl");
        PublishJournal::create(&p, &header()).unwrap();
        PublishJournal::append(&p, &record(0)).unwrap();
        PublishJournal::append(&p, &record(1)).unwrap();
        PublishJournal::append(&p, &record(2)).unwrap();
        // The process died part-way through writing segment 2.
        let len = std::fs::metadata(&p).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(len - 9)
            .unwrap();
        let j = PublishJournal::load(&p).unwrap();
        assert_eq!(j.segments.len(), 2);
        // The next append continues cleanly after the torn record.
        PublishJournal::append(&p, &record(2)).unwrap();
        assert_eq!(PublishJournal::load(&p).unwrap().segments.len(), 3);
    }

    #[test]
    fn nothing_after_a_gap_is_used() {
        let dir = test_dir();
        let p = dir.path().join("j.jsonl");
        PublishJournal::create(&p, &header()).unwrap();
        PublishJournal::append(&p, &record(0)).unwrap();
        PublishJournal::append(&p, &record(2)).unwrap(); // 1 is missing
        assert_eq!(PublishJournal::load(&p).unwrap().segments.len(), 1);
    }

    #[test]
    fn a_missing_empty_or_unreadable_header_means_no_journal() {
        let dir = test_dir();
        assert!(PublishJournal::load(&dir.path().join("nope")).is_none());
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(PublishJournal::load(&empty).is_none());
        let bad = dir.path().join("bad");
        std::fs::write(&bad, b"not json\n").unwrap();
        assert!(PublishJournal::load(&bad).is_none());
        let mut h = header();
        h.version = 77;
        let wrong = dir.path().join("wrong");
        PublishJournal::create(&wrong, &h).unwrap();
        assert!(PublishJournal::load(&wrong).is_none());
    }

    #[test]
    fn truncating_keeps_only_the_first_n_segments() {
        let dir = test_dir();
        let p = dir.path().join("j.jsonl");
        PublishJournal::create(&p, &header()).unwrap();
        for i in 0..6 {
            PublishJournal::append(&p, &record(i)).unwrap();
        }
        let j = PublishJournal::load(&p).unwrap();
        j.truncate_to(&p, 3).unwrap();
        let again = PublishJournal::load(&p).unwrap();
        assert_eq!(again.segments.len(), 3);
        assert_eq!(again.header, header());
    }

    #[test]
    fn appending_costs_one_record_not_a_rewrite() {
        let dir = test_dir();
        let p = dir.path().join("j.jsonl");
        PublishJournal::create(&p, &header()).unwrap();
        PublishJournal::append(&p, &record(0)).unwrap();
        let before = std::fs::metadata(&p).unwrap().len();
        PublishJournal::append(&p, &record(1)).unwrap();
        let grew = std::fs::metadata(&p).unwrap().len() - before;
        let body = to_record(&record(1)).unwrap().len() as u64;
        // length prefix + nonce + ciphertext + tag
        assert_eq!(
            grew,
            4 + 24 + body + 16,
            "an append adds exactly its own record"
        );
    }

    #[test]
    fn the_journal_carries_no_password() {
        let raw = String::from_utf8(to_record(&header()).unwrap())
            .unwrap()
            .to_lowercase();
        assert!(!raw.contains("password\":\"") && !raw.contains("secret"));
    }

    #[test]
    fn journal_names_are_per_source_path() {
        let d = Path::new("transfers");
        let a = publish_journal_path(d, Path::new("C:/a.bin"));
        let b = publish_journal_path(d, Path::new("C:/b.bin"));
        assert_ne!(a, b);
        assert_eq!(a, publish_journal_path(d, Path::new("C:/a.bin")));
        let name = a.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("send-") && name.ends_with(".jsonl"));
        assert!(!name.contains(['/', '\\', ':']));
    }
}
