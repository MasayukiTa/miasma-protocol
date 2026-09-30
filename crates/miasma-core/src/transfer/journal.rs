//! The receive journal: what a resumed transfer needs to know.
//!
//! One small JSON file per transfer, replaced atomically (write a temp file,
//! then rename) after every completed segment. It records *where the transfer
//! got to*, never the password, and it is never trusted on its own: on resume
//! the partial file itself is re-read and re-verified against the manifest.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{crypto::hash::ContentId, MiasmaError};

pub const JOURNAL_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveJournal {
    pub version: u8,
    /// `miasma:<base58>` form.
    pub mid: String,
    pub output_path: String,
    pub part_path: String,
    pub data_shards: u8,
    pub total_shards: u8,
    pub segment_count: u32,
    pub total_bytes: u64,
    /// Hex of `TransferManifest::manifest_hash`; `None` for a legacy record.
    /// A journal is only resumed against the manifest it was written for.
    pub manifest_hash: Option<String>,
    /// Segments `0..next_segment` are complete in the `.part` file.
    pub next_segment: u32,
    /// Bytes of plaintext those segments occupy.
    pub bytes_done: u64,
    pub started_at: u64,
    pub updated_at: u64,
    pub last_error: Option<String>,
    /// The share ID the transfer was started from, if any (public, not a
    /// secret). A resume then keeps checking the publisher; absent in journals
    /// written before share IDs, and for a transfer started from a bare MID.
    #[serde(default)]
    pub share_id: Option<String>,
}

/// Where the journal for `mid` lives inside `dir`. Base58 is filesystem-safe.
pub fn journal_path(dir: &Path, mid: &ContentId) -> PathBuf {
    dir.join(format!(
        "recv-{}.json",
        bs58::encode(mid.as_bytes()).into_string()
    ))
}

/// The partial file next to the final output.
pub fn part_path_for(output: &Path) -> PathBuf {
    let mut name = output
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".part");
    output.with_file_name(name)
}

impl ReceiveJournal {
    /// Load a journal. A missing or unreadable file is `None`: the transfer
    /// then simply starts from the beginning, which is always safe.
    pub fn load(path: &Path) -> Option<Self> {
        let raw = std::fs::read_to_string(path).ok()?;
        let journal: Self = serde_json::from_str(&raw).ok()?;
        (journal.version == JOURNAL_VERSION).then_some(journal)
    }

    /// Replace the journal atomically.
    pub fn save(&self, path: &Path) -> Result<(), MiasmaError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn remove(path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ReceiveJournal {
        ReceiveJournal {
            version: JOURNAL_VERSION,
            mid: "miasma:abc".into(),
            output_path: "C:/out/file.bin".into(),
            part_path: "C:/out/file.bin.part".into(),
            data_shards: 10,
            total_shards: 12,
            segment_count: 1600,
            total_bytes: 100 * 1024 * 1024 * 1024,
            manifest_hash: Some("ab".repeat(32)),
            next_segment: 42,
            bytes_done: 42 * 64 * 1024 * 1024,
            started_at: 1,
            updated_at: 2,
            last_error: None,
            share_id: Some("miasma-share:abc".into()),
        }
    }

    #[test]
    fn a_journal_written_before_share_ids_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.json");
        let mut value = serde_json::to_value(sample()).unwrap();
        value.as_object_mut().unwrap().remove("share_id");
        std::fs::write(&path, value.to_string()).unwrap();
        let back = ReceiveJournal::load(&path).expect("loads without the field");
        assert_eq!(back.share_id, None);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transfers").join("j.json");
        let j = sample();
        j.save(&path).unwrap();
        assert_eq!(ReceiveJournal::load(&path), Some(j));
    }

    #[test]
    fn a_missing_corrupt_or_wrong_version_journal_loads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ReceiveJournal::load(&dir.path().join("nope.json")).is_none());

        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, b"{ not json").unwrap();
        assert!(ReceiveJournal::load(&bad).is_none());

        let wrong = dir.path().join("wrong.json");
        let mut j = sample();
        j.version = 99;
        j.save(&wrong).unwrap();
        assert!(ReceiveJournal::load(&wrong).is_none());
    }

    #[test]
    fn saving_replaces_the_previous_journal_without_leaving_a_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.json");
        let mut j = sample();
        j.save(&path).unwrap();
        j.next_segment = 43;
        j.save(&path).unwrap();
        assert_eq!(ReceiveJournal::load(&path).unwrap().next_segment, 43);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn the_journal_carries_no_password_field() {
        // Guards against ever adding one: the serialized form is the whole record.
        let raw = serde_json::to_string(&sample()).unwrap().to_lowercase();
        assert!(!raw.contains("password"));
        assert!(!raw.contains("secret"));
    }

    #[test]
    fn journal_names_are_per_mid_and_filesystem_safe() {
        let dir = Path::new("transfers");
        let a = ContentId::compute(b"a", b"p");
        let b = ContentId::compute(b"b", b"p");
        let pa = journal_path(dir, &a);
        assert_ne!(pa, journal_path(dir, &b));
        let name = pa.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("recv-") && name.ends_with(".json"));
        assert!(!name.contains(':') && !name.contains('/'));
    }

    #[test]
    fn the_part_file_sits_next_to_the_output() {
        assert_eq!(
            part_path_for(Path::new("C:/out/file.bin")),
            PathBuf::from("C:/out/file.bin.part")
        );
        assert_eq!(
            part_path_for(Path::new("noext")),
            PathBuf::from("noext.part")
        );
    }
}
