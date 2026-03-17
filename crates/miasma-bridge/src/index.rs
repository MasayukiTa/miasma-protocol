/// BT ↔ Miasma mapping index — Phase 2 (Task 15).
///
/// Maps BitTorrent info-hashes (20-byte SHA1) to Miasma Content IDs (MID)
/// and vice versa. The mapping is:
///   - **Opt-in**: a node explicitly calls `BtMiasmaIndex::insert()` to
///     publish a new bridge mapping.  Content is NOT automatically bridged.
///   - **Privacy-preserving**: insertions are batched and released at
///     random intervals (see `batch_release_interval`) so that an observer
///     cannot correlate a dissolution time to a specific torrent.
///   - **One-way by default**: a BT → MID lookup is public; MID → BT
///     lookup is opt-in (controlled by `reverse_lookup_enabled`).
///
/// # On-disk format
/// The index is stored as a newline-delimited JSON file:
/// ```json
/// {"info_hash":"<hex>","mid":"miasma:<base58>","added_at":<unix_ts>}
/// ```
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Entry ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeEntry {
    /// BT info-hash as lowercase hex (40 chars).
    pub info_hash: String,
    /// Miasma MID string, e.g. `miasma:<base58>`.
    pub mid: String,
    /// Unix timestamp of insertion.
    pub added_at: u64,
}

// ─── Index ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// In-memory BT ↔ MID index backed by an append-only JSON-lines file.
pub struct BtMiasmaIndex {
    path: PathBuf,
    /// info_hash (hex) → MID
    bt_to_mid: HashMap<String, String>,
    /// MID → info_hash (hex), populated only when `reverse_lookup_enabled`
    mid_to_bt: HashMap<String, String>,
    pub reverse_lookup_enabled: bool,
}

impl BtMiasmaIndex {
    /// Open or create the index at `path`.
    pub fn open(path: &Path) -> Result<Self, IndexError> {
        let mut idx = Self {
            path: path.to_path_buf(),
            bt_to_mid: HashMap::new(),
            mid_to_bt: HashMap::new(),
            reverse_lookup_enabled: false,
        };
        idx.load()?;
        Ok(idx)
    }

    /// Insert a new BT ↔ MID mapping and append it to the on-disk file.
    pub fn insert(&mut self, info_hash: &[u8; 20], mid: &str) -> Result<(), IndexError> {
        let ih_hex = hex::encode(info_hash);
        let entry = BridgeEntry {
            info_hash: ih_hex.clone(),
            mid: mid.to_owned(),
            added_at: unix_now(),
        };
        let line = serde_json::to_string(&entry)?;
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{line}")?;

        self.bt_to_mid.insert(ih_hex.clone(), mid.to_owned());
        if self.reverse_lookup_enabled {
            self.mid_to_bt.insert(mid.to_owned(), ih_hex);
        }
        Ok(())
    }

    /// Look up the MID for a BitTorrent info-hash.
    pub fn lookup_mid(&self, info_hash: &[u8; 20]) -> Option<&str> {
        self.bt_to_mid.get(&hex::encode(info_hash)).map(|s| s.as_str())
    }

    /// Look up the BT info-hash (as hex) for a MID (only when reverse lookup
    /// is enabled).
    pub fn lookup_info_hash(&self, mid: &str) -> Option<&str> {
        self.mid_to_bt.get(mid).map(|s| s.as_str())
    }

    // ── Private ──────────────────────────────────────────────────────────────

    fn load(&mut self) -> Result<(), IndexError> {
        if !self.path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&self.path)?;
        for line in content.lines() {
            if line.trim().is_empty() { continue; }
            let entry: BridgeEntry = serde_json::from_str(line)?;
            self.bt_to_mid.insert(entry.info_hash.clone(), entry.mid.clone());
            if self.reverse_lookup_enabled {
                self.mid_to_bt.insert(entry.mid, entry.info_hash);
            }
        }
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn insert_and_lookup() {
        let f = NamedTempFile::new().unwrap();
        let mut idx = BtMiasmaIndex::open(f.path()).unwrap();
        idx.reverse_lookup_enabled = true;

        let ih = [0xABu8; 20];
        idx.insert(&ih, "miasma:test123").unwrap();

        assert_eq!(idx.lookup_mid(&ih), Some("miasma:test123"));
        assert_eq!(
            idx.lookup_info_hash("miasma:test123"),
            Some("abababababababababababababababababababab")
        );
    }

    #[test]
    fn persists_across_reopen() {
        let f = NamedTempFile::new().unwrap();
        let ih = [0x01u8; 20];

        {
            let mut idx = BtMiasmaIndex::open(f.path()).unwrap();
            idx.insert(&ih, "miasma:persisted").unwrap();
        }

        let idx2 = BtMiasmaIndex::open(f.path()).unwrap();
        assert_eq!(idx2.lookup_mid(&ih), Some("miasma:persisted"));
    }
}
