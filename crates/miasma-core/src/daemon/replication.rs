//! Persistent replication queue.
//!
//! Tracks DHT records that were stored locally but have not yet been
//! acknowledged by any remote Kademlia node.  The daemon retries
//! re-announcement periodically until at least one remote peer confirms
//! receipt (indicated by `PutRecord(Ok(_))` in the Kademlia event loop).

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::network::types::DhtRecord;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const QUEUE_FILE: &str = "replication_queue.json";

// ─── PendingReplication ───────────────────────────────────────────────────────

/// A content item whose DHT record is stored locally but may not yet have
/// been replicated to any remote Kademlia peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReplication {
    /// Human-readable MID (for logging and status display).
    pub mid_str: String,
    /// Full DHT record — re-used verbatim on re-announcement attempts.
    pub record: DhtRecord,
    /// UNIX timestamp (seconds) when the item was first published.
    pub published_at: u64,
    /// Total number of announce attempts so far (including the first).
    pub attempt_count: u32,
    /// UNIX timestamp of the most recent attempt (0 = never attempted).
    pub last_attempt_secs: u64,
    /// True once at least one remote Kademlia peer acknowledged the PUT.
    pub replicated: bool,
}

impl PendingReplication {
    pub fn new(mid_str: String, record: DhtRecord) -> Self {
        Self {
            mid_str,
            record,
            published_at: now_secs(),
            attempt_count: 0,
            last_attempt_secs: 0,
            replicated: false,
        }
    }
}

// ─── ReplicationQueue ────────────────────────────────────────────────────────

/// Durable, append-able list of content items awaiting DHT replication.
///
/// Loaded from `<data_dir>/replication_queue.json` at daemon startup.
/// Flushed to disk after every mutation so a crash does not silently
/// forget un-replicated content.
pub struct ReplicationQueue {
    items: Vec<PendingReplication>,
    path: PathBuf,
}

impl ReplicationQueue {
    /// Load from disk, or start with an empty queue.
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(QUEUE_FILE);
        let items = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            serde_json::from_str::<Vec<PendingReplication>>(&raw).unwrap_or_else(|e| {
                warn!("replication queue corrupt, starting fresh: {e}");
                vec![]
            })
        } else {
            vec![]
        };
        info!(
            path = %path.display(),
            items = items.len(),
            "replication queue loaded"
        );
        Ok(Self { items, path })
    }

    fn save(&self) -> Result<()> {
        let raw = serde_json::to_string_pretty(&self.items).context("serialize queue")?;
        std::fs::write(&self.path, raw)
            .with_context(|| format!("write {}", self.path.display()))
    }

    /// Add an item (deduplicates by `mid_digest`) and flush to disk.
    pub fn push(&mut self, item: PendingReplication) -> Result<()> {
        self.items
            .retain(|i| i.record.mid_digest != item.record.mid_digest);
        self.items.push(item);
        info!(
            pending = self.pending_count(),
            "replication queue updated"
        );
        self.save()
    }

    /// Mark the given item as replicated and flush.
    pub fn mark_replicated(&mut self, mid_digest: &[u8; 32]) -> Result<()> {
        let mut changed = false;
        for item in &mut self.items {
            if &item.record.mid_digest == mid_digest && !item.replicated {
                item.replicated = true;
                changed = true;
                info!(mid = %item.mid_str, "replication confirmed by remote peer");
            }
        }
        if changed {
            self.save()?;
        }
        Ok(())
    }

    /// Increment attempt counter and update timestamp, then flush.
    pub fn record_attempt(&mut self, mid_digest: &[u8; 32]) -> Result<()> {
        for item in &mut self.items {
            if &item.record.mid_digest == mid_digest {
                item.attempt_count += 1;
                item.last_attempt_secs = now_secs();
            }
        }
        self.save()
    }

    /// Items that still need network replication.
    pub fn pending(&self) -> impl Iterator<Item = &PendingReplication> {
        self.items.iter().filter(|i| !i.replicated)
    }

    pub fn pending_count(&self) -> usize {
        self.items.iter().filter(|i| !i.replicated).count()
    }

    pub fn replicated_count(&self) -> usize {
        self.items.iter().filter(|i| i.replicated).count()
    }
}
