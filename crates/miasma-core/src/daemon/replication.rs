//! Event-driven durable replication engine.
//!
//! Tracks DHT records that were stored locally but have not yet been
//! acknowledged by any remote Kademlia node.  Retries are driven primarily
//! by topology-change events (new peers becoming available) with a long
//! fallback timer.  Each item carries its own exponential-backoff schedule
//! and items that exhaust their retry budget enter a *degraded* state
//! that is only re-activated by topology events (with a bounded promotion
//! budget per event).
//!
//! # Persistence
//!
//! State is stored as a JSONL write-ahead log (`replication_wal.jsonl`).
//! Each mutation appends one line.  On startup the log is replayed to
//! rebuild in-memory state, then compacted to a clean snapshot via atomic
//! rename so recovery stays fast.

use std::{
    collections::HashMap,
    io::Write as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::network::types::DhtRecord;

// ─── Time helper ─────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Backoff configuration ──────────────────────────────────────────────────

/// Configuration for the per-item retry policy.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Base delay between first and second attempt (seconds).
    pub base_delay_secs: u64,
    /// Maximum delay cap (seconds).
    pub max_delay_secs: u64,
    /// After this many consecutive failures the item enters Degraded state.
    pub max_attempts: u32,
    /// Maximum jitter as a fraction of the computed delay (0.0–1.0).
    pub jitter_fraction: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base_delay_secs: 5,
            max_delay_secs: 300, // 5 minutes
            max_attempts: 20,
            jitter_fraction: 0.25,
        }
    }
}

impl RetryPolicy {
    /// Compute the next-attempt time for a given attempt count.
    ///
    /// Uses exponential backoff: `base * 2^(attempt-1)` capped at `max_delay`,
    /// plus uniform jitter in `[-jitter_fraction * delay, +jitter_fraction * delay]`.
    pub fn next_attempt_secs(&self, attempt_count: u32, now: u64) -> u64 {
        if attempt_count == 0 {
            return now; // first attempt is immediate
        }
        let exp = (attempt_count - 1).min(30); // prevent overflow
        let delay = self
            .base_delay_secs
            .saturating_mul(1u64 << exp)
            .min(self.max_delay_secs);
        let jitter_range = (delay as f64 * self.jitter_fraction) as u64;
        let jitter = if jitter_range > 0 {
            // Simple deterministic-ish jitter from the attempt count.
            // Not cryptographic, just spread.
            let seed = now.wrapping_mul(6364136223846793005).wrapping_add(attempt_count as u64);
            seed % (jitter_range * 2 + 1)
        } else {
            jitter_range // 0
        };
        now.saturating_add(delay).saturating_add(jitter).saturating_sub(jitter_range)
    }
}

// ─── Item state ──────────────────────────────────────────────────────────────

/// Lifecycle state of a replication item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemState {
    /// Actively being retried according to the backoff schedule.
    Pending,
    /// Exhausted retry budget.  Only re-activated by a topology event
    /// that spends part of its promotion budget on this item.
    Degraded,
    /// Successfully replicated — no further work needed.
    Replicated,
}

// ─── PendingReplication ─────────────────────────────────────────────────────

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
    /// Earliest time (UNIX secs) at which the next attempt is allowed.
    pub next_attempt_secs: u64,
    /// Current lifecycle state.
    pub state: ItemState,
    /// How many times this item has been promoted from Degraded back to
    /// Pending by a topology event.  Higher generation → lower promotion
    /// priority (prevents retry storms).
    pub promotion_generation: u32,
}

impl PendingReplication {
    pub fn new(mid_str: String, record: DhtRecord) -> Self {
        let now = now_secs();
        Self {
            mid_str,
            record,
            published_at: now,
            attempt_count: 0,
            last_attempt_secs: 0,
            next_attempt_secs: now, // eligible immediately
            state: ItemState::Pending,
            promotion_generation: 0,
        }
    }
}

// ─── WAL entry types ─────────────────────────────────────────────────────────

const WAL_FILE: &str = "replication_wal.jsonl";
const WAL_TMP: &str = "replication_wal.jsonl.tmp";
/// Legacy JSON file — migrated on first load then deleted.
const LEGACY_FILE: &str = "replication_queue.json";
/// Compact after this many appended entries to keep replay fast.
const COMPACT_THRESHOLD: usize = 200;

#[derive(Debug, Serialize, Deserialize)]
enum WalEntry {
    /// Full snapshot of one item (used during compaction).
    Snapshot(PendingReplication),
    /// A new item was pushed.
    Push(PendingReplication),
    /// An item was acknowledged by a remote peer.
    Ack { mid_digest: [u8; 32] },
    /// An attempt was recorded (updates attempt_count, timestamps, state).
    Attempt {
        mid_digest: [u8; 32],
        attempt_count: u32,
        last_attempt_secs: u64,
        next_attempt_secs: u64,
        state: ItemState,
    },
    /// Item promoted from Degraded → Pending by a topology event.
    Promote {
        mid_digest: [u8; 32],
        next_attempt_secs: u64,
        promotion_generation: u32,
    },
}

// ─── ReplicationQueue ───────────────────────────────────────────────────────

/// Durable, event-driven replication queue with per-item backoff.
///
/// Persistence is via a JSONL write-ahead log that is periodically compacted.
/// The queue is designed to be held behind a `Mutex` — all public methods
/// are `&mut self` and return `Result` to surface I/O errors.
pub struct ReplicationQueue {
    /// Items keyed by `mid_digest` for O(1) lookup.
    items: HashMap<[u8; 32], PendingReplication>,
    wal_path: PathBuf,
    wal_tmp_path: PathBuf,
    /// Number of entries appended since last compaction.
    appended_since_compact: usize,
    /// Retry policy (shared, not per-item — simplifies config).
    pub policy: RetryPolicy,
}

impl ReplicationQueue {
    /// Load from WAL (or migrate from legacy JSON), or start fresh.
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        Self::load_or_create_with_policy(data_dir, RetryPolicy::default())
    }

    /// Load with a custom retry policy (useful for tests).
    pub fn load_or_create_with_policy(data_dir: &Path, policy: RetryPolicy) -> Result<Self> {
        let wal_path = data_dir.join(WAL_FILE);
        let wal_tmp_path = data_dir.join(WAL_TMP);
        let legacy_path = data_dir.join(LEGACY_FILE);

        let mut queue = Self {
            items: HashMap::new(),
            wal_path,
            wal_tmp_path,
            appended_since_compact: 0,
            policy,
        };

        // Try to replay existing WAL.
        if queue.wal_path.exists() {
            queue.replay_wal()?;
        } else if legacy_path.exists() {
            // Migrate from the old single-JSON format.
            queue.migrate_legacy(&legacy_path)?;
        }

        info!(
            path = %queue.wal_path.display(),
            items = queue.items.len(),
            pending = queue.pending_count(),
            "replication queue loaded"
        );
        Ok(queue)
    }

    fn replay_wal(&mut self) -> Result<()> {
        let raw = std::fs::read_to_string(&self.wal_path)
            .with_context(|| format!("read WAL {}", self.wal_path.display()))?;

        for (lineno, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<WalEntry>(line) {
                Ok(entry) => self.apply_entry(entry),
                Err(e) => {
                    warn!(lineno, "WAL line corrupt, skipping: {e}");
                }
            }
        }
        // Compact after full replay so the next startup is fast.
        self.compact()?;
        Ok(())
    }

    fn migrate_legacy(&mut self, legacy_path: &Path) -> Result<()> {
        let raw = std::fs::read_to_string(legacy_path)
            .with_context(|| format!("read legacy {}", legacy_path.display()))?;

        // Legacy format: plain JSON array of old-style PendingReplication.
        // The old struct didn't have `state`, `next_attempt_secs`, or
        // `promotion_generation`.  serde will use defaults for missing fields
        // because we derive Deserialize on the new struct.  But the old struct
        // had a `replicated: bool` field instead of `state`.  We handle both.
        #[derive(Deserialize)]
        struct LegacyItem {
            mid_str: String,
            record: DhtRecord,
            #[serde(default)]
            published_at: u64,
            #[serde(default)]
            attempt_count: u32,
            #[serde(default)]
            last_attempt_secs: u64,
            #[serde(default)]
            replicated: bool,
        }

        let legacy_items: Vec<LegacyItem> = serde_json::from_str(&raw).unwrap_or_else(|e| {
            warn!("legacy queue corrupt, starting fresh: {e}");
            vec![]
        });

        let now = now_secs();
        for li in legacy_items {
            let state = if li.replicated {
                ItemState::Replicated
            } else {
                ItemState::Pending
            };
            let item = PendingReplication {
                mid_str: li.mid_str,
                record: li.record,
                published_at: li.published_at,
                attempt_count: li.attempt_count,
                last_attempt_secs: li.last_attempt_secs,
                next_attempt_secs: if state == ItemState::Pending { now } else { 0 },
                state,
                promotion_generation: 0,
            };
            self.items.insert(item.record.mid_digest, item);
        }

        // Write a clean WAL and remove legacy file.
        self.compact()?;
        let _ = std::fs::remove_file(legacy_path);
        info!("migrated legacy replication_queue.json → WAL");
        Ok(())
    }

    fn apply_entry(&mut self, entry: WalEntry) {
        match entry {
            WalEntry::Snapshot(item) | WalEntry::Push(item) => {
                self.items.insert(item.record.mid_digest, item);
            }
            WalEntry::Ack { mid_digest } => {
                if let Some(item) = self.items.get_mut(&mid_digest) {
                    item.state = ItemState::Replicated;
                }
            }
            WalEntry::Attempt {
                mid_digest,
                attempt_count,
                last_attempt_secs,
                next_attempt_secs,
                state,
            } => {
                if let Some(item) = self.items.get_mut(&mid_digest) {
                    item.attempt_count = attempt_count;
                    item.last_attempt_secs = last_attempt_secs;
                    item.next_attempt_secs = next_attempt_secs;
                    item.state = state;
                }
            }
            WalEntry::Promote {
                mid_digest,
                next_attempt_secs,
                promotion_generation,
            } => {
                if let Some(item) = self.items.get_mut(&mid_digest) {
                    item.state = ItemState::Pending;
                    item.next_attempt_secs = next_attempt_secs;
                    item.promotion_generation = promotion_generation;
                }
            }
        }
    }

    /// Append a single WAL entry.  Uses write + fsync for crash safety.
    fn append_wal(&mut self, entry: &WalEntry) -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.wal_path)
            .with_context(|| format!("open WAL {}", self.wal_path.display()))?;
        let line = serde_json::to_string(entry).context("serialize WAL entry")?;
        writeln!(file, "{}", line).context("write WAL entry")?;
        file.flush().context("flush WAL")?;
        // fsync for crash safety (best-effort on Windows).
        let _ = file.sync_all();

        self.appended_since_compact += 1;
        if self.appended_since_compact >= COMPACT_THRESHOLD {
            self.compact()?;
        }
        Ok(())
    }

    /// Rewrite the WAL as a clean set of Snapshot entries via atomic rename.
    fn compact(&mut self) -> Result<()> {
        let mut file = std::fs::File::create(&self.wal_tmp_path)
            .with_context(|| format!("create WAL tmp {}", self.wal_tmp_path.display()))?;
        for item in self.items.values() {
            let entry = WalEntry::Snapshot(item.clone());
            let line = serde_json::to_string(&entry).context("serialize snapshot")?;
            writeln!(file, "{}", line)?;
        }
        file.flush()?;
        let _ = file.sync_all();
        std::fs::rename(&self.wal_tmp_path, &self.wal_path)
            .with_context(|| "atomic WAL rename")?;
        self.appended_since_compact = 0;
        debug!(items = self.items.len(), "WAL compacted");
        Ok(())
    }

    // ── Public mutation API ──────────────────────────────────────────────────

    /// Add an item (deduplicates by `mid_digest`) and persist.
    pub fn push(&mut self, item: PendingReplication) -> Result<()> {
        let entry = WalEntry::Push(item.clone());
        self.items.insert(item.record.mid_digest, item);
        self.append_wal(&entry)?;
        info!(pending = self.pending_count(), "replication queue updated");
        Ok(())
    }

    /// Mark the given item as replicated and persist.
    pub fn mark_replicated(&mut self, mid_digest: &[u8; 32]) -> Result<()> {
        if let Some(item) = self.items.get_mut(mid_digest) {
            if item.state != ItemState::Replicated {
                item.state = ItemState::Replicated;
                info!(mid = %item.mid_str, "replication confirmed by remote peer");
                self.append_wal(&WalEntry::Ack {
                    mid_digest: *mid_digest,
                })?;
            }
        }
        Ok(())
    }

    /// Record an attempt: bump counters, compute next backoff, and persist.
    /// Returns the new state (Pending or Degraded).
    pub fn record_attempt(&mut self, mid_digest: &[u8; 32]) -> Result<ItemState> {
        let now = now_secs();
        let (new_state, entry) = {
            let item = match self.items.get_mut(mid_digest) {
                Some(i) => i,
                None => return Ok(ItemState::Pending),
            };
            item.attempt_count += 1;
            item.last_attempt_secs = now;

            if item.attempt_count >= self.policy.max_attempts {
                item.state = ItemState::Degraded;
                item.next_attempt_secs = u64::MAX; // never auto-retry
                info!(
                    mid = %item.mid_str,
                    attempts = item.attempt_count,
                    "item degraded — awaiting topology event for re-promotion"
                );
            } else {
                item.next_attempt_secs =
                    self.policy.next_attempt_secs(item.attempt_count, now);
            }

            (
                item.state,
                WalEntry::Attempt {
                    mid_digest: *mid_digest,
                    attempt_count: item.attempt_count,
                    last_attempt_secs: item.last_attempt_secs,
                    next_attempt_secs: item.next_attempt_secs,
                    state: item.state,
                },
            )
        };
        self.append_wal(&entry)?;
        Ok(new_state)
    }

    /// Promote up to `budget` degraded items back to Pending, preferring
    /// items with the lowest `promotion_generation` (and oldest publish time
    /// as tiebreaker).
    ///
    /// Returns the number of items actually promoted.
    pub fn promote_degraded(&mut self, budget: usize) -> Result<usize> {
        if budget == 0 {
            return Ok(0);
        }

        // Collect candidate digests sorted by (generation ASC, published_at ASC).
        let mut candidates: Vec<([u8; 32], u32, u64)> = self
            .items
            .values()
            .filter(|i| i.state == ItemState::Degraded)
            .map(|i| (i.record.mid_digest, i.promotion_generation, i.published_at))
            .collect();
        candidates.sort_by_key(|&(_, gen, ts)| (gen, ts));
        candidates.truncate(budget);

        let now = now_secs();
        let mut promoted = 0;
        // Collect WAL entries to append after releasing the item borrows.
        let mut wal_entries: Vec<(WalEntry, String)> = Vec::new();
        for (digest, _, _) in &candidates {
            if let Some(item) = self.items.get_mut(digest) {
                item.state = ItemState::Pending;
                item.promotion_generation += 1;
                item.attempt_count = 0; // reset backoff after promotion
                item.next_attempt_secs = now;
                wal_entries.push((
                    WalEntry::Promote {
                        mid_digest: *digest,
                        next_attempt_secs: now,
                        promotion_generation: item.promotion_generation,
                    },
                    item.mid_str.clone(),
                ));
                promoted += 1;
            }
        }
        for (entry, mid_str) in &wal_entries {
            self.append_wal(entry)?;
            info!(mid = %mid_str, "degraded item promoted by topology event");
        }
        Ok(promoted)
    }

    /// Reset `next_attempt_secs` to `now` for up to `limit` Pending items
    /// whose next attempt is in the future.  This makes them eligible for
    /// `due_items()` immediately.
    ///
    /// Called on topology events: a new peer is a fresh replication target,
    /// so items should get a chance to retry regardless of their backoff
    /// schedule.  The `limit` parameter bounds the work to avoid storms.
    pub fn make_items_due(&mut self, limit: usize) -> usize {
        let now = now_secs();
        let mut count = 0;
        for item in self.items.values_mut() {
            if count >= limit {
                break;
            }
            if item.state == ItemState::Pending && item.next_attempt_secs > now {
                item.next_attempt_secs = now;
                count += 1;
            }
        }
        count
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /// Items that are due for a retry attempt right now.
    pub fn due_items(&self, now: u64) -> Vec<PendingReplication> {
        self.items
            .values()
            .filter(|i| i.state == ItemState::Pending && i.next_attempt_secs <= now)
            .cloned()
            .collect()
    }

    /// Items that still need network replication (Pending or Degraded).
    pub fn pending(&self) -> impl Iterator<Item = &PendingReplication> {
        self.items.values().filter(|i| i.state != ItemState::Replicated)
    }

    pub fn pending_count(&self) -> usize {
        self.items.values().filter(|i| i.state != ItemState::Replicated).count()
    }

    pub fn replicated_count(&self) -> usize {
        self.items.values().filter(|i| i.state == ItemState::Replicated).count()
    }

    pub fn degraded_count(&self) -> usize {
        self.items.values().filter(|i| i.state == ItemState::Degraded).count()
    }

    /// Look up a single item by MID digest.
    pub fn get(&self, mid_digest: &[u8; 32]) -> Option<&PendingReplication> {
        self.items.get(mid_digest)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_record(id: u8) -> DhtRecord {
        let mut digest = [0u8; 32];
        digest[0] = id;
        DhtRecord {
            mid_digest: digest,
            data_shards: 2,
            total_shards: 3,
            version: 1,
            locations: vec![],
            published_at: 100,
        }
    }

    fn dummy_item(id: u8) -> PendingReplication {
        PendingReplication::new(format!("mid-{id}"), dummy_record(id))
    }

    // ── Backoff tests ────────────────────────────────────────────────────────

    #[test]
    fn backoff_is_exponential_and_capped() {
        let policy = RetryPolicy {
            base_delay_secs: 4,
            max_delay_secs: 60,
            jitter_fraction: 0.0, // disable jitter for determinism
            max_attempts: 20,
        };

        let now = 1000;
        // attempt 0 → immediate
        assert_eq!(policy.next_attempt_secs(0, now), now);
        // attempt 1 → base * 2^0 = 4
        assert_eq!(policy.next_attempt_secs(1, now), now + 4);
        // attempt 2 → base * 2^1 = 8
        assert_eq!(policy.next_attempt_secs(2, now), now + 8);
        // attempt 3 → base * 2^2 = 16
        assert_eq!(policy.next_attempt_secs(3, now), now + 16);
        // attempt 5 → base * 2^4 = 64, capped at 60
        assert_eq!(policy.next_attempt_secs(5, now), now + 60);
    }

    #[test]
    fn backoff_jitter_stays_within_bounds() {
        let policy = RetryPolicy {
            base_delay_secs: 10,
            max_delay_secs: 300,
            jitter_fraction: 0.5,
            max_attempts: 20,
        };

        // Run a few different "now" values to exercise the jitter path.
        for t in [1000u64, 2000, 3000, 9999] {
            let next = policy.next_attempt_secs(3, t);
            // attempt 3: base * 2^2 = 40, jitter range = 20
            // so next ∈ [t + 40 - 20, t + 40 + 20] = [t+20, t+60]
            assert!(next >= t + 20, "next={next} too low for t={t}");
            assert!(next <= t + 60, "next={next} too high for t={t}");
        }
    }

    // ── WAL persistence tests ────────────────────────────────────────────────

    #[test]
    fn wal_roundtrip_and_crash_recovery() {
        let dir = tempfile::tempdir().unwrap();

        // Session 1: push two items, mark one replicated, record attempt on other.
        {
            let mut q = ReplicationQueue::load_or_create(dir.path()).unwrap();
            q.push(dummy_item(1)).unwrap();
            q.push(dummy_item(2)).unwrap();
            q.mark_replicated(&dummy_record(1).mid_digest).unwrap();
            q.record_attempt(&dummy_record(2).mid_digest).unwrap();
            assert_eq!(q.replicated_count(), 1);
            assert_eq!(q.pending_count(), 1);
        }
        // "Crash" — drop the queue without explicit shutdown.

        // Session 2: reload from WAL.
        {
            let q = ReplicationQueue::load_or_create(dir.path()).unwrap();
            assert_eq!(q.replicated_count(), 1);
            assert_eq!(q.pending_count(), 1);
            let item2 = q.get(&dummy_record(2).mid_digest).unwrap();
            assert_eq!(item2.attempt_count, 1);
            assert_eq!(item2.state, ItemState::Pending);
        }
    }

    #[test]
    fn legacy_migration() {
        let dir = tempfile::tempdir().unwrap();

        // Write a legacy-format JSON file.
        let digest: Vec<u8> = vec![42; 32];
        let legacy = serde_json::json!([
            {
                "mid_str": "mid-legacy",
                "record": {
                    "mid_digest": digest,
                    "data_shards": 2,
                    "total_shards": 3,
                    "version": 1,
                    "locations": [],
                    "published_at": 50
                },
                "published_at": 50,
                "attempt_count": 3,
                "last_attempt_secs": 60,
                "replicated": false
            }
        ]);
        std::fs::write(
            dir.path().join(LEGACY_FILE),
            serde_json::to_string(&legacy).unwrap(),
        )
        .unwrap();

        let q = ReplicationQueue::load_or_create(dir.path()).unwrap();
        assert_eq!(q.pending_count(), 1);
        // Legacy file should be removed.
        assert!(!dir.path().join(LEGACY_FILE).exists());
        // WAL should exist.
        assert!(dir.path().join(WAL_FILE).exists());
    }

    // ── Due-item selection tests ─────────────────────────────────────────────

    #[test]
    fn due_items_respects_next_attempt_time() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = ReplicationQueue::load_or_create(dir.path()).unwrap();

        let mut item1 = dummy_item(1);
        item1.next_attempt_secs = 100;
        q.push(item1).unwrap();

        let mut item2 = dummy_item(2);
        item2.next_attempt_secs = 200;
        q.push(item2).unwrap();

        assert_eq!(q.due_items(99).len(), 0);
        assert_eq!(q.due_items(100).len(), 1);
        assert_eq!(q.due_items(200).len(), 2);
    }

    #[test]
    fn degraded_items_not_in_due_list() {
        let dir = tempfile::tempdir().unwrap();
        let policy = RetryPolicy {
            max_attempts: 2,
            jitter_fraction: 0.0,
            ..RetryPolicy::default()
        };
        let mut q =
            ReplicationQueue::load_or_create_with_policy(dir.path(), policy).unwrap();

        q.push(dummy_item(1)).unwrap();
        let digest = dummy_record(1).mid_digest;

        // Exhaust retry budget.
        q.record_attempt(&digest).unwrap();
        let state = q.record_attempt(&digest).unwrap();
        assert_eq!(state, ItemState::Degraded);

        // Degraded → not due even at far-future time.
        assert_eq!(q.due_items(u64::MAX).len(), 0);
        assert_eq!(q.degraded_count(), 1);
    }

    // ── Promotion tests ─────────────────────────────────────────────────────

    #[test]
    fn promote_respects_budget_and_generation() {
        let dir = tempfile::tempdir().unwrap();
        let policy = RetryPolicy {
            max_attempts: 1,
            jitter_fraction: 0.0,
            ..RetryPolicy::default()
        };
        let mut q =
            ReplicationQueue::load_or_create_with_policy(dir.path(), policy).unwrap();

        // Push 3 items and degrade them all.
        for id in 1..=3 {
            q.push(dummy_item(id)).unwrap();
            q.record_attempt(&dummy_record(id).mid_digest).unwrap();
        }
        assert_eq!(q.degraded_count(), 3);

        // Promote budget = 2 → only 2 promoted.
        let promoted = q.promote_degraded(2).unwrap();
        assert_eq!(promoted, 2);
        assert_eq!(q.degraded_count(), 1);

        // Promoted items have generation=1; still-degraded has generation=0.
        // Re-degrade the promoted ones.
        for id in 1..=3 {
            let item = q.get(&dummy_record(id).mid_digest).unwrap();
            if item.state == ItemState::Pending {
                q.record_attempt(&dummy_record(id).mid_digest).unwrap();
            }
        }

        // Now promote budget=2 again: the one with gen=0 goes first,
        // then one of the gen=1 items.
        let promoted = q.promote_degraded(2).unwrap();
        assert_eq!(promoted, 2);
        assert_eq!(q.degraded_count(), 1);
    }

    #[test]
    fn promote_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let policy = RetryPolicy {
            max_attempts: 1,
            jitter_fraction: 0.0,
            ..RetryPolicy::default()
        };

        {
            let mut q =
                ReplicationQueue::load_or_create_with_policy(dir.path(), policy.clone()).unwrap();
            q.push(dummy_item(1)).unwrap();
            q.record_attempt(&dummy_record(1).mid_digest).unwrap();
            assert_eq!(q.degraded_count(), 1);
            q.promote_degraded(1).unwrap();
            assert_eq!(q.degraded_count(), 0);
        }

        // Reload.
        let q = ReplicationQueue::load_or_create_with_policy(dir.path(), policy).unwrap();
        let item = q.get(&dummy_record(1).mid_digest).unwrap();
        assert_eq!(item.state, ItemState::Pending);
        assert_eq!(item.promotion_generation, 1);
    }
}
