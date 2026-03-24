/// Connection health monitoring — peer scoring, dial backoff, stale address pruning.
///
/// # Architecture
/// ```text
/// ┌─────────────────────────────┐
/// │   ConnectionHealthMonitor   │
/// │  ├─ PeerConnectionScore[]   │  per-peer success/failure/latency tracking
/// │  ├─ DialBackoff             │  exponential backoff per peer-address
/// │  └─ StaleAddressPruner      │  mark addresses stale after repeated failures
/// └─────────────────────────────┘
/// ```
///
/// The monitor runs periodically (configurable interval, default 30s) and:
/// 1. Updates connection scores from recent outcomes
/// 2. Prunes addresses with too many consecutive failures
/// 3. Emits connectivity warnings when peer count drops below threshold
use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─── Dial backoff ───────────────────────────────────────────────────────────

/// Exponential backoff state for a single peer address.
#[derive(Debug, Clone)]
pub struct DialBackoffEntry {
    /// Number of consecutive failures.
    pub consecutive_failures: u32,
    /// When the last failure occurred.
    pub last_failure: Instant,
    /// When the next dial attempt is allowed.
    pub next_allowed: Instant,
}

/// Manages exponential backoff for dialing peer addresses.
///
/// Each address independently tracks failures and computes a backoff window.
/// On success, the address is removed from the backoff map entirely.
#[derive(Debug)]
pub struct DialBackoff {
    entries: HashMap<String, DialBackoffEntry>,
    /// Base backoff duration (default: 2s).
    pub base: Duration,
    /// Maximum backoff duration (default: 300s).
    pub max: Duration,
}

impl Default for DialBackoff {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            base: Duration::from_secs(2),
            max: Duration::from_secs(300),
        }
    }
}

impl DialBackoff {
    /// Create with custom base and max durations.
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            base,
            max,
        }
    }

    /// Record a dial failure for the given address. Returns the backoff duration.
    pub fn record_failure(&mut self, addr: &str) -> Duration {
        let now = Instant::now();
        let entry = self.entries.entry(addr.to_owned()).or_insert(DialBackoffEntry {
            consecutive_failures: 0,
            last_failure: now,
            next_allowed: now,
        });
        entry.consecutive_failures += 1;
        entry.last_failure = now;

        // Exponential backoff: base * 2^(failures-1), capped at max
        let backoff = self
            .base
            .saturating_mul(1u32.checked_shl(entry.consecutive_failures.saturating_sub(1)).unwrap_or(u32::MAX))
            .min(self.max);

        // Add jitter: ±25% of the backoff
        let jitter_range = backoff.as_millis() as u64 / 4;
        let jitter = if jitter_range > 0 {
            // Simple deterministic jitter based on failure count (no RNG needed in core)
            let pseudo = (entry.consecutive_failures as u64).wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            Duration::from_millis(pseudo % jitter_range)
        } else {
            Duration::ZERO
        };

        let total = backoff + jitter;
        entry.next_allowed = now + total;
        total
    }

    /// Record a successful dial — removes the address from backoff tracking.
    pub fn record_success(&mut self, addr: &str) {
        self.entries.remove(addr);
    }

    /// Check if dialing this address is currently allowed (backoff expired).
    pub fn is_allowed(&self, addr: &str) -> bool {
        match self.entries.get(addr) {
            None => true,
            Some(entry) => Instant::now() >= entry.next_allowed,
        }
    }

    /// Get the current backoff state for an address, if any.
    pub fn get(&self, addr: &str) -> Option<&DialBackoffEntry> {
        self.entries.get(addr)
    }

    /// Number of addresses currently in backoff.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the backoff map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of addresses currently in active backoff (alias for `len()`).
    pub fn active_count(&self) -> usize {
        self.entries.len()
    }

    /// Remove entries whose backoff has expired (cleanup).
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.next_allowed > now);
    }
}

// ─── Peer connection score ──────────────────────────────────────────────────

/// Tracks connection quality for a single peer.
#[derive(Debug, Clone)]
pub struct PeerConnectionScore {
    /// Total successful operations.
    pub successes: u64,
    /// Total failed operations.
    pub failures: u64,
    /// Consecutive failures (reset on success).
    pub consecutive_failures: u32,
    /// Exponential moving average of latency in milliseconds (α = 0.3).
    pub latency_ema_ms: f64,
    /// When this peer was last seen active (connected, responded to ping, etc.).
    pub last_seen: Option<Instant>,
    /// When this score was created.
    pub created: Instant,
}

impl Default for PeerConnectionScore {
    fn default() -> Self {
        Self {
            successes: 0,
            failures: 0,
            consecutive_failures: 0,
            latency_ema_ms: 0.0,
            last_seen: None,
            created: Instant::now(),
        }
    }
}

impl PeerConnectionScore {
    /// Record a successful operation with the given latency.
    pub fn record_success(&mut self, latency: Duration) {
        self.successes += 1;
        self.consecutive_failures = 0;
        self.last_seen = Some(Instant::now());

        let latency_ms = latency.as_secs_f64() * 1000.0;
        if self.successes == 1 && self.failures == 0 {
            self.latency_ema_ms = latency_ms;
        } else {
            // EMA with α = 0.3
            self.latency_ema_ms = 0.3 * latency_ms + 0.7 * self.latency_ema_ms;
        }
    }

    /// Record a failed operation.
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.consecutive_failures += 1;
    }

    /// Compute a quality score (0.0 = dead, 1.0 = perfect).
    ///
    /// Score factors in success rate and consecutive failure penalty.
    pub fn quality(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 0.5; // Unknown — neutral score
        }
        let success_rate = self.successes as f64 / total as f64;
        // Penalty for consecutive failures: each consecutive failure reduces score by 15%
        let penalty = 0.85f64.powi(self.consecutive_failures as i32);
        (success_rate * penalty).clamp(0.0, 1.0)
    }

    /// Whether this peer is considered stale (not seen for the given duration).
    pub fn is_stale(&self, max_age: Duration) -> bool {
        match self.last_seen {
            None => self.created.elapsed() > max_age,
            Some(seen) => seen.elapsed() > max_age,
        }
    }
}

// ─── Stale address pruner ───────────────────────────────────────────────────

/// Configuration for stale address pruning.
#[derive(Debug, Clone)]
pub struct StaleAddressConfig {
    /// Maximum consecutive failures before marking an address as stale.
    pub max_consecutive_failures: u32,
    /// Maximum age of a peer without activity before marking as stale.
    pub max_idle_age: Duration,
}

impl Default for StaleAddressConfig {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 5,
            max_idle_age: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Tracks per-address failure counts for stale detection.
#[derive(Debug, Default)]
pub struct StaleAddressPruner {
    /// Per-address consecutive failure count.
    address_failures: HashMap<String, u32>,
    /// Config thresholds.
    config: StaleAddressConfig,
    /// Running count of addresses pruned.
    pub pruned_count: u64,
}

impl StaleAddressPruner {
    pub fn new(config: StaleAddressConfig) -> Self {
        Self {
            address_failures: HashMap::new(),
            config,
            pruned_count: 0,
        }
    }

    /// Record a failure for an address. Returns true if the address should be pruned.
    pub fn record_failure(&mut self, addr: &str) -> bool {
        let count = self.address_failures.entry(addr.to_owned()).or_insert(0);
        *count += 1;
        if *count >= self.config.max_consecutive_failures {
            self.pruned_count += 1;
            true
        } else {
            false
        }
    }

    /// Record a success — resets the failure count for this address.
    pub fn record_success(&mut self, addr: &str) {
        self.address_failures.remove(addr);
    }

    /// Get the number of addresses currently tracked.
    pub fn tracked_count(&self) -> usize {
        self.address_failures.len()
    }

    /// Get the failure count for a specific address.
    pub fn failure_count(&self, addr: &str) -> u32 {
        self.address_failures.get(addr).copied().unwrap_or(0)
    }
}

// ─── Connection health snapshot (for diagnostics) ───────────────────────────

/// Serializable snapshot of connection health for diagnostics export.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionHealthSnapshot {
    /// Overall connection quality score (0.0–1.0).
    pub quality_score: f64,
    /// Number of peers currently tracked.
    pub tracked_peers: usize,
    /// Number of peers considered stale.
    pub stale_peers: usize,
    /// Number of addresses currently in dial backoff.
    pub backoff_addresses: usize,
    /// Total addresses pruned since startup.
    pub addresses_pruned: u64,
    /// Whether connectivity is considered degraded.
    pub degraded: bool,
    /// Reason for degraded state, if applicable.
    pub degraded_reason: Option<String>,
}

// ─── Connection health monitor ──────────────────────────────────────────────

/// Aggregates peer scores, backoff, and pruning into a unified monitor.
///
/// The monitor does not own the event loop — it provides methods that the
/// node event loop calls on relevant events (dial success/failure, ping, etc.).
#[derive(Debug)]
pub struct ConnectionHealthMonitor {
    /// Per-peer connection scores (keyed by PeerId string).
    scores: HashMap<String, PeerConnectionScore>,
    /// Dial backoff tracker.
    pub backoff: DialBackoff,
    /// Stale address pruner.
    pub pruner: StaleAddressPruner,
    /// Minimum peer count before declaring degraded connectivity.
    pub min_peer_count: usize,
    /// Stale threshold for peer scores.
    pub stale_threshold: Duration,
}

impl Default for ConnectionHealthMonitor {
    fn default() -> Self {
        Self {
            scores: HashMap::new(),
            backoff: DialBackoff::default(),
            pruner: StaleAddressPruner::new(StaleAddressConfig::default()),
            min_peer_count: 1,
            stale_threshold: Duration::from_secs(3600),
        }
    }
}

impl ConnectionHealthMonitor {
    /// Record a successful connection/operation for a peer.
    pub fn record_peer_success(&mut self, peer_id: &str, latency: Duration) {
        let score = self.scores.entry(peer_id.to_owned()).or_default();
        score.record_success(latency);
    }

    /// Record a failed connection/operation for a peer.
    pub fn record_peer_failure(&mut self, peer_id: &str) {
        let score = self.scores.entry(peer_id.to_owned()).or_default();
        score.record_failure();
    }

    /// Record a successful dial to an address.
    pub fn record_dial_success(&mut self, addr: &str) {
        self.backoff.record_success(addr);
        self.pruner.record_success(addr);
    }

    /// Record a failed dial to an address. Returns the backoff duration.
    pub fn record_dial_failure(&mut self, addr: &str) -> Duration {
        let backoff = self.backoff.record_failure(addr);
        let _should_prune = self.pruner.record_failure(addr);
        backoff
    }

    /// Check if dialing an address is currently allowed.
    pub fn is_dial_allowed(&self, addr: &str) -> bool {
        self.backoff.is_allowed(addr)
    }

    /// Get the connection score for a peer.
    pub fn peer_score(&self, peer_id: &str) -> Option<&PeerConnectionScore> {
        self.scores.get(peer_id)
    }

    /// Get the average quality score across all tracked peers.
    pub fn average_quality(&self) -> f64 {
        if self.scores.is_empty() {
            return 0.0;
        }
        let total: f64 = self.scores.values().map(|s| s.quality()).sum();
        total / self.scores.len() as f64
    }

    /// Count peers considered stale.
    pub fn stale_peer_count(&self) -> usize {
        self.scores
            .values()
            .filter(|s| s.is_stale(self.stale_threshold))
            .count()
    }

    /// Generate a diagnostics snapshot.
    pub fn snapshot(&self, current_peer_count: usize) -> ConnectionHealthSnapshot {
        let quality = self.average_quality();
        let stale = self.stale_peer_count();
        let degraded = current_peer_count < self.min_peer_count;
        let degraded_reason = if degraded {
            Some(format!(
                "peer count {} below minimum {}",
                current_peer_count, self.min_peer_count
            ))
        } else {
            None
        };

        ConnectionHealthSnapshot {
            quality_score: quality,
            tracked_peers: self.scores.len(),
            stale_peers: stale,
            backoff_addresses: self.backoff.len(),
            addresses_pruned: self.pruner.pruned_count,
            degraded,
            degraded_reason,
        }
    }

    /// Remove scores for peers that haven't been seen in a long time.
    /// Returns the number of peers removed.
    pub fn prune_stale_peers(&mut self) -> usize {
        let threshold = self.stale_threshold;
        let before = self.scores.len();
        self.scores.retain(|_, score| !score.is_stale(threshold));
        self.backoff.prune_expired();
        before - self.scores.len()
    }

    /// Number of tracked peers.
    pub fn tracked_peer_count(&self) -> usize {
        self.scores.len()
    }

    /// Whether connectivity is considered degraded at the given peer count.
    pub fn is_degraded(&self, peer_count: usize) -> bool {
        peer_count < self.min_peer_count
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DialBackoff ─────────────────────────────────────────────────────

    #[test]
    fn backoff_starts_empty() {
        let b = DialBackoff::default();
        assert!(b.is_empty());
        assert!(b.is_allowed("1.2.3.4:4001"));
    }

    #[test]
    fn backoff_exponential_growth() {
        let mut b = DialBackoff::new(Duration::from_secs(2), Duration::from_secs(300));
        let d1 = b.record_failure("addr1");
        let d2 = b.record_failure("addr1");
        let d3 = b.record_failure("addr1");
        // Each failure should roughly double (plus jitter)
        // d1 ≈ 2s, d2 ≈ 4s, d3 ≈ 8s (before jitter)
        assert!(d1 >= Duration::from_secs(2));
        assert!(d2 >= Duration::from_secs(4));
        assert!(d3 >= Duration::from_secs(8));
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut b = DialBackoff::new(Duration::from_secs(2), Duration::from_secs(10));
        // 10 failures should not exceed max + jitter
        for _ in 0..10 {
            b.record_failure("addr1");
        }
        let entry = b.get("addr1").unwrap();
        // next_allowed should be within max + 25% jitter
        let elapsed = entry.next_allowed.duration_since(entry.last_failure);
        assert!(elapsed <= Duration::from_millis(12500)); // 10s + 25%
    }

    #[test]
    fn backoff_reset_on_success() {
        let mut b = DialBackoff::default();
        b.record_failure("addr1");
        b.record_failure("addr1");
        assert!(!b.is_empty());
        b.record_success("addr1");
        assert!(b.is_empty());
        assert!(b.is_allowed("addr1"));
    }

    #[test]
    fn backoff_independent_addresses() {
        let mut b = DialBackoff::default();
        b.record_failure("addr1");
        b.record_failure("addr2");
        assert_eq!(b.len(), 2);
        b.record_success("addr1");
        assert_eq!(b.len(), 1);
        assert!(b.is_allowed("addr1"));
    }

    // ── PeerConnectionScore ─────────────────────────────────────────────

    #[test]
    fn score_default_quality() {
        let s = PeerConnectionScore::default();
        assert!((s.quality() - 0.5).abs() < f64::EPSILON); // Unknown = 0.5
    }

    #[test]
    fn score_perfect_after_successes() {
        let mut s = PeerConnectionScore::default();
        s.record_success(Duration::from_millis(50));
        s.record_success(Duration::from_millis(60));
        s.record_success(Duration::from_millis(40));
        assert!(s.quality() > 0.99);
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn score_degrades_on_failure() {
        let mut s = PeerConnectionScore::default();
        s.record_success(Duration::from_millis(50));
        s.record_failure();
        s.record_failure();
        s.record_failure();
        assert!(s.quality() < 0.5);
        assert_eq!(s.consecutive_failures, 3);
    }

    #[test]
    fn score_consecutive_failures_reset() {
        let mut s = PeerConnectionScore::default();
        s.record_failure();
        s.record_failure();
        assert_eq!(s.consecutive_failures, 2);
        s.record_success(Duration::from_millis(50));
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn score_latency_ema() {
        let mut s = PeerConnectionScore::default();
        s.record_success(Duration::from_millis(100));
        assert!((s.latency_ema_ms - 100.0).abs() < 0.1);
        s.record_success(Duration::from_millis(200));
        // EMA: 0.3 * 200 + 0.7 * 100 = 130
        assert!((s.latency_ema_ms - 130.0).abs() < 0.1);
    }

    #[test]
    fn score_stale_detection() {
        let mut s = PeerConnectionScore::default();
        // Just created, not stale with 1-hour threshold
        assert!(!s.is_stale(Duration::from_secs(3600)));
        // But stale with 0-second threshold
        assert!(s.is_stale(Duration::ZERO));
        // After seeing the peer, reset stale timer
        s.record_success(Duration::from_millis(50));
        assert!(!s.is_stale(Duration::from_secs(3600)));
    }

    // ── StaleAddressPruner ──────────────────────────────────────────────

    #[test]
    fn pruner_tracks_failures() {
        let mut p = StaleAddressPruner::new(StaleAddressConfig {
            max_consecutive_failures: 3,
            max_idle_age: Duration::from_secs(3600),
        });
        assert!(!p.record_failure("addr1"));
        assert!(!p.record_failure("addr1"));
        assert!(p.record_failure("addr1")); // 3rd failure → prune
        assert_eq!(p.pruned_count, 1);
    }

    #[test]
    fn pruner_reset_on_success() {
        let mut p = StaleAddressPruner::new(StaleAddressConfig {
            max_consecutive_failures: 3,
            max_idle_age: Duration::from_secs(3600),
        });
        p.record_failure("addr1");
        p.record_failure("addr1");
        p.record_success("addr1");
        assert_eq!(p.failure_count("addr1"), 0);
        // Now need 3 more failures
        assert!(!p.record_failure("addr1"));
        assert!(!p.record_failure("addr1"));
        assert!(p.record_failure("addr1"));
    }

    // ── ConnectionHealthMonitor ─────────────────────────────────────────

    #[test]
    fn monitor_snapshot_healthy() {
        let mut m = ConnectionHealthMonitor::default();
        m.record_peer_success("peer1", Duration::from_millis(50));
        m.record_peer_success("peer2", Duration::from_millis(60));
        let snap = m.snapshot(2);
        assert!(!snap.degraded);
        assert!(snap.quality_score > 0.9);
        assert_eq!(snap.tracked_peers, 2);
    }

    #[test]
    fn monitor_snapshot_degraded() {
        let m = ConnectionHealthMonitor {
            min_peer_count: 3,
            ..Default::default()
        };
        let snap = m.snapshot(1); // Only 1 peer, need 3
        assert!(snap.degraded);
        assert!(snap.degraded_reason.is_some());
    }

    #[test]
    fn monitor_dial_backoff_integration() {
        let mut m = ConnectionHealthMonitor::default();
        assert!(m.is_dial_allowed("addr1"));
        let _d = m.record_dial_failure("addr1");
        // Immediately after failure, should be in backoff
        assert!(!m.is_dial_allowed("addr1"));
        // After success, cleared
        m.record_dial_success("addr1");
        assert!(m.is_dial_allowed("addr1"));
    }

    #[test]
    fn monitor_prune_stale() {
        let mut m = ConnectionHealthMonitor {
            stale_threshold: Duration::ZERO, // Everything is stale immediately
            ..Default::default()
        };
        m.record_peer_success("peer1", Duration::from_millis(50));
        m.record_peer_success("peer2", Duration::from_millis(60));
        assert_eq!(m.tracked_peer_count(), 2);
        let pruned = m.prune_stale_peers();
        assert_eq!(pruned, 2);
        assert_eq!(m.tracked_peer_count(), 0);
    }

    #[test]
    fn snapshot_serialization() {
        let snap = ConnectionHealthSnapshot {
            quality_score: 0.85,
            tracked_peers: 5,
            stale_peers: 1,
            backoff_addresses: 2,
            addresses_pruned: 10,
            degraded: false,
            degraded_reason: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let deserialized: ConnectionHealthSnapshot = serde_json::from_str(&json).unwrap();
        assert!((deserialized.quality_score - 0.85).abs() < f64::EPSILON);
        assert_eq!(deserialized.tracked_peers, 5);
    }
}
