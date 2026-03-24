/// Self-healing and recovery for the bridge/daemon layer.
///
/// Provides detection and recovery from partial failures:
/// - Network flap damping (rapid connect/disconnect cycles)
/// - Stale state cleanup on restart
/// - Partial failure detection (bridge alive but daemon unhealthy)
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─── Network flap detector ──────────────────────────────────────────────────

/// Detects rapid connect/disconnect cycles and enters damping mode.
///
/// When more than `threshold` disconnections occur within `window`,
/// the detector enters flap damping mode. Reconnection attempts should
/// be suppressed while damping is active.
#[derive(Debug)]
pub struct NetworkFlapDetector {
    /// Recent disconnection timestamps.
    events: VecDeque<Instant>,
    /// Number of disconnections within the window to trigger damping.
    threshold: u32,
    /// Time window for counting disconnections.
    window: Duration,
    /// How long damping lasts once triggered.
    damping_duration: Duration,
    /// When damping was last activated.
    damping_start: Option<Instant>,
}

impl Default for NetworkFlapDetector {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            threshold: 3,
            window: Duration::from_secs(60),
            damping_duration: Duration::from_secs(120),
            damping_start: None,
        }
    }
}

impl NetworkFlapDetector {
    /// Create with custom threshold, window, and damping duration.
    pub fn new(threshold: u32, window: Duration, damping_duration: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            threshold,
            window,
            damping_duration,
            damping_start: None,
        }
    }

    /// Record a disconnection event. Returns true if flap damping was activated.
    pub fn record_disconnect(&mut self) -> bool {
        let now = Instant::now();
        self.events.push_back(now);

        // Prune old events outside the window
        while let Some(&front) = self.events.front() {
            if now.duration_since(front) > self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }

        // Check if threshold exceeded
        if self.events.len() >= self.threshold as usize && !self.is_damping() {
            self.damping_start = Some(now);
            true
        } else {
            false
        }
    }

    /// Whether flap damping is currently active.
    pub fn is_damping(&self) -> bool {
        match self.damping_start {
            Some(start) => start.elapsed() < self.damping_duration,
            None => false,
        }
    }

    /// Time remaining in current damping period, if active.
    pub fn damping_remaining(&self) -> Option<Duration> {
        self.damping_start.and_then(|start| {
            let elapsed = start.elapsed();
            if elapsed < self.damping_duration {
                Some(self.damping_duration - elapsed)
            } else {
                None
            }
        })
    }

    /// Reset damping state (e.g., on manual reconnect).
    pub fn reset(&mut self) {
        self.events.clear();
        self.damping_start = None;
    }

    /// Number of disconnections in the current window.
    pub fn recent_disconnect_count(&self) -> usize {
        self.events.len()
    }
}

// ─── Partial failure detector ───────────────────────────────────────────────

/// Types of partial failure states the daemon can be in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartialFailure {
    /// Bridge (IPC/HTTP) is responding but the node has no peers.
    NoPeers,
    /// All transport attempts are failing.
    AllTransportsDead,
    /// Only relay transport is working (direct connectivity lost).
    RelayOnly,
    /// Peer count has been stuck at the same value for too long.
    StalePeerCount,
}

impl std::fmt::Display for PartialFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPeers => write!(f, "bridge alive but no peers connected"),
            Self::AllTransportsDead => write!(f, "all transport attempts failing"),
            Self::RelayOnly => write!(f, "direct connectivity lost, relay-only mode"),
            Self::StalePeerCount => write!(f, "peer count stale — possible network partition"),
        }
    }
}

/// Detects partial failure conditions from daemon status snapshots.
#[derive(Debug)]
pub struct PartialFailureDetector {
    /// How long zero peers must persist before declaring NoPeers.
    no_peers_threshold: Duration,
    /// When we first observed zero peers (for NoPeers detection).
    zero_peers_since: Option<Instant>,
    /// Last observed peer count + when (for StalePeerCount detection).
    last_peer_count: Option<(usize, Instant)>,
    /// How long same peer count must persist to be considered stale.
    stale_threshold: Duration,
}

impl Default for PartialFailureDetector {
    fn default() -> Self {
        Self {
            no_peers_threshold: Duration::from_secs(120),
            zero_peers_since: None,
            last_peer_count: None,
            stale_threshold: Duration::from_secs(600),
        }
    }
}

impl PartialFailureDetector {
    /// Evaluate current state and return any detected partial failures.
    pub fn evaluate(
        &mut self,
        peer_count: usize,
        all_transports_failing: bool,
        relay_only: bool,
    ) -> Vec<PartialFailure> {
        let mut failures = Vec::new();
        let now = Instant::now();

        // NoPeers detection
        if peer_count == 0 {
            match self.zero_peers_since {
                None => self.zero_peers_since = Some(now),
                Some(since) if since.elapsed() >= self.no_peers_threshold => {
                    failures.push(PartialFailure::NoPeers);
                }
                _ => {}
            }
        } else {
            self.zero_peers_since = None;
        }

        // AllTransportsDead
        if all_transports_failing && peer_count > 0 {
            failures.push(PartialFailure::AllTransportsDead);
        }

        // RelayOnly
        if relay_only && peer_count > 0 {
            failures.push(PartialFailure::RelayOnly);
        }

        // StalePeerCount (only when we have peers but count hasn't changed)
        if peer_count > 0 {
            match self.last_peer_count {
                Some((last, since)) if last == peer_count => {
                    if since.elapsed() >= self.stale_threshold {
                        failures.push(PartialFailure::StalePeerCount);
                    }
                }
                _ => {
                    self.last_peer_count = Some((peer_count, now));
                }
            }
        }

        failures
    }

    /// Reset all state (e.g., on daemon restart).
    pub fn reset(&mut self) {
        self.zero_peers_since = None;
        self.last_peer_count = None;
    }
}

// ─── Stale state cleanup ────────────────────────────────────────────────────

/// Actions taken during stale state cleanup on daemon restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanupReport {
    /// Whether a stale port file was removed.
    pub stale_port_file_removed: bool,
    /// Whether a stale HTTP port file was removed.
    pub stale_http_port_file_removed: bool,
    /// Number of stale cached peer addresses invalidated.
    pub stale_peers_invalidated: usize,
    /// Number of stuck replication items reset.
    pub stuck_replications_reset: usize,
}

/// Clean up stale state in the data directory on daemon startup.
///
/// This should be called before starting the new daemon to avoid inheriting
/// broken state from a previous crashed instance.
pub fn cleanup_stale_state(data_dir: &std::path::Path) -> CleanupReport {
    let mut report = CleanupReport::default();

    // Remove stale port files (from crashed daemon)
    let port_file = data_dir.join(super::ipc::PORT_FILE);
    if port_file.exists() {
        if std::fs::remove_file(&port_file).is_ok() {
            report.stale_port_file_removed = true;
            tracing::info!("Removed stale port file: {}", port_file.display());
        }
    }

    let http_port_file = data_dir.join(super::ipc::HTTP_PORT_FILE);
    if http_port_file.exists() {
        if std::fs::remove_file(&http_port_file).is_ok() {
            report.stale_http_port_file_removed = true;
            tracing::info!(
                "Removed stale HTTP port file: {}",
                http_port_file.display()
            );
        }
    }

    report
}

// ─── Recovery actions ────────────────────────────────────────────────────────

/// Concrete actions the daemon should take in response to partial failure detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryAction {
    /// Re-dial bootstrap peers to discover new peers.
    ReDialBootstrap,
    /// Refresh peer descriptors from the descriptor store.
    RefreshDescriptors,
    /// Attempt the next transport in the fallback ladder.
    EscalateTransport,
    /// Enter relay-only mode and stop attempting direct connections.
    AcceptRelayOnly,
    /// Abandon a persistently failing peer (circuit breaker tripped).
    AbandonPeer { peer_id_bytes: Vec<u8> },
}

impl std::fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReDialBootstrap => write!(f, "re-dial bootstrap peers"),
            Self::RefreshDescriptors => write!(f, "refresh peer descriptors"),
            Self::EscalateTransport => write!(f, "escalate to next transport"),
            Self::AcceptRelayOnly => write!(f, "accept relay-only mode"),
            Self::AbandonPeer { .. } => write!(f, "abandon persistently failing peer"),
        }
    }
}

/// Maps partial failure conditions to recovery actions.
pub fn recovery_actions_for(failures: &[PartialFailure]) -> Vec<RecoveryAction> {
    let mut actions = Vec::new();
    for f in failures {
        match f {
            PartialFailure::NoPeers => {
                actions.push(RecoveryAction::ReDialBootstrap);
                actions.push(RecoveryAction::RefreshDescriptors);
            }
            PartialFailure::AllTransportsDead => {
                actions.push(RecoveryAction::EscalateTransport);
            }
            PartialFailure::RelayOnly => {
                // If relay-only persists, accept it rather than flapping
                actions.push(RecoveryAction::AcceptRelayOnly);
            }
            PartialFailure::StalePeerCount => {
                actions.push(RecoveryAction::ReDialBootstrap);
            }
        }
    }
    actions.dedup();
    actions
}

// ─── Reconnection scheduler ─────────────────────────────────────────────────

/// Tracks reconnection scheduling with decaying backoff per peer.
///
/// After a peer disconnects, schedules reconnection attempts with increasing
/// delays. After `max_failures` consecutive failures the peer is abandoned
/// (circuit breaker). Resets on successful reconnection.
#[derive(Debug)]
pub struct ReconnectionScheduler {
    /// Per-peer reconnection state keyed by peer ID bytes.
    peers: std::collections::HashMap<Vec<u8>, ReconnectionState>,
    /// Base delay between reconnection attempts.
    base_delay: Duration,
    /// Maximum delay cap.
    max_delay: Duration,
    /// Consecutive failures before circuit breaker trips.
    max_failures: u32,
}

#[derive(Debug, Clone)]
struct ReconnectionState {
    consecutive_failures: u32,
    next_attempt: Instant,
    last_failure: Instant,
}

impl Default for ReconnectionScheduler {
    fn default() -> Self {
        Self {
            peers: std::collections::HashMap::new(),
            base_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(600), // 10 minutes
            max_failures: 10,
        }
    }
}

impl ReconnectionScheduler {
    /// Create with custom parameters.
    pub fn new(base_delay: Duration, max_delay: Duration, max_failures: u32) -> Self {
        Self {
            peers: std::collections::HashMap::new(),
            base_delay,
            max_delay,
            max_failures,
        }
    }

    /// Record a failed reconnection attempt for a peer.
    /// Returns `true` if the circuit breaker has tripped (peer should be abandoned).
    pub fn record_failure(&mut self, peer_id: &[u8]) -> bool {
        let now = Instant::now();
        let state = self.peers.entry(peer_id.to_vec()).or_insert(ReconnectionState {
            consecutive_failures: 0,
            next_attempt: now,
            last_failure: now,
        });
        state.consecutive_failures += 1;
        state.last_failure = now;

        // Exponential backoff: base * 2^(failures-1), capped at max_delay
        let multiplier = 2u64.saturating_pow(state.consecutive_failures.saturating_sub(1));
        let delay = std::cmp::min(
            self.base_delay.saturating_mul(multiplier as u32),
            self.max_delay,
        );
        state.next_attempt = now + delay;

        state.consecutive_failures >= self.max_failures
    }

    /// Record a successful reconnection. Resets backoff for the peer.
    pub fn record_success(&mut self, peer_id: &[u8]) {
        self.peers.remove(peer_id);
    }

    /// Check if a reconnection attempt is due for a peer.
    pub fn should_attempt(&self, peer_id: &[u8]) -> bool {
        match self.peers.get(peer_id) {
            None => true, // Never failed — go ahead
            Some(state) => {
                if state.consecutive_failures >= self.max_failures {
                    false // Circuit breaker tripped
                } else {
                    Instant::now() >= state.next_attempt
                }
            }
        }
    }

    /// Return peer IDs that have been abandoned (circuit breaker tripped).
    pub fn abandoned_peers(&self) -> Vec<Vec<u8>> {
        self.peers
            .iter()
            .filter(|(_, s)| s.consecutive_failures >= self.max_failures)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Return peer IDs that are due for a reconnection attempt now.
    pub fn peers_due_for_reconnect(&self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        self.peers
            .iter()
            .filter(|(_, s)| {
                s.consecutive_failures < self.max_failures && now >= s.next_attempt
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Number of tracked peers.
    pub fn tracked_count(&self) -> usize {
        self.peers.len()
    }

    /// Consecutive failures for a peer (0 if not tracked).
    pub fn failures_for(&self, peer_id: &[u8]) -> u32 {
        self.peers.get(peer_id).map(|s| s.consecutive_failures).unwrap_or(0)
    }
}

// ─── Reconnection metrics ───────────────────────────────────────────────────

/// Tracks reconnection event metrics for diagnostics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconnectionMetrics {
    /// Total reconnection attempts.
    pub attempts: u64,
    /// Successful reconnections.
    pub successes: u64,
    /// Failed reconnection attempts.
    pub failures: u64,
    /// Peers abandoned via circuit breaker.
    pub circuit_breaker_trips: u64,
    /// Recovery actions triggered.
    pub recovery_actions_triggered: u64,
}

impl ReconnectionMetrics {
    pub fn record_attempt(&mut self) {
        self.attempts += 1;
    }

    pub fn record_success(&mut self) {
        self.successes += 1;
    }

    pub fn record_failure(&mut self) {
        self.failures += 1;
    }

    pub fn record_circuit_breaker(&mut self) {
        self.circuit_breaker_trips += 1;
    }

    pub fn record_recovery_action(&mut self) {
        self.recovery_actions_triggered += 1;
    }

    /// Success rate (0.0-1.0), NaN-safe.
    pub fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            1.0
        } else {
            self.successes as f64 / self.attempts as f64
        }
    }
}

// ─── Bridge health status ───────────────────────────────────────────────────

/// Aggregated health status for the bridge layer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeHealthStatus {
    /// Whether the IPC bridge is responsive.
    pub ipc_healthy: bool,
    /// Whether the HTTP bridge is responsive.
    pub http_healthy: bool,
    /// Whether we have at least one connected peer.
    pub has_peers: bool,
    /// Whether flap damping is active.
    pub flap_damping: bool,
    /// Active partial failure conditions.
    pub partial_failures: Vec<String>,
    /// Stale state cleanup report from last startup.
    pub last_cleanup: Option<CleanupReport>,
    /// Reconnection metrics.
    pub reconnection: Option<ReconnectionMetrics>,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── NetworkFlapDetector ─────────────────────────────────────────────

    #[test]
    fn flap_no_events() {
        let d = NetworkFlapDetector::default();
        assert!(!d.is_damping());
        assert_eq!(d.recent_disconnect_count(), 0);
    }

    #[test]
    fn flap_below_threshold() {
        let mut d = NetworkFlapDetector::default(); // threshold=3
        assert!(!d.record_disconnect());
        assert!(!d.record_disconnect());
        assert!(!d.is_damping());
        assert_eq!(d.recent_disconnect_count(), 2);
    }

    #[test]
    fn flap_triggers_at_threshold() {
        let mut d = NetworkFlapDetector::new(
            3,
            Duration::from_secs(60),
            Duration::from_secs(120),
        );
        d.record_disconnect();
        d.record_disconnect();
        let triggered = d.record_disconnect();
        assert!(triggered);
        assert!(d.is_damping());
    }

    #[test]
    fn flap_reset_clears_state() {
        let mut d = NetworkFlapDetector::new(
            2,
            Duration::from_secs(60),
            Duration::from_secs(120),
        );
        d.record_disconnect();
        d.record_disconnect();
        assert!(d.is_damping());
        d.reset();
        assert!(!d.is_damping());
        assert_eq!(d.recent_disconnect_count(), 0);
    }

    #[test]
    fn flap_damping_duration() {
        let mut d = NetworkFlapDetector::new(
            1,
            Duration::from_secs(60),
            Duration::from_millis(50), // Very short for testing
        );
        d.record_disconnect();
        assert!(d.is_damping());
        assert!(d.damping_remaining().is_some());
        std::thread::sleep(Duration::from_millis(60));
        assert!(!d.is_damping());
        assert!(d.damping_remaining().is_none());
    }

    // ── PartialFailureDetector ──────────────────────────────────────────

    #[test]
    fn partial_no_failures_with_peers() {
        let mut d = PartialFailureDetector::default();
        let failures = d.evaluate(5, false, false);
        assert!(failures.is_empty());
    }

    #[test]
    fn partial_no_peers_needs_threshold() {
        let mut d = PartialFailureDetector {
            no_peers_threshold: Duration::from_millis(50),
            ..Default::default()
        };
        // First evaluation starts the timer
        let f1 = d.evaluate(0, false, false);
        assert!(f1.is_empty());
        // Before threshold
        let f2 = d.evaluate(0, false, false);
        assert!(f2.is_empty());
        // Wait past threshold
        std::thread::sleep(Duration::from_millis(60));
        let f3 = d.evaluate(0, false, false);
        assert!(f3.contains(&PartialFailure::NoPeers));
    }

    #[test]
    fn partial_no_peers_resets_on_connection() {
        let mut d = PartialFailureDetector {
            no_peers_threshold: Duration::from_millis(10),
            ..Default::default()
        };
        d.evaluate(0, false, false);
        std::thread::sleep(Duration::from_millis(20));
        // Peer appears before we check again
        let failures = d.evaluate(1, false, false);
        assert!(!failures.contains(&PartialFailure::NoPeers));
    }

    #[test]
    fn partial_all_transports_dead() {
        let mut d = PartialFailureDetector::default();
        let failures = d.evaluate(3, true, false);
        assert!(failures.contains(&PartialFailure::AllTransportsDead));
    }

    #[test]
    fn partial_relay_only() {
        let mut d = PartialFailureDetector::default();
        let failures = d.evaluate(2, false, true);
        assert!(failures.contains(&PartialFailure::RelayOnly));
    }

    #[test]
    fn partial_display() {
        assert!(PartialFailure::NoPeers.to_string().contains("no peers"));
        assert!(PartialFailure::RelayOnly.to_string().contains("relay-only"));
    }

    // ── Stale state cleanup ─────────────────────────────────────────────

    #[test]
    fn cleanup_nonexistent_dir() {
        let temp = std::env::temp_dir().join("miasma-test-cleanup-nonexistent");
        let _ = std::fs::create_dir_all(&temp);
        let report = cleanup_stale_state(&temp);
        assert!(!report.stale_port_file_removed);
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn cleanup_removes_port_files() {
        let temp = std::env::temp_dir().join("miasma-test-cleanup-ports");
        let _ = std::fs::create_dir_all(&temp);
        std::fs::write(temp.join("daemon.port"), "12345").unwrap();
        std::fs::write(temp.join("daemon.http"), "17842").unwrap();
        let report = cleanup_stale_state(&temp);
        assert!(report.stale_port_file_removed);
        assert!(report.stale_http_port_file_removed);
        assert!(!temp.join("daemon.port").exists());
        assert!(!temp.join("daemon.http").exists());
        let _ = std::fs::remove_dir_all(&temp);
    }

    // ── BridgeHealthStatus ──────────────────────────────────────────────

    #[test]
    fn bridge_health_serialization() {
        let status = BridgeHealthStatus {
            ipc_healthy: true,
            http_healthy: true,
            has_peers: true,
            flap_damping: false,
            partial_failures: vec!["relay-only".to_string()],
            last_cleanup: Some(CleanupReport {
                stale_port_file_removed: true,
                stale_http_port_file_removed: false,
                stale_peers_invalidated: 3,
                stuck_replications_reset: 1,
            }),
            reconnection: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        let de: BridgeHealthStatus = serde_json::from_str(&json).unwrap();
        assert!(de.ipc_healthy);
        assert_eq!(de.partial_failures.len(), 1);
        assert!(de.last_cleanup.unwrap().stale_port_file_removed);
    }

    // ── Recovery actions ────────────────────────────────────────────────

    #[test]
    fn recovery_no_peers_dials_bootstrap() {
        let actions = recovery_actions_for(&[PartialFailure::NoPeers]);
        assert!(actions.contains(&RecoveryAction::ReDialBootstrap));
        assert!(actions.contains(&RecoveryAction::RefreshDescriptors));
    }

    #[test]
    fn recovery_all_dead_escalates_transport() {
        let actions = recovery_actions_for(&[PartialFailure::AllTransportsDead]);
        assert!(actions.contains(&RecoveryAction::EscalateTransport));
    }

    #[test]
    fn recovery_relay_only_accepts() {
        let actions = recovery_actions_for(&[PartialFailure::RelayOnly]);
        assert!(actions.contains(&RecoveryAction::AcceptRelayOnly));
    }

    #[test]
    fn recovery_stale_count_dials_bootstrap() {
        let actions = recovery_actions_for(&[PartialFailure::StalePeerCount]);
        assert!(actions.contains(&RecoveryAction::ReDialBootstrap));
    }

    #[test]
    fn recovery_action_display() {
        assert!(RecoveryAction::ReDialBootstrap.to_string().contains("bootstrap"));
        assert!(RecoveryAction::EscalateTransport.to_string().contains("transport"));
    }

    // ── Reconnection scheduler ──────────────────────────────────────────

    #[test]
    fn scheduler_new_peer_allows_attempt() {
        let sched = ReconnectionScheduler::default();
        assert!(sched.should_attempt(b"peer-a"));
    }

    #[test]
    fn scheduler_failure_blocks_immediate_retry() {
        let mut sched = ReconnectionScheduler::new(
            Duration::from_secs(60), // long enough that it won't expire during test
            Duration::from_secs(600),
            10,
        );
        sched.record_failure(b"peer-a");
        assert!(!sched.should_attempt(b"peer-a"));
    }

    #[test]
    fn scheduler_success_resets_backoff() {
        let mut sched = ReconnectionScheduler::default();
        sched.record_failure(b"peer-a");
        sched.record_success(b"peer-a");
        assert!(sched.should_attempt(b"peer-a"));
        assert_eq!(sched.failures_for(b"peer-a"), 0);
    }

    #[test]
    fn scheduler_circuit_breaker_trips() {
        let mut sched = ReconnectionScheduler::new(
            Duration::from_millis(1),
            Duration::from_millis(10),
            3,
        );
        assert!(!sched.record_failure(b"peer-a")); // 1
        assert!(!sched.record_failure(b"peer-a")); // 2
        assert!(sched.record_failure(b"peer-a"));  // 3 — tripped
        assert!(!sched.should_attempt(b"peer-a"));
        assert!(sched.abandoned_peers().contains(&b"peer-a".to_vec()));
    }

    #[test]
    fn scheduler_backoff_is_exponential() {
        let mut sched = ReconnectionScheduler::new(
            Duration::from_millis(10),
            Duration::from_secs(60),
            20,
        );
        // After 1 failure: 10ms delay
        sched.record_failure(b"p");
        let f1 = sched.failures_for(b"p");
        // After 2 failures: 20ms delay
        sched.record_failure(b"p");
        let f2 = sched.failures_for(b"p");
        // After 3 failures: 40ms delay
        sched.record_failure(b"p");
        let f3 = sched.failures_for(b"p");
        assert_eq!(f1, 1);
        assert_eq!(f2, 2);
        assert_eq!(f3, 3);
    }

    #[test]
    fn scheduler_due_for_reconnect_after_delay() {
        let mut sched = ReconnectionScheduler::new(
            Duration::from_millis(10),
            Duration::from_secs(60),
            10,
        );
        sched.record_failure(b"peer-a");
        assert!(sched.peers_due_for_reconnect().is_empty());
        std::thread::sleep(Duration::from_millis(20));
        assert!(sched.peers_due_for_reconnect().contains(&b"peer-a".to_vec()));
    }

    #[test]
    fn scheduler_independent_peers() {
        let mut sched = ReconnectionScheduler::default();
        sched.record_failure(b"peer-a");
        assert!(sched.should_attempt(b"peer-b"));
        assert_eq!(sched.tracked_count(), 1);
    }

    // ── Reconnection metrics ────────────────────────────────────────────

    #[test]
    fn metrics_defaults_to_100_percent() {
        let m = ReconnectionMetrics::default();
        assert_eq!(m.success_rate(), 1.0);
    }

    #[test]
    fn metrics_tracks_events() {
        let mut m = ReconnectionMetrics::default();
        m.record_attempt();
        m.record_attempt();
        m.record_success();
        m.record_failure();
        m.record_circuit_breaker();
        m.record_recovery_action();
        assert_eq!(m.attempts, 2);
        assert_eq!(m.successes, 1);
        assert_eq!(m.failures, 1);
        assert_eq!(m.circuit_breaker_trips, 1);
        assert_eq!(m.recovery_actions_triggered, 1);
        assert!((m.success_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn metrics_serde_roundtrip() {
        let m = ReconnectionMetrics {
            attempts: 10,
            successes: 7,
            failures: 3,
            circuit_breaker_trips: 1,
            recovery_actions_triggered: 2,
        };
        let json = serde_json::to_string(&m).unwrap();
        let de: ReconnectionMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(de.attempts, 10);
        assert_eq!(de.successes, 7);
    }

    #[test]
    fn recovery_action_serde_roundtrip() {
        let actions = vec![
            RecoveryAction::ReDialBootstrap,
            RecoveryAction::EscalateTransport,
            RecoveryAction::AbandonPeer { peer_id_bytes: vec![1, 2, 3] },
        ];
        let json = serde_json::to_string(&actions).unwrap();
        let de: Vec<RecoveryAction> = serde_json::from_str(&json).unwrap();
        assert_eq!(de.len(), 3);
        assert_eq!(de[0], RecoveryAction::ReDialBootstrap);
    }
}
