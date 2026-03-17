/// Offline peer detector — Phase 3 (Task 20).
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ─── Peer health ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerHealth {
    /// Peer responded to the most recent probe.
    Healthy,
    /// Peer missed one probe — monitoring more closely.
    Suspected,
    /// Peer missed `max_failures` consecutive probes — considered offline.
    Offline,
}

#[derive(Debug, Clone)]
struct PeerState {
    health: PeerHealth,
    consecutive_failures: u32,
    last_probe: Option<Instant>,
    last_success: Option<Instant>,
}

// ─── Detector ─────────────────────────────────────────────────────────────────

/// Tracks the liveness of peers that hold shares of content we care about.
pub struct OfflineDetector {
    /// Peer ID (string) → state.
    peers: HashMap<String, PeerState>,
    /// Number of consecutive failures before a peer is declared offline.
    pub max_failures: u32,
    /// Interval between probes for a healthy peer.
    pub probe_interval: Duration,
    /// Interval between probes for a suspected peer (more frequent).
    pub suspect_interval: Duration,
}

impl Default for OfflineDetector {
    fn default() -> Self {
        Self {
            peers: HashMap::new(),
            max_failures: 3,
            probe_interval: Duration::from_secs(3600),   // 1 hour
            suspect_interval: Duration::from_secs(300),  // 5 minutes
        }
    }
}

impl OfflineDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a peer for liveness monitoring.
    pub fn track(&mut self, peer_id: &str) {
        self.peers.entry(peer_id.to_owned()).or_insert(PeerState {
            health: PeerHealth::Healthy,
            consecutive_failures: 0,
            last_probe: None,
            last_success: None,
        });
    }

    /// Record that a probe to `peer_id` succeeded.
    pub fn record_success(&mut self, peer_id: &str) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.health = PeerHealth::Healthy;
            state.consecutive_failures = 0;
            state.last_success = Some(Instant::now());
            state.last_probe = Some(Instant::now());
        }
    }

    /// Record that a probe to `peer_id` failed.
    pub fn record_failure(&mut self, peer_id: &str) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.consecutive_failures += 1;
            state.last_probe = Some(Instant::now());
            state.health = if state.consecutive_failures >= self.max_failures {
                PeerHealth::Offline
            } else {
                PeerHealth::Suspected
            };
        }
    }

    /// Return peers that are due for a probe.
    pub fn peers_due_for_probe(&self) -> Vec<String> {
        let now = Instant::now();
        self.peers
            .iter()
            .filter(|(_, state)| {
                let interval = match state.health {
                    PeerHealth::Suspected => self.suspect_interval,
                    _ => self.probe_interval,
                };
                state.last_probe.map(|t| now.duration_since(t) >= interval).unwrap_or(true)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Return all peers currently classified as offline.
    pub fn offline_peers(&self) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, s)| s.health == PeerHealth::Offline)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Current health of a peer.
    pub fn health(&self, peer_id: &str) -> Option<&PeerHealth> {
        self.peers.get(peer_id).map(|s| &s.health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_tracks_failures() {
        let mut det = OfflineDetector::new();
        det.max_failures = 2;
        det.track("peer1");

        det.record_failure("peer1");
        assert_eq!(det.health("peer1"), Some(&PeerHealth::Suspected));

        det.record_failure("peer1");
        assert_eq!(det.health("peer1"), Some(&PeerHealth::Offline));

        det.record_success("peer1");
        assert_eq!(det.health("peer1"), Some(&PeerHealth::Healthy));
    }

    #[test]
    fn detector_offline_peers_list() {
        let mut det = OfflineDetector::new();
        det.max_failures = 1;
        det.track("a");
        det.track("b");
        det.record_failure("a");
        let offline = det.offline_peers();
        assert!(offline.contains(&"a".to_string()));
        assert!(!offline.contains(&"b".to_string()));
    }
}
