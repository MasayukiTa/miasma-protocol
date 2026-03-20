/// Routing overlay — trust-based preference, diversity, and difficulty (ADR-004 Phase 3c).
///
/// libp2p 0.54's Kademlia does not expose k-bucket internals, so we implement
/// routing quality as an overlay that tracks per-peer scores, enforces IP
/// diversity limits, and provides routing preference when selecting peers
/// for DHT queries and shard fetches.
///
/// # Design
///
/// The `RoutingTable` wraps the peer registry with:
///
/// 1. **Reliability scores** — per-peer success/failure counters that decay
///    over time. Unreliable peers are deprioritised in routing decisions.
///
/// 2. **IP diversity constraints** — limits on how many peers from the same
///    /16 subnet (IPv4) or /48 prefix (IPv6) can be active in routing.
///    Prevents a single operator from dominating the routing table.
///
/// 3. **Routing preference** — when multiple peers can serve a request,
///    prefer Verified > Observed, high-reliability > low-reliability,
///    diverse-prefix > same-prefix.
///
/// 4. **Dynamic PoW difficulty** — adjusts required difficulty based on
///    observed network size and peer churn.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::address::{AddressClass, AddressTrust, classify_multiaddr};
use super::sybil;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum peers from the same /16 IPv4 subnet in the routing overlay.
const MAX_PEERS_PER_IPV4_SLASH16: usize = 3;

/// Maximum peers from the same /48 IPv6 prefix in the routing overlay.
const MAX_PEERS_PER_IPV6_SLASH48: usize = 3;

/// Reliability score threshold below which a peer is considered unreliable.
const UNRELIABLE_THRESHOLD: f64 = 0.3;

/// Minimum number of interactions before reliability score is meaningful.
const MIN_INTERACTIONS_FOR_SCORE: u64 = 3;

/// Maximum number of interactions tracked before old ones decay.
const INTERACTION_WINDOW: u64 = 200;

// ─── IP prefix types ────────────────────────────────────────────────────────

/// Coarse IP prefix for diversity enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpPrefix {
    /// First two octets of an IPv4 address (/16).
    V4Slash16([u8; 2]),
    /// First three 16-bit segments of an IPv6 address (/48).
    V6Slash48([u16; 3]),
    /// Loopback / unknown — not subject to diversity constraints.
    Local,
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpPrefix::V4Slash16([a, b]) => write!(f, "{a}.{b}.0.0/16"),
            IpPrefix::V6Slash48([a, b, c]) => write!(f, "{a:x}:{b:x}:{c:x}::/48"),
            IpPrefix::Local => write!(f, "local"),
        }
    }
}

/// Extract the IP prefix from a multiaddr.
pub fn ip_prefix_of(addr: &Multiaddr) -> IpPrefix {
    for proto in addr.iter() {
        match proto {
            libp2p::multiaddr::Protocol::Ip4(ip) => {
                let octets = ip.octets();
                if ip.is_loopback() || ip.is_link_local() {
                    return IpPrefix::Local;
                }
                return IpPrefix::V4Slash16([octets[0], octets[1]]);
            }
            libp2p::multiaddr::Protocol::Ip6(ip) => {
                if ip.is_loopback() {
                    return IpPrefix::Local;
                }
                let segs = ip.segments();
                return IpPrefix::V6Slash48([segs[0], segs[1], segs[2]]);
            }
            _ => continue,
        }
    }
    IpPrefix::Local
}

// ─── Per-peer routing state ─────────────────────────────────────────────────

/// Extended per-peer routing metadata tracked by the overlay.
#[derive(Debug, Clone)]
pub struct PeerRoutingState {
    /// IP prefix derived from the peer's primary address.
    pub ip_prefix: IpPrefix,
    /// Number of successful DHT interactions (queries, fetches).
    pub successes: u64,
    /// Number of failed DHT interactions.
    pub failures: u64,
    /// When the peer was first added to the routing overlay.
    pub first_seen: Instant,
    /// When the peer last had a successful interaction.
    pub last_success: Option<Instant>,
}

impl PeerRoutingState {
    pub fn new(ip_prefix: IpPrefix) -> Self {
        Self {
            ip_prefix,
            successes: 0,
            failures: 0,
            first_seen: Instant::now(),
            last_success: None,
        }
    }

    /// Reliability score: 0.0 (all failures) to 1.0 (all successes).
    /// Returns 1.0 if fewer than MIN_INTERACTIONS_FOR_SCORE interactions.
    pub fn reliability(&self) -> f64 {
        let total = self.successes + self.failures;
        if total < MIN_INTERACTIONS_FOR_SCORE {
            return 1.0; // benefit of the doubt
        }
        self.successes as f64 / total as f64
    }

    /// Record a successful interaction.
    pub fn record_success(&mut self) {
        self.successes = self.successes.saturating_add(1);
        self.last_success = Some(Instant::now());
        self.decay_if_needed();
    }

    /// Record a failed interaction.
    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.decay_if_needed();
    }

    /// Halve counters when the window is exceeded, preserving the ratio.
    fn decay_if_needed(&mut self) {
        if self.successes + self.failures > INTERACTION_WINDOW {
            self.successes /= 2;
            self.failures /= 2;
        }
    }

    /// Whether this peer is considered unreliable.
    pub fn is_unreliable(&self) -> bool {
        let total = self.successes + self.failures;
        total >= MIN_INTERACTIONS_FOR_SCORE && self.reliability() < UNRELIABLE_THRESHOLD
    }
}

// ─── Diversity check result ─────────────────────────────────────────────────

/// Why a peer was rejected or deprioritised for diversity reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiversityViolation {
    /// Too many peers from the same IPv4 /16 subnet.
    Ipv4SubnetSaturated { prefix: String, count: usize, limit: usize },
    /// Too many peers from the same IPv6 /48 prefix.
    Ipv6PrefixSaturated { prefix: String, count: usize, limit: usize },
}

impl std::fmt::Display for DiversityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiversityViolation::Ipv4SubnetSaturated { prefix, count, limit } => {
                write!(f, "IPv4 /16 {prefix}: {count}/{limit} peers")
            }
            DiversityViolation::Ipv6PrefixSaturated { prefix, count, limit } => {
                write!(f, "IPv6 /48 {prefix}: {count}/{limit} peers")
            }
        }
    }
}

// ─── RoutingTable overlay ───────────────────────────────────────────────────

/// Routing overlay that enforces trust preference, IP diversity, and
/// reliability tracking on top of libp2p's Kademlia.
pub struct RoutingTable {
    /// Per-peer routing state.
    peers: HashMap<PeerId, PeerRoutingState>,
    /// Count of peers per IP prefix.
    prefix_counts: HashMap<IpPrefix, usize>,
    /// Whether diversity enforcement is active (disabled in local/test mode).
    diversity_enabled: bool,
    /// Cumulative count of diversity-based rejections.
    diversity_rejections: u64,
    /// Current PoW difficulty for the network.
    current_difficulty: u8,
    /// Peer count observations for difficulty adjustment.
    difficulty_observations: Vec<(Instant, usize)>,
}

impl RoutingTable {
    pub fn new(diversity_enabled: bool) -> Self {
        Self {
            peers: HashMap::new(),
            prefix_counts: HashMap::new(),
            diversity_enabled,
            diversity_rejections: 0,
            current_difficulty: sybil::DEFAULT_POW_DIFFICULTY,
            difficulty_observations: Vec::new(),
        }
    }

    /// Check whether a peer with the given addresses can be admitted to the
    /// routing overlay without violating diversity constraints.
    ///
    /// Returns `Ok(IpPrefix)` if the peer passes, or `Err(DiversityViolation)`
    /// if the peer would create a prefix cluster.
    pub fn check_diversity(&self, addrs: &[Multiaddr]) -> Result<IpPrefix, DiversityViolation> {
        if !self.diversity_enabled {
            let prefix = addrs.first().map(|a| ip_prefix_of(a)).unwrap_or(IpPrefix::Local);
            return Ok(prefix);
        }

        // Use the first non-local address for prefix determination.
        let prefix = addrs.iter()
            .map(|a| ip_prefix_of(a))
            .find(|p| *p != IpPrefix::Local)
            .unwrap_or(IpPrefix::Local);

        // Local prefix is exempt from diversity.
        if prefix == IpPrefix::Local {
            return Ok(prefix);
        }

        let current_count = self.prefix_counts.get(&prefix).copied().unwrap_or(0);
        let limit = match prefix {
            IpPrefix::V4Slash16(_) => MAX_PEERS_PER_IPV4_SLASH16,
            IpPrefix::V6Slash48(_) => MAX_PEERS_PER_IPV6_SLASH48,
            IpPrefix::Local => return Ok(prefix),
        };

        if current_count >= limit {
            let violation = match prefix {
                IpPrefix::V4Slash16(_) => DiversityViolation::Ipv4SubnetSaturated {
                    prefix: prefix.to_string(),
                    count: current_count,
                    limit,
                },
                IpPrefix::V6Slash48(_) => DiversityViolation::Ipv6PrefixSaturated {
                    prefix: prefix.to_string(),
                    count: current_count,
                    limit,
                },
                IpPrefix::Local => unreachable!(),
            };
            return Err(violation);
        }

        Ok(prefix)
    }

    /// Add a peer to the routing overlay after it passes diversity checks.
    pub fn add_peer(&mut self, peer_id: PeerId, prefix: IpPrefix) {
        if self.peers.contains_key(&peer_id) {
            return; // already tracked
        }
        self.peers.insert(peer_id, PeerRoutingState::new(prefix));
        if prefix != IpPrefix::Local {
            *self.prefix_counts.entry(prefix).or_insert(0) += 1;
        }
    }

    /// Remove a peer from the routing overlay.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.peers.remove(peer_id) {
            if state.ip_prefix != IpPrefix::Local {
                if let Some(count) = self.prefix_counts.get_mut(&state.ip_prefix) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.prefix_counts.remove(&state.ip_prefix);
                    }
                }
            }
        }
    }

    /// Record a successful interaction with a peer.
    pub fn record_success(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.record_success();
        }
    }

    /// Record a failed interaction with a peer.
    pub fn record_failure(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.record_failure();
        }
    }

    /// Record a diversity-based rejection.
    pub fn record_diversity_rejection(&mut self) {
        self.diversity_rejections += 1;
    }

    /// Rank peers by routing quality. Returns peer IDs sorted best-first.
    ///
    /// Scoring factors (in priority order):
    /// 1. Trust tier (Verified > Observed > Claimed)
    /// 2. Reliability (higher success rate preferred)
    /// 3. Prefix diversity (prefer unique prefixes)
    ///
    /// `trust_of` is a closure that looks up the peer's trust tier.
    pub fn rank_peers<F>(&self, candidates: &[PeerId], trust_of: F) -> Vec<PeerId>
    where
        F: Fn(&PeerId) -> AddressTrust,
    {
        let mut scored: Vec<(PeerId, u32)> = candidates
            .iter()
            .filter_map(|peer_id| {
                let state = self.peers.get(peer_id)?;
                let trust = trust_of(peer_id);

                // Trust tier score: Verified=300, Observed=100, Claimed=0.
                let trust_score = match trust {
                    AddressTrust::Verified => 300,
                    AddressTrust::Observed => 100,
                    AddressTrust::Claimed => 0,
                };

                // Reliability score: 0–100.
                let reliability_score = (state.reliability() * 100.0) as u32;

                // Diversity bonus: peers from less-common prefixes get a bonus.
                let prefix_count = self.prefix_counts.get(&state.ip_prefix).copied().unwrap_or(1);
                let diversity_score = 50 / prefix_count as u32;

                // Penalty for unreliable peers.
                let penalty = if state.is_unreliable() { 200 } else { 0 };

                let total = trust_score + reliability_score + diversity_score - penalty;
                Some((*peer_id, total))
            })
            .collect();

        scored.sort_by(|a, b| b.1.cmp(&a.1));
        scored.into_iter().map(|(id, _)| id).collect()
    }

    /// Get the routing state for a peer.
    pub fn peer_state(&self, peer_id: &PeerId) -> Option<&PeerRoutingState> {
        self.peers.get(peer_id)
    }

    /// Returns the number of peers in the routing overlay.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns prefix distribution for diagnostics.
    pub fn prefix_distribution(&self) -> Vec<(String, usize)> {
        let mut dist: Vec<_> = self.prefix_counts.iter()
            .map(|(p, c)| (p.to_string(), *c))
            .collect();
        dist.sort_by(|a, b| b.1.cmp(&a.1));
        dist
    }

    /// Returns all unreliable peers (for diagnostics).
    pub fn unreliable_peers(&self) -> Vec<(PeerId, f64)> {
        self.peers.iter()
            .filter(|(_, s)| s.is_unreliable())
            .map(|(id, s)| (*id, s.reliability()))
            .collect()
    }

    /// Snapshot of routing overlay health for diagnostics.
    pub fn stats(&self) -> RoutingStats {
        let total = self.peers.len();
        let unreliable = self.peers.values().filter(|s| s.is_unreliable()).count();
        let unique_prefixes = self.prefix_counts.len();
        let max_prefix_count = self.prefix_counts.values().max().copied().unwrap_or(0);

        RoutingStats {
            total_peers: total,
            unreliable_peers: unreliable,
            unique_prefixes,
            max_prefix_concentration: max_prefix_count,
            diversity_rejections: self.diversity_rejections,
            current_difficulty: self.current_difficulty,
        }
    }

    // ─── Dynamic difficulty ─────────────────────────────────────────────────

    /// Record an observation of the current connected peer count.
    /// Called periodically (e.g., every 60s) to build a history for
    /// difficulty adjustment.
    pub fn observe_network_size(&mut self, peer_count: usize) {
        let now = Instant::now();
        self.difficulty_observations.push((now, peer_count));

        // Keep only the last 60 observations (~1 hour at 60s intervals).
        if self.difficulty_observations.len() > 60 {
            self.difficulty_observations.remove(0);
        }
    }

    /// Compute the recommended PoW difficulty based on observed network size.
    ///
    /// # Difficulty schedule
    /// - < 10 peers: 8 bits (bootstrap)
    /// - 10–50 peers: 12 bits
    /// - 50–200 peers: 16 bits
    /// - 200–1000 peers: 20 bits
    /// - > 1000 peers: 24 bits
    ///
    /// The adjustment is based on the median of recent observations to
    /// smooth out transient fluctuations.
    pub fn recommended_difficulty(&self) -> u8 {
        if self.difficulty_observations.is_empty() {
            return sybil::DEFAULT_POW_DIFFICULTY;
        }

        let mut sizes: Vec<usize> = self.difficulty_observations.iter()
            .map(|(_, s)| *s)
            .collect();
        sizes.sort();
        let median = sizes[sizes.len() / 2];

        match median {
            0..=9 => 8,
            10..=49 => 12,
            50..=199 => 16,
            200..=999 => 20,
            _ => 24,
        }
    }

    /// Update the current difficulty if the recommended value differs.
    /// Returns the new difficulty if it changed.
    pub fn maybe_adjust_difficulty(&mut self) -> Option<u8> {
        let recommended = self.recommended_difficulty();
        if recommended != self.current_difficulty {
            let old = self.current_difficulty;
            self.current_difficulty = recommended;
            info!(
                "PoW difficulty adjusted: {} → {} bits (median network size: {})",
                old, recommended,
                self.difficulty_observations.iter()
                    .map(|(_, s)| *s)
                    .sum::<usize>()
                    .checked_div(self.difficulty_observations.len())
                    .unwrap_or(0)
            );
            Some(recommended)
        } else {
            None
        }
    }

    /// Current effective PoW difficulty.
    pub fn current_difficulty(&self) -> u8 {
        self.current_difficulty
    }
}

// ─── Routing stats ──────────────────────────────────────────────────────────

/// Snapshot of routing overlay health for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingStats {
    /// Total peers in the routing overlay.
    pub total_peers: usize,
    /// Peers flagged as unreliable.
    pub unreliable_peers: usize,
    /// Number of unique IP prefixes.
    pub unique_prefixes: usize,
    /// Highest number of peers from a single prefix.
    pub max_prefix_concentration: usize,
    /// Cumulative diversity-based rejections.
    pub diversity_rejections: u64,
    /// Current PoW difficulty in bits.
    pub current_difficulty: u8,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn ip_prefix_extraction_ipv4() {
        assert_eq!(ip_prefix_of(&ma("/ip4/8.8.4.4/tcp/4001")), IpPrefix::V4Slash16([8, 8]));
        assert_eq!(ip_prefix_of(&ma("/ip4/192.168.1.1/tcp/4001")), IpPrefix::V4Slash16([192, 168]));
    }

    #[test]
    fn ip_prefix_loopback_is_local() {
        assert_eq!(ip_prefix_of(&ma("/ip4/127.0.0.1/tcp/4001")), IpPrefix::Local);
    }

    #[test]
    fn ip_prefix_extraction_ipv6() {
        let prefix = ip_prefix_of(&ma("/ip6/2001:db8:85a3::1/tcp/4001"));
        assert_eq!(prefix, IpPrefix::V6Slash48([0x2001, 0x0db8, 0x85a3]));
    }

    #[test]
    fn diversity_allows_different_prefixes() {
        let rt = RoutingTable::new(true);
        let addrs = vec![ma("/ip4/8.8.4.4/tcp/4001")];
        assert!(rt.check_diversity(&addrs).is_ok());
    }

    #[test]
    fn diversity_blocks_saturated_prefix() {
        let mut rt = RoutingTable::new(true);
        let prefix = IpPrefix::V4Slash16([8, 8]);

        // Fill to the limit.
        for i in 0..MAX_PEERS_PER_IPV4_SLASH16 {
            let peer = PeerId::random();
            rt.add_peer(peer, prefix);
        }

        // Next peer from same prefix should be rejected.
        let addrs = vec![ma("/ip4/8.8.99.1/tcp/4001")];
        let result = rt.check_diversity(&addrs);
        assert!(result.is_err());
        if let Err(DiversityViolation::Ipv4SubnetSaturated { count, limit, .. }) = result {
            assert_eq!(count, MAX_PEERS_PER_IPV4_SLASH16);
            assert_eq!(limit, MAX_PEERS_PER_IPV4_SLASH16);
        }
    }

    #[test]
    fn diversity_disabled_allows_everything() {
        let mut rt = RoutingTable::new(false);
        let prefix = IpPrefix::V4Slash16([8, 8]);

        for _ in 0..10 {
            rt.add_peer(PeerId::random(), prefix);
        }

        let addrs = vec![ma("/ip4/8.8.99.1/tcp/4001")];
        assert!(rt.check_diversity(&addrs).is_ok());
    }

    #[test]
    fn diversity_local_prefix_exempt() {
        let mut rt = RoutingTable::new(true);
        let prefix = IpPrefix::Local;
        for _ in 0..20 {
            rt.add_peer(PeerId::random(), prefix);
        }
        let addrs = vec![ma("/ip4/127.0.0.1/tcp/4001")];
        assert!(rt.check_diversity(&addrs).is_ok());
    }

    #[test]
    fn remove_peer_updates_prefix_count() {
        let mut rt = RoutingTable::new(true);
        let prefix = IpPrefix::V4Slash16([8, 8]);
        let peer = PeerId::random();
        rt.add_peer(peer, prefix);
        assert_eq!(rt.prefix_counts.get(&prefix), Some(&1));

        rt.remove_peer(&peer);
        assert_eq!(rt.prefix_counts.get(&prefix), None);
    }

    #[test]
    fn reliability_tracking() {
        let mut state = PeerRoutingState::new(IpPrefix::Local);
        assert_eq!(state.reliability(), 1.0); // benefit of the doubt

        for _ in 0..5 {
            state.record_success();
        }
        for _ in 0..5 {
            state.record_failure();
        }
        assert!((state.reliability() - 0.5).abs() < 0.01);

        // Not unreliable at 50%.
        assert!(!state.is_unreliable());
    }

    #[test]
    fn unreliable_detection() {
        let mut state = PeerRoutingState::new(IpPrefix::Local);
        for _ in 0..1 {
            state.record_success();
        }
        for _ in 0..9 {
            state.record_failure();
        }
        assert!(state.is_unreliable());
    }

    #[test]
    fn decay_halves_counters() {
        let mut state = PeerRoutingState::new(IpPrefix::Local);
        state.successes = 150;
        state.failures = 60;
        // Total = 210 > INTERACTION_WINDOW (200), so decay triggers on next record.
        state.record_success();
        // After decay: (150+1)/2 = 75 (approx), failures = 30
        assert!(state.successes < 100);
        assert!(state.failures < 40);
    }

    #[test]
    fn rank_peers_prefers_verified() {
        let mut rt = RoutingTable::new(true);
        let verified = PeerId::random();
        let observed = PeerId::random();
        rt.add_peer(verified, IpPrefix::V4Slash16([1, 1]));
        rt.add_peer(observed, IpPrefix::V4Slash16([2, 2]));

        let ranked = rt.rank_peers(&[observed, verified], |id| {
            if *id == verified { AddressTrust::Verified } else { AddressTrust::Observed }
        });

        assert_eq!(ranked[0], verified, "verified peer should be ranked first");
    }

    #[test]
    fn rank_peers_deprioritises_unreliable() {
        let mut rt = RoutingTable::new(true);
        let reliable = PeerId::random();
        let unreliable = PeerId::random();
        rt.add_peer(reliable, IpPrefix::V4Slash16([1, 1]));
        rt.add_peer(unreliable, IpPrefix::V4Slash16([2, 2]));

        // Make unreliable fail a lot.
        for _ in 0..10 {
            rt.record_failure(&unreliable);
        }

        let ranked = rt.rank_peers(&[unreliable, reliable], |_| AddressTrust::Verified);
        assert_eq!(ranked[0], reliable, "reliable peer should be ranked first");
    }

    #[test]
    fn rank_peers_diversity_bonus() {
        let mut rt = RoutingTable::new(true);
        let common = PeerId::random();
        let rare = PeerId::random();
        let prefix = IpPrefix::V4Slash16([8, 8]);
        rt.add_peer(common, prefix);
        rt.add_peer(PeerId::random(), prefix); // another from same /16
        rt.add_peer(rare, IpPrefix::V4Slash16([1, 1])); // unique /16

        let ranked = rt.rank_peers(&[common, rare], |_| AddressTrust::Verified);
        // rare should get a diversity bonus.
        assert_eq!(ranked[0], rare, "peer from rare prefix should be preferred");
    }

    #[test]
    fn difficulty_schedule() {
        let mut rt = RoutingTable::new(true);
        assert_eq!(rt.recommended_difficulty(), 8); // no observations

        // Simulate bootstrap (5 peers).
        for _ in 0..5 {
            rt.observe_network_size(5);
        }
        assert_eq!(rt.recommended_difficulty(), 8);

        // Simulate growth (30 peers).
        for _ in 0..10 {
            rt.observe_network_size(30);
        }
        assert_eq!(rt.recommended_difficulty(), 12);

        // Simulate larger network (100 peers).
        rt.difficulty_observations.clear();
        for _ in 0..10 {
            rt.observe_network_size(100);
        }
        assert_eq!(rt.recommended_difficulty(), 16);
    }

    #[test]
    fn difficulty_adjustment() {
        let mut rt = RoutingTable::new(true);
        assert_eq!(rt.current_difficulty(), 8);

        for _ in 0..10 {
            rt.observe_network_size(100);
        }
        let new = rt.maybe_adjust_difficulty();
        assert_eq!(new, Some(16));
        assert_eq!(rt.current_difficulty(), 16);

        // No change if already correct.
        let same = rt.maybe_adjust_difficulty();
        assert_eq!(same, None);
    }

    #[test]
    fn stats_snapshot() {
        let mut rt = RoutingTable::new(true);
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        rt.add_peer(p1, IpPrefix::V4Slash16([1, 1]));
        rt.add_peer(p2, IpPrefix::V4Slash16([2, 2]));

        for _ in 0..10 {
            rt.record_failure(&p2);
        }
        rt.record_diversity_rejection();

        let stats = rt.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.unreliable_peers, 1);
        assert_eq!(stats.unique_prefixes, 2);
        assert_eq!(stats.max_prefix_concentration, 1);
        assert_eq!(stats.diversity_rejections, 1);
    }

    #[test]
    fn prefix_distribution() {
        let mut rt = RoutingTable::new(true);
        rt.add_peer(PeerId::random(), IpPrefix::V4Slash16([1, 1]));
        rt.add_peer(PeerId::random(), IpPrefix::V4Slash16([1, 1]));
        rt.add_peer(PeerId::random(), IpPrefix::V4Slash16([2, 2]));

        let dist = rt.prefix_distribution();
        assert_eq!(dist.len(), 2);
        assert_eq!(dist[0].1, 2); // sorted descending
    }
}
