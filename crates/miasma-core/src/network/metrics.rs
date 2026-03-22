/// Freenet-style outcome metrics for measuring network health.
///
/// These metrics quantify the protocol's effectiveness at its core goals:
/// censorship resistance, identification difficulty, and trust resilience.
/// They are computed from live network state rather than being abstract counters.
///
/// # Metric categories
///
/// - **Censorship resistance**: how hard is it for an adversary to suppress content?
/// - **Identification difficulty**: how hard is it to link a user to their activity?
/// - **Trust health**: how robust is the admission/credential system against Sybils?
use serde::{Deserialize, Serialize};

use super::credential::CredentialTier;
use super::descriptor::DescriptorStore;
use super::peer_state::PeerRegistry;
use super::routing::RoutingTable;

/// Snapshot of Freenet-style outcome metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeMetrics {
    // ── Censorship resistance ───────────────────────────────────────────
    /// Fraction of stored shares retrievable via at least 2 independent paths.
    /// Higher = harder to censor by taking down a single route.
    pub multi_path_retrievability: f64,

    /// Number of distinct /16 IPv4 prefixes in the relay set.
    /// Higher = more geographically/organisationally diverse relay infrastructure.
    pub relay_prefix_diversity: usize,

    /// Fraction of descriptors that advertise relay capability.
    /// A healthy network has ≥10% relay nodes.
    pub relay_fraction: f64,

    /// Number of relay peers routable for circuit construction (have PeerId mapping).
    pub relay_peers_routable: usize,

    // ── Identification difficulty ────────────────────────────────────────
    /// Fraction of peers using pseudonymous descriptors (non-direct reachability
    /// or credentialed without raw PeerId binding).
    pub pseudonymous_fraction: f64,

    /// Pseudonym churn rate: fraction of current pseudonyms not seen in
    /// the previous epoch. Higher churn = harder to build long-term profiles.
    pub pseudonym_churn_rate: f64,

    /// Whether anonymous retrieval (relay routing) is available.
    pub onion_routing_available: bool,

    /// Number of BBS+-credentialed descriptors (within-epoch unlinkability).
    pub bbs_credentialed_count: usize,

    // ── Trust health ────────────────────────────────────────────────────
    /// Fraction of connected peers that hold a valid credential at ≥ Observed tier.
    pub credentialed_peer_fraction: f64,

    /// Current PoW difficulty (dynamic, in bits). Higher = more expensive to Sybil.
    pub current_pow_difficulty: u8,

    /// Ratio of verified peers to total connected peers.
    pub verification_ratio: f64,

    /// Admission rejection rate (recent rejections / total admission attempts).
    pub admission_rejection_rate: f64,

    // ── Retention / churn ───────────────────────────────────────────────
    /// Number of stale descriptors (age ≥ 1 hour) still in store.
    pub stale_descriptor_count: usize,

    /// Descriptor store utilisation (total / capacity limit).
    pub descriptor_utilisation: f64,

    /// Timestamp when these metrics were computed (Unix seconds).
    pub computed_at: u64,
}

impl Default for OutcomeMetrics {
    fn default() -> Self {
        Self {
            multi_path_retrievability: 0.0,
            relay_prefix_diversity: 0,
            relay_fraction: 0.0,
            relay_peers_routable: 0,
            pseudonymous_fraction: 0.0,
            pseudonym_churn_rate: 0.0,
            onion_routing_available: false,
            bbs_credentialed_count: 0,
            credentialed_peer_fraction: 0.0,
            current_pow_difficulty: 8,
            verification_ratio: 0.0,
            admission_rejection_rate: 0.0,
            stale_descriptor_count: 0,
            descriptor_utilisation: 0.0,
            computed_at: 0,
        }
    }
}

impl OutcomeMetrics {
    /// Compute a snapshot of outcome metrics from live network state.
    pub fn compute(
        descriptor_store: &DescriptorStore,
        peer_registry: &PeerRegistry,
        routing_table: &RoutingTable,
        onion_enabled: bool,
    ) -> Self {
        use std::collections::HashSet;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let active = descriptor_store.active_descriptors();
        let total_descriptors = active.len();

        // Relay metrics.
        let relay_count = active.iter().filter(|d| d.is_relay()).count();
        let relay_fraction = if total_descriptors > 0 {
            relay_count as f64 / total_descriptors as f64
        } else {
            0.0
        };

        // Relay prefix diversity: count unique /16 prefixes among relay addresses.
        let mut relay_prefixes = HashSet::new();
        for desc in active.iter().filter(|d| d.is_relay()) {
            for addr in &desc.addresses {
                if let Some(prefix) = extract_ipv4_prefix_16(addr) {
                    relay_prefixes.insert(prefix);
                }
            }
        }

        // Pseudonymous fraction: peers that are relayed or have credentials.
        let pseudonymous_count = active
            .iter()
            .filter(|d| d.is_relayed() || d.credential.is_some())
            .count();
        let pseudonymous_fraction = if total_descriptors > 0 {
            pseudonymous_count as f64 / total_descriptors as f64
        } else {
            0.0
        };

        // Credentialed fraction (among active descriptors).
        let credentialed = active
            .iter()
            .filter(|d| d.meets_tier(CredentialTier::Observed))
            .count();
        let credentialed_peer_fraction = if total_descriptors > 0 {
            credentialed as f64 / total_descriptors as f64
        } else {
            0.0
        };

        // Multi-path retrievability estimate: if we have ≥2 diverse relays,
        // content can be retrieved via multiple paths.
        let multi_path = if relay_prefixes.len() >= 2 {
            // Rough estimate: fraction of content addressable via ≥2 prefix-diverse relays.
            (relay_prefixes.len() as f64 / (relay_prefixes.len() as f64 + 1.0)).min(1.0)
        } else {
            0.0
        };

        // Trust health from peer registry.
        let admission_stats = peer_registry.stats();
        let total_peers = admission_stats.verified_peers
            + admission_stats.observed_peers
            + admission_stats.claimed_peers;
        let verified = admission_stats.verified_peers;
        let verification_ratio = if total_peers > 0 {
            verified as f64 / total_peers as f64
        } else {
            0.0
        };
        let total_attempts = (verified as u64) + admission_stats.total_rejections;
        let rejection_rate = if total_attempts > 0 {
            admission_stats.total_rejections as f64 / total_attempts as f64
        } else {
            0.0
        };

        let current_difficulty = routing_table.current_difficulty();

        // BBS+ credentialed count.
        let bbs_credentialed = active.iter().filter(|d| d.bbs_proof.is_some()).count();

        // Stale descriptor count and utilisation.
        let desc_stats = descriptor_store.stats();

        Self {
            multi_path_retrievability: multi_path,
            relay_prefix_diversity: relay_prefixes.len(),
            relay_fraction,
            relay_peers_routable: desc_stats.relay_peers_routable,
            pseudonymous_fraction,
            pseudonym_churn_rate: descriptor_store.churn_rate(),
            onion_routing_available: onion_enabled,
            bbs_credentialed_count: bbs_credentialed,
            credentialed_peer_fraction,
            current_pow_difficulty: current_difficulty,
            verification_ratio,
            admission_rejection_rate: rejection_rate,
            stale_descriptor_count: desc_stats.stale_descriptors,
            descriptor_utilisation: total_descriptors as f64 / 10_000.0,
            computed_at: now,
        }
    }
}

/// Extract the /16 prefix from an IPv4 multiaddr string.
/// Returns `"A.B"` from `/ip4/A.B.C.D/tcp/...`.
fn extract_ipv4_prefix_16(addr: &str) -> Option<String> {
    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() >= 3 && parts[1] == "ip4" {
        let ip_parts: Vec<&str> = parts[2].split('.').collect();
        if ip_parts.len() >= 2 {
            return Some(format!("{}.{}", ip_parts[0], ip_parts[1]));
        }
    }
    None
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_prefix_from_multiaddr() {
        assert_eq!(
            extract_ipv4_prefix_16("/ip4/10.0.1.5/tcp/4001"),
            Some("10.0".to_string())
        );
        assert_eq!(
            extract_ipv4_prefix_16("/ip4/192.168.0.1/udp/9000"),
            Some("192.168".to_string())
        );
        assert_eq!(extract_ipv4_prefix_16("/ip6/::1/tcp/4001"), None);
    }

    #[test]
    fn default_metrics_are_zero() {
        let m = OutcomeMetrics::default();
        assert_eq!(m.relay_prefix_diversity, 0);
        assert_eq!(m.relay_fraction, 0.0);
        assert!(!m.onion_routing_available);
    }

    #[test]
    fn compute_with_empty_state() {
        let ds = DescriptorStore::new();
        let pr = PeerRegistry::new();
        let rt = RoutingTable::new(true);

        let m = OutcomeMetrics::compute(&ds, &pr, &rt, false);
        assert_eq!(m.relay_fraction, 0.0);
        assert_eq!(m.verification_ratio, 0.0);
        assert!(!m.onion_routing_available);
        assert!(m.computed_at > 0);
    }
}
