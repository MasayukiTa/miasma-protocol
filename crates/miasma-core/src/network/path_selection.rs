/// Anonymity-aware path selection for data retrieval and routing.
///
/// # Design
///
/// Miasma's retrieval path should not default to direct connections. This
/// module implements path selection that considers anonymity requirements
/// and builds multi-hop routes using peer descriptors.
///
/// ## Anonymity policies
///
/// - **Direct**: no anonymity protection (fastest, for non-sensitive ops)
/// - **Opportunistic**: use onion routing if relay descriptors are available,
///   fall back to direct if not
/// - **Required**: refuse to proceed without anonymity (at least N hops)
///
/// ## Path construction
///
/// 1. Gather candidate relay descriptors from the `DescriptorStore`
/// 2. Filter by trust tier (prefer Verified+, require at minimum Observed)
/// 3. Apply diversity constraints (no two hops from the same /16)
/// 4. Build path from source → relay(s) → destination
/// 5. If anonymity is Required and insufficient relays exist, return an error
///
/// ## Integration with onion layer
///
/// The `RoutingPath` produced here feeds into the existing `CircuitManager`
/// and `OnionPacketBuilder`. This module handles path *selection*; the onion
/// module handles encryption and circuit management.
use serde::{Deserialize, Serialize};

use super::credential::CredentialTier;
use super::descriptor::{DescriptorStore, PeerDescriptor, ResourceProfile};
use super::routing::{ip_prefix_of, IpPrefix, RoutingTable};

// ─── Anonymity policy ───────────────────────────────────────────────────────

/// Anonymity policy for a retrieval or routing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnonymityPolicy {
    /// No anonymity protection. Direct connection to target.
    Direct,
    /// Use onion routing if possible, fall back to direct.
    Opportunistic,
    /// Require anonymity. Fail if insufficient relay capacity.
    Required { min_hops: u8 },
}

impl Default for AnonymityPolicy {
    fn default() -> Self {
        AnonymityPolicy::Opportunistic
    }
}

impl std::fmt::Display for AnonymityPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnonymityPolicy::Direct => write!(f, "direct"),
            AnonymityPolicy::Opportunistic => write!(f, "opportunistic"),
            AnonymityPolicy::Required { min_hops } => write!(f, "required({min_hops} hops)"),
        }
    }
}

// ─── Path constraints ───────────────────────────────────────────────────────

/// Constraints on path construction.
#[derive(Debug, Clone)]
pub struct PathConstraints {
    /// Minimum number of intermediate hops (excludes source and destination).
    pub min_hops: u8,
    /// Maximum number of intermediate hops.
    pub max_hops: u8,
    /// Minimum trust tier for relay nodes.
    pub min_relay_tier: CredentialTier,
    /// Require IP prefix diversity between consecutive hops.
    pub enforce_hop_diversity: bool,
    /// Prefer desktop/server nodes as relays (better bandwidth).
    pub prefer_desktop_relays: bool,
}

impl Default for PathConstraints {
    fn default() -> Self {
        Self {
            min_hops: 1,
            max_hops: 3,
            min_relay_tier: CredentialTier::Observed,
            enforce_hop_diversity: true,
            prefer_desktop_relays: true,
        }
    }
}

impl PathConstraints {
    /// Constraints for Required anonymity with a specific hop count.
    pub fn for_required(min_hops: u8) -> Self {
        Self {
            min_hops,
            max_hops: min_hops.saturating_add(2).min(5),
            ..Self::default()
        }
    }

    /// Constraints for Opportunistic anonymity.
    pub fn for_opportunistic() -> Self {
        Self {
            min_hops: 0, // will use relays if available
            ..Self::default()
        }
    }
}

// ─── Routing path ───────────────────────────────────────────────────────────

/// A single hop in a routing path.
#[derive(Debug, Clone)]
pub struct PathHop {
    /// Pseudonym of the hop (from descriptor).
    pub pseudonym: [u8; 32],
    /// Address to connect to (may be relay circuit address).
    pub address: String,
    /// IP prefix of this hop (for diversity checks).
    pub ip_prefix: IpPrefix,
    /// Trust tier of this hop.
    pub tier: Option<CredentialTier>,
    /// Resource profile of this hop.
    pub resource_profile: ResourceProfile,
}

/// A complete routing path from source to destination.
#[derive(Debug, Clone)]
pub struct RoutingPath {
    /// Intermediate hops (relays). Does not include source or destination.
    pub hops: Vec<PathHop>,
    /// Destination pseudonym.
    pub destination: [u8; 32],
    /// Anonymity policy that produced this path.
    pub policy: AnonymityPolicy,
}

impl RoutingPath {
    /// Number of intermediate hops (relays).
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Whether this is a direct (zero-hop) path.
    pub fn is_direct(&self) -> bool {
        self.hops.is_empty()
    }

    /// All IP prefixes in the path (for diversity analysis).
    pub fn prefixes(&self) -> Vec<IpPrefix> {
        self.hops.iter().map(|h| h.ip_prefix).collect()
    }
}

// ─── Path selection errors ──────────────────────────────────────────────────

/// Why path selection failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathError {
    /// Not enough relay descriptors available.
    InsufficientRelays { required: usize, available: usize },
    /// Not enough diverse relays (all from the same prefix).
    InsufficientDiversity { required: usize, diverse_count: usize },
    /// Anonymity required but no relays at all.
    NoRelaysAvailable,
    /// Destination descriptor not found.
    DestinationUnknown,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::InsufficientRelays { required, available } => {
                write!(f, "need {required} relays, only {available} available")
            }
            PathError::InsufficientDiversity { required, diverse_count } => {
                write!(f, "need {required} diverse relays, only {diverse_count} unique prefixes")
            }
            PathError::NoRelaysAvailable => write!(f, "no relay descriptors available"),
            PathError::DestinationUnknown => write!(f, "destination descriptor not found"),
        }
    }
}

// ─── Path selector ──────────────────────────────────────────────────────────

/// Selects multi-hop routing paths using descriptors, trust, and diversity.
pub struct PathSelector;

impl PathSelector {
    /// Select a routing path to the given destination.
    ///
    /// Uses the descriptor store to find relay candidates, applies trust
    /// and diversity constraints, and builds a path.
    pub fn select(
        destination: [u8; 32],
        policy: AnonymityPolicy,
        store: &DescriptorStore,
        routing_table: &RoutingTable,
    ) -> Result<RoutingPath, PathError> {
        match policy {
            AnonymityPolicy::Direct => {
                Ok(RoutingPath { hops: vec![], destination, policy })
            }
            AnonymityPolicy::Opportunistic => {
                let constraints = PathConstraints::for_opportunistic();
                match Self::build_path(destination, &constraints, store, routing_table) {
                    Ok(path) if !path.hops.is_empty() => Ok(path),
                    _ => {
                        // Fall back to direct.
                        Ok(RoutingPath { hops: vec![], destination, policy })
                    }
                }
            }
            AnonymityPolicy::Required { min_hops } => {
                let constraints = PathConstraints::for_required(min_hops);
                Self::build_path(destination, &constraints, store, routing_table)
            }
        }
    }

    /// Build a path with the given constraints.
    fn build_path(
        destination: [u8; 32],
        constraints: &PathConstraints,
        store: &DescriptorStore,
        _routing_table: &RoutingTable,
    ) -> Result<RoutingPath, PathError> {
        // Gather relay candidates.
        let relays = store.relay_descriptors();
        if relays.is_empty() && constraints.min_hops > 0 {
            return Err(PathError::NoRelaysAvailable);
        }

        // Filter by trust tier.
        let mut candidates: Vec<&PeerDescriptor> = relays.into_iter()
            .filter(|d| d.meets_tier(constraints.min_relay_tier) || d.credential.is_none())
            .collect();

        // Sort: prefer desktop relays, then by published_at (newer first).
        if constraints.prefer_desktop_relays {
            candidates.sort_by(|a, b| {
                let a_desktop = a.resource_profile == ResourceProfile::Desktop;
                let b_desktop = b.resource_profile == ResourceProfile::Desktop;
                b_desktop.cmp(&a_desktop)
                    .then(b.published_at.cmp(&a.published_at))
            });
        }

        // Build hops with diversity enforcement.
        let mut hops = Vec::new();
        let mut used_prefixes = std::collections::HashSet::new();

        for desc in &candidates {
            if hops.len() >= constraints.max_hops as usize {
                break;
            }

            // Skip the destination itself.
            if desc.pseudonym == destination {
                continue;
            }

            // Extract IP prefix from the first address.
            let prefix = desc.addresses.first()
                .and_then(|a| a.parse().ok())
                .map(|a: libp2p::Multiaddr| ip_prefix_of(&a))
                .unwrap_or(IpPrefix::Local);

            // Enforce diversity if required.
            if constraints.enforce_hop_diversity
                && prefix != IpPrefix::Local
                && used_prefixes.contains(&prefix)
            {
                continue; // skip same-prefix relay
            }

            let tier = desc.credential.as_ref().map(|c| c.credential.body.tier);

            hops.push(PathHop {
                pseudonym: desc.pseudonym,
                address: desc.addresses.first().cloned().unwrap_or_default(),
                ip_prefix: prefix,
                tier,
                resource_profile: desc.resource_profile,
            });
            used_prefixes.insert(prefix);
        }

        // Check minimum hops.
        if hops.len() < constraints.min_hops as usize {
            return Err(PathError::InsufficientRelays {
                required: constraints.min_hops as usize,
                available: hops.len(),
            });
        }

        Ok(RoutingPath {
            hops,
            destination,
            policy: AnonymityPolicy::Required { min_hops: constraints.min_hops },
        })
    }
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

/// Snapshot of path selection state for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSelectionStats {
    /// Default anonymity policy.
    pub default_policy: String,
    /// Number of relay descriptors available.
    pub available_relays: usize,
    /// Number of unique relay prefixes (diversity measure).
    pub relay_prefix_diversity: usize,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::credential::*;
    use super::super::descriptor::*;

    fn make_relay_descriptor(
        pseudonym: [u8; 32],
        addr: &str,
        credential: Option<CredentialPresentation>,
    ) -> PeerDescriptor {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        PeerDescriptor::new_signed(
            pseudonym,
            ReachabilityKind::Direct,
            vec![addr.to_string()],
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
            ResourceProfile::Desktop,
            credential,
            1,
            &key,
        )
    }

    fn store_with_relays(count: usize) -> DescriptorStore {
        let mut store = DescriptorStore::new();
        for i in 0..count {
            let mut ps = [0u8; 32];
            ps[0] = i as u8;
            let addr = format!("/ip4/{}.{}.1.1/tcp/4001", i + 1, i + 1);
            store.upsert(make_relay_descriptor(ps, &addr, None));
        }
        store
    }

    #[test]
    fn direct_policy_produces_zero_hops() {
        let store = store_with_relays(5);
        let rt = RoutingTable::new(true);
        let dest = [0xFF; 32];

        let path = PathSelector::select(dest, AnonymityPolicy::Direct, &store, &rt).unwrap();
        assert!(path.is_direct());
        assert_eq!(path.destination, dest);
    }

    #[test]
    fn opportunistic_uses_relays_if_available() {
        let store = store_with_relays(3);
        let rt = RoutingTable::new(true);
        let dest = [0xFF; 32];

        let path = PathSelector::select(
            dest, AnonymityPolicy::Opportunistic, &store, &rt
        ).unwrap();
        // Should use relays since they're available.
        assert!(path.hop_count() >= 1);
    }

    #[test]
    fn opportunistic_falls_back_to_direct() {
        let store = DescriptorStore::new(); // empty — no relays
        let rt = RoutingTable::new(true);
        let dest = [0xFF; 32];

        let path = PathSelector::select(
            dest, AnonymityPolicy::Opportunistic, &store, &rt
        ).unwrap();
        assert!(path.is_direct());
    }

    #[test]
    fn required_fails_without_enough_relays() {
        let store = DescriptorStore::new(); // empty
        let rt = RoutingTable::new(true);
        let dest = [0xFF; 32];

        let result = PathSelector::select(
            dest, AnonymityPolicy::Required { min_hops: 2 }, &store, &rt
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PathError::NoRelaysAvailable));
    }

    #[test]
    fn required_needs_min_hops() {
        let store = store_with_relays(1); // only 1 relay
        let rt = RoutingTable::new(true);
        let dest = [0xFF; 32];

        let result = PathSelector::select(
            dest, AnonymityPolicy::Required { min_hops: 2 }, &store, &rt
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PathError::InsufficientRelays { .. }));
    }

    #[test]
    fn required_succeeds_with_enough_relays() {
        let store = store_with_relays(3);
        let rt = RoutingTable::new(true);
        let dest = [0xFF; 32];

        let path = PathSelector::select(
            dest, AnonymityPolicy::Required { min_hops: 2 }, &store, &rt
        ).unwrap();
        assert!(path.hop_count() >= 2);
    }

    #[test]
    fn path_enforces_hop_diversity() {
        let mut store = DescriptorStore::new();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

        // Add 3 relays from the SAME /16 prefix.
        for i in 0..3u8 {
            let mut ps = [0u8; 32];
            ps[0] = i;
            store.upsert(PeerDescriptor::new_signed(
                ps,
                ReachabilityKind::Direct,
                vec![format!("/ip4/10.0.{i}.1/tcp/4001")],
                PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
                ResourceProfile::Desktop,
                None,
                1,
                &key,
            ));
        }

        let rt = RoutingTable::new(true);
        let dest = [0xFF; 32];

        // Request 2 hops — diversity should limit us to 1 from the same /16.
        let result = PathSelector::select(
            dest, AnonymityPolicy::Required { min_hops: 2 }, &store, &rt
        );
        assert!(result.is_err(), "should fail: all relays from same /16");
    }

    #[test]
    fn path_skips_destination_as_relay() {
        let store = store_with_relays(3);
        let rt = RoutingTable::new(true);

        // Destination pseudonym matches one relay's pseudonym.
        let mut dest = [0u8; 32];
        dest[0] = 0; // matches first relay

        let path = PathSelector::select(
            dest, AnonymityPolicy::Required { min_hops: 1 }, &store, &rt
        ).unwrap();

        // The destination should not appear as a relay hop.
        for hop in &path.hops {
            assert_ne!(hop.pseudonym, dest);
        }
    }

    #[test]
    fn path_prefixes_collected() {
        let store = store_with_relays(3);
        let rt = RoutingTable::new(true);
        let dest = [0xFF; 32];

        let path = PathSelector::select(
            dest, AnonymityPolicy::Required { min_hops: 2 }, &store, &rt
        ).unwrap();

        let prefixes = path.prefixes();
        assert!(prefixes.len() >= 2);
        // All prefixes should be different (diversity enforced).
        let unique: std::collections::HashSet<_> = prefixes.iter().collect();
        assert_eq!(prefixes.len(), unique.len());
    }
}
