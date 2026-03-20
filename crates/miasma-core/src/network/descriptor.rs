/// Peer descriptors — routing material that replaces raw address claims.
///
/// # Design
///
/// In a Freenet-like model, peers should not be identified or routed-to
/// primarily by their network addresses. Instead, descriptors provide
/// structured routing material that separates:
///
/// 1. **Discovery** — how to learn that a peer exists
/// 2. **Introduction** — how to initiate contact (possibly via relay)
/// 3. **Transport reachability** — how to actually reach them
///
/// A `PeerDescriptor` is the unit of routing material that flows through
/// the network. It contains enough information for routing decisions
/// without requiring the peer's raw IP address.
///
/// # Descriptor types
///
/// - **Direct**: peer is directly reachable at a public address
/// - **Relayed**: peer is reachable through a relay node
/// - **Rendezvous**: peer publishes a rendezvous point; requesters connect there
/// - **Service**: peer advertises a specific service (e.g., storage, relay)
///
/// # Relationship to existing address model
///
/// Descriptors wrap the existing `Multiaddr` infrastructure but add:
/// - Credential binding (prove tier without revealing PeerId)
/// - Relay indirection (reach a peer without knowing their real address)
/// - Capability advertisement (what the peer can do for you)
/// - Staleness tracking (when was this descriptor last confirmed valid)
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use super::credential::{CredentialPresentation, CredentialTier};

// ─── Descriptor types ───────────────────────────────────────────────────────

/// How a peer can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReachabilityKind {
    /// Directly reachable at a public address.
    Direct,
    /// Reachable only through a relay.
    Relayed {
        /// PeerId of the relay node.
        relay_peer: String,
        /// Address of the relay node.
        relay_addr: String,
    },
    /// Peer publishes a rendezvous point (future: onion-based).
    Rendezvous {
        /// Identifier for the rendezvous point.
        rendezvous_id: [u8; 32],
    },
}

/// Capabilities that a peer advertises via its descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Can store shares on behalf of others.
    pub can_store: bool,
    /// Can act as a relay for NAT traversal.
    pub can_relay: bool,
    /// Participates in DHT routing.
    pub can_route: bool,
    /// Can issue trust credentials.
    pub can_issue: bool,
    /// Estimated bandwidth class (0=unknown, 1=low, 2=medium, 3=high).
    pub bandwidth_class: u8,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            can_store: false,
            can_relay: false,
            can_route: true, // most nodes participate in routing
            can_issue: false,
            bandwidth_class: 0,
        }
    }
}

/// Resource profile hint — helps the network decide what to ask of this peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceProfile {
    /// Desktop/server: ample CPU, storage, and bandwidth.
    Desktop,
    /// Mobile: constrained CPU and battery, variable bandwidth.
    Mobile,
    /// Embedded/IoT: very limited resources.
    Constrained,
}

impl Default for ResourceProfile {
    fn default() -> Self {
        ResourceProfile::Desktop
    }
}

/// A peer descriptor — structured routing material.
///
/// This replaces raw `(PeerId, Multiaddr)` pairs as the unit of routing
/// information. Descriptors flow through the network and are used for
/// routing decisions without requiring knowledge of the peer's raw address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDescriptor {
    /// Pseudonymous identifier (holder_tag from credential, or PeerId hash).
    pub pseudonym: [u8; 32],
    /// How the peer can be reached.
    pub reachability: ReachabilityKind,
    /// Multiaddrs (may be relay circuit addresses, not raw IPs).
    pub addresses: Vec<String>,
    /// What the peer can do.
    pub capabilities: PeerCapabilities,
    /// Resource profile hint.
    pub resource_profile: ResourceProfile,
    /// Optional credential presentation (proves tier without revealing PeerId).
    pub credential: Option<CredentialPresentation>,
    /// When this descriptor was published (Unix timestamp).
    pub published_at: u64,
    /// Descriptor version (monotonically increasing per pseudonym).
    pub version: u64,
    /// Ed25519 public key of the descriptor signer (for self-verification).
    pub signing_pubkey: [u8; 32],
    /// Ed25519 signature over the descriptor body (by the descriptor owner).
    /// For pseudonymous descriptors, this is signed by the ephemeral key.
    pub signature: Vec<u8>,
}

impl PeerDescriptor {
    /// Create a signed descriptor.
    pub fn new_signed(
        pseudonym: [u8; 32],
        reachability: ReachabilityKind,
        addresses: Vec<String>,
        capabilities: PeerCapabilities,
        resource_profile: ResourceProfile,
        credential: Option<CredentialPresentation>,
        version: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;

        let published_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut desc = Self {
            pseudonym,
            reachability,
            addresses,
            capabilities,
            resource_profile,
            credential,
            published_at,
            version,
            signing_pubkey: signing_key.verifying_key().to_bytes(),
            signature: Vec::new(),
        };

        // Sign the descriptor body (everything except the signature field).
        let body_bytes = desc.body_bytes();
        let message = blake3::hash(&[b"miasma-descriptor-v1".as_slice(), &body_bytes].concat());
        let sig = signing_key.sign(message.as_bytes());
        desc.signature = sig.to_bytes().to_vec();

        desc
    }

    /// Serialize the descriptor body (excludes signature) for signing.
    fn body_bytes(&self) -> Vec<u8> {
        // Serialize everything except signature.
        let mut body = Vec::new();
        body.extend_from_slice(&self.pseudonym);
        body.extend_from_slice(&bincode::serialize(&self.reachability).unwrap_or_default());
        body.extend_from_slice(&bincode::serialize(&self.addresses).unwrap_or_default());
        body.extend_from_slice(&bincode::serialize(&self.capabilities).unwrap_or_default());
        body.extend_from_slice(&bincode::serialize(&self.resource_profile).unwrap_or_default());
        body.extend_from_slice(&self.published_at.to_le_bytes());
        body.extend_from_slice(&self.version.to_le_bytes());
        body.extend_from_slice(&self.signing_pubkey);
        body
    }

    /// Verify the descriptor signature using the embedded public key.
    ///
    /// Returns `true` if the signature is valid for the embedded `signing_pubkey`.
    /// This makes the descriptor self-authenticating.
    pub fn verify_self(&self) -> bool {
        let Ok(pubkey) = ed25519_dalek::VerifyingKey::from_bytes(&self.signing_pubkey) else {
            return false;
        };
        self.verify_signature(&pubkey)
    }

    /// Verify the descriptor signature against a specific public key.
    pub fn verify_signature(&self, pubkey: &ed25519_dalek::VerifyingKey) -> bool {
        use ed25519_dalek::Verifier;
        let body_bytes = self.body_bytes();
        let message = blake3::hash(&[b"miasma-descriptor-v1".as_slice(), &body_bytes].concat());
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        pubkey.verify(message.as_bytes(), &sig).is_ok()
    }

    /// Whether this descriptor advertises relay capability.
    pub fn is_relay(&self) -> bool {
        self.capabilities.can_relay
    }

    /// Whether this descriptor uses a relay for reachability.
    pub fn is_relayed(&self) -> bool {
        matches!(self.reachability, ReachabilityKind::Relayed { .. })
    }

    /// Age of this descriptor in seconds.
    pub fn age_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.published_at)
    }

    /// Whether the descriptor has a valid credential at or above the given tier.
    pub fn meets_tier(&self, min_tier: CredentialTier) -> bool {
        self.credential
            .as_ref()
            .map(|c| c.credential.body.tier >= min_tier)
            .unwrap_or(false)
    }
}

// ─── Descriptor store ───────────────────────────────────────────────────────

/// Maximum descriptor age before it's considered stale (1 hour).
const MAX_DESCRIPTOR_AGE_SECS: u64 = 3600;

/// Maximum number of descriptors stored (prevents flooding).
const MAX_DESCRIPTORS: usize = 10_000;

/// In-memory store for peer descriptors.
///
/// Indexed by pseudonym (holder_tag). Supports staleness pruning,
/// capacity limits, and capability-based queries.
pub struct DescriptorStore {
    /// Descriptors keyed by pseudonym.
    descriptors: HashMap<[u8; 32], PeerDescriptor>,
    /// Optional mapping from PeerId to pseudonym (for legacy/transition).
    peer_to_pseudonym: HashMap<PeerId, [u8; 32]>,
}

impl DescriptorStore {
    pub fn new() -> Self {
        Self {
            descriptors: HashMap::new(),
            peer_to_pseudonym: HashMap::new(),
        }
    }

    /// Insert or update a descriptor. Newer version wins.
    ///
    /// Rejects descriptors that are already stale on arrival or that would
    /// exceed the store capacity limit (evicting oldest stale entries first).
    pub fn upsert(&mut self, desc: PeerDescriptor) -> bool {
        // Reject descriptors that arrive already stale.
        if desc.age_secs() >= MAX_DESCRIPTOR_AGE_SECS {
            return false;
        }

        let pseudonym = desc.pseudonym;
        if let Some(existing) = self.descriptors.get(&pseudonym) {
            if desc.version <= existing.version {
                return false; // stale or duplicate
            }
        }

        // Enforce capacity: if at limit and this is a new pseudonym, evict stalest.
        if !self.descriptors.contains_key(&pseudonym)
            && self.descriptors.len() >= MAX_DESCRIPTORS
        {
            // Prune stale first; if still over limit, evict the oldest descriptor.
            self.prune_stale();
            if self.descriptors.len() >= MAX_DESCRIPTORS {
                if let Some(oldest_key) = self
                    .descriptors
                    .iter()
                    .max_by_key(|(_, d)| d.age_secs())
                    .map(|(k, _)| *k)
                {
                    self.descriptors.remove(&oldest_key);
                    self.peer_to_pseudonym.retain(|_, p| *p != oldest_key);
                }
            }
        }

        self.descriptors.insert(pseudonym, desc);
        true
    }

    /// Register a PeerId→pseudonym mapping (for transition from address-based routing).
    pub fn register_peer_pseudonym(&mut self, peer_id: PeerId, pseudonym: [u8; 32]) {
        self.peer_to_pseudonym.insert(peer_id, pseudonym);
    }

    /// Look up a descriptor by pseudonym.
    pub fn get(&self, pseudonym: &[u8; 32]) -> Option<&PeerDescriptor> {
        self.descriptors.get(pseudonym)
    }

    /// Look up a descriptor by PeerId (via pseudonym mapping).
    pub fn get_by_peer(&self, peer_id: &PeerId) -> Option<&PeerDescriptor> {
        self.peer_to_pseudonym.get(peer_id)
            .and_then(|p| self.descriptors.get(p))
    }

    /// Return all descriptors that advertise relay capability.
    pub fn relay_descriptors(&self) -> Vec<&PeerDescriptor> {
        self.descriptors.values()
            .filter(|d| d.is_relay() && d.age_secs() < MAX_DESCRIPTOR_AGE_SECS)
            .collect()
    }

    /// Return all descriptors meeting a minimum tier.
    pub fn descriptors_at_tier(&self, min_tier: CredentialTier) -> Vec<&PeerDescriptor> {
        self.descriptors.values()
            .filter(|d| d.meets_tier(min_tier) && d.age_secs() < MAX_DESCRIPTOR_AGE_SECS)
            .collect()
    }

    /// Return all non-stale descriptors.
    pub fn active_descriptors(&self) -> Vec<&PeerDescriptor> {
        self.descriptors.values()
            .filter(|d| d.age_secs() < MAX_DESCRIPTOR_AGE_SECS)
            .collect()
    }

    /// Prune stale descriptors. Returns number removed.
    pub fn prune_stale(&mut self) -> usize {
        let before = self.descriptors.len();
        self.descriptors.retain(|_, d| d.age_secs() < MAX_DESCRIPTOR_AGE_SECS);
        // Also clean up peer mappings that no longer have descriptors.
        self.peer_to_pseudonym.retain(|_, p| self.descriptors.contains_key(p));
        before - self.descriptors.len()
    }

    /// Total descriptors stored.
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    /// Diagnostics snapshot.
    pub fn stats(&self) -> DescriptorStats {
        let total = self.descriptors.len();
        let relay_count = self.descriptors.values().filter(|d| d.is_relay()).count();
        let relayed_count = self.descriptors.values().filter(|d| d.is_relayed()).count();
        let credentialed = self.descriptors.values()
            .filter(|d| d.credential.is_some())
            .count();
        let stale = self.descriptors.values()
            .filter(|d| d.age_secs() >= MAX_DESCRIPTOR_AGE_SECS)
            .count();

        DescriptorStats {
            total_descriptors: total,
            relay_descriptors: relay_count,
            relayed_descriptors: relayed_count,
            credentialed_descriptors: credentialed,
            stale_descriptors: stale,
        }
    }
}

/// Diagnostics for the descriptor store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorStats {
    pub total_descriptors: usize,
    pub relay_descriptors: usize,
    pub relayed_descriptors: usize,
    pub credentialed_descriptors: usize,
    pub stale_descriptors: usize,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_descriptor(pseudonym: [u8; 32], version: u64) -> PeerDescriptor {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        PeerDescriptor::new_signed(
            pseudonym,
            ReachabilityKind::Direct,
            vec!["/ip4/8.8.8.8/tcp/4001".to_string()],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            version,
            &key,
        )
    }

    #[test]
    fn descriptor_signature_valid() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let desc = test_descriptor([0x01; 32], 1);
        assert!(desc.verify_signature(&key.verifying_key()));
        assert!(desc.verify_self());
    }

    #[test]
    fn descriptor_signature_rejects_tampered() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let mut desc = test_descriptor([0x01; 32], 1);
        desc.addresses.push("/ip4/1.2.3.4/tcp/9999".to_string()); // tamper
        assert!(!desc.verify_signature(&key.verifying_key()));
        assert!(!desc.verify_self());
    }

    #[test]
    fn descriptor_verify_self_rejects_wrong_pubkey() {
        let mut desc = test_descriptor([0x01; 32], 1);
        // Replace pubkey with a different key — signature won't match.
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
        desc.signing_pubkey = other_key.verifying_key().to_bytes();
        assert!(!desc.verify_self());
    }

    #[test]
    fn store_upsert_newer_version_wins() {
        let mut store = DescriptorStore::new();
        let ps = [0x01; 32];
        let d1 = test_descriptor(ps, 1);
        let d2 = test_descriptor(ps, 2);
        let d3 = test_descriptor(ps, 1); // same version as d1

        assert!(store.upsert(d1));
        assert!(store.upsert(d2));  // newer, should replace
        assert!(!store.upsert(d3)); // older, should be rejected

        assert_eq!(store.get(&ps).unwrap().version, 2);
    }

    #[test]
    fn store_relay_query() {
        let mut store = DescriptorStore::new();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

        let relay_desc = PeerDescriptor::new_signed(
            [0x01; 32],
            ReachabilityKind::Direct,
            vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        );
        let normal_desc = test_descriptor([0x02; 32], 1);

        store.upsert(relay_desc);
        store.upsert(normal_desc);

        assert_eq!(store.relay_descriptors().len(), 1);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn store_peer_pseudonym_lookup() {
        let mut store = DescriptorStore::new();
        let peer = PeerId::random();
        let ps = [0x01; 32];

        store.upsert(test_descriptor(ps, 1));
        store.register_peer_pseudonym(peer, ps);

        assert!(store.get_by_peer(&peer).is_some());
        assert_eq!(store.get_by_peer(&peer).unwrap().pseudonym, ps);
    }

    #[test]
    fn descriptor_reachability_kinds() {
        let desc = test_descriptor([0x01; 32], 1);
        assert!(!desc.is_relayed());

        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let relayed = PeerDescriptor::new_signed(
            [0x02; 32],
            ReachabilityKind::Relayed {
                relay_peer: "12D3KooW...".to_string(),
                relay_addr: "/ip4/1.2.3.4/tcp/4001".to_string(),
            },
            vec![],
            PeerCapabilities::default(),
            ResourceProfile::Mobile,
            None,
            1,
            &key,
        );
        assert!(relayed.is_relayed());
        assert_eq!(relayed.resource_profile, ResourceProfile::Mobile);
    }

    #[test]
    fn descriptor_stats() {
        let mut store = DescriptorStore::new();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

        store.upsert(test_descriptor([0x01; 32], 1));
        store.upsert(PeerDescriptor::new_signed(
            [0x02; 32],
            ReachabilityKind::Direct,
            vec![],
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));

        let stats = store.stats();
        assert_eq!(stats.total_descriptors, 2);
        assert_eq!(stats.relay_descriptors, 1);
    }

    #[test]
    fn descriptor_serde_roundtrip() {
        let desc = test_descriptor([0x01; 32], 1);
        let bytes = bincode::serialize(&desc).unwrap();
        let deserialized: PeerDescriptor = bincode::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.pseudonym, desc.pseudonym);
        assert_eq!(deserialized.version, desc.version);
        assert_eq!(deserialized.addresses, desc.addresses);
    }
}
