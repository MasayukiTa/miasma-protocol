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

use super::bbs_credential::BbsProof;
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
    /// Peer is reachable only via introduction points.
    ///
    /// Unlike `Relayed` (which names a specific relay+addr), a rendezvous
    /// descriptor stores pseudonyms of introduction-point peers. The
    /// requester resolves each pseudonym through the descriptor store to
    /// discover the intro point's PeerId and addresses, then routes
    /// through that relay to reach the hidden peer.
    ///
    /// This separates **discovery** (the rendezvous descriptor) from
    /// **introduction** (the intro-point pseudonym) from **transport**
    /// (the relay circuit the requester builds).
    Rendezvous {
        /// Pseudonyms of introduction-point relay peers.
        /// Resolved via `DescriptorStore::peer_for_pseudonym()`.
        intro_points: Vec<[u8; 32]>,
    },
}

// ─── Relay trust tiers ──────────────────────────────────────────────────────

/// Trust tier for a peer's relay capability, driven by observed behavior.
///
/// Promotion requires real successful relay participation — descriptor
/// claims alone only reach `Claimed`. Demotion happens on failure or
/// inactivity so stale trust does not linger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum RelayTrustTier {
    /// Descriptor says `can_relay` but we have no observation.
    Claimed,
    /// At least one successful relay operation observed.
    Observed,
    /// Consistent relay behavior: ≥3 successes AND success rate ≥75%.
    Verified,
}

impl Default for RelayTrustTier {
    fn default() -> Self {
        Self::Claimed
    }
}

/// Accumulated relay behavior observations for a single peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayObservation {
    pub tier: RelayTrustTier,
    pub successes: u32,
    pub failures: u32,
    /// Unix timestamp of last successful relay.
    pub last_success_at: u64,
    /// Unix timestamp of last failed relay.
    pub last_failure_at: u64,
    /// Unix timestamp of last successful active probe (nonce echo).
    #[serde(default)]
    pub probe_succeeded_at: Option<u64>,
    /// Unix timestamp of last successful forwarding verification
    /// (probe sent through R1's relay circuit to R2).
    #[serde(default)]
    pub forwarding_verified_at: Option<u64>,
}

impl RelayObservation {
    fn new() -> Self {
        Self {
            tier: RelayTrustTier::Claimed,
            successes: 0,
            failures: 0,
            last_success_at: 0,
            last_failure_at: 0,
            probe_succeeded_at: None,
            forwarding_verified_at: None,
        }
    }

    fn record_success(&mut self) {
        self.successes += 1;
        self.last_success_at = now_secs();
        self.recompute_tier();
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure_at = now_secs();
        self.recompute_tier();
    }

    /// Record a successful active probe (nonce echo verification).
    pub fn record_probe_success(&mut self) {
        self.probe_succeeded_at = Some(now_secs());
        self.recompute_tier();
    }

    /// Record a successful forwarding verification (circuit-routed probe).
    pub fn record_forwarding_verification(&mut self) {
        self.forwarding_verified_at = Some(now_secs());
        self.recompute_tier();
    }

    /// Whether this relay has a probe result within `freshness_secs`.
    pub fn has_fresh_probe(&self, freshness_secs: u64) -> bool {
        match self.probe_succeeded_at {
            Some(t) => now_secs().saturating_sub(t) < freshness_secs,
            None => false,
        }
    }

    /// Whether this relay has a forwarding verification within `freshness_secs`.
    pub fn has_fresh_forwarding(&self, freshness_secs: u64) -> bool {
        match self.forwarding_verified_at {
            Some(t) => now_secs().saturating_sub(t) < freshness_secs,
            None => false,
        }
    }

    /// Halve counters (epoch decay) so stale trust decays.
    /// Probe/forwarding timestamps are NOT cleared — they have their own
    /// time-based freshness and represent stronger evidence.
    fn decay(&mut self) {
        self.successes /= 2;
        self.failures /= 2;
        self.recompute_tier();
    }

    /// Unified tier computation using all available evidence:
    ///
    /// 1. Forwarding-verified + ≥1 passive success → Verified (strongest)
    /// 2. Probe-verified + ≥2 passive successes at ≥66% rate → Verified
    /// 3. ≥3 passive successes at ≥75% rate → Verified (original rule)
    /// 4. ≥1 passive success OR probe success → Observed
    /// 5. Otherwise → Claimed
    fn recompute_tier(&mut self) {
        let total = self.successes + self.failures;
        let rate = if total > 0 { self.successes as f64 / total as f64 } else { 0.0 };

        // Forwarding-verified fast-track: strongest possible evidence.
        if self.forwarding_verified_at.is_some() && self.successes >= 1 {
            self.tier = RelayTrustTier::Verified;
        }
        // Probe-verified with corroborating passive evidence.
        else if self.probe_succeeded_at.is_some() && self.successes >= 2 && rate >= 0.66 {
            self.tier = RelayTrustTier::Verified;
        }
        // Original passive-only rule.
        else if self.successes >= 3 && total > 0 && rate >= 0.75 {
            self.tier = RelayTrustTier::Verified;
        } else if self.successes >= 1 || self.probe_succeeded_at.is_some() {
            self.tier = RelayTrustTier::Observed;
        } else {
            self.tier = RelayTrustTier::Claimed;
        }
    }

    #[allow(dead_code)]
    fn success_rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 { 0.0 } else { self.successes as f64 / total as f64 }
    }
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
    /// Optional BBS+ proof of credential possession (privacy-preserving trust signal).
    /// Verifiers can extract the tier from disclosed attributes without linking
    /// multiple descriptors to the same holder.
    #[serde(default)]
    pub bbs_proof: Option<BbsProof>,
    /// X25519 static public key for onion-layer encryption.
    /// Relay-capable and target nodes publish this so initiators can build
    /// per-hop encrypted onion packets.
    #[serde(default)]
    pub onion_pubkey: Option<[u8; 32]>,
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
        Self::new_signed_with_bbs(
            pseudonym, reachability, addresses, capabilities, resource_profile,
            credential, None, version, signing_key,
        )
    }

    /// Create a signed descriptor with an optional BBS+ proof attached.
    pub fn new_signed_with_bbs(
        pseudonym: [u8; 32],
        reachability: ReachabilityKind,
        addresses: Vec<String>,
        capabilities: PeerCapabilities,
        resource_profile: ResourceProfile,
        credential: Option<CredentialPresentation>,
        bbs_proof: Option<BbsProof>,
        version: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        Self::new_signed_full(
            pseudonym, reachability, addresses, capabilities, resource_profile,
            credential, bbs_proof, None, version, signing_key,
        )
    }

    /// Create a signed descriptor with all optional fields.
    pub fn new_signed_full(
        pseudonym: [u8; 32],
        reachability: ReachabilityKind,
        addresses: Vec<String>,
        capabilities: PeerCapabilities,
        resource_profile: ResourceProfile,
        credential: Option<CredentialPresentation>,
        bbs_proof: Option<BbsProof>,
        onion_pubkey: Option<[u8; 32]>,
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
            bbs_proof,
            onion_pubkey,
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
        // Include BBS+ proof bytes so tampering/removal is detected by signature.
        if let Some(ref proof) = self.bbs_proof {
            body.extend_from_slice(&bincode::serialize(proof).unwrap_or_default());
        }
        // Include onion pubkey so tampering/removal is detected by signature.
        if let Some(ref opk) = self.onion_pubkey {
            body.extend_from_slice(opk);
        }
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

    /// Whether this descriptor uses rendezvous (introduction points).
    pub fn is_rendezvous(&self) -> bool {
        matches!(self.reachability, ReachabilityKind::Rendezvous { .. })
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

    /// Extract the credential tier from the BBS+ proof's disclosed attributes, if present.
    ///
    /// Returns `None` if no BBS+ proof is attached or if tier (index 1) is not disclosed.
    pub fn bbs_tier(&self) -> Option<CredentialTier> {
        let proof = self.bbs_proof.as_ref()?;
        let tier_val = proof.disclosed.iter()
            .find(|&&(idx, _)| idx == 1)
            .map(|&(_, val)| val)?;
        match tier_val {
            1 => Some(CredentialTier::Observed),
            2 => Some(CredentialTier::Verified),
            3 => Some(CredentialTier::Endorsed),
            _ => None,
        }
    }
}

// ─── Descriptor store ───────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Maximum descriptor age before it's considered stale (1 hour).
const MAX_DESCRIPTOR_AGE_SECS: u64 = 3600;

/// Rendezvous descriptors expire faster (20 minutes) because intro points
/// change more frequently under churn and NAT re-binding.
const MAX_RENDEZVOUS_AGE_SECS: u64 = 1200;

/// Maximum number of descriptors stored (prevents flooding).
const MAX_DESCRIPTORS: usize = 10_000;

/// Per-kind max age: rendezvous descriptors expire faster.
fn max_age_for(desc: &PeerDescriptor) -> u64 {
    if desc.is_rendezvous() {
        MAX_RENDEZVOUS_AGE_SECS
    } else {
        MAX_DESCRIPTOR_AGE_SECS
    }
}

/// Whether a descriptor is still fresh (not stale) given its kind.
fn is_fresh(desc: &PeerDescriptor) -> bool {
    desc.age_secs() < max_age_for(desc)
}

/// In-memory store for peer descriptors.
///
/// Indexed by pseudonym (holder_tag). Supports staleness pruning,
/// capacity limits, capability-based queries, pseudonym churn tracking,
/// and per-peer relay trust observation.
pub struct DescriptorStore {
    /// Descriptors keyed by pseudonym.
    descriptors: HashMap<[u8; 32], PeerDescriptor>,
    /// Optional mapping from PeerId to pseudonym (for legacy/transition).
    peer_to_pseudonym: HashMap<PeerId, [u8; 32]>,
    /// Reverse mapping: pseudonym → PeerId (for relay circuit address construction).
    pseudonym_to_peer: HashMap<[u8; 32], PeerId>,
    /// Pseudonym churn tracker: pseudonyms seen in the previous epoch.
    prev_epoch_pseudonyms: std::collections::HashSet<[u8; 32]>,
    /// Current epoch being tracked (matches credential epoch).
    tracked_epoch: u64,
    /// Count of pseudonyms first seen in the current epoch (new arrivals).
    new_pseudonyms_this_epoch: usize,
    /// Relay behavior observations keyed by pseudonym.
    relay_observations: HashMap<[u8; 32], RelayObservation>,
}

impl DescriptorStore {
    pub fn new() -> Self {
        Self {
            descriptors: HashMap::new(),
            peer_to_pseudonym: HashMap::new(),
            pseudonym_to_peer: HashMap::new(),
            prev_epoch_pseudonyms: std::collections::HashSet::new(),
            tracked_epoch: 0,
            new_pseudonyms_this_epoch: 0,
            relay_observations: HashMap::new(),
        }
    }

    /// Insert or update a descriptor. Newer version wins.
    ///
    /// Rejects descriptors that are already stale on arrival or that would
    /// exceed the store capacity limit (evicting oldest stale entries first).
    pub fn upsert(&mut self, desc: PeerDescriptor) -> bool {
        // Reject descriptors that arrive already stale (per-kind max age).
        if desc.age_secs() >= max_age_for(&desc) {
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

        // Track pseudonym churn before inserting.
        if !self.descriptors.contains_key(&pseudonym) {
            self.track_pseudonym(pseudonym);
        }

        self.descriptors.insert(pseudonym, desc);
        true
    }

    /// Register a PeerId↔pseudonym mapping (for transition from address-based routing).
    pub fn register_peer_pseudonym(&mut self, peer_id: PeerId, pseudonym: [u8; 32]) {
        self.peer_to_pseudonym.insert(peer_id, pseudonym);
        self.pseudonym_to_peer.insert(pseudonym, peer_id);
    }

    /// Look up the PeerId associated with a pseudonym.
    pub fn peer_for_pseudonym(&self, pseudonym: &[u8; 32]) -> Option<&PeerId> {
        self.pseudonym_to_peer.get(pseudonym)
    }

    /// Return relay-capable peer info for the coordinator's relay routing.
    ///
    /// Returns `(PeerId, addresses)` for each relay-capable descriptor that
    /// has a known PeerId mapping. Used to construct libp2p relay circuit addresses.
    /// Return relay-capable peer info, sorted by relay trust tier (Verified first).
    pub fn relay_peer_info(&self) -> Vec<(PeerId, Vec<String>)> {
        let mut relays: Vec<_> = self.descriptors.values()
            .filter(|d| d.is_relay() && is_fresh(d))
            .filter_map(|d| {
                let pid = self.pseudonym_to_peer.get(&d.pseudonym)?;
                let tier = self.relay_tier(&d.pseudonym);
                Some((tier, *pid, d.addresses.clone()))
            })
            .collect();
        // Sort by tier descending (Verified > Observed > Claimed).
        relays.sort_by(|a, b| b.0.cmp(&a.0));
        relays.into_iter().map(|(_, pid, addrs)| (pid, addrs)).collect()
    }

    /// Return relay-capable peers with their onion X25519 public keys.
    ///
    /// Used by the onion encryption layer to build per-hop encrypted packets.
    /// Only returns relays that have published an `onion_pubkey`.
    /// Return relay peers with onion keys, sorted by relay trust tier (Verified first).
    pub fn relay_onion_info(&self) -> Vec<crate::onion::circuit::RelayInfo> {
        let mut relays: Vec<_> = self.descriptors.values()
            .filter(|d| d.is_relay() && is_fresh(d))
            .filter_map(|d| {
                let onion_pubkey = d.onion_pubkey?;
                let peer_id = self.pseudonym_to_peer.get(&d.pseudonym)?;
                let tier = self.relay_tier(&d.pseudonym);
                Some((tier, crate::onion::circuit::RelayInfo {
                    peer_id: peer_id.to_bytes(),
                    onion_pubkey,
                    addr: d.addresses.first()
                        .map(|a| a.as_bytes().to_vec())
                        .unwrap_or_default(),
                }))
            })
            .collect();
        relays.sort_by(|a, b| b.0.cmp(&a.0));
        relays.into_iter().map(|(_, info)| info).collect()
    }

    /// Look up a peer's onion X25519 public key from their descriptor.
    pub fn onion_pubkey_for_peer(&self, peer_id: &PeerId) -> Option<[u8; 32]> {
        self.peer_to_pseudonym.get(peer_id)
            .and_then(|ps| self.descriptors.get(ps))
            .and_then(|d| d.onion_pubkey)
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
            .filter(|d| d.is_relay() && is_fresh(d))
            .collect()
    }

    /// Return all descriptors meeting a minimum tier.
    pub fn descriptors_at_tier(&self, min_tier: CredentialTier) -> Vec<&PeerDescriptor> {
        self.descriptors.values()
            .filter(|d| d.meets_tier(min_tier) && is_fresh(d))
            .collect()
    }

    /// Return all non-stale descriptors.
    pub fn active_descriptors(&self) -> Vec<&PeerDescriptor> {
        self.descriptors.values()
            .filter(|d| is_fresh(d))
            .collect()
    }

    /// Prune stale descriptors (per-kind age limits). Returns number removed.
    pub fn prune_stale(&mut self) -> usize {
        let before = self.descriptors.len();
        self.descriptors.retain(|_, d| is_fresh(d));
        // Also clean up peer mappings and relay observations for removed descriptors.
        self.peer_to_pseudonym.retain(|_, p| self.descriptors.contains_key(p));
        self.pseudonym_to_peer.retain(|p, _| self.descriptors.contains_key(p));
        self.relay_observations.retain(|p, _| self.descriptors.contains_key(p));
        before - self.descriptors.len()
    }

    // ── Relay trust observation ─────────────────────────────────────────────

    /// Record a successful relay operation for a pseudonym.
    /// Promotes the relay's trust tier based on accumulated evidence.
    pub fn record_relay_success(&mut self, pseudonym: &[u8; 32]) {
        self.relay_observations
            .entry(*pseudonym)
            .or_insert_with(RelayObservation::new)
            .record_success();
    }

    /// Record a failed relay operation for a pseudonym.
    /// Demotes the relay's trust tier if failure rate is too high.
    pub fn record_relay_failure(&mut self, pseudonym: &[u8; 32]) {
        self.relay_observations
            .entry(*pseudonym)
            .or_insert_with(RelayObservation::new)
            .record_failure();
    }

    /// Current relay trust tier for a pseudonym.
    pub fn relay_tier(&self, pseudonym: &[u8; 32]) -> RelayTrustTier {
        self.relay_observations
            .get(pseudonym)
            .map(|o| o.tier)
            .unwrap_or(RelayTrustTier::Claimed)
    }

    /// Get relay observation details for a pseudonym.
    pub fn relay_observation(&self, pseudonym: &[u8; 32]) -> Option<&RelayObservation> {
        self.relay_observations.get(pseudonym)
    }

    /// Record a successful active probe for a pseudonym.
    pub fn record_probe_success(&mut self, pseudonym: &[u8; 32]) {
        self.relay_observations
            .entry(*pseudonym)
            .or_insert_with(RelayObservation::new)
            .record_probe_success();
    }

    /// Record a successful forwarding verification for a pseudonym.
    pub fn record_forwarding_verification(&mut self, pseudonym: &[u8; 32]) {
        self.relay_observations
            .entry(*pseudonym)
            .or_insert_with(RelayObservation::new)
            .record_forwarding_verification();
    }

    /// Check if a pseudonym has a fresh probe result.
    pub fn has_fresh_probe(&self, pseudonym: &[u8; 32], freshness_secs: u64) -> bool {
        self.relay_observations
            .get(pseudonym)
            .map(|o| o.has_fresh_probe(freshness_secs))
            .unwrap_or(false)
    }

    /// Count relay observations with fresh probe evidence.
    pub fn probed_fresh_count(&self, freshness_secs: u64) -> usize {
        self.relay_observations.values()
            .filter(|o| o.has_fresh_probe(freshness_secs))
            .count()
    }

    /// Count relay observations with forwarding verification evidence.
    pub fn forwarding_verified_count(&self) -> usize {
        self.relay_observations.values()
            .filter(|o| o.forwarding_verified_at.is_some())
            .count()
    }

    /// Decay all relay observations (call on epoch rotation).
    /// Halves success/failure counters so stale trust does not linger.
    pub fn decay_relay_observations(&mut self) {
        for obs in self.relay_observations.values_mut() {
            obs.decay();
        }
    }

    /// Count relay peers by trust tier.
    pub fn relay_tier_counts(&self) -> (usize, usize, usize) {
        let mut claimed = 0usize;
        let mut observed = 0usize;
        let mut verified = 0usize;
        for d in self.descriptors.values() {
            if d.is_relay() && is_fresh(d) {
                match self.relay_tier(&d.pseudonym) {
                    RelayTrustTier::Claimed => claimed += 1,
                    RelayTrustTier::Observed => observed += 1,
                    RelayTrustTier::Verified => verified += 1,
                }
            }
        }
        (claimed, observed, verified)
    }

    // ── Rendezvous / introduction-point resolution ────────────────────────

    /// Resolve introduction-point pseudonyms to (PeerId, addresses, relay_trust_tier).
    ///
    /// Returns only intro points that:
    /// 1. Have a fresh descriptor in the store
    /// 2. Have a known PeerId mapping
    /// 3. Advertise `can_relay: true`
    ///
    /// Results are sorted by relay trust tier (Verified first).
    pub fn resolve_intro_points(
        &self,
        intro_pseudonyms: &[[u8; 32]],
    ) -> Vec<ResolvedIntroPoint> {
        let mut resolved: Vec<ResolvedIntroPoint> = intro_pseudonyms.iter()
            .filter_map(|ps| {
                let desc = self.descriptors.get(ps)?;
                if !is_fresh(desc) || !desc.is_relay() {
                    return None;
                }
                let peer_id = self.pseudonym_to_peer.get(ps)?;
                let tier = self.relay_tier(ps);
                let onion_pubkey = desc.onion_pubkey;
                Some(ResolvedIntroPoint {
                    pseudonym: *ps,
                    peer_id: *peer_id,
                    addresses: desc.addresses.clone(),
                    relay_tier: tier,
                    onion_pubkey,
                })
            })
            .collect();
        resolved.sort_by(|a, b| b.relay_tier.cmp(&a.relay_tier));
        resolved
    }

    /// Select introduction points for a NAT'd node to publish in a
    /// Rendezvous descriptor.
    ///
    /// Prefers relay peers with higher trust tiers. Returns up to `count`
    /// pseudonyms, excluding the node's own pseudonym.
    pub fn select_intro_points(
        &self,
        own_pseudonym: &[u8; 32],
        count: usize,
    ) -> Vec<[u8; 32]> {
        let mut candidates: Vec<_> = self.descriptors.values()
            .filter(|d| {
                d.is_relay()
                    && is_fresh(d)
                    && &d.pseudonym != own_pseudonym
                    && self.pseudonym_to_peer.contains_key(&d.pseudonym)
            })
            .map(|d| (self.relay_tier(&d.pseudonym), d.pseudonym))
            .collect();
        // Sort by trust tier descending (Verified first).
        candidates.sort_by(|a, b| b.0.cmp(&a.0));
        candidates.into_iter().take(count).map(|(_, ps)| ps).collect()
    }

    /// Count rendezvous-capable peers (those with Rendezvous reachability).
    pub fn rendezvous_peer_count(&self) -> usize {
        self.descriptors.values()
            .filter(|d| d.is_rendezvous() && is_fresh(d))
            .count()
    }

    /// Total descriptors stored.
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    /// Notify the store of an epoch transition for pseudonym churn tracking.
    ///
    /// Call this when the credential epoch rotates. The store snapshots the
    /// current pseudonym set as "previous" and starts counting new arrivals.
    pub fn on_epoch_rotate(&mut self, new_epoch: u64) {
        if new_epoch <= self.tracked_epoch && self.tracked_epoch > 0 {
            return; // already tracking this epoch or a later one
        }
        // Snapshot current pseudonyms as the previous epoch's set.
        self.prev_epoch_pseudonyms = self.descriptors.keys().copied().collect();
        self.tracked_epoch = new_epoch;
        self.new_pseudonyms_this_epoch = 0;
        // Decay relay observations so stale trust doesn't linger.
        self.decay_relay_observations();
    }

    /// Record a pseudonym as newly observed (for churn tracking).
    fn track_pseudonym(&mut self, pseudonym: [u8; 32]) {
        if self.tracked_epoch > 0 && !self.prev_epoch_pseudonyms.contains(&pseudonym) {
            self.new_pseudonyms_this_epoch += 1;
        }
    }

    /// Compute the pseudonym churn rate: fraction of current pseudonyms that
    /// are new (not present in the previous epoch).
    ///
    /// Returns 0.0 if no epoch tracking data is available yet.
    pub fn churn_rate(&self) -> f64 {
        if self.tracked_epoch == 0 || self.descriptors.is_empty() {
            return 0.0;
        }
        let total = self.descriptors.len();
        let new_count = self.descriptors.keys()
            .filter(|ps| !self.prev_epoch_pseudonyms.contains(*ps))
            .count();
        new_count as f64 / total as f64
    }

    /// Diagnostics snapshot.
    pub fn stats(&self) -> DescriptorStats {
        let total = self.descriptors.len();
        let relay_count = self.descriptors.values().filter(|d| d.is_relay()).count();
        let relayed_count = self.descriptors.values().filter(|d| d.is_relayed()).count();
        let credentialed = self.descriptors.values()
            .filter(|d| d.credential.is_some())
            .count();
        let bbs_credentialed = self.descriptors.values()
            .filter(|d| d.bbs_proof.is_some())
            .count();
        let stale = self.descriptors.values()
            .filter(|d| !is_fresh(d))
            .count();
        let rendezvous_count = self.descriptors.values()
            .filter(|d| d.is_rendezvous() && is_fresh(d))
            .count();

        let relay_peers_routable = self.relay_peer_info().len();
        let (relay_claimed, relay_observed, relay_verified) = self.relay_tier_counts();

        DescriptorStats {
            total_descriptors: total,
            relay_descriptors: relay_count,
            relayed_descriptors: relayed_count,
            rendezvous_descriptors: rendezvous_count,
            credentialed_descriptors: credentialed,
            bbs_credentialed_descriptors: bbs_credentialed,
            stale_descriptors: stale,
            pseudonym_churn_rate: self.churn_rate(),
            relay_peers_routable,
            relay_claimed,
            relay_observed,
            relay_verified,
            probed_fresh: self.probed_fresh_count(300),
            forwarding_verified_count: self.forwarding_verified_count(),
        }
    }
}

/// A resolved introduction point with all information needed for routing.
#[derive(Debug, Clone)]
pub struct ResolvedIntroPoint {
    pub pseudonym: [u8; 32],
    pub peer_id: PeerId,
    pub addresses: Vec<String>,
    pub relay_tier: RelayTrustTier,
    /// X25519 onion pubkey if available (enables content-blind routing).
    pub onion_pubkey: Option<[u8; 32]>,
}

/// Diagnostics for the descriptor store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorStats {
    pub total_descriptors: usize,
    pub relay_descriptors: usize,
    pub relayed_descriptors: usize,
    pub rendezvous_descriptors: usize,
    pub credentialed_descriptors: usize,
    pub bbs_credentialed_descriptors: usize,
    pub stale_descriptors: usize,
    /// Pseudonym churn rate: fraction of current pseudonyms not seen last epoch.
    pub pseudonym_churn_rate: f64,
    /// Number of relay peers with known PeerId mappings (usable for circuit routing).
    pub relay_peers_routable: usize,
    /// Relay peers at Claimed trust tier (descriptor claim only, untested).
    pub relay_claimed: usize,
    /// Relay peers at Observed trust tier (≥1 successful relay operation).
    pub relay_observed: usize,
    /// Relay peers at Verified trust tier (≥3 successes, ≥75% success rate).
    pub relay_verified: usize,
    /// Number of relays with fresh (within 300s) active probe evidence.
    pub probed_fresh: usize,
    /// Number of relays with forwarding verification evidence.
    pub forwarding_verified_count: usize,
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
