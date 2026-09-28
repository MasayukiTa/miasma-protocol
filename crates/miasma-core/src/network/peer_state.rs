/// Per-peer trust state tracking and promotion pipeline (ADR-004 Phase 3b).
///
/// Each peer progresses through trust tiers:
///   Connected → Observed (Identify + address filter) → Verified (PoW admission)
///
/// The `PeerRegistry` tracks this state for all known peers and provides
/// queries used by routing, replication, and diagnostics.
use std::collections::HashMap;
use std::time::Instant;

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use super::address::AddressTrust;
use super::sybil::NodeIdPoW;

/// Per-peer trust state.
#[derive(Debug, Clone)]
pub struct PeerTrustState {
    /// Current trust tier.
    pub trust: AddressTrust,
    /// Their PoW proof, once received and verified.
    pub pow: Option<NodeIdPoW>,
    /// Ed25519 network-identity public key authenticated by Identify/PeerId and,
    /// in production, confirmed again by PoW admission.
    pub identity_pubkey: Option<[u8; 32]>,
    /// When the connection was established.
    pub connected_at: Instant,
    /// Whether Identify exchange completed and addresses passed filtering.
    pub identify_received: bool,
    /// Whether PoW admission exchange completed successfully.
    pub admission_verified: bool,
}

/// Reason a peer was rejected or not promoted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RejectionReason {
    /// No addresses passed the address-class filter.
    NoRoutableAddresses,
    /// PoW proof was missing from admission exchange.
    NoPoW,
    /// PoW proof was malformed (deserialization failed).
    MalformedPoW,
    /// PoW hash did not meet difficulty requirement.
    InsufficientDifficulty,
    /// PoW pubkey did not match the peer's actual identity.
    PubkeyMismatch,
    /// Remote peer explicitly rejected our admission request.
    RemoteRejected,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectionReason::NoRoutableAddresses => write!(f, "no routable addresses"),
            RejectionReason::NoPoW => write!(f, "no PoW proof"),
            RejectionReason::MalformedPoW => write!(f, "malformed PoW proof"),
            RejectionReason::InsufficientDifficulty => write!(f, "insufficient PoW difficulty"),
            RejectionReason::PubkeyMismatch => write!(f, "PoW pubkey does not match peer identity"),
            RejectionReason::RemoteRejected => {
                write!(f, "remote peer rejected admission request")
            }
        }
    }
}

/// Snapshot of admission stats for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionStats {
    pub verified_peers: usize,
    pub observed_peers: usize,
    pub claimed_peers: usize,
    pub total_rejections: u64,
}

/// Tracks trust state for all connected peers.
pub struct PeerRegistry {
    peers: HashMap<PeerId, PeerTrustState>,
    /// Cumulative count of peers rejected at any stage.
    rejection_count: u64,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            rejection_count: 0,
        }
    }

    /// Called on ConnectionEstablished — creates a Claimed entry.
    pub fn on_connected(&mut self, peer_id: PeerId) {
        self.peers.entry(peer_id).or_insert_with(|| PeerTrustState {
            trust: AddressTrust::Claimed,
            pow: None,
            identity_pubkey: None,
            connected_at: Instant::now(),
            identify_received: false,
            admission_verified: false,
        });
    }

    /// Called after Identify exchange succeeds and at least one address
    /// passed filtering. Promotes the peer from Claimed to Observed.
    pub fn on_identify(&mut self, peer_id: PeerId) {
        if let Some(state) = self.peers.get_mut(&peer_id) {
            state.identify_received = true;
            if state.trust < AddressTrust::Observed {
                state.trust = AddressTrust::Observed;
            }
        }
    }

    /// Record the authenticated Ed25519 network identity learned from Identify.
    /// The caller must first verify that this public key maps to `peer_id`.
    pub fn on_identify_identity(&mut self, peer_id: PeerId, identity_pubkey: [u8; 32]) {
        self.on_identify(peer_id);
        if let Some(state) = self.peers.get_mut(&peer_id) {
            state.identity_pubkey = Some(identity_pubkey);
        }
    }

    /// Called after successful PoW admission exchange. Promotes to Verified.
    pub fn on_admission_verified(&mut self, peer_id: PeerId, pow: NodeIdPoW) {
        if let Some(state) = self.peers.get_mut(&peer_id) {
            state.identity_pubkey = Some(pow.pubkey);
            state.pow = Some(pow);
            state.admission_verified = true;
            state.trust = AddressTrust::Verified;
        }
    }

    /// Mark a loopback/development peer Verified after authenticated Identify.
    /// No fake PoW is recorded: local mode skips the proof-of-work cost but still
    /// preserves the remote peer's real identity key for later key binding.
    pub fn on_local_admission_verified(&mut self, peer_id: PeerId) {
        if let Some(state) = self.peers.get_mut(&peer_id) {
            state.admission_verified = true;
            state.trust = AddressTrust::Verified;
        }
    }

    /// Called on ConnectionClosed — removes the peer entry.
    pub fn on_disconnected(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Record a rejection (for diagnostics).
    pub fn record_rejection(&mut self) {
        self.rejection_count += 1;
    }

    /// Returns the trust tier for a peer, if known.
    pub fn trust_of(&self, peer_id: &PeerId) -> Option<AddressTrust> {
        self.peers.get(peer_id).map(|s| s.trust)
    }

    /// Returns true if the peer is Verified.
    pub fn is_verified(&self, peer_id: &PeerId) -> bool {
        self.peers
            .get(peer_id)
            .is_some_and(|s| s.trust == AddressTrust::Verified)
    }

    /// Return the authenticated Ed25519 identity key for a Verified peer.
    pub fn verified_identity_pubkey(&self, peer_id: &PeerId) -> Option<[u8; 32]> {
        self.peers
            .get(peer_id)
            .filter(|state| state.admission_verified)
            .and_then(|state| state.identity_pubkey)
    }

    /// Return the PoW proof for a Verified peer when PoW was actually performed.
    /// Loopback mode intentionally leaves this `None` instead of fabricating one.
    pub fn verified_pow(&self, peer_id: &PeerId) -> Option<&NodeIdPoW> {
        self.peers
            .get(peer_id)
            .filter(|state| state.admission_verified)
            .and_then(|state| state.pow.as_ref())
    }

    /// Returns all peers at the Verified tier.
    pub fn verified_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, s)| s.trust == AddressTrust::Verified)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Snapshot for diagnostics.
    pub fn stats(&self) -> AdmissionStats {
        let mut verified = 0;
        let mut observed = 0;
        let mut claimed = 0;
        for state in self.peers.values() {
            match state.trust {
                AddressTrust::Verified => verified += 1,
                AddressTrust::Observed => observed += 1,
                AddressTrust::Claimed => claimed += 1,
            }
        }
        AdmissionStats {
            verified_peers: verified,
            observed_peers: observed,
            claimed_peers: claimed,
            total_rejections: self.rejection_count,
        }
    }

    /// Full snapshot: (PeerId, trust tier) pairs.
    pub fn snapshot(&self) -> Vec<(PeerId, AddressTrust)> {
        self.peers.iter().map(|(id, s)| (*id, s.trust)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn new_peer_starts_as_claimed() {
        let mut reg = PeerRegistry::new();
        let peer = random_peer();
        reg.on_connected(peer);
        assert_eq!(reg.trust_of(&peer), Some(AddressTrust::Claimed));
        assert!(!reg.is_verified(&peer));
    }

    #[test]
    fn identify_promotes_to_observed() {
        let mut reg = PeerRegistry::new();
        let peer = random_peer();
        reg.on_connected(peer);
        reg.on_identify(peer);
        assert_eq!(reg.trust_of(&peer), Some(AddressTrust::Observed));
    }

    #[test]
    fn admission_promotes_to_verified() {
        let mut reg = PeerRegistry::new();
        let peer = random_peer();
        let pow = crate::network::sybil::mine_pow([0xAB; 32], 8);
        reg.on_connected(peer);
        reg.on_identify(peer);
        reg.on_admission_verified(peer, pow);
        assert_eq!(reg.trust_of(&peer), Some(AddressTrust::Verified));
        assert!(reg.is_verified(&peer));
    }

    #[test]
    fn disconnect_removes_peer() {
        let mut reg = PeerRegistry::new();
        let peer = random_peer();
        reg.on_connected(peer);
        reg.on_disconnected(&peer);
        assert_eq!(reg.trust_of(&peer), None);
    }

    #[test]
    fn stats_counts_tiers() {
        let mut reg = PeerRegistry::new();
        let p1 = random_peer();
        let p2 = random_peer();
        let p3 = random_peer();
        let pow = crate::network::sybil::mine_pow([0xAB; 32], 8);

        reg.on_connected(p1);
        reg.on_connected(p2);
        reg.on_connected(p3);
        reg.on_identify(p2);
        reg.on_identify(p3);
        reg.on_admission_verified(p3, pow);

        let stats = reg.stats();
        assert_eq!(stats.claimed_peers, 1);
        assert_eq!(stats.observed_peers, 1);
        assert_eq!(stats.verified_peers, 1);
    }

    #[test]
    fn verified_peers_list() {
        let mut reg = PeerRegistry::new();
        let p1 = random_peer();
        let p2 = random_peer();
        let pow = crate::network::sybil::mine_pow([0xAB; 32], 8);

        reg.on_connected(p1);
        reg.on_connected(p2);
        reg.on_identify(p1);
        reg.on_admission_verified(p1, pow);

        let verified = reg.verified_peers();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0], p1);
    }

    #[test]
    fn rejection_counter() {
        let mut reg = PeerRegistry::new();
        reg.record_rejection();
        reg.record_rejection();
        assert_eq!(reg.stats().total_rejections, 2);
    }
}
