/// Network-level type definitions.
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

/// Node classification — determines storage and routing duties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NodeType {
    /// Stores a limited share quota; participates in DHT routing.
    Light,
    /// Stores full quota; participates in DHT routing with higher priority.
    #[default]
    Full,
    /// Translates BitTorrent magnets into Miasma dissolves (Phase 2).
    Bridge,
    /// Well-known entry points; provide initial DHT routing tables.
    Bootstrap,
}

/// Location of a single shard on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardLocation {
    /// libp2p PeerId bytes (32-byte Ed25519 public key, or full peer ID).
    pub peer_id_bytes: Vec<u8>,
    /// Global shard index (0-based, matches `MiasmaShare::slot_index`).
    pub shard_index: u16,
    /// Multiaddr strings where this peer can be reached.
    pub addrs: Vec<String>,
}

/// DHT record stored under a MID key.
///
/// Encodes: which nodes hold which shards of a given content item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRecord {
    /// Raw 32-byte BLAKE3 digest of the MID.
    pub mid_digest: [u8; 32],
    /// Number of data shards (k).
    pub data_shards: u8,
    /// Total shards (n = data + recovery).
    pub total_shards: u8,
    /// Protocol version.
    pub version: u8,
    /// Known shard locations at time of dissolution.
    pub locations: Vec<ShardLocation>,
    /// Unix timestamp (seconds) when this record was published.
    pub published_at: u64,
}

impl DhtRecord {
    /// DHT key used to store/retrieve this record: the raw MID digest.
    pub fn dht_key(&self) -> Vec<u8> {
        self.mid_digest.to_vec()
    }
}

// ─── Topology events ─────────────────────────────────────────────────────────

/// Signals meaningful changes in the network topology that may warrant
/// replication work.
///
/// This enum is `#[non_exhaustive]` so new variants (e.g. `PeerRoutable`,
/// `DhtRefreshComplete`) can be added without breaking downstream code.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum TopologyEvent {
    /// A new peer connection was established (raw transport level).
    /// This fires before the peer is added to Kademlia — prefer
    /// `PeerRoutable` for replication triggers.
    PeerConnected { peer_id: PeerId },
    /// The Identify protocol completed for a peer and its addresses were
    /// added to Kademlia.  This is the right signal for "this peer can
    /// now participate in DHT operations".
    PeerRoutable { peer_id: PeerId },
    /// A peer disconnected.
    PeerDisconnected { peer_id: PeerId },
    /// A directed envelope was received from a peer over the P2P protocol.
    DirectedEnvelopeReceived {
        peer_id: PeerId,
        envelope: Box<crate::directed::envelope::DirectedEnvelope>,
    },
    /// A sender revoked a directed share over the P2P protocol.
    DirectedRevokeReceived { envelope_id: [u8; 32] },
}

impl TopologyEvent {
    /// How many degraded items should be promoted back to pending when this
    /// event fires.  Returns 0 for events that do not warrant any promotion.
    ///
    /// This is intentionally conservative — a single routable peer promotes
    /// a small batch, not the whole degraded set.  Future variants like
    /// `DhtRefreshComplete` may return larger budgets.
    pub fn promotion_budget(&self) -> usize {
        match self {
            TopologyEvent::PeerRoutable { .. } => 4,
            TopologyEvent::PeerConnected { .. } => 0,
            TopologyEvent::PeerDisconnected { .. } => 0,
            #[allow(unreachable_patterns)]
            _ => 0,
        }
    }
}
