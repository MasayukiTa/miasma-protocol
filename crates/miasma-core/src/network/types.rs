/// Network-level type definitions.
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::MiasmaError;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardLocation {
    /// libp2p PeerId bytes (32-byte Ed25519 public key, or full peer ID).
    pub peer_id_bytes: Vec<u8>,
    /// Global shard index (0-based, matches `MiasmaShare::slot_index`).
    pub shard_index: u16,
    /// Segment index for multi-segment files (0-based).
    /// Defaults to 0 for backward compatibility with single-segment records.
    #[serde(default)]
    pub segment_index: u32,
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

/// Hard ceiling on the segment count a record (or manifest) may describe.
///
/// A segment is at most 64 MiB (`DEFAULT_SEGMENT_SIZE`), so 65 536 segments is
/// 4 TiB of plaintext, far above anything the beta transfers. Every count that
/// a receiver derives from a record or manifest, and every allocation sized by
/// it, is checked against this before it happens: the record comes from the
/// network and any peer that knows a MID can sign one.
pub const MAX_SEGMENTS: u32 = 65_536;

/// Hard ceiling on `locations` in one record.
///
/// One DHT value is capped at 16 MiB and the smallest encoded `ShardLocation`
/// is about 22 bytes, so no genuine record can hold more than ~760 000; 2^20
/// leaves headroom. The count is additionally bounded by
/// `MAX_SEGMENTS * total_shards` in [`DhtRecord::validate`].
pub const MAX_RECORD_LOCATIONS: usize = 1 << 20;

/// Bounds on the per-location fields (a holder announces a handful of dial
/// addresses; a libp2p peer id is at most ~42 bytes).
pub const MAX_LOCATION_ADDRS: usize = 32;
pub const MAX_LOCATION_ADDR_LEN: usize = 512;
pub const MAX_PEER_ID_BYTES: usize = 128;

impl DhtRecord {
    /// DHT key used to store/retrieve this record: the raw MID digest.
    pub fn dht_key(&self) -> Vec<u8> {
        self.mid_digest.to_vec()
    }

    /// Check an *untrusted* record before any count in it is used to size an
    /// allocation or a loop. Rejects; never clamps.
    ///
    /// The shard parameters obey the rule the publisher applies (`0 < k <= n`,
    /// both fit the `u8` Shamir/RS parameters), every location must name a slot
    /// below `n` and a segment below [`MAX_SEGMENTS`], and the number of
    /// locations and the size of each are bounded.
    pub fn validate(&self) -> Result<(), MiasmaError> {
        let bad = |m: String| Err(MiasmaError::InvalidManifest(format!("invalid record: {m}")));
        let (k, n) = (self.data_shards as usize, self.total_shards as usize);
        if k == 0 || n < k {
            return bad(format!("invalid shard counts k={k}, n={n}"));
        }
        let max_locations = MAX_RECORD_LOCATIONS.min(MAX_SEGMENTS as usize * n);
        if self.locations.len() > max_locations {
            return bad(format!(
                "{} locations, limit {max_locations}",
                self.locations.len()
            ));
        }
        for loc in &self.locations {
            if loc.segment_index >= MAX_SEGMENTS {
                return bad(format!(
                    "segment index {} is not below the limit {MAX_SEGMENTS}",
                    loc.segment_index
                ));
            }
            if loc.shard_index as usize >= n {
                return bad(format!(
                    "shard index {} is not below n={n}",
                    loc.shard_index
                ));
            }
            if loc.peer_id_bytes.len() > MAX_PEER_ID_BYTES
                || loc.addrs.len() > MAX_LOCATION_ADDRS
                || loc.addrs.iter().any(|a| a.len() > MAX_LOCATION_ADDR_LEN)
            {
                return bad("oversized location entry".into());
            }
        }
        Ok(())
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
