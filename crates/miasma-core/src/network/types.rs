/// Network-level type definitions.
use serde::{Deserialize, Serialize};

/// Node classification — determines storage and routing duties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// Stores a limited share quota; participates in DHT routing.
    Light,
    /// Stores full quota; participates in DHT routing with higher priority.
    Full,
    /// Translates BitTorrent magnets into Miasma dissolves (Phase 2).
    Bridge,
    /// Well-known entry points; provide initial DHT routing tables.
    Bootstrap,
}

impl Default for NodeType {
    fn default() -> Self {
        Self::Full
    }
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
