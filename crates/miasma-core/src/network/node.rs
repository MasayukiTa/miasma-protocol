/// Miasma libp2p node — Phase 3b enforced admission and trust-tier routing.
///
/// Transport: TCP + QUIC for local loopback testing and production paths
/// DHT: Kademlia via `DhtHandle` / `OnionAwareDhtExecutor` (ADR-002)
/// Share exchange: `/miasma/share/1.0.0` request-response protocol
/// Admission: `/miasma/admission/1.0.0` PoW proof exchange (ADR-004)
/// NAT: AutoNAT + DCUtR + relay
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use libp2p::{
    autonat, dcutr, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore, store::RecordStore},
    noise, ping, relay, request_response, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::{crypto::keyderive::NodeKeys, share::MiasmaShare, store::LocalShareStore, MiasmaError};

use super::peer_state::{AdmissionStats, PeerRegistry, RejectionReason};
use super::routing::{self, RoutingStats, RoutingTable};
use super::sybil::{self, NodeIdPoW, SignedDhtRecord};
use super::types::{DhtRecord, NodeType};

// ─── Share-exchange wire types ────────────────────────────────────────────────

/// Request a specific shard from a remote peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFetchRequest {
    pub mid_digest: [u8; 32],
    pub slot_index: u16,
    pub segment_index: u32,
}

/// Response to a `ShareFetchRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFetchResponse {
    /// The requested shard, or `None` if not stored on this peer.
    pub share: Option<MiasmaShare>,
}

// ─── Admission wire types (ADR-004 Phase 3b) ────────────────────────────────

/// PoW admission request — sent after Identify to exchange proof of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRequest {
    /// The requesting node's own PoW proof.
    pub pow: NodeIdPoW,
}

/// PoW admission response — peer replies with their own PoW proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionResponse {
    /// The responding node's PoW proof.
    pub pow: NodeIdPoW,
}

// ─── ShareCodec ───────────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/share/1.0.0`.
#[derive(Clone, Default)]
pub struct ShareCodec;

/// Max message size for share exchange (4 MiB).
const SHARE_MSG_MAX: usize = 4 * 1024 * 1024;
/// Max message size for admission protocol (4 KiB — PoW proofs are tiny).
const ADMISSION_MSG_MAX: usize = 4 * 1024;

#[async_trait::async_trait]
impl request_response::Codec for ShareCodec {
    type Protocol = StreamProtocol;
    type Request = ShareFetchRequest;
    type Response = ShareFetchResponse;

    async fn read_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > SHARE_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("share exchange message too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > SHARE_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("share exchange message too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&res)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await?;
        Ok(())
    }
}

// ─── AdmissionCodec ──────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/admission/1.0.0`.
#[derive(Clone, Default)]
pub struct AdmissionCodec;

#[async_trait::async_trait]
impl request_response::Codec for AdmissionCodec {
    type Protocol = StreamProtocol;
    type Request = AdmissionRequest;
    type Response = AdmissionResponse;

    async fn read_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > ADMISSION_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("admission message too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > ADMISSION_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("admission message too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&res)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await?;
        Ok(())
    }
}

// ─── DHT command channel ──────────────────────────────────────────────────────

pub enum DhtCommand {
    /// PUT a serialised record into Kademlia.
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
        reply: oneshot::Sender<Result<(), MiasmaError>>,
    },
    /// GET raw record bytes from Kademlia.
    Get {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, MiasmaError>>,
    },
    /// Register a bootstrap peer and dial from within the running event loop.
    ///
    /// Dialing from inside the event loop avoids the ECONNREFUSED race that
    /// occurs when `swarm.dial()` is called before the remote node's `run()`
    /// has started accepting connections.
    AddBootstrapPeer {
        peer_id: PeerId,
        addr: Multiaddr,
        reply: oneshot::Sender<()>,
    },
    /// Trigger Kademlia FIND_NODE bootstrap for this node's own key.
    BootstrapDht {
        reply: oneshot::Sender<Result<(), MiasmaError>>,
    },
    /// Query the number of currently connected peers.
    GetPeerCount {
        reply: oneshot::Sender<usize>,
    },
    /// Query admission statistics.
    GetAdmissionStats {
        reply: oneshot::Sender<AdmissionStats>,
    },
    /// Query routing overlay statistics.
    GetRoutingStats {
        reply: oneshot::Sender<RoutingStats>,
    },
}

/// Sender side of the DHT command channel.
///
/// Wraps the low-level channel with typed `put`/`get_record` helpers that
/// handle bincode serialisation / deserialisation of `DhtRecord`.
#[derive(Clone)]
pub struct DhtHandle {
    pub(crate) tx: mpsc::Sender<DhtCommand>,
}

impl DhtHandle {
    /// Publish a `DhtRecord` to Kademlia.
    pub async fn put(&self, record: DhtRecord) -> Result<(), MiasmaError> {
        let key = record.mid_digest.to_vec();
        let value = bincode::serialize(&record)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::Put { key, value, reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await
            .map_err(|_| MiasmaError::Network("DHT reply channel dropped".into()))?
    }

    /// Register a bootstrap peer inside the running event loop.
    ///
    /// Sends `AddBootstrapPeer` to the event loop so the dial happens from
    /// within `run()`, ensuring the remote TCP socket is already accepting.
    pub async fn add_bootstrap_peer(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Result<(), MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::AddBootstrapPeer { peer_id, addr, reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Trigger Kademlia FIND_NODE bootstrap.
    ///
    /// Call after `add_bootstrap_peer`; allow ~1–3 s for convergence before
    /// issuing DHT PUT or GET operations.
    pub async fn bootstrap(&self) -> Result<(), MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::BootstrapDht { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))?
    }

    /// Return the number of currently connected peers.
    pub async fn peer_count(&self) -> Result<usize, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetPeerCount { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Retrieve a `DhtRecord` from Kademlia by raw mid-digest bytes.
    pub async fn get_record(
        &self,
        mid_digest: [u8; 32],
    ) -> Result<Option<DhtRecord>, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::Get { key: mid_digest.to_vec(), reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        let raw_opt = rx
            .await
            .map_err(|_| MiasmaError::Network("DHT reply channel dropped".into()))??;
        match raw_opt {
            Some(bytes) => {
                // Try to unwrap SignedDhtRecord envelope first, fall back to plain DhtRecord.
                if let Ok(signed) = bincode::deserialize::<SignedDhtRecord>(&bytes) {
                    if signed.verify_signature() {
                        return Ok(Some(
                            bincode::deserialize(&signed.value)
                                .map_err(|e| MiasmaError::Serialization(e.to_string()))?,
                        ));
                    } else {
                        warn!("DHT GET: record has invalid signature, rejecting");
                        return Ok(None);
                    }
                }
                // Fall back: plain DhtRecord (transition compatibility).
                Ok(Some(
                    bincode::deserialize(&bytes)
                        .map_err(|e| MiasmaError::Serialization(e.to_string()))?,
                ))
            }
            None => Ok(None),
        }
    }

    /// Query admission statistics from the node.
    pub async fn admission_stats(&self) -> Result<AdmissionStats, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetAdmissionStats { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query routing overlay statistics from the node.
    pub async fn routing_stats(&self) -> Result<RoutingStats, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetRoutingStats { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }
}

// ─── Share-exchange command channel ──────────────────────────────────────────

pub struct ShareCommand {
    pub peer_id: PeerId,
    /// Known multiaddr strings for the peer (used to dial before sending).
    pub addrs: Vec<String>,
    pub request: ShareFetchRequest,
    pub reply: oneshot::Sender<Result<Option<MiasmaShare>, MiasmaError>>,
}

/// Sender side of the share-exchange command channel.
#[derive(Clone)]
pub struct ShareExchangeHandle {
    pub(crate) tx: mpsc::Sender<ShareCommand>,
}

impl ShareExchangeHandle {
    /// Fetch a shard from a specific peer.
    pub async fn fetch(
        &self,
        peer_id: PeerId,
        addrs: Vec<String>,
        request: ShareFetchRequest,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ShareCommand { peer_id, addrs, request, reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("share exchange channel closed".into()))?;
        rx.await
            .map_err(|_| MiasmaError::Network("share exchange reply dropped".into()))?
    }
}

// ─── Behaviour ────────────────────────────────────────────────────────────────

/// Combined libp2p behaviour for a Miasma node.
#[derive(NetworkBehaviour)]
pub struct MiasmaBehaviour {
    pub(crate) kademlia: kad::Behaviour<MemoryStore>,
    pub(crate) identify: identify::Behaviour,
    pub(crate) ping: ping::Behaviour,
    pub(crate) autonat: autonat::Behaviour,
    pub(crate) relay: relay::client::Behaviour,
    pub(crate) dcutr: dcutr::Behaviour,
    /// Share fetch: `/miasma/share/1.0.0` request-response.
    pub(crate) share_exchange: request_response::Behaviour<ShareCodec>,
    /// PoW admission: `/miasma/admission/1.0.0` request-response.
    pub(crate) admission: request_response::Behaviour<AdmissionCodec>,
}

// ─── MiasmaNode ───────────────────────────────────────────────────────────────

pub struct MiasmaNode {
    pub local_peer_id: PeerId,
    pub node_type: NodeType,
    swarm: Swarm<MiasmaBehaviour>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
    // DHT command channel (rx side owned by this node).
    dht_tx: mpsc::Sender<DhtCommand>,
    dht_rx: mpsc::Receiver<DhtCommand>,
    // Share exchange command channel.
    share_tx: mpsc::Sender<ShareCommand>,
    share_rx: mpsc::Receiver<ShareCommand>,
    // Pending Kademlia queries awaiting resolution.
    pending_puts: HashMap<kad::QueryId, oneshot::Sender<Result<(), MiasmaError>>>,
    pending_gets: HashMap<
        kad::QueryId,
        (oneshot::Sender<Result<Option<Vec<u8>>, MiasmaError>>, Option<Vec<u8>>),
    >,
    // Pending outbound share-fetch requests.
    pending_share_fetches:
        HashMap<request_response::OutboundRequestId, oneshot::Sender<Result<Option<MiasmaShare>, MiasmaError>>>,
    // Pending outbound admission requests: req_id → peer_id.
    pending_admissions: HashMap<request_response::OutboundRequestId, PeerId>,
    /// Local share store — used to serve inbound `ShareFetchRequest`s.
    local_store: Option<Arc<LocalShareStore>>,
    /// Optional channel to notify when a Kademlia PUT is acknowledged by remote peers.
    replication_success_tx: Option<mpsc::Sender<[u8; 32]>>,
    /// Optional channel to emit topology change events (peer connect/disconnect).
    topology_tx: Option<mpsc::Sender<super::types::TopologyEvent>>,
    /// When true, skip address filtering and PoW checks (loopback/private allowed).
    allow_local_addresses: bool,
    /// This node's pre-mined PoW proof for admission exchanges.
    local_pow: NodeIdPoW,
    /// Per-peer trust state tracking.
    peer_registry: PeerRegistry,
    /// Ed25519 signing key for signing DHT records.
    dht_signing_key: ed25519_dalek::SigningKey,
    /// Addresses held per peer while awaiting admission verification.
    /// Once verified, these are promoted to Kademlia.
    pending_peer_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    /// Routing overlay: trust preference, IP diversity, reliability tracking.
    routing_table: RoutingTable,
    /// Tick counter for periodic network-size observation (difficulty adjustment).
    event_tick: u64,
}

impl MiasmaNode {
    /// Build a node from the given master key.
    pub fn new(
        master_key: &[u8; 32],
        node_type: NodeType,
        listen_addr: &str,
    ) -> Result<Self, MiasmaError> {
        let node_keys = NodeKeys::derive(master_key)?;

        let mut signing_bytes: [u8; 32] = *node_keys.dht_signing_key;
        let keypair = Keypair::ed25519_from_bytes(&mut signing_bytes)
            .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;

        // Derive Ed25519 signing key for DHT record signing.
        let dht_signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_bytes);
        zeroize::Zeroize::zeroize(&mut signing_bytes);

        let local_peer_id = PeerId::from(keypair.public());
        info!("Miasma node: peer_id={local_peer_id}, type={node_type:?}");

        // Mine PoW proof for this node's identity.
        // At difficulty 8 this is ~256 BLAKE3 hashes — sub-millisecond.
        let pubkey_bytes = dht_signing_key.verifying_key().to_bytes();
        let local_pow = sybil::mine_pow(pubkey_bytes, sybil::DEFAULT_POW_DIFFICULTY);
        debug!("PoW mined: nonce={}, difficulty={}", local_pow.nonce, sybil::DEFAULT_POW_DIFFICULTY);

        let swarm = build_swarm(keypair, local_peer_id, listen_addr)?;

        // Auto-detect local mode: if listening on loopback, allow local addresses
        // through the Identify filter so loopback-based tests and local development work.
        let allow_local = listen_addr.contains("127.0.0.1") || listen_addr.contains("::1");

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (dht_tx, dht_rx) = mpsc::channel(64);
        let (share_tx, share_rx) = mpsc::channel(64);

        Ok(Self {
            local_peer_id,
            node_type,
            swarm,
            shutdown_tx,
            shutdown_rx,
            dht_tx,
            dht_rx,
            share_tx,
            share_rx,
            pending_puts: HashMap::new(),
            pending_gets: HashMap::new(),
            pending_share_fetches: HashMap::new(),
            pending_admissions: HashMap::new(),
            local_store: None,
            replication_success_tx: None,
            topology_tx: None,
            allow_local_addresses: allow_local,
            local_pow,
            peer_registry: PeerRegistry::new(),
            dht_signing_key,
            pending_peer_addrs: HashMap::new(),
            routing_table: RoutingTable::new(!allow_local),
            event_tick: 0,
        })
    }

    /// Attach a local share store so this node can serve inbound shard requests.
    pub fn set_store(&mut self, store: Arc<LocalShareStore>) {
        self.local_store = Some(store);
    }

    /// Set a channel to receive notifications when a Kademlia PUT is acknowledged.
    pub fn set_replication_notifier(&mut self, tx: mpsc::Sender<[u8; 32]>) {
        self.replication_success_tx = Some(tx);
    }

    /// Set a channel to receive topology change events (peer connect/disconnect).
    pub fn set_topology_notifier(&mut self, tx: mpsc::Sender<super::types::TopologyEvent>) {
        self.topology_tx = Some(tx);
    }

    /// Allow loopback/private addresses (for local testing only).
    pub fn set_allow_local_addresses(&mut self, allow: bool) {
        self.allow_local_addresses = allow;
    }

    /// Returns a sender that drives DHT PUT/GET via the Kademlia event loop.
    pub fn dht_handle(&self) -> DhtHandle {
        DhtHandle { tx: self.dht_tx.clone() }
    }

    /// Returns a sender that drives outbound share-fetch requests.
    pub fn share_exchange_handle(&self) -> ShareExchangeHandle {
        ShareExchangeHandle { tx: self.share_tx.clone() }
    }

    /// Register a bootstrap peer in the Kademlia routing table and dial it.
    ///
    /// Explicitly dialing ensures the QUIC connection is established as soon
    /// as the event loop starts, rather than waiting for Kademlia's first
    /// outbound query to trigger the dial.
    pub fn add_bootstrap_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        // Explicit dial so the QUIC connection is in flight from loop start.
        let p2p_addr = addr.clone().with(libp2p::multiaddr::Protocol::P2p(peer_id));
        if let Err(e) = self.swarm.dial(p2p_addr) {
            debug!("bootstrap dial queued error (may be harmless): {e}");
        }
        info!("Bootstrap peer added + dial queued: {peer_id} @ {addr}");
    }

    /// Register a relay server for NAT traversal.
    pub fn add_relay_server(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        let peer_id_str = peer_id.to_string();
        let addr_str = addr.to_string();
        let relay_addr = addr
            .with(libp2p::multiaddr::Protocol::P2p(peer_id))
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        if let Err(e) = self.swarm.dial(relay_addr) {
            debug!("relay dial failed for {peer_id_str}: {e}");
        } else {
            info!("Relay server registered: {peer_id_str} @ {addr_str}");
        }
    }

    /// Initiate Kademlia bootstrap.
    pub fn bootstrap_dht(&mut self) -> Result<(), MiasmaError> {
        self.swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map_err(|e| MiasmaError::Sss(format!("DHT bootstrap: {e:?}")))?;
        Ok(())
    }

    /// Clone of the shutdown sender — send `()` to stop the event loop.
    pub fn shutdown_handle(&self) -> mpsc::Sender<()> {
        self.shutdown_tx.clone()
    }

    /// Poll the swarm briefly to collect `NewListenAddr` events.
    ///
    /// Call this after `new()` to discover the OS-assigned port when
    /// listening on port 0. Blocks for up to `timeout_ms` milliseconds.
    ///
    /// Uses `tokio::select!` rather than `tokio::time::timeout` so that
    /// each `swarm.next()` poll completes cleanly before the deadline
    /// check runs — avoiding the cancel-unsafety of dropping a
    /// mid-poll swarm future inside `timeout`.
    pub async fn collect_listen_addrs(&mut self, timeout_ms: u64) -> Vec<Multiaddr> {
        let mut addrs = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                biased;
                event = self.swarm.next() => {
                    match event {
                        Some(SwarmEvent::NewListenAddr { address, .. }) => {
                            addrs.push(address);
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                _ = &mut sleep => break,
            }
        }
        addrs
    }

    /// Run the node event loop. Blocks until shutdown or error.
    pub async fn run(&mut self) -> Result<(), MiasmaError> {
        loop {
            tokio::select! {
                event = self.swarm.next() => {
                    match event {
                        Some(ev) => self.handle_event(ev),
                        None => break,
                    }
                }
                cmd = self.dht_rx.recv() => {
                    if let Some(cmd) = cmd { self.handle_dht_command(cmd); }
                }
                cmd = self.share_rx.recv() => {
                    if let Some(cmd) = cmd { self.handle_share_command(cmd); }
                }
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }
        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn handle_dht_command(&mut self, cmd: DhtCommand) {
        match cmd {
            DhtCommand::Put { key, value, reply } => {
                // Wrap the raw value in a SignedDhtRecord envelope.
                let signed = SignedDhtRecord::sign(
                    key.clone(),
                    value,
                    &self.dht_signing_key,
                );
                let signed_bytes = bincode::serialize(&signed).unwrap_or_default();

                let record = kad::Record {
                    key: kad::RecordKey::new(&key),
                    value: signed_bytes,
                    publisher: None,
                    expires: None,
                };
                // Always store locally first so remote peers can retrieve the
                // record via GET even if no other peers are reachable yet.
                let _ = self.swarm.behaviour_mut().kademlia.store_mut().put(record.clone());
                // Fire-and-forget network replication: reply success immediately.
                let _ = self.swarm.behaviour_mut().kademlia.put_record(record, kad::Quorum::One);
                let _ = reply.send(Ok(()));
            }
            DhtCommand::Get { key, reply } => {
                let qid = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_record(kad::RecordKey::new(&key));
                self.pending_gets.insert(qid, (reply, None));
            }
            DhtCommand::AddBootstrapPeer { peer_id, addr, reply } => {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                self.swarm.add_peer_address(peer_id, addr.clone());
                let p2p_addr = addr.with(libp2p::multiaddr::Protocol::P2p(peer_id));
                if let Err(e) = self.swarm.dial(p2p_addr) {
                    debug!("bootstrap dial queued error (may be harmless): {e}");
                }
                let _ = reply.send(());
            }
            DhtCommand::BootstrapDht { reply } => {
                let result = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .bootstrap()
                    .map(|_| ())
                    .map_err(|e| MiasmaError::Sss(format!("DHT bootstrap: {e:?}")));
                let _ = reply.send(result);
            }
            DhtCommand::GetPeerCount { reply } => {
                let count = self.swarm.connected_peers().count();
                let _ = reply.send(count);
            }
            DhtCommand::GetAdmissionStats { reply } => {
                let stats = self.peer_registry.stats();
                let _ = reply.send(stats);
            }
            DhtCommand::GetRoutingStats { reply } => {
                let stats = self.routing_table.stats();
                let _ = reply.send(stats);
            }
        }
    }

    fn handle_share_command(&mut self, cmd: ShareCommand) {
        let ShareCommand { peer_id, addrs, request, reply } = cmd;

        // Register addresses with both Kademlia (routing) and share_exchange
        // (address book used by request_response when it dials the peer).
        for addr_str in &addrs {
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                self.swarm.add_peer_address(peer_id, addr.clone());
            }
        }

        let req_id = self.swarm.behaviour_mut().share_exchange.send_request(&peer_id, request);
        self.pending_share_fetches.insert(req_id, reply);
    }

    fn handle_event(&mut self, event: SwarmEvent<MiasmaBehaviourEvent>) {
        // Periodic network-size observation for difficulty adjustment.
        // Every ~500 events, sample the connected peer count and adjust difficulty.
        self.event_tick = self.event_tick.wrapping_add(1);
        if self.event_tick % 500 == 0 {
            let peer_count = self.swarm.connected_peers().count();
            self.routing_table.observe_network_size(peer_count);
            if let Some(new_diff) = self.routing_table.maybe_adjust_difficulty() {
                info!("routing.difficulty_changed bits={new_diff}");
            }
        }

        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {address}");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connected: {peer_id}");
                self.peer_registry.on_connected(peer_id);
                if let Some(tx) = &self.topology_tx {
                    let _ = tx.try_send(super::types::TopologyEvent::PeerConnected { peer_id });
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                debug!("Disconnected: {peer_id} ({cause:?})");
                self.peer_registry.on_disconnected(&peer_id);
                self.routing_table.remove_peer(&peer_id);
                self.pending_peer_addrs.remove(&peer_id);
                if let Some(tx) = &self.topology_tx {
                    let _ = tx.try_send(super::types::TopologyEvent::PeerDisconnected { peer_id });
                }
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                self.handle_identify(peer_id, info);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Kademlia(ev)) => {
                self.handle_kad_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::ShareExchange(ev)) => {
                self.handle_share_exchange_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Admission(ev)) => {
                self.handle_admission_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Autonat(ev)) => match &ev {
                autonat::Event::StatusChanged { old, new } => {
                    info!("AutoNAT: {old:?} → {new:?}");
                }
                _ => debug!("AutoNAT: {ev:?}"),
            },
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Dcutr(ev)) => {
                debug!("DCUtR: {ev:?}");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Relay(ev)) => {
                debug!("Relay client: {ev:?}");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Ping(_)) => {}
            _ => {}
        }
    }

    /// Handle Identify protocol completion for a peer.
    fn handle_identify(&mut self, peer_id: PeerId, info: identify::Info) {
        // Filter addresses: reject loopback, link-local, private, unknown.
        // In local/test mode, skip filtering to allow loopback addresses.
        let addrs_to_use = if self.allow_local_addresses {
            info.listen_addrs.clone()
        } else {
            super::address::filter_peer_addresses(&peer_id, &info.listen_addrs)
        };

        if addrs_to_use.is_empty() {
            debug!("admission.rejected peer={peer_id} reason=no_routable_addresses");
            self.peer_registry.record_rejection();
            return;
        }

        // Promote to Observed in peer registry.
        self.peer_registry.on_identify(peer_id);

        if self.allow_local_addresses {
            // Local mode: skip PoW admission, add directly to Kademlia and
            // auto-promote to Verified.
            for addr in &addrs_to_use {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
            }
            if let Some(first_addr) = addrs_to_use.first() {
                self.swarm.behaviour_mut().autonat.add_server(peer_id, Some(first_addr.clone()));
            }
            // Auto-promote: in local mode, treat as verified.
            let fake_pow = self.local_pow.clone();
            self.peer_registry.on_admission_verified(peer_id, fake_pow);

            if let Some(tx) = &self.topology_tx {
                let _ = tx.try_send(super::types::TopologyEvent::PeerRoutable { peer_id });
            }
        } else {
            // Production mode: check IP diversity before proceeding.
            match self.routing_table.check_diversity(&addrs_to_use) {
                Err(violation) => {
                    warn!("routing.diversity_rejected peer={peer_id} reason={violation}");
                    self.routing_table.record_diversity_rejection();
                    self.peer_registry.record_rejection();
                    return;
                }
                Ok(_prefix) => {}
            }

            // Hold addresses pending admission verification.
            // Register addresses in the swarm address book so the admission
            // protocol can dial the peer, but do NOT add to Kademlia yet.
            for addr in &addrs_to_use {
                self.swarm.add_peer_address(peer_id, addr.clone());
            }
            self.pending_peer_addrs.insert(peer_id, addrs_to_use);

            // Initiate PoW admission exchange.
            let req = AdmissionRequest { pow: self.local_pow.clone() };
            let req_id = self.swarm.behaviour_mut().admission.send_request(&peer_id, req);
            self.pending_admissions.insert(req_id, peer_id);
            debug!("admission.requested peer={peer_id}");
        }
    }

    /// Verify a remote peer's PoW proof and return the rejection reason if invalid.
    fn verify_remote_pow(&self, peer_id: &PeerId, pow: &NodeIdPoW) -> Result<(), RejectionReason> {
        // Check that the PoW pubkey matches the peer's libp2p identity.
        // Reconstruct the PeerId from the PoW's Ed25519 public key bytes.
        let ed_pubkey = libp2p::identity::ed25519::PublicKey::try_from_bytes(&pow.pubkey)
            .map_err(|_| RejectionReason::MalformedPoW)?;
        let libp2p_pubkey = libp2p::identity::PublicKey::from(ed_pubkey);
        let claimed_peer_id = PeerId::from(libp2p_pubkey);

        if &claimed_peer_id != peer_id {
            return Err(RejectionReason::PubkeyMismatch);
        }

        // Verify the PoW difficulty (uses dynamic difficulty from routing table).
        let required_difficulty = self.routing_table.current_difficulty();
        match sybil::check_peer_admission(Some(pow), required_difficulty) {
            sybil::AdmissionResult::Admitted => Ok(()),
            sybil::AdmissionResult::RejectedNoPoW => Err(RejectionReason::NoPoW),
            sybil::AdmissionResult::RejectedLowDifficulty => Err(RejectionReason::InsufficientDifficulty),
        }
    }

    /// Handle admission protocol events.
    fn handle_admission_event(
        &mut self,
        ev: request_response::Event<AdmissionRequest, AdmissionResponse>,
    ) {
        match ev {
            // Inbound admission request: verify their PoW, respond with ours.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Request { request, channel, .. },
            } => {
                // Verify the requester's PoW.
                match self.verify_remote_pow(&peer, &request.pow) {
                    Ok(()) => {
                        info!("admission.inbound_verified peer={peer}");
                        // Respond with our own PoW.
                        let resp = AdmissionResponse { pow: self.local_pow.clone() };
                        let _ = self.swarm.behaviour_mut().admission.send_response(channel, resp);

                        // Promote the peer to Verified and add to Kademlia.
                        self.promote_peer_to_verified(peer, request.pow);
                    }
                    Err(reason) => {
                        warn!("admission.rejected peer={peer} reason={reason}");
                        self.peer_registry.record_rejection();
                        // Still respond (protocol requires it) but peer won't be promoted.
                        let resp = AdmissionResponse { pow: self.local_pow.clone() };
                        let _ = self.swarm.behaviour_mut().admission.send_response(channel, resp);
                    }
                }
            }
            // Outbound admission response received: verify their PoW.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Response { request_id, response },
            } => {
                self.pending_admissions.remove(&request_id);
                match self.verify_remote_pow(&peer, &response.pow) {
                    Ok(()) => {
                        info!("admission.verified peer={peer}");
                        self.promote_peer_to_verified(peer, response.pow);
                    }
                    Err(reason) => {
                        warn!("admission.rejected peer={peer} reason={reason}");
                        self.peer_registry.record_rejection();
                    }
                }
            }
            request_response::Event::OutboundFailure { request_id, peer, error } => {
                self.pending_admissions.remove(&request_id);
                warn!("admission.outbound_failure peer={peer} error={error}");
                self.peer_registry.record_rejection();
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!("admission.inbound_failure peer={peer} error={error}");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Promote a peer to Verified: add addresses to Kademlia, signal routable.
    fn promote_peer_to_verified(&mut self, peer_id: PeerId, pow: NodeIdPoW) {
        self.peer_registry.on_admission_verified(peer_id, pow);

        // Promote held addresses to Kademlia routing table.
        if let Some(addrs) = self.pending_peer_addrs.remove(&peer_id) {
            // Add peer to routing overlay with its IP prefix.
            let prefix = routing::ip_prefix_of(addrs.first().unwrap_or(
                &"/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            ));
            self.routing_table.add_peer(peer_id, prefix);

            for addr in &addrs {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
            }
            if let Some(first_addr) = addrs.first() {
                self.swarm.behaviour_mut().autonat.add_server(peer_id, Some(first_addr.clone()));
            }
        }

        // Signal that this peer is now routable.
        if let Some(tx) = &self.topology_tx {
            let _ = tx.try_send(super::types::TopologyEvent::PeerRoutable { peer_id });
        }
    }

    fn handle_kad_event(&mut self, ev: kad::Event) {
        match ev {
            kad::Event::OutboundQueryProgressed { id, result, step, .. } => match result {
                kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                    // Notify replication tracker: network PUT acknowledged by remote peer.
                    if let Some(tx) = &self.replication_success_tx {
                        let key_bytes = key.as_ref();
                        if key_bytes.len() == 32 {
                            let mut digest = [0u8; 32];
                            digest.copy_from_slice(key_bytes);
                            let _ = tx.try_send(digest);
                        }
                    }
                    // Record successful DHT interaction for all connected peers.
                    for peer_id in self.swarm.connected_peers().cloned().collect::<Vec<_>>() {
                        self.routing_table.record_success(&peer_id);
                    }
                    if let Some(reply) = self.pending_puts.remove(&id) {
                        let _ = reply.send(Ok(()));
                    }
                }
                kad::QueryResult::PutRecord(Err(e)) => {
                    if let Some(reply) = self.pending_puts.remove(&id) {
                        let _ = reply.send(Err(MiasmaError::Dht(format!("{e:?}"))));
                    }
                }
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(pr))) => {
                    // Validate signature on retrieved records.
                    let value = pr.record.value;
                    let validated = if let Ok(signed) = bincode::deserialize::<SignedDhtRecord>(&value) {
                        if signed.verify_signature() {
                            // Record successful interaction for the peer that provided this record.
                            if let Some(peer) = pr.peer {
                                self.routing_table.record_success(&peer);
                            }
                            Some(value)
                        } else {
                            warn!("dht.record_rejected reason=invalid_signature key={:?}", pr.record.key);
                            // Record failure for the peer that sent a bad record.
                            if let Some(peer) = pr.peer {
                                self.routing_table.record_failure(&peer);
                            }
                            None
                        }
                    } else {
                        // Accept plain DhtRecord during transition period.
                        Some(value)
                    };

                    if let Some(valid_value) = validated {
                        if let Some((reply, _)) = self.pending_gets.remove(&id) {
                            let _ = reply.send(Ok(Some(valid_value)));
                        }
                    }
                    // If invalid, don't resolve — wait for more results or timeout.
                }
                kad::QueryResult::GetRecord(
                    Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }),
                )
                | kad::QueryResult::GetRecord(Err(_)) => {
                    if step.last {
                        if let Some((reply, cached)) = self.pending_gets.remove(&id) {
                            let _ = reply.send(Ok(cached));
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_share_exchange_event(
        &mut self,
        ev: request_response::Event<ShareFetchRequest, ShareFetchResponse>,
    ) {
        match ev {
            // Inbound request: serve from local store.
            request_response::Event::Message {
                message:
                    request_response::Message::Request { request, channel, .. },
                ..
            } => {
                let share = self.local_store.as_ref().and_then(|store| {
                    let prefix: [u8; 8] = request.mid_digest[..8].try_into().ok()?;
                    let candidates = store.search_by_mid_prefix(&prefix);
                    candidates.iter().find_map(|addr| {
                        store.get(addr).ok().and_then(|s| {
                            if s.slot_index == request.slot_index
                                && s.segment_index == request.segment_index
                            {
                                Some(s)
                            } else {
                                None
                            }
                        })
                    })
                });
                let response = ShareFetchResponse { share };
                let _ = self.swarm.behaviour_mut().share_exchange.send_response(channel, response);
            }
            // Outbound response received: resolve pending future.
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, response },
                ..
            } => {
                if let Some(reply) = self.pending_share_fetches.remove(&request_id) {
                    let _ = reply.send(Ok(response.share));
                }
            }
            request_response::Event::OutboundFailure { request_id, error, .. } => {
                warn!("Share fetch outbound failure: {error}");
                if let Some(reply) = self.pending_share_fetches.remove(&request_id) {
                    let _ = reply.send(Err(MiasmaError::Network(error.to_string())));
                }
            }
            request_response::Event::InboundFailure { error, .. } => {
                warn!("Share fetch inbound failure: {error}");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }
}

// ─── Swarm builder ────────────────────────────────────────────────────────────

fn build_swarm(
    keypair: Keypair,
    local_peer_id: PeerId,
    listen_addr: &str,
) -> Result<Swarm<MiasmaBehaviour>, MiasmaError> {
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| MiasmaError::Sss(format!("TCP init failed: {e}")))?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| MiasmaError::Sss(format!("relay client init failed: {e}")))?
        .with_behaviour(|key: &Keypair, relay_client| {
            let store = MemoryStore::new(local_peer_id);
            let kad_config = kad::Config::new(StreamProtocol::new("/miasma/kad/1.0.0"));
            let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);
            kademlia.set_mode(Some(kad::Mode::Server));

            let identify =
                identify::Behaviour::new(identify::Config::new("/miasma/id/1.0.0".into(), key.public()));

            let ping = ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(30)),
            );

            let autonat = autonat::Behaviour::new(
                local_peer_id,
                autonat::Config {
                    refresh_interval: Duration::from_secs(60),
                    retry_interval: Duration::from_secs(10),
                    ..Default::default()
                },
            );

            let dcutr = dcutr::Behaviour::new(local_peer_id);

            let share_exchange = request_response::Behaviour::<ShareCodec>::new(
                [(
                    StreamProtocol::new("/miasma/share/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            let admission = request_response::Behaviour::<AdmissionCodec>::new(
                [(
                    StreamProtocol::new("/miasma/admission/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            Ok(MiasmaBehaviour {
                kademlia,
                identify,
                ping,
                autonat,
                relay: relay_client,
                dcutr,
                share_exchange,
                admission,
            })
        })
        .map_err(|e| MiasmaError::Sss(format!("behaviour init failed: {e}")))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    let addr: Multiaddr = listen_addr
        .parse()
        .map_err(|e| MiasmaError::Sss(format!("invalid listen addr '{listen_addr}': {e}")))?;
    swarm
        .listen_on(addr)
        .map_err(|e| MiasmaError::Sss(format!("listen_on failed: {e}")))?;

    Ok(swarm)
}
