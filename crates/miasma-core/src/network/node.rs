/// Miasma libp2p node — Phase 2 P2P wiring.
///
/// Transport: TCP + QUIC for local loopback testing and production paths
/// DHT: Kademlia via `DhtHandle` / `OnionAwareDhtExecutor` (ADR-002)
/// Share exchange: `/miasma/share/1.0.0` request-response protocol
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

// ─── ShareCodec ───────────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/share/1.0.0`.
#[derive(Clone, Default)]
pub struct ShareCodec;

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
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| MiasmaError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
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
    /// Local share store — used to serve inbound `ShareFetchRequest`s.
    local_store: Option<Arc<LocalShareStore>>,
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
        zeroize::Zeroize::zeroize(&mut signing_bytes);

        let local_peer_id = PeerId::from(keypair.public());
        info!("Miasma node: peer_id={local_peer_id}, type={node_type:?}");

        let swarm = build_swarm(keypair, local_peer_id, listen_addr)?;

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
            local_store: None,
        })
    }

    /// Attach a local share store so this node can serve inbound shard requests.
    pub fn set_store(&mut self, store: Arc<LocalShareStore>) {
        self.local_store = Some(store);
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
                let record = kad::Record {
                    key: kad::RecordKey::new(&key),
                    value,
                    publisher: None,
                    expires: None,
                };
                // Always store locally first so remote peers can retrieve the
                // record via GET even if no other peers are reachable yet.
                // This is critical for the 2-node local flow: Node A publishes
                // before Node B connects; B's GET_VALUE query to A must find it.
                let _ = self.swarm.behaviour_mut().kademlia.store_mut().put(record.clone());
                // Fire-and-forget network replication: reply success immediately.
                // Quorum failure (no remote peers) is non-fatal since local
                // storage guarantees serving inbound GET_VALUE queries.
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
        }
    }

    fn handle_share_command(&mut self, cmd: ShareCommand) {
        let ShareCommand { peer_id, addrs, request, reply } = cmd;

        // Register addresses with both Kademlia (routing) and share_exchange
        // (address book used by request_response when it dials the peer).
        // Adding to share_exchange is critical: send_request emits
        // ToSwarm::Dial{DialOpts::peer_id(peer).build()} which consults
        // handle_pending_outbound_connection — if no address is registered
        // there, the dial fails immediately with OutboundFailure::DialFailure.
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
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {address}");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connected: {peer_id}");
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                debug!("Disconnected: {peer_id} ({cause:?})");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                for addr in &info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
                if let Some(first_addr) = info.listen_addrs.first() {
                    self.swarm
                        .behaviour_mut()
                        .autonat
                        .add_server(peer_id, Some(first_addr.clone()));
                }
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Kademlia(ev)) => {
                self.handle_kad_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::ShareExchange(ev)) => {
                self.handle_share_exchange_event(ev);
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

    fn handle_kad_event(&mut self, ev: kad::Event) {
        match ev {
            kad::Event::OutboundQueryProgressed { id, result, step, .. } => match result {
                kad::QueryResult::PutRecord(Ok(_)) => {
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
                    // Resolve on first found record (don't wait for more).
                    if let Some((reply, _)) = self.pending_gets.remove(&id) {
                        let _ = reply.send(Ok(Some(pr.record.value)));
                    }
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

            Ok(MiasmaBehaviour {
                kademlia,
                identify,
                ping,
                autonat,
                relay: relay_client,
                dcutr,
                share_exchange,
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
