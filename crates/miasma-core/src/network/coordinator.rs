/// MiasmaCoordinator — ties node, store, DHT, and share exchange together.
///
/// # Roles
/// - `dissolve_and_publish`: dissolves content locally, publishes a `DhtRecord`
///   that lists this node as the holder of all generated shards.
/// - `retrieve_from_network`: queries the DHT for shard locations, fetches each
///   shard from its holder via the `/miasma/share/1.0.0` request-response
///   protocol, and reconstructs the plaintext.
///
/// # Wire path
/// ```text
/// dissolve_and_publish:
///   plaintext → dissolve() → shares (local store) + DhtRecord (Kademlia)
///
/// retrieve_from_network:
///   DhtRecord ← Kademlia GET
///   for each shard: ShareFetchRequest →(quic)→ holder node → ShareFetchResponse
///   shares → reconstruct() → plaintext
/// ```
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc;
use tracing::error;

use crate::{
    crypto::hash::ContentId,
    network::{
        dht::DirectDhtExecutor,
        node::{DhtHandle, MiasmaNode, ShareExchangeHandle, ShareFetchRequest},
        types::{DhtRecord, ShardLocation},
    },
    onion::share::OnionShareFetcher,
    pipeline::{dissolve, DissolutionParams},
    retrieval::{
        coordinator::RetrievalCoordinator,
        dht_source::DhtShareSource,
        transport_source::FallbackShareSource,
    },
    share::MiasmaShare,
    store::LocalShareStore,
    transport::payload::{
        Libp2pPayloadTransport, PayloadTransportSelector, TransportAttempt, TransportStats,
    },
    MiasmaError,
};

// ─── NetworkShareFetcher ──────────────────────────────────────────────────────

/// Fetches shards from remote peers via the share-exchange request-response
/// protocol, using the DHT to locate which peer holds each shard.
///
/// Caches the `DhtRecord` after the first lookup so that fetching all
/// `total_shards` shards for the same content triggers only one DHT GET.
pub struct NetworkShareFetcher {
    dht_handle: DhtHandle,
    share_handle: ShareExchangeHandle,
    /// Cache keyed by raw mid-digest to avoid redundant DHT GETs.
    record_cache: Mutex<HashMap<[u8; 32], DhtRecord>>,
}

impl NetworkShareFetcher {
    pub fn new(dht_handle: DhtHandle, share_handle: ShareExchangeHandle) -> Self {
        Self {
            dht_handle,
            share_handle,
            record_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Variant with a pre-seeded record cache entry.
    ///
    /// Allows integration tests to bypass the real DHT lookup and
    /// exercise only the share request-response transport layer.
    pub fn with_initial_record(
        dht_handle: DhtHandle,
        share_handle: ShareExchangeHandle,
        record: DhtRecord,
    ) -> Self {
        let mut cache = HashMap::new();
        cache.insert(record.mid_digest, record);
        Self {
            dht_handle,
            share_handle,
            record_cache: Mutex::new(cache),
        }
    }

    async fn get_cached_record(
        &self,
        mid_digest: [u8; 32],
    ) -> Result<Option<DhtRecord>, MiasmaError> {
        // Fast path: return cached record if available.
        {
            let cache = self.record_cache.lock().unwrap();
            if let Some(r) = cache.get(&mid_digest) {
                return Ok(Some(r.clone()));
            }
        }
        // Slow path: DHT lookup.
        match self.dht_handle.get_record(mid_digest).await? {
            Some(record) => {
                let mut cache = self.record_cache.lock().unwrap();
                cache.insert(mid_digest, record.clone());
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl OnionShareFetcher for NetworkShareFetcher {
    async fn fetch_share(
        &self,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        // 1. Find which peer holds this shard.
        let record = match self.get_cached_record(mid_digest).await? {
            Some(r) => r,
            None => return Ok(None),
        };

        let location = match record.locations.iter().find(|l| l.shard_index == slot_index) {
            Some(l) => l,
            None => return Ok(None),
        };

        // 2. Parse peer ID from location bytes.
        let peer_id = PeerId::from_bytes(&location.peer_id_bytes)
            .map_err(|e| MiasmaError::Network(format!("invalid peer_id in DhtRecord: {e}")))?;

        // 3. Send request-response to the holder.
        let request = ShareFetchRequest { mid_digest, slot_index, segment_index };
        self.share_handle.fetch(peer_id, location.addrs.clone(), request).await
    }
}

// ─── MiasmaCoordinator ────────────────────────────────────────────────────────

/// High-level coordinator: owns the node handle, store, and channel handles.
pub struct MiasmaCoordinator {
    store: Arc<LocalShareStore>,
    dht_handle: DhtHandle,
    share_handle: ShareExchangeHandle,
    shutdown_tx: mpsc::Sender<()>,
    /// This node's libp2p PeerId, embedded in published `DhtRecord`s.
    peer_id: PeerId,
    /// Announced listen addresses included in `DhtRecord.locations`.
    listen_addrs: Vec<String>,
    /// Payload transport selector for multi-transport fallback retrieval.
    transport_selector: Arc<PayloadTransportSelector>,
}

impl MiasmaCoordinator {
    /// Spawn the node's event loop and return a coordinator wrapping its handles.
    ///
    /// `listen_addrs` — the multiaddr strings that remote peers can use to reach
    /// this node (e.g. `"/ip4/1.2.3.4/udp/4001/quic-v1"`). These are written into
    /// the `DhtRecord` so that retrievers know where to send share-fetch requests.
    pub async fn start(
        mut node: MiasmaNode,
        store: Arc<LocalShareStore>,
        listen_addrs: Vec<String>,
    ) -> Self {
        let peer_id = node.local_peer_id;
        let dht_handle = node.dht_handle();
        let share_handle = node.share_exchange_handle();
        let shutdown_tx = node.shutdown_handle();

        // Give the node a reference to the store so it can serve inbound requests.
        node.set_store(store.clone());

        tokio::spawn(async move {
            if let Err(e) = node.run().await {
                error!("MiasmaNode event loop error: {e}");
            }
        });

        // Build the payload transport selector with the default fallback chain.
        // Phase 1: only libp2p direct. Phase 2.1 adds WSS + obfuscated.
        let transport_selector = Arc::new(PayloadTransportSelector::new(vec![
            Box::new(Libp2pPayloadTransport::new(
                share_handle.clone(),
                dht_handle.clone(),
            )),
        ]));

        Self { store, dht_handle, share_handle, shutdown_tx, peer_id, listen_addrs, transport_selector }
    }

    /// Register a bootstrap peer and dial it from within the running event loop.
    ///
    /// **Must be called after `start()`.**  Dialing from inside the event loop
    /// ensures the remote TCP socket is already accepting when the SYN arrives,
    /// avoiding the ECONNREFUSED race seen with pre-start `add_bootstrap_peer`.
    pub async fn add_bootstrap_peer(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Result<(), MiasmaError> {
        self.dht_handle.add_bootstrap_peer(peer_id, addr).await
    }

    /// Trigger Kademlia FIND_NODE bootstrap.
    ///
    /// Call after `add_bootstrap_peer`; sleep ~1–3 s before issuing DHT
    /// PUT/GET so Kademlia has time to populate both routing tables.
    pub async fn bootstrap_dht(&self) -> Result<(), MiasmaError> {
        self.dht_handle.bootstrap().await
    }

    /// Send a shutdown signal to the background node task.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(()).await;
    }

    /// Return the number of currently connected peers.
    pub async fn peer_count(&self) -> Result<usize, MiasmaError> {
        self.dht_handle.peer_count().await
    }

    /// Publish a pre-built `DhtRecord` to Kademlia.
    ///
    /// Used by the daemon's replication retry loop to re-announce content
    /// without re-dissolving it.
    pub async fn publish_record(&self, record: DhtRecord) -> Result<(), MiasmaError> {
        self.dht_handle.put(record).await
    }

    /// The listen addresses announced by this node (e.g. written into DhtRecords).
    pub fn listen_addrs(&self) -> &[String] {
        &self.listen_addrs
    }

    /// This node's libp2p peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Dissolve `data` into shares, store them locally, and publish the
    /// `DhtRecord` that announces this node as the shard holder.
    pub async fn dissolve_and_publish(
        &self,
        data: &[u8],
        params: DissolutionParams,
    ) -> Result<ContentId, MiasmaError> {
        let (mid, shares) = dissolve(data, params)?;

        // Store shares in the local encrypted share store.
        for share in &shares {
            self.store.put(share)?;
        }

        // Build shard-location entries: this node holds all shards.
        let peer_bytes = self.peer_id.to_bytes();
        let locations: Vec<ShardLocation> = shares
            .iter()
            .map(|s| ShardLocation {
                peer_id_bytes: peer_bytes.clone(),
                shard_index: s.slot_index,
                addrs: self.listen_addrs.clone(),
            })
            .collect();

        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations,
            published_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Publish to the real Kademlia DHT.
        self.dht_handle.put(record).await?;

        Ok(mid)
    }

    /// Retrieve content by MID from the P2P network using the transport
    /// fallback engine.
    ///
    /// Queries the DHT for the `DhtRecord`, then fetches `≥k` shards using
    /// the configured transport fallback chain (libp2p → TCP → WSS → relay),
    /// and reconstructs the plaintext.
    ///
    /// Returns `(plaintext, transport_attempts)` so the caller can observe
    /// which transports were tried and which succeeded.
    pub async fn retrieve_from_network(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
    ) -> Result<Vec<u8>, MiasmaError> {
        let dht_exec = DirectDhtExecutor::new(self.dht_handle.clone());
        let source = FallbackShareSource::new(
            dht_exec,
            self.transport_selector.clone(),
        );
        RetrievalCoordinator::new(source).retrieve(mid, params).await
    }

    /// Like `retrieve_from_network` but also returns transport attempt diagnostics.
    pub async fn retrieve_from_network_with_diagnostics(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
    ) -> Result<(Vec<u8>, Vec<TransportAttempt>), MiasmaError> {
        let dht_exec = DirectDhtExecutor::new(self.dht_handle.clone());
        let source = FallbackShareSource::new(
            dht_exec,
            self.transport_selector.clone(),
        );
        let result = RetrievalCoordinator::new(source).retrieve(mid, params).await;
        // Note: drain_attempts is called after retrieve, capturing all attempts.
        // We can't easily get the source back from RetrievalCoordinator,
        // so transport stats are available via self.transport_stats() instead.
        result.map(|data| (data, vec![]))
    }

    /// Return a snapshot of payload transport statistics.
    pub fn transport_stats(&self) -> &TransportStats {
        self.transport_selector.stats()
    }

    /// Retrieve using the legacy path (DhtShareSource + NetworkShareFetcher).
    ///
    /// Kept for backward compatibility during migration; will be removed
    /// once the fallback engine is fully validated.
    pub async fn retrieve_from_network_legacy(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
    ) -> Result<Vec<u8>, MiasmaError> {
        let dht_exec = DirectDhtExecutor::new(self.dht_handle.clone());
        let share_fetcher =
            NetworkShareFetcher::new(self.dht_handle.clone(), self.share_handle.clone());
        let source = DhtShareSource::new(dht_exec, share_fetcher);
        RetrievalCoordinator::new(source).retrieve(mid, params).await
    }
}
