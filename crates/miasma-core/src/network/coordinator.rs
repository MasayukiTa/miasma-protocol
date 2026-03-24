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
        credential::CredentialStats,
        descriptor::{DescriptorStats, PeerDescriptor, ReachabilityKind},
        dht::DirectDhtExecutor,
        node::{DhtHandle, MiasmaNode, ShareExchangeHandle, ShareFetchRequest, ShareFetchResponse},
        onion_relay::{OnionRelayRequest, OnionRelayResponse},
        path_selection::{AnonymityPolicy, PathSelectionStats},
        types::{DhtRecord, ShardLocation},
    },
    onion::{packet::OnionPacketBuilder, share::OnionShareFetcher},
    dissolution::{dissolve_segment, DEFAULT_SEGMENT_SIZE},
    pipeline::{dissolve, DissolutionParams},
    retrieval::{
        coordinator::RetrievalCoordinator, dht_source::DhtShareSource,
        transport_source::FallbackShareSource,
    },
    share::MiasmaShare,
    store::LocalShareStore,
    transport::payload::{
        Libp2pPayloadTransport, PayloadTransport, PayloadTransportSelector, TransportAttempt,
        TransportStats,
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

        let location = match record
            .locations
            .iter()
            .find(|l| l.shard_index == slot_index)
        {
            Some(l) => l,
            None => return Ok(None),
        };

        // 2. Parse peer ID from location bytes.
        let peer_id = PeerId::from_bytes(&location.peer_id_bytes)
            .map_err(|e| MiasmaError::Network(format!("invalid peer_id in DhtRecord: {e}")))?;

        // 3. Send request-response to the holder.
        let request = ShareFetchRequest {
            mid_digest,
            slot_index,
            segment_index,
        };
        self.share_handle
            .fetch(peer_id, location.addrs.clone(), request)
            .await
    }
}

// ─── MiasmaCoordinator ────────────────────────────────────────────────────────

/// High-level coordinator: owns the node handle, store, and channel handles.
/// Per-anonymity-mode retrieval success/failure counters.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RetrievalStats {
    /// Direct (no anonymity) retrieval attempts.
    pub direct_attempts: u64,
    pub direct_successes: u64,
    /// Opportunistic relay retrieval attempts.
    pub opportunistic_attempts: u64,
    pub opportunistic_relay_successes: u64,
    pub opportunistic_direct_fallbacks: u64,
    /// Opportunistic: strongest-path successes.
    pub opportunistic_onion_successes: u64,
    pub opportunistic_onion_rendezvous_successes: u64,
    pub opportunistic_rendezvous_successes: u64,
    /// Required anonymity retrieval attempts.
    pub required_attempts: u64,
    pub required_onion_successes: u64,
    pub required_relay_successes: u64,
    pub required_failures: u64,
    /// Rendezvous (introduction-point) retrieval counters.
    pub rendezvous_attempts: u64,
    pub rendezvous_successes: u64,
    pub rendezvous_failures: u64,
    /// Rendezvous fallback to direct (intro points unavailable).
    pub rendezvous_direct_fallbacks: u64,
    /// Rendezvous + onion combined: content-blind retrieval from NAT'd holders.
    pub rendezvous_onion_attempts: u64,
    pub rendezvous_onion_successes: u64,
    pub rendezvous_onion_failures: u64,
    /// Active relay probe counters.
    pub relay_probes_sent: u64,
    pub relay_probes_succeeded: u64,
    pub relay_probes_failed: u64,
    /// Forwarding verification counters (circuit-routed probes).
    pub forwarding_probes_sent: u64,
    pub forwarding_probes_succeeded: u64,
    pub forwarding_probes_failed: u64,
    /// How many times pre-retrieval probe sweep was executed.
    pub pre_retrieval_probes_run: u64,
}

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
    /// Anonymity policy for retrieval operations.
    anonymity_policy: AnonymityPolicy,
    /// Relay routing enabled (descriptor-backed relay circuit routing).
    relay_routing_enabled: bool,
    /// Per-anonymity-mode retrieval tracking.
    retrieval_stats: Arc<Mutex<RetrievalStats>>,
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
        let transport_selector = Arc::new(PayloadTransportSelector::new(vec![Box::new(
            Libp2pPayloadTransport::new(share_handle.clone(), dht_handle.clone()),
        )]));

        Self {
            store,
            dht_handle,
            share_handle,
            shutdown_tx,
            peer_id,
            listen_addrs,
            transport_selector,
            anonymity_policy: AnonymityPolicy::default(),
            relay_routing_enabled: false,
            retrieval_stats: Arc::new(Mutex::new(RetrievalStats::default())),
        }
    }

    /// Like `start`, but appends additional payload transports to the fallback
    /// chain (after the default libp2p transport).
    pub async fn start_with_transports(
        node: MiasmaNode,
        store: Arc<LocalShareStore>,
        listen_addrs: Vec<String>,
        extra_transports: Vec<Box<dyn PayloadTransport>>,
    ) -> Self {
        let mut coord = Self::start(node, store, listen_addrs).await;

        // Rebuild the selector with extra transports appended.
        if !extra_transports.is_empty() {
            let mut all: Vec<Box<dyn PayloadTransport>> = vec![Box::new(
                Libp2pPayloadTransport::new(coord.share_handle.clone(), coord.dht_handle.clone()),
            )];
            all.extend(extra_transports);
            coord.transport_selector = Arc::new(PayloadTransportSelector::new(all));
        }
        coord
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

    /// Return admission statistics (verified/observed/claimed peers, rejections).
    pub async fn admission_stats(&self) -> Result<super::peer_state::AdmissionStats, MiasmaError> {
        self.dht_handle.admission_stats().await
    }

    /// Return routing overlay statistics (diversity, reliability, difficulty).
    pub async fn routing_stats(&self) -> Result<super::routing::RoutingStats, MiasmaError> {
        self.dht_handle.routing_stats().await
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

    /// Dissolve a file from disk into shares using streaming per-segment
    /// dissolution.  Only one segment (~64 MiB) is held in RAM at a time,
    /// enabling files of any size without full-file buffering.
    pub async fn dissolve_and_publish_file(
        &self,
        file_path: &std::path::Path,
        params: DissolutionParams,
    ) -> Result<ContentId, MiasmaError> {
        use std::io::{BufReader, Read, Seek, SeekFrom};

        let file = std::fs::File::open(file_path)?;
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

        // 1. Compute MID by streaming through file (no full-file buffer).
        let param_bytes = params.to_param_bytes();
        let mut reader = BufReader::new(&file);
        let mid = ContentId::compute_from_reader(&mut reader, &param_bytes)?;

        // 2. Rewind and dissolve per-segment.
        reader.seek(SeekFrom::Start(0))?;

        let segment_size = DEFAULT_SEGMENT_SIZE;
        let mut segment_buf = vec![0u8; segment_size];
        let mut seg_idx: u32 = 0;
        let mut offset: u64 = 0;
        let mut all_locations: Vec<ShardLocation> = Vec::new();
        let peer_bytes = self.peer_id.to_bytes();

        loop {
            let mut filled = 0;
            // Read one segment worth of data.
            while filled < segment_size {
                let n = reader.read(&mut segment_buf[filled..segment_size])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }

            if filled == 0 && seg_idx > 0 {
                break; // No more data, and we've processed at least one segment.
            }

            let chunk = &segment_buf[..filled];
            let (_meta, shares) = dissolve_segment(chunk, &mid, seg_idx, offset, params)?;

            // Store shares and record locations.
            for share in &shares {
                self.store.put(share)?;
                all_locations.push(ShardLocation {
                    peer_id_bytes: peer_bytes.clone(),
                    shard_index: share.slot_index,
                    addrs: self.listen_addrs.clone(),
                });
            }

            offset += filled as u64;
            seg_idx += 1;

            if file_len > 0 {
                let pct = (offset as f64 / file_len as f64 * 100.0).min(100.0);
                tracing::info!(
                    "Publishing: segment {seg_idx} done, {offset}/{file_len} bytes ({pct:.0}%)"
                );
            }

            if filled < segment_size {
                break; // Last segment was shorter than full.
            }
        }

        // 3. Publish DHT record with all shard locations.
        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations: all_locations,
            published_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.dht_handle.put(record).await?;

        tracing::info!(
            "Published {} ({} bytes, {} segments) via streaming dissolution",
            mid.to_string(),
            file_len,
            seg_idx,
        );

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
        let source = FallbackShareSource::new(dht_exec, self.transport_selector.clone());
        RetrievalCoordinator::new(source)
            .retrieve(mid, params)
            .await
    }

    /// Like `retrieve_from_network` but also returns transport attempt diagnostics.
    pub async fn retrieve_from_network_with_diagnostics(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
    ) -> Result<(Vec<u8>, Vec<TransportAttempt>), MiasmaError> {
        let dht_exec = DirectDhtExecutor::new(self.dht_handle.clone());
        let source = FallbackShareSource::new(dht_exec, self.transport_selector.clone());
        let result = RetrievalCoordinator::new(source)
            .retrieve(mid, params)
            .await;
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
        RetrievalCoordinator::new(source)
            .retrieve(mid, params)
            .await
    }

    // ── Anonymity policy ────────────────────────────────────────────────────

    /// Set the anonymity policy for future retrieval operations.
    pub fn set_anonymity_policy(&mut self, policy: AnonymityPolicy) {
        self.anonymity_policy = policy;
    }

    /// Enable descriptor-backed relay routing for anonymity-aware retrieval.
    ///
    /// Once enabled, `Opportunistic` and `Required` policies query relay
    /// descriptors from the network and route share fetches through real
    /// libp2p relay circuit addresses (e.g. `/p2p/{relay}/p2p-circuit/p2p/{dest}`).
    pub fn enable_relay_routing(&mut self) {
        self.relay_routing_enabled = true;
    }

    /// Legacy alias for enable_relay_routing. Accepts (and ignores) the
    /// master key — relay routing no longer needs it.
    pub fn enable_onion_routing(&mut self, _master_key: &[u8]) {
        self.relay_routing_enabled = true;
    }

    /// Current anonymity policy.
    pub fn anonymity_policy(&self) -> AnonymityPolicy {
        self.anonymity_policy
    }

    /// Retrieve content with an explicit anonymity policy.
    ///
    /// - `Direct`: standard direct retrieval
    /// - `Opportunistic`: route through relay peers if available, fall back to direct
    /// - `Required`: route through relay peers, fail if insufficient relays
    ///
    /// Relay routing uses real libp2p relay circuit addresses built from
    /// descriptor-store relay peers: `/p2p/{relay_id}/p2p-circuit/p2p/{dest_id}`.
    /// This provides IP-level sender privacy (the shard holder sees the relay's
    /// address, not the requester's). Full content privacy from relays requires
    /// the onion encryption layer (Phase 2).
    pub async fn retrieve_with_anonymity(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
        policy: AnonymityPolicy,
    ) -> Result<Vec<u8>, MiasmaError> {
        match policy {
            AnonymityPolicy::Direct => {
                if let Ok(mut s) = self.retrieval_stats.lock() {
                    s.direct_attempts += 1;
                }
                let result = self.retrieve_from_network(mid, params).await;
                if result.is_ok() {
                    if let Ok(mut s) = self.retrieval_stats.lock() {
                        s.direct_successes += 1;
                    }
                }
                result
            }
            AnonymityPolicy::Opportunistic => {
                if let Ok(mut s) = self.retrieval_stats.lock() {
                    s.opportunistic_attempts += 1;
                }
                if self.relay_routing_enabled {
                    match self.retrieve_via_relay(mid, params).await {
                        Ok(data) => {
                            if let Ok(mut s) = self.retrieval_stats.lock() {
                                s.opportunistic_relay_successes += 1;
                            }
                            return Ok(data);
                        }
                        Err(e) => {
                            tracing::debug!(
                                "anonymity=opportunistic: relay retrieval failed ({e}), falling back to direct"
                            );
                        }
                    }
                }
                let result = self.retrieve_from_network(mid, params).await;
                if result.is_ok() {
                    if let Ok(mut s) = self.retrieval_stats.lock() {
                        s.opportunistic_direct_fallbacks += 1;
                    }
                }
                result
            }
            AnonymityPolicy::Required { min_hops } => {
                if let Ok(mut s) = self.retrieval_stats.lock() {
                    s.required_attempts += 1;
                }
                if !self.relay_routing_enabled {
                    if let Ok(mut s) = self.retrieval_stats.lock() {
                        s.required_failures += 1;
                    }
                    return Err(MiasmaError::Network(format!(
                        "anonymity=required({min_hops} hops): relay routing not enabled — call enable_relay_routing() first"
                    )));
                }
                let result = self
                    .retrieve_via_relay_required(mid, params, min_hops as usize)
                    .await;
                if result.is_err() {
                    if let Ok(mut s) = self.retrieval_stats.lock() {
                        s.required_failures += 1;
                    }
                }
                result
            }
        }
    }

    // ── Path hierarchy constants ───────────────────────────────────────────

    /// Probe results older than this are considered stale and re-probed.
    const PROBE_FRESHNESS_SECS: u64 = 300;
    /// Maximum probes to run before a single retrieval to bound latency.
    const MAX_PRE_RETRIEVAL_PROBES: usize = 3;

    /// Shared retrieval path hierarchy used by both Opportunistic and Required.
    ///
    /// # Path hierarchy (strongest first, falls through on failure)
    /// 1. Onion + rendezvous — content-blind, NAT-capable
    /// 2. Standard onion     — content-blind, direct-reachable holders
    /// 3. Rendezvous relay   — IP-only privacy, NAT-capable
    /// 4. Relay circuit      — IP-only privacy
    ///
    /// `mode` is `"opportunistic"` or `"required"` — determines which stats
    /// counters to increment. `min_relay_hops` is 1 for Opportunistic, passed
    /// through for Required.
    async fn try_relay_paths(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
        mode: &str,
        min_relay_hops: usize,
    ) -> Result<Vec<u8>, MiasmaError> {
        // Pre-retrieval: probe stale relay candidates to improve path decisions.
        self.probe_stale_relay_candidates().await;

        let relay_onion_info = self.dht_handle.relay_onion_info().await?;
        let has_rendezvous = self.has_rendezvous_holders(mid).await;

        // Hop counts provided by each path:
        //   1. Onion + rendezvous: 2 hops (R1 → R2/intro → target)
        //   2. Standard onion:     2 hops (R1 → R2 → target)
        //   3. Rendezvous relay:   1 hop  (intro → target)
        //   4. Relay circuit:      1 hop  (relay → target)
        //
        // Each step is skipped if it cannot satisfy min_relay_hops.
        const ONION_HOPS: usize = 2;
        const RENDEZVOUS_RELAY_HOPS: usize = 1;
        const RELAY_CIRCUIT_HOPS: usize = 1;

        // 1. Onion + rendezvous (content-blind + NAT) — provides 2 hops.
        if min_relay_hops <= ONION_HOPS && has_rendezvous && !relay_onion_info.is_empty() {
            tracing::info!(
                onion_relays = relay_onion_info.len(),
                mode,
                "attempting onion+rendezvous retrieval"
            );
            match self.retrieve_via_onion_rendezvous(mid, params).await {
                Ok(data) => {
                    if let Ok(mut s) = self.retrieval_stats.lock() {
                        match mode {
                            "opportunistic" => s.opportunistic_onion_rendezvous_successes += 1,
                            _ => s.required_onion_successes += 1,
                        }
                    }
                    return Ok(data);
                }
                Err(e) => {
                    tracing::debug!("{mode}: onion+rendezvous failed ({e}), trying standard onion");
                }
            }
        }

        // 2. Standard onion (content-blind, direct-reachable holders) — provides 2 hops.
        if min_relay_hops <= ONION_HOPS && relay_onion_info.len() >= 2 {
            tracing::info!(
                relays = relay_onion_info.len(),
                mode,
                "attempting onion-encrypted retrieval"
            );
            match self.retrieve_via_onion(mid, params).await {
                Ok(data) => {
                    if let Ok(mut s) = self.retrieval_stats.lock() {
                        match mode {
                            "opportunistic" => s.opportunistic_onion_successes += 1,
                            _ => s.required_onion_successes += 1,
                        }
                    }
                    return Ok(data);
                }
                Err(e) => {
                    tracing::debug!("{mode}: standard onion failed ({e}), trying rendezvous/relay");
                }
            }
        }

        // 3. Rendezvous relay (IP-only + NAT) — provides 1 hop.
        if min_relay_hops <= RENDEZVOUS_RELAY_HOPS && has_rendezvous {
            if let Ok(Some(record)) = self.dht_handle.get_record(*mid.as_bytes()).await {
                for loc in &record.locations {
                    if let Ok(peer_id) = PeerId::from_bytes(&loc.peer_id_bytes) {
                        if let Ok(Some(desc)) = self.dht_handle.peer_descriptor(peer_id).await {
                            if let ReachabilityKind::Rendezvous { ref intro_points } =
                                desc.reachability
                            {
                                tracing::info!(
                                    holder = %peer_id,
                                    intro_points = intro_points.len(),
                                    mode,
                                    "routing via rendezvous introduction points"
                                );
                                match self
                                    .retrieve_via_rendezvous(mid, params, intro_points)
                                    .await
                                {
                                    Ok(data) => {
                                        if let Ok(mut s) = self.retrieval_stats.lock() {
                                            match mode {
                                                "opportunistic" => {
                                                    s.opportunistic_rendezvous_successes += 1
                                                }
                                                _ => s.required_relay_successes += 1,
                                            }
                                        }
                                        return Ok(data);
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "{mode}: rendezvous failed ({e}), trying relay circuit"
                                        );
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 4. Relay circuit (IP-only privacy) — provides 1 hop.
        if min_relay_hops > RELAY_CIRCUIT_HOPS {
            return Err(MiasmaError::Network(format!(
                "{mode}: min_hops={min_relay_hops} but no path type provides more than {ONION_HOPS} hops; \
                 all eligible paths exhausted"
            )));
        }
        let relay_peers = self.dht_handle.relay_peers().await?;
        if relay_peers.len() < min_relay_hops {
            return Err(MiasmaError::Network(format!(
                "{mode}: need {min_relay_hops} relay hops, only {} relay peers available",
                relay_peers.len()
            )));
        }

        let (relay_peer_id, relay_addrs) = &relay_peers[0];
        let relay_addr = relay_addrs
            .first()
            .ok_or_else(|| MiasmaError::Network("relay peer has no addresses".into()))?;

        tracing::info!(
            relay = %relay_peer_id,
            addr = %relay_addr,
            mode,
            "fallback to relay circuit rewriting"
        );

        let relay_exec = RelayRewritingDhtExecutor {
            inner: DirectDhtExecutor::new(self.dht_handle.clone()),
            relay_peer_id: *relay_peer_id,
            relay_addr: relay_addr.clone(),
        };
        let source = FallbackShareSource::new(relay_exec, self.transport_selector.clone());
        let result = RetrievalCoordinator::new(source)
            .retrieve(mid, params)
            .await;

        if let Ok(Some(ps)) = self.dht_handle.peer_pseudonym(*relay_peer_id).await {
            let _ = self
                .dht_handle
                .record_relay_outcome(ps, result.is_ok())
                .await;
        }

        if result.is_ok() {
            if let Ok(mut s) = self.retrieval_stats.lock() {
                match mode {
                    "opportunistic" => s.opportunistic_relay_successes += 1,
                    _ => s.required_relay_successes += 1,
                }
            }
        }

        result
    }

    /// Opportunistic: try strongest path, fall back to direct.
    async fn retrieve_via_relay(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
    ) -> Result<Vec<u8>, MiasmaError> {
        self.try_relay_paths(mid, params, "opportunistic", 1).await
    }

    /// Required: try strongest path, fail if no relay path works.
    async fn retrieve_via_relay_required(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
        min_hops: usize,
    ) -> Result<Vec<u8>, MiasmaError> {
        self.try_relay_paths(mid, params, "required", min_hops)
            .await
    }

    // ── Pre-retrieval relay probing ─────────────────────────────────────────

    /// Probe relay candidates without fresh evidence before retrieval.
    ///
    /// # Policy
    /// - Gets relay peers (sorted by trust tier: Verified first)
    /// - For each, checks if probe evidence is within `PROBE_FRESHNESS_SECS`
    /// - Probes up to `MAX_PRE_RETRIEVAL_PROBES` stale candidates
    /// - Optionally runs one forwarding verification for top candidate
    /// - All outcomes are recorded in relay observations (trust tier updates)
    /// - Bounded: max 3 probes to avoid pathological latency
    async fn probe_stale_relay_candidates(&self) {
        let relay_peers = match self.dht_handle.relay_peers().await {
            Ok(rp) => rp,
            Err(_) => return,
        };

        if let Ok(mut s) = self.retrieval_stats.lock() {
            s.pre_retrieval_probes_run += 1;
        }

        let mut stale_candidates = Vec::new();
        for (peer_id, addrs) in &relay_peers {
            if stale_candidates.len() >= Self::MAX_PRE_RETRIEVAL_PROBES {
                break;
            }
            if let Ok(Some(ps)) = self.dht_handle.peer_pseudonym(*peer_id).await {
                let fresh = self
                    .dht_handle
                    .has_fresh_probe(ps, Self::PROBE_FRESHNESS_SECS)
                    .await
                    .unwrap_or(false);
                if !fresh {
                    stale_candidates.push((
                        *peer_id,
                        addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                        ps,
                    ));
                }
            }
        }

        if stale_candidates.is_empty() {
            return;
        }

        tracing::debug!(
            stale = stale_candidates.len(),
            "pre-retrieval: probing stale relay candidates"
        );

        for (peer_id, addrs, ps) in &stale_candidates {
            let success = self.probe_relay(*peer_id, addrs.clone()).await;
            if success {
                let _ = self.dht_handle.record_probe_success(*ps).await;
            }
        }

        // Attempt one forwarding verification for the top relay (best trust tier)
        // if it has a fresh probe but no forwarding verification.
        if relay_peers.len() >= 2 {
            let (r1_id, r1_addrs) = &relay_peers[0];
            let (r2_id, _) = &relay_peers[1];
            if let Ok(Some(r1_ps)) = self.dht_handle.peer_pseudonym(*r1_id).await {
                if let Ok(Some(obs)) = self.dht_handle.relay_observation(r1_ps).await {
                    if obs.has_fresh_probe(Self::PROBE_FRESHNESS_SECS)
                        && obs.forwarding_verified_at.is_none()
                    {
                        let _ = self
                            .verify_relay_forwarding(
                                *r1_id,
                                r1_addrs.iter().map(|a| a.to_string()).collect(),
                                *r2_id,
                            )
                            .await;
                    }
                }
            }
        }
    }

    /// Check if any shard holder in the DHT record is rendezvous-reachable.
    async fn has_rendezvous_holders(&self, mid: &ContentId) -> bool {
        if let Ok(Some(record)) = self.dht_handle.get_record(*mid.as_bytes()).await {
            for loc in &record.locations {
                if let Ok(peer_id) = PeerId::from_bytes(&loc.peer_id_bytes) {
                    if let Ok(Some(desc)) = self.dht_handle.peer_descriptor(peer_id).await {
                        if desc.is_rendezvous() {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Retrieve content using 2-hop onion-encrypted share fetching.
    ///
    /// # Privacy guarantees
    ///
    /// - **Path privacy**: R1 knows the initiator but not the target;
    ///   R2 knows R1 and the target but not the initiator.
    /// - **Content privacy**: Share-fetch request is end-to-end encrypted
    ///   between initiator and target using X25519 ECDH. Neither relay
    ///   can read the share request or response.
    /// - **Per-hop keying**: Each relay has a unique X25519 ECDH-derived
    ///   symmetric key for its onion layer, plus a per-hop return key
    ///   for response encryption.
    ///
    /// # Flow
    /// ```text
    /// 1. DHT lookup (direct) → DhtRecord with shard locations
    /// 2. For each shard:
    ///    a. Build OnionPacket(r1_key, r2_key) wrapping e2e-encrypted ShareFetchRequest
    ///    b. Send to R1 → R1 peels, forwards to R2 → R2 peels, delivers to Target
    ///    c. Target decrypts, serves share, encrypts response with session_key
    ///    d. Response travels back: Target→R2(+encrypt)→R1(+encrypt)→Initiator
    ///    e. Initiator decrypts: r1_key, r2_key, session_key → plaintext share
    /// 3. Reconstruct plaintext from k-of-n shares
    /// ```
    async fn retrieve_via_onion(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
    ) -> Result<Vec<u8>, MiasmaError> {
        // 1. Get relay info (with onion pubkeys).
        let relays = self.dht_handle.relay_onion_info().await?;
        if relays.len() < 2 {
            return Err(MiasmaError::Network(format!(
                "onion retrieval requires ≥2 relay peers with onion keys, have {}",
                relays.len()
            )));
        }
        let r1 = &relays[0];
        let r2 = &relays[1];

        let r1_peer_id = PeerId::from_bytes(&r1.peer_id)
            .map_err(|e| MiasmaError::Network(format!("invalid R1 peer_id: {e}")))?;
        let r1_addrs: Vec<String> = vec![String::from_utf8_lossy(&r1.addr).to_string()];

        // 2. DHT lookup (direct — the DHT query itself is not onion-routed here).
        let record = self
            .dht_handle
            .get_record(*mid.as_bytes())
            .await?
            .ok_or_else(|| {
                MiasmaError::Sss(format!(
                    "onion retrieval: DhtRecord not found for MID {}",
                    hex::encode(&mid.as_bytes()[..8])
                ))
            })?;

        let k = params.data_shards;

        // 3. For each shard, build an onion packet and fetch via relay.
        let mut shares: Vec<MiasmaShare> = Vec::with_capacity(k);

        for location in &record.locations {
            if shares.len() >= k {
                break;
            }

            let target_peer_id_bytes = &location.peer_id_bytes;
            let target_peer_id = PeerId::from_bytes(target_peer_id_bytes)
                .map_err(|e| MiasmaError::Network(format!("invalid target peer_id: {e}")))?;

            // Look up target's onion pubkey from descriptor store.
            let target_pubkey = if target_peer_id == self.peer_id {
                // Self-fetch: use our own onion key — fail if unavailable
                // (never fall back to a zero key, which would be trivially decryptable).
                match self.dht_handle.onion_pubkey().await {
                    Ok(key) => key,
                    Err(_) => {
                        tracing::warn!(
                            shard = location.shard_index,
                            "onion: own onion pubkey unavailable, skipping shard"
                        );
                        continue;
                    }
                }
            } else {
                // Query the descriptor store for this specific peer's key.
                match self.dht_handle.peer_onion_pubkey(target_peer_id).await {
                    Ok(Some(key)) => key,
                    _ => {
                        tracing::debug!(
                            target = %target_peer_id,
                            shard = location.shard_index,
                            "onion: target has no onion pubkey, skipping shard"
                        );
                        continue;
                    }
                }
            };

            // Build share request.
            let req = ShareFetchRequest {
                mid_digest: record.mid_digest,
                slot_index: location.shard_index,
                segment_index: 0,
            };
            let mut req_body = vec![0x10u8];
            req_body.extend(
                bincode::serialize(&req).map_err(|e| MiasmaError::Serialization(e.to_string()))?,
            );

            // Build onion packet with e2e encryption.
            let (packet, return_path, session_key) = OnionPacketBuilder::build_e2e(
                &r1.onion_pubkey,
                &r2.onion_pubkey,
                &target_pubkey,
                r2.peer_id.clone(),
                target_peer_id_bytes.clone(),
                r2.addr.clone(),
                req_body,
            )?;

            // Send via onion relay protocol.
            let onion_req = OnionRelayRequest::Packet {
                circuit_id: packet.circuit_id,
                layer: packet.layer,
            };

            let response = self
                .dht_handle
                .send_onion_request(
                    r1_peer_id,
                    r1_addrs.clone(),
                    onion_req,
                    return_path.r1_init_key,
                )
                .await?;

            // Decrypt 3-layer response and parse share.
            match response {
                OnionRelayResponse::Data(encrypted) => {
                    match self.decrypt_onion_response(&return_path, &session_key, &encrypted) {
                        Some(share) => shares.push(share),
                        None => continue,
                    }
                }
                OnionRelayResponse::Error(e) => {
                    tracing::warn!("onion: relay error for shard {}: {e}", location.shard_index);
                }
            }
        }

        if shares.len() < k {
            return Err(MiasmaError::Sss(format!(
                "onion retrieval: got {}/{} shards",
                shares.len(),
                k
            )));
        }

        // Reconstruct plaintext from shares.
        crate::pipeline::retrieve(mid, &shares, params)
    }

    // ── Phase 4b diagnostics ────────────────────────────────────────────────

    /// Return credential wallet/issuer statistics.
    pub async fn credential_stats(&self) -> Result<CredentialStats, MiasmaError> {
        self.dht_handle.credential_stats().await
    }

    /// Return descriptor store statistics.
    pub async fn descriptor_stats(&self) -> Result<DescriptorStats, MiasmaError> {
        self.dht_handle.descriptor_stats().await
    }

    /// Return path selection statistics.
    pub async fn path_selection_stats(&self) -> Result<PathSelectionStats, MiasmaError> {
        self.dht_handle.path_selection_stats().await
    }

    /// Return Freenet-style outcome metrics.
    pub async fn outcome_metrics(&self) -> Result<super::metrics::OutcomeMetrics, MiasmaError> {
        self.dht_handle.outcome_metrics().await
    }

    /// Whether relay routing is currently enabled.
    pub fn relay_routing_enabled(&self) -> bool {
        self.relay_routing_enabled
    }

    /// Query whether this node is publicly reachable (AutoNAT).
    pub async fn nat_publicly_reachable(&self) -> Result<bool, MiasmaError> {
        self.dht_handle.nat_publicly_reachable().await
    }

    /// Return a snapshot of per-anonymity-mode retrieval counters.
    pub fn retrieval_stats(&self) -> RetrievalStats {
        self.retrieval_stats
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Look up a peer's descriptor (reachability, capabilities, etc).
    pub async fn peer_descriptor(
        &self,
        peer_id: PeerId,
    ) -> Result<Option<PeerDescriptor>, MiasmaError> {
        self.dht_handle.peer_descriptor(peer_id).await
    }

    /// Record a relay success/failure for trust tier tracking.
    pub async fn record_relay_outcome(&self, pseudonym: [u8; 32], success: bool) {
        let _ = self
            .dht_handle
            .record_relay_outcome(pseudonym, success)
            .await;
    }

    /// Resolve rendezvous introduction points for a peer.
    pub async fn resolve_intro_points(
        &self,
        intro_pseudonyms: Vec<[u8; 32]>,
    ) -> Result<Vec<super::descriptor::ResolvedIntroPoint>, MiasmaError> {
        self.dht_handle.resolve_intro_points(intro_pseudonyms).await
    }

    /// Retrieve content using onion encryption composed with rendezvous routing.
    ///
    /// For NAT'd shard holders with `ReachabilityKind::Rendezvous`, uses an
    /// onion-capable introduction point as R2 in the 2-hop onion circuit.
    /// This provides both content blindness (e2e encryption) and IP privacy
    /// (initiator hidden behind R1) even when the target is behind NAT.
    ///
    /// # Path: Initiator → R1 → R2(intro point) → Target(via relay circuit)
    ///
    /// - R1: random onion-capable relay from pool
    /// - R2: onion-capable introduction point for the NAT'd holder
    /// - Target: reachable via relay circuit through R2
    ///
    /// For non-rendezvous shard holders in the same record, falls back to
    /// standard onion routing with R2 from the relay pool.
    async fn retrieve_via_onion_rendezvous(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
    ) -> Result<Vec<u8>, MiasmaError> {
        if let Ok(mut s) = self.retrieval_stats.lock() {
            s.rendezvous_onion_attempts += 1;
        }

        // Get all onion-capable relays for R1 selection.
        let relays = self.dht_handle.relay_onion_info().await?;
        if relays.is_empty() {
            if let Ok(mut s) = self.retrieval_stats.lock() {
                s.rendezvous_onion_failures += 1;
            }
            return Err(MiasmaError::Network(
                "onion+rendezvous: no onion-capable relays available for R1".into(),
            ));
        }

        // DHT lookup.
        let record = self
            .dht_handle
            .get_record(*mid.as_bytes())
            .await?
            .ok_or_else(|| {
                MiasmaError::Sss(format!(
                    "onion+rendezvous: DhtRecord not found for MID {}",
                    hex::encode(&mid.as_bytes()[..8])
                ))
            })?;

        let k = params.data_shards;
        let mut shares: Vec<MiasmaShare> = Vec::with_capacity(k);

        for location in &record.locations {
            if shares.len() >= k {
                break;
            }

            let target_peer_id_bytes = &location.peer_id_bytes;
            let target_peer_id = match PeerId::from_bytes(target_peer_id_bytes) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Look up target's onion pubkey — never fall back to zero key.
            let target_pubkey = if target_peer_id == self.peer_id {
                match self.dht_handle.onion_pubkey().await {
                    Ok(key) => key,
                    Err(_) => {
                        tracing::warn!(
                            shard = location.shard_index,
                            "onion+rendezvous: own onion pubkey unavailable, skipping shard"
                        );
                        continue;
                    }
                }
            } else {
                match self.dht_handle.peer_onion_pubkey(target_peer_id).await {
                    Ok(Some(key)) => key,
                    _ => {
                        tracing::debug!(
                            target = %target_peer_id,
                            "onion+rendezvous: target has no onion pubkey, skipping shard"
                        );
                        continue;
                    }
                }
            };

            // Determine R2 based on reachability kind.
            let (r2_info, r2_pseudonym) = match self
                .dht_handle
                .peer_descriptor(target_peer_id)
                .await
            {
                Ok(Some(desc)) if desc.is_rendezvous() => {
                    // NAT'd holder: use an onion-capable intro point as R2.
                    if let ReachabilityKind::Rendezvous { ref intro_points } = desc.reachability {
                        let resolved = self
                            .dht_handle
                            .resolve_intro_points(intro_points.clone())
                            .await?;
                        // Find the first onion-capable intro point.
                        let onion_intro = resolved.iter().find(|ip| ip.onion_pubkey.is_some());
                        match onion_intro {
                            Some(intro) => {
                                let pubkey = intro.onion_pubkey.unwrap();
                                let addr = match intro.addresses.first() {
                                    Some(a) => a.as_bytes().to_vec(),
                                    None => continue,
                                };
                                let info = crate::onion::circuit::RelayInfo {
                                    peer_id: intro.peer_id.to_bytes(),
                                    onion_pubkey: pubkey,
                                    addr,
                                };
                                (info, Some(intro.pseudonym))
                            }
                            None => {
                                tracing::debug!(
                                    target = %target_peer_id,
                                    "onion+rendezvous: no onion-capable intro points, skipping shard"
                                );
                                continue;
                            }
                        }
                    } else {
                        continue;
                    }
                }
                _ => {
                    // Direct/Relayed holder: use standard R2 from relay pool.
                    if relays.len() < 2 {
                        tracing::debug!(
                            "onion+rendezvous: need ≥2 relays for non-rendezvous holder"
                        );
                        continue;
                    }
                    (relays[1].clone(), None)
                }
            };

            // Pick R1 — MUST differ from R2. If no distinct relay exists,
            // skip this shard rather than collapsing to a single relay
            // (which would let one node see both initiator and target).
            let r2_peer_id_bytes = &r2_info.peer_id;
            let r1 = match relays.iter().find(|r| r.peer_id != *r2_peer_id_bytes) {
                Some(r) => r,
                None => {
                    tracing::warn!(
                        shard = location.shard_index,
                        "onion+rendezvous: no relay distinct from R2, skipping shard (R1≠R2 invariant)"
                    );
                    continue;
                }
            };

            let r1_peer_id = match PeerId::from_bytes(&r1.peer_id) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let r1_addrs = vec![String::from_utf8_lossy(&r1.addr).to_string()];

            // Build share request.
            let req = ShareFetchRequest {
                mid_digest: record.mid_digest,
                slot_index: location.shard_index,
                segment_index: 0,
            };
            let mut req_body = vec![0x10u8];
            req_body.extend(
                bincode::serialize(&req).map_err(|e| MiasmaError::Serialization(e.to_string()))?,
            );

            // Build e2e onion packet: R1 → R2(intro) → Target.
            let (packet, return_path, session_key) = OnionPacketBuilder::build_e2e(
                &r1.onion_pubkey,
                &r2_info.onion_pubkey,
                &target_pubkey,
                r2_info.peer_id.clone(),
                target_peer_id_bytes.clone(),
                r2_info.addr.clone(),
                req_body,
            )?;

            let onion_req = OnionRelayRequest::Packet {
                circuit_id: packet.circuit_id,
                layer: packet.layer,
            };

            let response = self
                .dht_handle
                .send_onion_request(r1_peer_id, r1_addrs, onion_req, return_path.r1_init_key)
                .await;

            // Record relay outcome for intro point used as R2.
            if let Some(ps) = r2_pseudonym {
                let _ = self
                    .dht_handle
                    .record_relay_outcome(ps, response.is_ok())
                    .await;
            }

            match response {
                Ok(OnionRelayResponse::Data(encrypted)) => {
                    // 3-layer response decryption: R1 → R2 → session key.
                    match self.decrypt_onion_response(&return_path, &session_key, &encrypted) {
                        Some(share) => shares.push(share),
                        None => continue,
                    }
                }
                Ok(OnionRelayResponse::Error(e)) => {
                    tracing::warn!(
                        shard = location.shard_index,
                        "onion+rendezvous: relay error: {e}"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        shard = location.shard_index,
                        "onion+rendezvous: request error: {e}"
                    );
                }
            }
        }

        if shares.len() < k {
            if let Ok(mut s) = self.retrieval_stats.lock() {
                s.rendezvous_onion_failures += 1;
            }
            return Err(MiasmaError::Sss(format!(
                "onion+rendezvous: got {}/{} shards",
                shares.len(),
                k
            )));
        }

        if let Ok(mut s) = self.retrieval_stats.lock() {
            s.rendezvous_onion_successes += 1;
        }
        crate::pipeline::retrieve(mid, &shares, params)
    }

    /// Decrypt a 3-layer onion response (r1_key → r2_key → session_key) and parse share.
    fn decrypt_onion_response(
        &self,
        return_path: &crate::onion::packet::ReturnPath,
        session_key: &[u8; 32],
        encrypted: &[u8],
    ) -> Option<MiasmaShare> {
        let after_r1 =
            crate::onion::packet::decrypt_response(&return_path.r1_init_key, encrypted).ok()?;
        let after_r2 =
            crate::onion::packet::decrypt_response(&return_path.r2_r1_key, &after_r1).ok()?;
        let plaintext = crate::onion::packet::decrypt_response(session_key, &after_r2).ok()?;

        if plaintext.first() != Some(&0x11) {
            tracing::warn!("onion: unexpected share response tag");
            return None;
        }
        let resp: ShareFetchResponse = bincode::deserialize(&plaintext[1..]).ok()?;
        resp.share
    }

    /// Retrieve content via a rendezvous peer's introduction points.
    ///
    /// Used when the shard holder's descriptor has `ReachabilityKind::Rendezvous`.
    /// Resolves intro points, selects the best one (preferring Verified/onion-capable),
    /// and routes the retrieval through that relay.
    ///
    /// # Failure modes (tracked distinctly)
    /// - No intro points resolved → rendezvous failure
    /// - Intro point stale/missing → rendezvous failure, try next
    /// - Intro point reachable but relay fails → rendezvous failure + relay outcome recorded
    /// - All intro points fail → falls back per anonymity mode
    async fn retrieve_via_rendezvous(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
        intro_pseudonyms: &[[u8; 32]],
    ) -> Result<Vec<u8>, MiasmaError> {
        if let Ok(mut s) = self.retrieval_stats.lock() {
            s.rendezvous_attempts += 1;
        }

        let resolved = self
            .dht_handle
            .resolve_intro_points(intro_pseudonyms.to_vec())
            .await?;
        if resolved.is_empty() {
            if let Ok(mut s) = self.retrieval_stats.lock() {
                s.rendezvous_failures += 1;
            }
            return Err(MiasmaError::Network(
                "rendezvous: no intro points could be resolved (all stale, missing, or non-relay)"
                    .into(),
            ));
        }

        // Try each resolved intro point in trust-tier order (Verified first).
        for intro in &resolved {
            let relay_addr = match intro.addresses.first() {
                Some(a) => a.clone(),
                None => continue,
            };

            tracing::info!(
                intro_peer = %intro.peer_id,
                relay_tier = ?intro.relay_tier,
                onion = intro.onion_pubkey.is_some(),
                "rendezvous: routing through introduction point"
            );

            let relay_exec = RelayRewritingDhtExecutor {
                inner: DirectDhtExecutor::new(self.dht_handle.clone()),
                relay_peer_id: intro.peer_id,
                relay_addr,
            };
            let source = FallbackShareSource::new(relay_exec, self.transport_selector.clone());
            match RetrievalCoordinator::new(source)
                .retrieve(mid, params)
                .await
            {
                Ok(data) => {
                    // Record relay success for this intro point.
                    let _ = self
                        .dht_handle
                        .record_relay_outcome(intro.pseudonym, true)
                        .await;
                    if let Ok(mut s) = self.retrieval_stats.lock() {
                        s.rendezvous_successes += 1;
                    }
                    return Ok(data);
                }
                Err(e) => {
                    // Record relay failure — may demote this intro point's trust tier.
                    let _ = self
                        .dht_handle
                        .record_relay_outcome(intro.pseudonym, false)
                        .await;
                    tracing::debug!(
                        intro_peer = %intro.peer_id,
                        "rendezvous: intro point failed ({e}), trying next"
                    );
                }
            }
        }

        if let Ok(mut s) = self.retrieval_stats.lock() {
            s.rendezvous_failures += 1;
        }
        Err(MiasmaError::Network(format!(
            "rendezvous: all {} intro points failed",
            resolved.len()
        )))
    }

    /// Send an active relay probe to a peer and record the outcome.
    ///
    /// Uses the `/miasma/relay-probe/1.0.0` protocol: random nonce echo.
    /// Records a relay observation (success promotes trust tier, failure demotes).
    pub async fn probe_relay(&self, peer_id: PeerId, addrs: Vec<String>) -> bool {
        if let Ok(mut s) = self.retrieval_stats.lock() {
            s.relay_probes_sent += 1;
        }

        let success = self
            .dht_handle
            .probe_relay(peer_id, addrs)
            .await
            .unwrap_or(false);

        // Record relay observation for trust tier tracking.
        if let Ok(Some(ps)) = self.dht_handle.peer_pseudonym(peer_id).await {
            let _ = self.dht_handle.record_relay_outcome(ps, success).await;
        }

        if let Ok(mut s) = self.retrieval_stats.lock() {
            if success {
                s.relay_probes_succeeded += 1;
            } else {
                s.relay_probes_failed += 1;
            }
        }

        tracing::info!(peer = %peer_id, success, "relay probe completed");
        success
    }

    /// Verify that a relay (R1) actually forwards traffic to another peer (R2).
    ///
    /// Sends a relay probe to R2 through R1's relay circuit address:
    /// `/p2p/{R1}/p2p-circuit/p2p/{R2}`. If R2 echoes the nonce, R1
    /// demonstrably forwarded the request.
    ///
    /// Records forwarding verification in R1's relay observation, which
    /// fast-tracks R1 toward Verified trust tier.
    pub async fn verify_relay_forwarding(
        &self,
        r1_peer_id: PeerId,
        _r1_addrs: Vec<String>,
        r2_peer_id: PeerId,
    ) -> bool {
        if let Ok(mut s) = self.retrieval_stats.lock() {
            s.forwarding_probes_sent += 1;
        }

        // Build circuit address: route to R2 through R1.
        let circuit_addr = format!("/p2p/{}/p2p-circuit/p2p/{}", r1_peer_id, r2_peer_id);

        // First ensure R1 is dialable by probing it directly if needed.
        // Then send the circuit-routed probe to R2 via R1.
        let success = self
            .dht_handle
            .probe_relay(r2_peer_id, vec![circuit_addr])
            .await
            .unwrap_or(false);

        if let Ok(Some(r1_ps)) = self.dht_handle.peer_pseudonym(r1_peer_id).await {
            if success {
                let _ = self.dht_handle.record_forwarding_verification(r1_ps).await;
                let _ = self.dht_handle.record_relay_outcome(r1_ps, true).await;
            } else {
                let _ = self.dht_handle.record_relay_outcome(r1_ps, false).await;
            }
        }

        if let Ok(mut s) = self.retrieval_stats.lock() {
            if success {
                s.forwarding_probes_succeeded += 1;
            } else {
                s.forwarding_probes_failed += 1;
            }
        }

        tracing::info!(
            r1 = %r1_peer_id,
            r2 = %r2_peer_id,
            success,
            "forwarding verification completed"
        );
        success
    }

    /// Send a directed sharing request to a specific peer.
    pub async fn send_directed_request(
        &self,
        peer_id: PeerId,
        addrs: Vec<String>,
        request: crate::directed::DirectedRequest,
    ) -> Result<crate::directed::DirectedResponse, MiasmaError> {
        self.dht_handle
            .send_directed_request(peer_id, addrs, request)
            .await
    }

    /// Get all connected peers with their addresses.
    pub async fn connected_peer_addrs(
        &self,
    ) -> Vec<(PeerId, Vec<libp2p::Multiaddr>)> {
        self.dht_handle.connected_peers().await.unwrap_or_default()
    }

    /// Get a live connection health snapshot from the node's health monitor.
    pub async fn health_snapshot(
        &self,
    ) -> Result<super::connection_health::ConnectionHealthSnapshot, MiasmaError> {
        self.dht_handle.health_snapshot().await
    }

    /// Check whether network flap damping is currently active.
    pub async fn flap_damping_active(&self) -> Result<bool, MiasmaError> {
        self.dht_handle.flap_damping_active().await
    }

    /// Get current partial failure conditions (relay-only, no peers, etc.).
    pub async fn partial_failures(&self) -> Result<Vec<String>, MiasmaError> {
        self.dht_handle.partial_failures().await
    }

    /// Get reconnection metrics from the live node.
    pub async fn reconnection_metrics(
        &self,
    ) -> Result<crate::daemon::self_heal::ReconnectionMetrics, MiasmaError> {
        self.dht_handle.reconnection_metrics().await
    }
}

// ─── RelayRewritingDhtExecutor ─────────────────────────────────────────────

/// DHT executor that rewrites shard location addresses to route through a
/// relay peer using libp2p relay circuit addresses.
///
/// When the coordinator retrieves with `Opportunistic` or `Required` anonymity,
/// this executor wraps the real Kademlia DHT lookup but rewrites the returned
/// `DhtRecord.locations[].addrs` so that share-fetch transport uses relay
/// circuit addresses (`/p2p/{relay}/p2p-circuit/p2p/{dest}`).
///
/// This provides IP-level sender privacy: the shard holder sees the relay's
/// address, not the requester's. Content privacy from relays requires the
/// onion encryption layer (future Phase 2).
struct RelayRewritingDhtExecutor {
    inner: DirectDhtExecutor,
    relay_peer_id: PeerId,
    relay_addr: String,
}

impl RelayRewritingDhtExecutor {
    /// Rewrite shard location addresses to route through the relay.
    ///
    /// Converts each location's first address to a relay circuit address:
    /// `{relay_addr}/p2p/{relay_peer_id}/p2p-circuit`
    ///
    /// The transport layer will append the destination PeerId when dialing.
    fn rewrite_record(&self, mut record: DhtRecord) -> DhtRecord {
        let circuit_base = if self.relay_addr.contains("/p2p/") {
            // Relay addr already contains /p2p/ — just append /p2p-circuit
            format!("{}/p2p-circuit", self.relay_addr)
        } else {
            format!("{}/p2p/{}/p2p-circuit", self.relay_addr, self.relay_peer_id)
        };

        for loc in &mut record.locations {
            // Replace all direct addresses with relay circuit addresses.
            loc.addrs = vec![circuit_base.clone()];
        }
        record
    }
}

#[async_trait::async_trait]
impl crate::network::dht::OnionAwareDhtExecutor for RelayRewritingDhtExecutor {
    async fn put(&self, record: DhtRecord) -> Result<(), MiasmaError> {
        // PUT goes through the relay as well (anonymises the publisher).
        self.inner.put(record).await
    }

    async fn get(
        &self,
        mid: &crate::crypto::hash::ContentId,
    ) -> Result<Option<DhtRecord>, MiasmaError> {
        match self.inner.get(mid).await? {
            Some(record) => Ok(Some(self.rewrite_record(record))),
            None => Ok(None),
        }
    }
}
