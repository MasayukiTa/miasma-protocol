//! Daemon server — long-lived P2P process owning the network stack.
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  DaemonServer                                       │
//! │  ├─ MiasmaCoordinator (libp2p node + DHT + share)  │
//! │  ├─ LocalShareStore (encrypted shard storage)       │
//! │  ├─ ReplicationQueue (WAL-backed, per-item backoff) │
//! │  ├─ IPC server task (TCP loopback, one conn/req)    │
//! │  └─ Replication engine (event-driven + fallback)    │
//! └─────────────────────────────────────────────────────┘
//!         ↑ ControlRequest / ↓ ControlResponse
//!  ┌──────────────┐   ┌──────────────┐
//!  │  miasma      │   │  miasma      │
//!  │  network-    │   │  network-get │
//!  │  publish     │   │              │
//!  └──────────────┘   └──────────────┘
//! ```

pub mod ipc;
pub mod replication;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use libp2p::PeerId;
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle, time::Duration};
use tracing::{debug, info, warn};

use crate::{
    config::TransportConfig,
    network::{
        coordinator::MiasmaCoordinator,
        node::MiasmaNode,
        types::{DhtRecord, ShardLocation, TopologyEvent},
    },
    pipeline::{dissolve, DissolutionParams},
    store::LocalShareStore,
    transport::payload::PayloadTransport,
    MiasmaError,
};

use ipc::{
    read_frame, remove_port_file, write_frame, write_port_file, ControlRequest,
    ControlResponse, DaemonStatus,
};
use replication::{PendingReplication, ReplicationQueue};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Maximum number of concurrent DHT announce operations per replication cycle.
const MAX_CONCURRENT_ANNOUNCES: usize = 8;

/// Fallback timer interval (seconds).  The primary replication driver is
/// topology events; this timer exists only as a safety net.
const FALLBACK_TIMER_SECS: u64 = 60;

// ─── DaemonServer ────────────────────────────────────────────────────────────

pub struct DaemonServer {
    coord: Arc<MiasmaCoordinator>,
    store: Arc<LocalShareStore>,
    queue: Arc<Mutex<ReplicationQueue>>,
    data_dir: PathBuf,
    listen_addrs: Vec<String>,
    control_port: u16,
    /// Port the WSS share server is bound to (0 if not started).
    wss_port: u16,
    /// Whether WSS TLS is enabled.
    wss_tls_enabled: bool,
    /// Whether a proxy is configured.
    proxy_configured: bool,
    /// Proxy type string (e.g. "socks5", "http_connect").
    proxy_type: Option<String>,
    /// Port the ObfuscatedQuic server is bound to (0 if not started).
    obfs_quic_port: u16,
    // Single-consumer resources moved into run():
    listener: Option<TcpListener>,
    rep_success_rx: Option<mpsc::Receiver<[u8; 32]>>,
    topology_rx: Option<mpsc::Receiver<TopologyEvent>>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: Option<mpsc::Receiver<()>>,
}

impl DaemonServer {
    /// Build and bind the daemon.
    ///
    /// After this returns the IPC port file exists, so CLI clients can
    /// connect immediately. Call `run()` to start accepting requests.
    pub async fn start(
        node: MiasmaNode,
        store: Arc<LocalShareStore>,
        data_dir: PathBuf,
    ) -> Result<Self> {
        Self::start_with_transport(node, store, data_dir, TransportConfig::default()).await
    }

    /// Build and bind the daemon with explicit transport configuration.
    pub async fn start_with_transport(
        mut node: MiasmaNode,
        store: Arc<LocalShareStore>,
        data_dir: PathBuf,
        transport_config: TransportConfig,
    ) -> Result<Self> {
        // 1. Collect actual OS-assigned listen addresses.
        let addrs = node.collect_listen_addrs(400).await;
        let listen_addr_strings: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();

        // 2. Wire replication-success notifications out of the Kademlia loop.
        let (rep_tx, rep_rx) = mpsc::channel(64);
        node.set_replication_notifier(rep_tx);

        // 3. Wire topology-change notifications.
        let (topo_tx, topo_rx) = mpsc::channel(64);
        node.set_topology_notifier(topo_tx);

        // 4. Bind IPC listener (OS-assigned port).
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("cannot bind IPC listener")?;
        let control_port = listener.local_addr()?.port();

        // 5. Persist the port so CLI clients can discover the daemon.
        write_port_file(&data_dir, control_port)?;

        // 6. Build extra transports based on config.
        let mut extra_transports: Vec<Box<dyn PayloadTransport>> = Vec::new();

        // 6a. WSS share server.
        let wss_tls_enabled = transport_config.wss_tls_enabled;
        let mut wss_config = crate::transport::websocket::WebSocketConfig {
            tls_enabled: wss_tls_enabled,
            ..Default::default()
        };
        // Load TLS cert/key from config paths.
        if wss_tls_enabled {
            if let Some(ref cert_path) = transport_config.wss_cert_pem_path {
                wss_config.tls_cert_pem = Some(std::fs::read(cert_path).context("reading WSS TLS cert")?);
            }
            if let Some(ref key_path) = transport_config.wss_key_pem_path {
                wss_config.tls_key_pem = Some(std::fs::read(key_path).context("reading WSS TLS key")?);
            }
            if let Some(ref sni) = transport_config.wss_sni {
                wss_config.sni_override = Some(sni.clone());
            }
        }
        // Configure proxy if present.
        let proxy_configured = transport_config.proxy_type.is_some();
        let proxy_type = transport_config.proxy_type.clone();
        if let Some(ref pt) = transport_config.proxy_type {
            if let Some(ref addr) = transport_config.proxy_addr {
                use crate::transport::websocket::{ProxyConfig as WssProxyConfig, ProxyKind};
                let kind = match pt.as_str() {
                    "socks5" => ProxyKind::Socks5,
                    _ => ProxyKind::Socks5, // default to socks5
                };
                wss_config.proxy = Some(WssProxyConfig {
                    addr: addr.clone(),
                    kind,
                });
            }
        }

        let wss_port = if wss_tls_enabled {
            // Bind TLS-enabled WSS server.
            match crate::transport::websocket::WssShareServer::bind_tls(
                store.clone(),
                0,
                &wss_config.tls_cert_pem.clone().unwrap_or_default(),
                &wss_config.tls_key_pem.clone().unwrap_or_default(),
            )
            .await
            {
                Ok(server) => {
                    let port = server.port;
                    tokio::spawn(server.run());
                    info!(wss_port = port, tls = true, "WSS share server started (TLS)");
                    // Add WSS transport to fallback chain.
                    let mut client_config = wss_config.clone();
                    client_config.port = port;
                    extra_transports.push(Box::new(
                        crate::transport::websocket::WssPayloadTransport::new(client_config),
                    ));
                    port
                }
                Err(e) => {
                    warn!("WSS TLS share server failed to start: {e}");
                    0
                }
            }
        } else {
            // Plain WSS server (no TLS).
            match crate::transport::websocket::WssShareServer::bind(store.clone(), 0).await {
                Ok(server) => {
                    let port = server.port;
                    tokio::spawn(server.run());
                    info!(wss_port = port, "WSS share server started");
                    let mut client_config = wss_config.clone();
                    client_config.port = port;
                    extra_transports.push(Box::new(
                        crate::transport::websocket::WssPayloadTransport::new(client_config),
                    ));
                    port
                }
                Err(e) => {
                    warn!("WSS share server failed to start: {e}");
                    0
                }
            }
        };

        // 6b. ObfuscatedQuic server.
        let mut obfs_quic_port = 0u16;
        if transport_config.obfuscated_quic_enabled {
            // Parse hex-encoded probe secret (32 bytes = 64 hex chars).
            let probe_secret = {
                let hex_str = transport_config
                    .obfuscated_quic_secret
                    .as_deref()
                    .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
                let bytes = hex::decode(hex_str).unwrap_or_else(|_| vec![0u8; 32]);
                let mut arr = [0u8; 32];
                let len = bytes.len().min(32);
                arr[..len].copy_from_slice(&bytes[..len]);
                arr
            };
            let obfs_config = crate::transport::obfuscated::ObfuscatedConfig::new(
                probe_secret,
                transport_config
                    .obfuscated_quic_sni
                    .as_deref()
                    .unwrap_or("cdn.example.com"),
                transport_config
                    .obfuscated_quic_fallback_url
                    .as_deref()
                    .unwrap_or("https://cdn.example.com"),
                crate::transport::obfuscated::BrowserFingerprint::Chrome124,
            );
            match crate::transport::obfuscated::ObfuscatedQuicServer::bind(
                store.clone(),
                0,
                obfs_config.clone(),
            )
            .await
            {
                Ok(server) => {
                    obfs_quic_port = server.port;
                    tokio::spawn(server.run());
                    info!(port = obfs_quic_port, "ObfuscatedQuic server started");
                    // Add to fallback chain.
                    extra_transports.push(Box::new(
                        crate::transport::obfuscated::ObfuscatedQuicPayloadTransport::new(
                            obfs_config,
                        ),
                    ));
                }
                Err(e) => {
                    warn!("ObfuscatedQuic server failed to start: {e}");
                }
            }
        }

        // 7. Start the coordinator with all transports.
        let coord = Arc::new(
            MiasmaCoordinator::start_with_transports(
                node,
                store.clone(),
                listen_addr_strings.clone(),
                extra_transports,
            )
            .await,
        );

        // 8. Load the persistent replication queue.
        let queue = Arc::new(Mutex::new(ReplicationQueue::load_or_create(&data_dir)?));

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        info!(
            port = control_port,
            peer_id = %coord.peer_id(),
            "daemon IPC server bound"
        );
        for addr in &listen_addr_strings {
            info!("  bootstrap addr: {addr}/p2p/{}", coord.peer_id());
        }

        Ok(Self {
            coord,
            store,
            queue,
            data_dir,
            listen_addrs: listen_addr_strings,
            control_port,
            wss_port,
            wss_tls_enabled,
            proxy_configured,
            proxy_type,
            obfs_quic_port,
            listener: Some(listener),
            rep_success_rx: Some(rep_rx),
            topology_rx: Some(topo_rx),
            shutdown_tx,
            shutdown_rx: Some(shutdown_rx),
        })
    }

    /// TCP port the IPC server is bound to.
    pub fn control_port(&self) -> u16 {
        self.control_port
    }

    /// The coordinator's libp2p peer ID.
    pub fn peer_id(&self) -> &PeerId {
        self.coord.peer_id()
    }

    /// Listen addresses in multiaddr format.
    pub fn listen_addrs(&self) -> &[String] {
        &self.listen_addrs
    }

    /// Port the WSS share server is listening on (0 if not started).
    pub fn wss_port(&self) -> u16 {
        self.wss_port
    }

    /// A clone of the shutdown sender.  Send `()` to stop the daemon.
    pub fn shutdown_handle(&self) -> mpsc::Sender<()> {
        self.shutdown_tx.clone()
    }

    /// Expose the replication queue for status/test inspection.
    pub fn queue(&self) -> Arc<Mutex<ReplicationQueue>> {
        self.queue.clone()
    }

    /// Run due replication items (up to the concurrency cap).
    ///
    /// Exposed for integration tests that want to trigger without waiting
    /// for the fallback timer or a topology event.
    pub async fn run_pending_replication(&self) {
        retry_due(&self.coord, &self.queue).await;
    }

    /// Register a bootstrap peer with the coordinator.
    pub async fn add_bootstrap_peer(
        &self,
        peer_id: PeerId,
        addr: libp2p::Multiaddr,
    ) -> Result<(), MiasmaError> {
        self.coord.add_bootstrap_peer(peer_id, addr).await
    }

    /// Trigger Kademlia bootstrap.
    pub async fn bootstrap_dht(&self) -> Result<(), MiasmaError> {
        self.coord.bootstrap_dht().await
    }

    /// Run the daemon event loop.  Blocks until `shutdown()` is called.
    pub async fn run(mut self) -> Result<()> {
        let listener = self.listener.take().expect("listener already consumed");
        let rep_success_rx = self.rep_success_rx.take().expect("rep_rx already consumed");
        let topology_rx = self.topology_rx.take().expect("topology_rx already consumed");
        let mut shutdown_rx = self.shutdown_rx.take().expect("shutdown_rx already consumed");

        let coord = self.coord.clone();
        let queue = self.queue.clone();
        let store = self.store.clone();
        let listen_addrs = self.listen_addrs.clone();

        // ── IPC server task ───────────────────────────────────────────────────
        let ipc_coord = coord.clone();
        let ipc_queue = queue.clone();
        let ipc_store = store.clone();
        let ipc_addrs = listen_addrs.clone();
        let ipc_wss_port = self.wss_port;
        let ipc_wss_tls = self.wss_tls_enabled;
        let ipc_proxy = self.proxy_configured;
        let ipc_proxy_type = self.proxy_type.clone();
        let ipc_obfs = self.obfs_quic_port;
        let ipc_handle: JoinHandle<()> = tokio::spawn(async move {
            ipc_server_loop(
                listener, ipc_coord, ipc_queue, ipc_store, ipc_addrs,
                ipc_wss_port, ipc_wss_tls, ipc_proxy, ipc_proxy_type, ipc_obfs,
            ).await;
        });

        // ── Event-driven replication engine ───────────────────────────────────
        let rep_coord = coord.clone();
        let rep_queue = queue.clone();
        let rep_handle: JoinHandle<()> = tokio::spawn(async move {
            replication_engine(rep_coord, rep_queue, rep_success_rx, topology_rx).await;
        });

        // ── Wait for shutdown ─────────────────────────────────────────────────
        shutdown_rx.recv().await;
        info!("daemon shutdown signal received");

        ipc_handle.abort();
        rep_handle.abort();

        coord.shutdown().await;
        remove_port_file(&self.data_dir);
        Ok(())
    }
}

// ─── IPC server ──────────────────────────────────────────────────────────────

async fn ipc_server_loop(
    listener: TcpListener,
    coord: Arc<MiasmaCoordinator>,
    queue: Arc<Mutex<ReplicationQueue>>,
    store: Arc<LocalShareStore>,
    listen_addrs: Vec<String>,
    wss_port: u16,
    wss_tls_enabled: bool,
    proxy_configured: bool,
    proxy_type: Option<String>,
    obfs_quic_port: u16,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!("IPC client connected from {peer}");
                let c = coord.clone();
                let q = queue.clone();
                let s = store.clone();
                let la = listen_addrs.clone();
                let wp = wss_port;
                let wt = wss_tls_enabled;
                let pc = proxy_configured;
                let pt = proxy_type.clone();
                let oq = obfs_quic_port;
                tokio::spawn(async move {
                    if let Err(e) = handle_ipc_client(stream, c, q, s, la, wp, wt, pc, pt, oq).await {
                        debug!("IPC client error: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("IPC accept error: {e}");
                break;
            }
        }
    }
}

async fn handle_ipc_client(
    mut stream: tokio::net::TcpStream,
    coord: Arc<MiasmaCoordinator>,
    queue: Arc<Mutex<ReplicationQueue>>,
    store: Arc<LocalShareStore>,
    listen_addrs: Vec<String>,
    wss_port: u16,
    wss_tls_enabled: bool,
    proxy_configured: bool,
    proxy_type: Option<String>,
    obfs_quic_port: u16,
) -> Result<()> {
    let req: ControlRequest = read_frame(&mut stream).await?;
    let resp = process_request(
        req, coord, queue, store, listen_addrs,
        wss_port, wss_tls_enabled, proxy_configured, proxy_type, obfs_quic_port,
    ).await;
    write_frame(&mut stream, &resp).await?;
    Ok(())
}

async fn process_request(
    req: ControlRequest,
    coord: Arc<MiasmaCoordinator>,
    queue: Arc<Mutex<ReplicationQueue>>,
    store: Arc<LocalShareStore>,
    listen_addrs: Vec<String>,
    wss_port: u16,
    wss_tls_enabled: bool,
    proxy_configured: bool,
    proxy_type: Option<String>,
    obfs_quic_port: u16,
) -> ControlResponse {
    match req {
        ControlRequest::Publish { data, data_shards, total_shards } => {
            let params = DissolutionParams {
                data_shards: data_shards as usize,
                total_shards: total_shards as usize,
            };
            match publish_content(&data, params, &coord, &queue, &store, &listen_addrs).await {
                Ok(mid) => ControlResponse::Published { mid },
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::Get { mid, data_shards, total_shards } => {
            let params = DissolutionParams {
                data_shards: data_shards as usize,
                total_shards: total_shards as usize,
            };
            match crate::crypto::hash::ContentId::from_str(&mid) {
                Ok(content_id) => match coord.retrieve_from_network(&content_id, params).await {
                    Ok(data) => ControlResponse::Retrieved { data },
                    Err(e) => ControlResponse::Error(e.to_string()),
                },
                Err(e) => ControlResponse::Error(format!("invalid MID: {e}")),
            }
        }

        ControlRequest::Status => {
            let peer_count = coord.peer_count().await.unwrap_or(0);
            let admission = coord.admission_stats().await.unwrap_or(
                crate::network::peer_state::AdmissionStats {
                    verified_peers: 0,
                    observed_peers: 0,
                    claimed_peers: 0,
                    total_rejections: 0,
                },
            );
            let routing = coord.routing_stats().await.unwrap_or(
                crate::network::routing::RoutingStats {
                    total_peers: 0,
                    unreliable_peers: 0,
                    unique_prefixes: 0,
                    max_prefix_concentration: 0,
                    diversity_rejections: 0,
                    current_difficulty: 8,
                },
            );
            let share_count = store.list().len();
            let storage_used_bytes = store.used_bytes();
            let (pending_replication, replicated_count) = {
                let q = queue.lock().unwrap();
                (q.pending_count(), q.replicated_count())
            };
            // Build transport readiness matrix from coordinator stats.
            let transport_readiness = coord
                .transport_stats()
                .snapshot()
                .into_iter()
                .map(|r| ipc::TransportStatus {
                    name: r.transport.to_string(),
                    available: r.available,
                    selected: r.selected,
                    success_count: r.success_count,
                    failure_count: r.failure_count,
                    session_failures: r.session_failures,
                    data_failures: r.data_failures,
                    last_error: r.last_error,
                    reason: r.reason,
                })
                .collect();

            // Phase 4b stats.
            let cred_stats = coord.credential_stats().await.unwrap_or(
                crate::network::credential::CredentialStats {
                    current_epoch: 0,
                    held_credentials: 0,
                    best_tier: None,
                    known_issuers: 0,
                    bootstrap_mode: true,
                },
            );
            let desc_stats = coord.descriptor_stats().await.unwrap_or(
                crate::network::descriptor::DescriptorStats {
                    total_descriptors: 0,
                    relay_descriptors: 0,
                    relayed_descriptors: 0,
                    credentialed_descriptors: 0,
                    bbs_credentialed_descriptors: 0,
                    stale_descriptors: 0,
                    pseudonym_churn_rate: 0.0,
                    relay_peers_routable: 0,
                },
            );
            let path_stats = coord.path_selection_stats().await.unwrap_or(
                crate::network::path_selection::PathSelectionStats {
                    default_policy: "unknown".to_string(),
                    available_relays: 0,
                    relay_prefix_diversity: 0,
                },
            );
            let outcome = coord.outcome_metrics().await.unwrap_or_default();

            ControlResponse::Status(DaemonStatus {
                peer_id: coord.peer_id().to_string(),
                listen_addrs,
                peer_count,
                share_count,
                storage_used_bytes,
                pending_replication,
                replicated_count,
                wss_port,
                wss_tls_enabled,
                proxy_configured,
                proxy_type: proxy_type.clone(),
                obfs_quic_port,
                transport_readiness,
                verified_peers: admission.verified_peers,
                observed_peers: admission.observed_peers,
                admission_rejections: admission.total_rejections,
                routing_peers: routing.total_peers,
                routing_unreliable: routing.unreliable_peers,
                routing_unique_prefixes: routing.unique_prefixes,
                routing_max_prefix_concentration: routing.max_prefix_concentration,
                routing_diversity_rejections: routing.diversity_rejections,
                routing_pow_difficulty: routing.current_difficulty,
                credential_epoch: cred_stats.current_epoch,
                credential_held: cred_stats.held_credentials,
                credential_issuers: cred_stats.known_issuers,
                descriptor_total: desc_stats.total_descriptors,
                descriptor_relays: desc_stats.relay_descriptors,
                descriptor_bbs_credentialed: desc_stats.bbs_credentialed_descriptors,
                path_available_relays: path_stats.available_relays,
                path_relay_prefix_diversity: path_stats.relay_prefix_diversity,
                anonymity_policy: coord.anonymity_policy().to_string(),
                metric_relay_prefix_diversity: outcome.relay_prefix_diversity,
                metric_credentialed_fraction: outcome.credentialed_peer_fraction,
                metric_pseudonymous_fraction: outcome.pseudonymous_fraction,
                metric_multi_path_retrievability: outcome.multi_path_retrievability,
                metric_pow_difficulty: outcome.current_pow_difficulty,
                metric_verification_ratio: outcome.verification_ratio,
                metric_rejection_rate: outcome.admission_rejection_rate,
                metric_pseudonym_churn_rate: outcome.pseudonym_churn_rate,
                metric_relay_peers_routable: outcome.relay_peers_routable,
                metric_bbs_credentialed: outcome.bbs_credentialed_count,
                metric_stale_descriptors: outcome.stale_descriptor_count,
                metric_descriptor_utilisation: outcome.descriptor_utilisation,
            })
        }

        ControlRequest::Wipe => {
            match store.distress_wipe() {
                Ok(_) => {
                    info!("distress wipe executed via IPC");
                    ControlResponse::Wiped
                }
                Err(e) => ControlResponse::Error(format!("wipe failed: {e}")),
            }
        }
    }
}

// ─── Publish helper ──────────────────────────────────────────────────────────

async fn publish_content(
    data: &[u8],
    params: DissolutionParams,
    coord: &MiasmaCoordinator,
    queue: &Arc<Mutex<ReplicationQueue>>,
    store: &LocalShareStore,
    listen_addrs: &[String],
) -> Result<String, MiasmaError> {
    // Dissolve into shares.
    let (mid, shares) = dissolve(data, params)?;

    // Store shares locally.
    for share in &shares {
        store.put(share)?;
    }

    // Build the DhtRecord (needed both for DHT PUT and the replication queue).
    let peer_bytes = coord.peer_id().to_bytes();
    let locations: Vec<ShardLocation> = shares
        .iter()
        .map(|s| ShardLocation {
            peer_id_bytes: peer_bytes.clone(),
            shard_index: s.slot_index,
            addrs: listen_addrs.to_vec(),
        })
        .collect();

    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations,
        published_at: now_secs(),
    };

    // Announce to DHT (local store + fire-and-forget network PUT).
    coord.publish_record(record.clone()).await?;

    // Add to the persistent replication queue so the retry loop can
    // re-announce when peers become available.
    let pending = PendingReplication::new(mid.to_string(), record);
    queue.lock().unwrap().push(pending).map_err(|e| MiasmaError::Storage(e.to_string()))?;

    let mid_str = mid.to_string();
    info!(mid = %mid_str, "content published; awaiting network replication");
    Ok(mid_str)
}

// ─── Event-driven replication engine ─────────────────────────────────────────

/// Core replication loop.  Three event sources:
///
/// 1. **Topology events** (primary) — new peer connections trigger due-item
///    retries and bounded promotion of degraded items.
/// 2. **Replication success** — mark items as Replicated.
/// 3. **Fallback timer** — safety net that sweeps due items every 60s.
async fn replication_engine(
    coord: Arc<MiasmaCoordinator>,
    queue: Arc<Mutex<ReplicationQueue>>,
    mut rep_success_rx: mpsc::Receiver<[u8; 32]>,
    mut topology_rx: mpsc::Receiver<TopologyEvent>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(FALLBACK_TIMER_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // ── Primary: topology change ────────────────────────────────────
            Some(event) = topology_rx.recv() => {
                let budget = event.promotion_budget();
                if budget > 0 {
                    let (promoted, made_due, pending) = {
                        let mut q = queue.lock().unwrap();
                        let promoted = q.promote_degraded(budget).unwrap_or(0);
                        // A new peer is a fresh target — make backed-off items
                        // immediately eligible, bounded by the concurrency cap.
                        let made_due = q.make_items_due(MAX_CONCURRENT_ANNOUNCES);
                        (promoted, made_due, q.pending_count())
                    };
                    if promoted > 0 || made_due > 0 || pending > 0 {
                        info!(
                            ?event,
                            promoted,
                            made_due,
                            pending,
                            "topology event: running due replication"
                        );
                        retry_due(&coord, &queue).await;
                    }
                }
            }

            // ── Replication success ack ──────────────────────────────────────
            Some(mid_digest) = rep_success_rx.recv() => {
                let _ = queue.lock().unwrap().mark_replicated(&mid_digest);
            }

            // ── Fallback timer ──────────────────────────────────────────────
            _ = interval.tick() => {
                let pending = queue.lock().unwrap().pending_count();
                if pending > 0 {
                    let peer_count = coord.peer_count().await.unwrap_or(0);
                    if peer_count > 0 {
                        debug!(peer_count, pending, "fallback timer: sweeping due items");
                        retry_due(&coord, &queue).await;
                    }
                }
            }
        }
    }
}

/// Retry only items whose `next_attempt_secs` has passed, up to the
/// concurrency cap.
async fn retry_due(coord: &MiasmaCoordinator, queue: &Arc<Mutex<ReplicationQueue>>) {
    let now = now_secs();
    let items: Vec<replication::PendingReplication> = {
        let q = queue.lock().unwrap();
        let mut due = q.due_items(now);
        due.truncate(MAX_CONCURRENT_ANNOUNCES);
        due
    };

    for item in items {
        let mid_digest = item.record.mid_digest;
        info!(
            mid = %item.mid_str,
            attempt = item.attempt_count + 1,
            "retrying DHT announce"
        );

        // Record the attempt (updates backoff schedule) *before* the network call.
        let _ = queue.lock().unwrap().record_attempt(&mid_digest);

        if let Err(e) = coord.publish_record(item.record).await {
            warn!(mid = %item.mid_str, "replication retry failed: {e}");
        }
        // Marking as replicated happens via the rep_success_rx channel
        // when the Kademlia PutRecord(Ok) event fires in the node event loop.
    }
}
