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

pub mod http_bridge;
pub mod ipc;
pub mod replication;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
#[allow(unused_imports)]
use libp2p::PeerId;
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle, time::Duration};
use tracing::{debug, info, warn};

use crate::{
    config::TransportConfig,
    directed::{self, DirectedInbox},
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
    read_frame, remove_port_file, write_frame, write_port_file, ControlRequest, ControlResponse,
    DaemonStatus,
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
    /// Port the HTTP bridge is bound to (0 if not started).
    #[allow(dead_code)]
    http_bridge_port: u16,
    /// X25519 sharing secret (derived from master key).
    sharing_secret: [u8; 32],
    /// X25519 sharing public key.
    sharing_pubkey: [u8; 32],
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

        // 3b. Set data_dir on node for directed sharing P2P confirm handling.
        node.set_directed_data_dir(data_dir.clone());

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
                wss_config.tls_cert_pem =
                    Some(std::fs::read(cert_path).context("reading WSS TLS cert")?);
            }
            if let Some(ref key_path) = transport_config.wss_key_pem_path {
                wss_config.tls_key_pem =
                    Some(std::fs::read(key_path).context("reading WSS TLS key")?);
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
                    info!(
                        wss_port = port,
                        tls = true,
                        "WSS share server started (TLS)"
                    );
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

        // 9. Derive sharing key from master.key for directed sharing.
        let (sharing_secret, sharing_pubkey) = {
            let master_key_path = data_dir.join("master.key");
            match std::fs::read(&master_key_path) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut mk = [0u8; 32];
                    mk.copy_from_slice(&bytes);
                    match crate::crypto::keyderive::derive_sharing_key(&mk) {
                        Ok(secret) => {
                            let static_secret = x25519_dalek::StaticSecret::from(*secret);
                            let pubkey = x25519_dalek::PublicKey::from(&static_secret);
                            (*secret, *pubkey.as_bytes())
                        }
                        Err(_) => ([0u8; 32], [0u8; 32]),
                    }
                }
                _ => ([0u8; 32], [0u8; 32]),
            }
        };

        // 10. Bind HTTP bridge for web client access.
        let http_bridge_port = match http_bridge::HttpBridge::bind(
            ipc::HTTP_BRIDGE_DEFAULT_PORT,
            coord.clone(),
            queue.clone(),
            store.clone(),
            listen_addr_strings.clone(),
            wss_port,
            wss_tls_enabled,
            proxy_configured,
            proxy_type.clone(),
            obfs_quic_port,
            sharing_secret,
            sharing_pubkey,
            data_dir.clone(),
        )
        .await
        {
            Ok(bridge) => {
                let port = bridge.port();
                ipc::write_http_port_file(&data_dir, port).ok();
                info!(port, "HTTP bridge started");
                tokio::spawn(bridge.run());
                port
            }
            Err(e) => {
                warn!("HTTP bridge failed to start: {e}");
                0
            }
        };

        info!(
            port = control_port,
            http_port = http_bridge_port,
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
            http_bridge_port,
            sharing_secret,
            sharing_pubkey,
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

    /// Port the HTTP bridge is listening on (0 if not started).
    #[allow(dead_code)]
    pub fn http_bridge_port(&self) -> u16 {
        self.http_bridge_port
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
        let topology_rx = self
            .topology_rx
            .take()
            .expect("topology_rx already consumed");
        let mut shutdown_rx = self
            .shutdown_rx
            .take()
            .expect("shutdown_rx already consumed");

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
        let ipc_sharing_secret = self.sharing_secret;
        let ipc_sharing_pubkey = self.sharing_pubkey;
        let ipc_data_dir = self.data_dir.clone();
        let ipc_handle: JoinHandle<()> = tokio::spawn(async move {
            ipc_server_loop(
                listener,
                ipc_coord,
                ipc_queue,
                ipc_store,
                ipc_addrs,
                ipc_wss_port,
                ipc_wss_tls,
                ipc_proxy,
                ipc_proxy_type,
                ipc_obfs,
                ipc_sharing_secret,
                ipc_sharing_pubkey,
                ipc_data_dir,
            )
            .await;
        });

        // ── Event-driven replication engine ───────────────────────────────────
        let rep_coord = coord.clone();
        let rep_queue = queue.clone();
        let rep_data_dir = self.data_dir.clone();
        let rep_handle: JoinHandle<()> = tokio::spawn(async move {
            replication_engine(
                rep_coord,
                rep_queue,
                rep_success_rx,
                topology_rx,
                rep_data_dir,
            )
            .await;
        });

        // ── Wait for shutdown ─────────────────────────────────────────────────
        shutdown_rx.recv().await;
        info!("daemon shutdown signal received");

        ipc_handle.abort();
        rep_handle.abort();

        coord.shutdown().await;
        remove_port_file(&self.data_dir);
        ipc::remove_http_port_file(&self.data_dir);
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
    sharing_secret: [u8; 32],
    sharing_pubkey: [u8; 32],
    data_dir: PathBuf,
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
                let ss = sharing_secret;
                let sp = sharing_pubkey;
                let dd = data_dir.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_ipc_client(stream, c, q, s, la, wp, wt, pc, pt, oq, ss, sp, dd).await
                    {
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
    sharing_secret: [u8; 32],
    sharing_pubkey: [u8; 32],
    data_dir: PathBuf,
) -> Result<()> {
    let req: ControlRequest = read_frame(&mut stream).await?;
    let resp = process_request(
        req,
        coord,
        queue,
        store,
        listen_addrs,
        wss_port,
        wss_tls_enabled,
        proxy_configured,
        proxy_type,
        obfs_quic_port,
        sharing_secret,
        sharing_pubkey,
        data_dir,
    )
    .await;
    write_frame(&mut stream, &resp).await?;
    Ok(())
}

pub(crate) async fn process_request(
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
    sharing_secret: [u8; 32],
    sharing_pubkey: [u8; 32],
    data_dir: PathBuf,
) -> ControlResponse {
    match req {
        ControlRequest::Publish {
            data,
            data_shards,
            total_shards,
        } => {
            let params = DissolutionParams {
                data_shards: data_shards as usize,
                total_shards: total_shards as usize,
            };
            match publish_content(&data, params, &coord, &queue, &store, &listen_addrs).await {
                Ok(mid) => ControlResponse::Published { mid },
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::Get {
            mid,
            data_shards,
            total_shards,
        } => {
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
            let routing =
                coord
                    .routing_stats()
                    .await
                    .unwrap_or(crate::network::routing::RoutingStats {
                        total_peers: 0,
                        unreliable_peers: 0,
                        unique_prefixes: 0,
                        max_prefix_concentration: 0,
                        diversity_rejections: 0,
                        current_difficulty: 8,
                    });
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
                    rendezvous_descriptors: 0,
                    credentialed_descriptors: 0,
                    bbs_credentialed_descriptors: 0,
                    stale_descriptors: 0,
                    pseudonym_churn_rate: 0.0,
                    relay_peers_routable: 0,
                    relay_claimed: 0,
                    relay_observed: 0,
                    relay_verified: 0,
                    probed_fresh: 0,
                    forwarding_verified_count: 0,
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
            let ret_stats = coord.retrieval_stats();

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
                metric_onion_relay_peers: desc_stats.relay_peers_routable, // peers with onion keys and PeerId mapping
                nat_publicly_reachable: coord.nat_publicly_reachable().await.unwrap_or(false),
                retrieval_direct_attempts: ret_stats.direct_attempts,
                retrieval_direct_successes: ret_stats.direct_successes,
                retrieval_opportunistic_attempts: ret_stats.opportunistic_attempts,
                retrieval_opportunistic_relay_successes: ret_stats.opportunistic_relay_successes,
                retrieval_opportunistic_direct_fallbacks: ret_stats.opportunistic_direct_fallbacks,
                retrieval_required_attempts: ret_stats.required_attempts,
                retrieval_required_onion_successes: ret_stats.required_onion_successes,
                retrieval_required_relay_successes: ret_stats.required_relay_successes,
                retrieval_required_failures: ret_stats.required_failures,
                retrieval_rendezvous_attempts: ret_stats.rendezvous_attempts,
                retrieval_rendezvous_successes: ret_stats.rendezvous_successes,
                retrieval_rendezvous_failures: ret_stats.rendezvous_failures,
                retrieval_rendezvous_direct_fallbacks: ret_stats.rendezvous_direct_fallbacks,
                retrieval_rendezvous_onion_attempts: ret_stats.rendezvous_onion_attempts,
                retrieval_rendezvous_onion_successes: ret_stats.rendezvous_onion_successes,
                retrieval_rendezvous_onion_failures: ret_stats.rendezvous_onion_failures,
                retrieval_opportunistic_onion_successes: ret_stats.opportunistic_onion_successes,
                retrieval_opportunistic_onion_rendezvous_successes: ret_stats
                    .opportunistic_onion_rendezvous_successes,
                retrieval_opportunistic_rendezvous_successes: ret_stats
                    .opportunistic_rendezvous_successes,
                relay_probes_sent: ret_stats.relay_probes_sent,
                relay_probes_succeeded: ret_stats.relay_probes_succeeded,
                relay_probes_failed: ret_stats.relay_probes_failed,
                forwarding_probes_sent: ret_stats.forwarding_probes_sent,
                forwarding_probes_succeeded: ret_stats.forwarding_probes_succeeded,
                forwarding_probes_failed: ret_stats.forwarding_probes_failed,
                pre_retrieval_probes_run: ret_stats.pre_retrieval_probes_run,
                rendezvous_peers: desc_stats.rendezvous_descriptors,
                relay_tier_claimed: desc_stats.relay_claimed,
                relay_tier_observed: desc_stats.relay_observed,
                relay_tier_verified: desc_stats.relay_verified,
                probe_cache_fresh: desc_stats.probed_fresh,
                forwarding_verified_relays: desc_stats.forwarding_verified_count,
            })
        }

        ControlRequest::Wipe => match store.distress_wipe() {
            Ok(_) => {
                info!("distress wipe executed via IPC");
                ControlResponse::Wiped
            }
            Err(e) => ControlResponse::Error(format!("wipe failed: {e}")),
        },

        // ── Directed sharing ────────────────────────────────────────────
        ControlRequest::SharingKey => {
            let key = directed::format_sharing_key(&sharing_pubkey);
            let contact =
                directed::format_sharing_contact(&sharing_pubkey, &coord.peer_id().to_string());
            ControlResponse::SharingKey { key, contact }
        }

        ControlRequest::DirectedSend {
            recipient_contact,
            data,
            password,
            retention_secs,
            filename,
        } => {
            match process_directed_send(
                &sharing_secret,
                &recipient_contact,
                &data,
                &password,
                retention_secs,
                filename,
                &coord,
                &queue,
                &store,
                &listen_addrs,
                &data_dir,
            )
            .await
            {
                Ok(envelope_id) => ControlResponse::DirectedSent { envelope_id },
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::DirectedSendFile {
            recipient_contact,
            file_path,
            password,
            retention_secs,
            filename,
        } => {
            // Read the file directly — avoids JSON Vec<u8> bloat over IPC.
            let data = match std::fs::read(&file_path) {
                Ok(d) => d,
                Err(e) => {
                    return ControlResponse::Error(format!(
                        "cannot read file {file_path}: {e}"
                    ))
                }
            };
            let fname = filename.or_else(|| {
                std::path::Path::new(&file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_owned())
            });
            match process_directed_send(
                &sharing_secret,
                &recipient_contact,
                &data,
                &password,
                retention_secs,
                fname,
                &coord,
                &queue,
                &store,
                &listen_addrs,
                &data_dir,
            )
            .await
            {
                Ok(envelope_id) => ControlResponse::DirectedSent { envelope_id },
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::DirectedConfirm {
            envelope_id,
            challenge_code,
        } => match process_directed_confirm(
            &envelope_id,
            &challenge_code,
            &data_dir,
            &coord,
            &listen_addrs,
        )
        .await
        {
            Ok(_) => ControlResponse::DirectedConfirmed,
            Err(e) => ControlResponse::Error(e.to_string()),
        },

        ControlRequest::DirectedRetrieve {
            envelope_id,
            password,
        } => {
            match process_directed_retrieve(
                &sharing_secret,
                &envelope_id,
                &password,
                &coord,
                &data_dir,
            )
            .await
            {
                Ok((data, filename)) => ControlResponse::DirectedRetrieved { data, filename },
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::DirectedRetrieveToFile {
            envelope_id,
            password,
            output_path,
        } => {
            match process_directed_retrieve(
                &sharing_secret,
                &envelope_id,
                &password,
                &coord,
                &data_dir,
            )
            .await
            {
                Ok((data, filename)) => {
                    // Write decrypted content to the requested output path.
                    match std::fs::write(&output_path, &data) {
                        Ok(_) => ControlResponse::DirectedRetrievedToFile {
                            output_path,
                            filename,
                            bytes_written: data.len() as u64,
                        },
                        Err(e) => ControlResponse::Error(format!(
                            "cannot write to {output_path}: {e}"
                        )),
                    }
                }
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::DirectedRevoke { envelope_id } => {
            match process_directed_revoke(
                &envelope_id,
                &sharing_pubkey,
                &data_dir,
                &coord,
                &listen_addrs,
            )
            .await
            {
                Ok(_) => ControlResponse::DirectedRevoked,
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::DirectedInbox => {
            let inbox = match DirectedInbox::open(&data_dir) {
                Ok(i) => i,
                Err(e) => return ControlResponse::Error(format!("inbox open failed: {e}")),
            };
            let now = now_secs();
            inbox.expire_all(now);
            ControlResponse::DirectedInboxList(inbox.list_incoming())
        }

        ControlRequest::DirectedOutbox => {
            let inbox = match DirectedInbox::open(&data_dir) {
                Ok(i) => i,
                Err(e) => return ControlResponse::Error(format!("outbox open failed: {e}")),
            };
            let now = now_secs();
            inbox.expire_all(now);
            ControlResponse::DirectedOutboxList(inbox.list_outgoing())
        }
    }
}

// ─── Directed sharing helpers ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_directed_send(
    sender_secret: &[u8; 32],
    recipient_contact: &str,
    data: &[u8],
    password: &str,
    retention_secs: u64,
    filename: Option<String>,
    coord: &MiasmaCoordinator,
    queue: &Arc<Mutex<ReplicationQueue>>,
    store: &LocalShareStore,
    listen_addrs: &[String],
    data_dir: &std::path::Path,
) -> Result<String, MiasmaError> {
    // Parse recipient contact.
    let (recipient_pubkey, _peer_id_str) = directed::parse_sharing_contact(recipient_contact)?;

    // Create envelope and protected data.
    let retention = directed::RetentionPeriod::Custom(retention_secs);
    let (mut envelope, protected_data, envelope_key) = directed::create_envelope(
        sender_secret,
        &recipient_pubkey,
        password,
        retention,
        data,
        filename,
    )?;

    // Dissolve protected data and publish to network.
    let params = DissolutionParams {
        data_shards: 10,
        total_shards: 20,
    };
    let mid_str =
        publish_content(&protected_data, params, coord, queue, store, listen_addrs).await?;

    // Finalize envelope with the MID.
    directed::finalize_envelope(&mut envelope, &envelope_key, &mid_str, 10, 20)?;

    let envelope_id_hex = envelope.id_hex();

    // Save to outbox.
    let inbox = DirectedInbox::open(data_dir)
        .map_err(|e| MiasmaError::Storage(format!("open inbox: {e}")))?;
    inbox
        .save_outgoing(&envelope)
        .map_err(|e| MiasmaError::Storage(format!("save outgoing: {e}")))?;

    // Deliver envelope to recipient via P2P (best-effort).
    let recipient_peer_id_str = directed::parse_sharing_contact(recipient_contact)
        .map(|(_, pid)| pid)
        .unwrap_or_default();

    // Store recipient PeerId alongside outgoing envelope for later confirm.
    inbox.save_outgoing_peer_id(&envelope_id_hex, &recipient_peer_id_str);
    if let Ok(peer_id) = recipient_peer_id_str.parse::<libp2p::PeerId>() {
        let invite_req = directed::DirectedRequest::Invite {
            envelope: envelope.clone(),
        };
        match coord
            .send_directed_request(peer_id, listen_addrs.to_vec(), invite_req)
            .await
        {
            Ok(directed::DirectedResponse::InviteAccepted { .. }) => {
                info!(envelope_id = %envelope_id_hex, "directed invite delivered to recipient");
            }
            Ok(other) => {
                warn!(envelope_id = %envelope_id_hex, ?other, "directed invite: unexpected response");
            }
            Err(e) => {
                warn!(envelope_id = %envelope_id_hex, %e, "directed invite delivery failed (recipient may be offline)");
            }
        }
    }

    info!(envelope_id = %envelope_id_hex, "directed share created and published");
    Ok(envelope_id_hex)
}

async fn process_directed_confirm(
    envelope_id: &str,
    challenge_code: &str,
    data_dir: &std::path::Path,
    coord: &MiasmaCoordinator,
    listen_addrs: &[String],
) -> Result<(), MiasmaError> {
    let inbox = DirectedInbox::open(data_dir)
        .map_err(|e| MiasmaError::Storage(format!("open inbox: {e}")))?;

    // Load outgoing envelope (sender confirming their own send).
    let mut envelope = inbox
        .load_outgoing(envelope_id)
        .map_err(|e| MiasmaError::Storage(format!("load envelope: {e}")))?;

    // Load the stored recipient PeerId.
    let peer_id_str = inbox.load_outgoing_peer_id(envelope_id).ok_or_else(|| {
        MiasmaError::Storage("no recipient peer ID stored for this envelope".into())
    })?;
    let peer_id = peer_id_str
        .parse::<libp2p::PeerId>()
        .map_err(|e| MiasmaError::Storage(format!("invalid peer ID: {e}")))?;

    // Send Confirm request to recipient via P2P.
    let confirm_req = directed::DirectedRequest::Confirm {
        envelope_id: envelope.envelope_id,
        challenge_code: challenge_code.to_string(),
    };

    match coord
        .send_directed_request(peer_id, listen_addrs.to_vec(), confirm_req)
        .await
    {
        Ok(directed::DirectedResponse::Confirmed { .. }) => {
            envelope.state = directed::EnvelopeState::Confirmed;
            inbox
                .save_outgoing(&envelope)
                .map_err(|e| MiasmaError::Storage(format!("save: {e}")))?;
            info!(envelope_id, "directed share challenge confirmed via P2P");
            Ok(())
        }
        Ok(directed::DirectedResponse::ChallengeFailed {
            attempts_remaining, ..
        }) => {
            envelope.challenge_attempts_remaining = attempts_remaining;
            if attempts_remaining == 0 {
                envelope.state = directed::EnvelopeState::ChallengeFailed;
            }
            let _ = inbox.save_outgoing(&envelope);
            Err(MiasmaError::Storage(format!(
                "wrong challenge code ({attempts_remaining} attempts remaining)"
            )))
        }
        Ok(directed::DirectedResponse::Error(e)) => Err(MiasmaError::Storage(format!(
            "recipient rejected confirm: {e}"
        ))),
        Err(e) => Err(MiasmaError::Network(format!(
            "could not reach recipient: {e}"
        ))),
        _ => Err(MiasmaError::Storage("unexpected response".into())),
    }
}

async fn process_directed_retrieve(
    recipient_secret: &[u8; 32],
    envelope_id: &str,
    password: &str,
    coord: &MiasmaCoordinator,
    data_dir: &std::path::Path,
) -> Result<(Vec<u8>, Option<String>), MiasmaError> {
    let inbox = DirectedInbox::open(data_dir)
        .map_err(|e| MiasmaError::Storage(format!("open inbox: {e}")))?;

    let mut envelope = inbox
        .load_incoming(envelope_id)
        .map_err(|e| MiasmaError::Storage(format!("load envelope: {e}")))?;

    // Check state.
    if !envelope.state.is_retrievable() {
        return Err(MiasmaError::Storage(format!(
            "envelope not retrievable (state: {:?})",
            envelope.state
        )));
    }

    // Check expiry.
    if envelope.is_expired(now_secs()) {
        envelope.state = directed::EnvelopeState::Expired;
        let _ = inbox.save_incoming(&envelope);
        return Err(MiasmaError::Storage("envelope expired".into()));
    }

    // Check password attempts.
    if envelope.password_attempts_remaining == 0 {
        envelope.state = directed::EnvelopeState::PasswordFailed;
        let _ = inbox.save_incoming(&envelope);
        return Err(MiasmaError::Storage(
            "max password attempts exceeded".into(),
        ));
    }

    // Decrypt envelope payload to get MID.
    let payload = directed::decrypt_envelope_payload(recipient_secret, &envelope)?;

    // Derive content key (ECDH + password).
    let content_key = directed::derive_content_key(recipient_secret, &envelope, password)?;

    // Retrieve protected content from network.
    let mid = crate::crypto::hash::ContentId::from_str(&payload.mid)?;
    let params = DissolutionParams {
        data_shards: payload.data_shards as usize,
        total_shards: payload.total_shards as usize,
    };
    let protected_data = coord.retrieve_from_network(&mid, params).await?;

    // Decrypt with directed key.
    match directed::decrypt_directed_content(&content_key, &payload.content_nonce, &protected_data)
    {
        Ok(plaintext) => {
            envelope.state = directed::EnvelopeState::Retrieved;
            let _ = inbox.save_incoming(&envelope);
            inbox.cleanup_challenge(envelope_id);
            info!(envelope_id, "directed share retrieved successfully");
            Ok((plaintext, payload.filename))
        }
        Err(_) => {
            envelope.password_attempts_remaining =
                envelope.password_attempts_remaining.saturating_sub(1);
            if envelope.password_attempts_remaining == 0 {
                envelope.state = directed::EnvelopeState::PasswordFailed;
                inbox.cleanup_challenge(envelope_id);
            }
            let _ = inbox.save_incoming(&envelope);
            Err(MiasmaError::Encryption(format!(
                "wrong password ({} attempts remaining)",
                envelope.password_attempts_remaining
            )))
        }
    }
}

async fn process_directed_revoke(
    envelope_id: &str,
    sharing_pubkey: &[u8; 32],
    data_dir: &std::path::Path,
    coord: &MiasmaCoordinator,
    listen_addrs: &[String],
) -> Result<(), MiasmaError> {
    let inbox = DirectedInbox::open(data_dir)
        .map_err(|e| MiasmaError::Storage(format!("open inbox: {e}")))?;

    // Try outgoing (sender revoke).
    if let Ok(mut envelope) = inbox.load_outgoing(envelope_id) {
        if envelope.sender_pubkey == *sharing_pubkey {
            if envelope.state.is_terminal() {
                return Err(MiasmaError::Storage(format!(
                    "cannot revoke: envelope in terminal state ({:?})",
                    envelope.state
                )));
            }
            envelope.state = directed::EnvelopeState::SenderRevoked;
            inbox
                .save_outgoing(&envelope)
                .map_err(|e| MiasmaError::Storage(format!("save: {e}")))?;
            inbox.cleanup_challenge(envelope_id);

            // Propagate revocation to recipient via P2P (best-effort).
            if let Some(peer_id_str) = inbox.load_outgoing_peer_id(envelope_id) {
                if let Ok(peer_id) = peer_id_str.parse::<libp2p::PeerId>() {
                    let revoke_req = directed::DirectedRequest::SenderRevoke {
                        envelope_id: envelope.envelope_id,
                    };
                    match coord
                        .send_directed_request(peer_id, listen_addrs.to_vec(), revoke_req)
                        .await
                    {
                        Ok(directed::DirectedResponse::Revoked { .. }) => {
                            info!(envelope_id, "revocation propagated to recipient");
                        }
                        Ok(other) => {
                            warn!(envelope_id, ?other, "revocation: unexpected response");
                        }
                        Err(e) => {
                            warn!(envelope_id, %e, "revocation propagation failed (recipient may be offline)");
                        }
                    }
                }
            }

            info!(envelope_id, "directed share sender-revoked");
            return Ok(());
        }
    }

    // Try incoming (recipient delete).
    if let Ok(mut envelope) = inbox.load_incoming(envelope_id) {
        if envelope.recipient_pubkey == *sharing_pubkey {
            if envelope.state.is_terminal() {
                return Err(MiasmaError::Storage(format!(
                    "cannot delete: envelope in terminal state ({:?})",
                    envelope.state
                )));
            }
            envelope.state = directed::EnvelopeState::RecipientDeleted;
            inbox
                .save_incoming(&envelope)
                .map_err(|e| MiasmaError::Storage(format!("save: {e}")))?;
            inbox.cleanup_challenge(envelope_id);
            info!(envelope_id, "directed share recipient-deleted");
            return Ok(());
        }
    }

    Err(MiasmaError::Storage(format!(
        "envelope not found: {envelope_id}"
    )))
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
    queue
        .lock()
        .unwrap()
        .push(pending)
        .map_err(|e| MiasmaError::Storage(e.to_string()))?;

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
    data_dir: PathBuf,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(FALLBACK_TIMER_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // ── Primary: topology change ────────────────────────────────────
            Some(event) = topology_rx.recv() => {
                // Handle directed sharing events.
                match &event {
                    TopologyEvent::DirectedEnvelopeReceived { peer_id, envelope } => {
                        match directed::DirectedInbox::open(&data_dir) {
                            Ok(inbox) => {
                                // Save incoming envelope first.
                                if let Err(e) = inbox.save_incoming(envelope) {
                                    warn!(%peer_id, "failed to save incoming envelope: {e}");
                                } else {
                                    // Generate challenge code and update envelope state.
                                    let id_hex = envelope.id_hex();
                                    let (code, hash) = directed::generate_challenge();
                                    inbox.save_challenge_code(&id_hex, &code).unwrap_or_else(|e| {
                                        warn!(id = %id_hex, "failed to save challenge code: {e}");
                                    });
                                    if let Ok(mut env) = inbox.load_incoming(&id_hex) {
                                        env.state = directed::EnvelopeState::ChallengeIssued;
                                        env.challenge_hash = Some(hash);
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        env.challenge_expires_at = now + directed::CHALLENGE_TTL_SECS;
                                        let _ = inbox.save_incoming(&env);
                                    }
                                }
                                info!(%peer_id, id = %envelope.id_hex(), "directed envelope received and saved");
                            }
                            Err(e) => warn!(%peer_id, "failed to open inbox: {e}"),
                        }
                    }
                    TopologyEvent::DirectedRevokeReceived { envelope_id } => {
                        match directed::DirectedInbox::open(&data_dir) {
                            Ok(inbox) => {
                                let id_hex = hex::encode(envelope_id);
                                if let Err(e) = inbox.update_incoming_state(&id_hex, directed::EnvelopeState::SenderRevoked) {
                                    warn!(id = %id_hex, "failed to update revoked envelope: {e}");
                                }
                                info!(id = %id_hex, "directed envelope revoked by sender");
                            }
                            Err(e) => warn!("failed to open inbox for revocation: {e}"),
                        }
                    }
                    _ => {}
                }

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
