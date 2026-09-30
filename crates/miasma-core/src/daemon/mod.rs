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

pub mod control_auth;
pub mod http_bridge;
pub mod ipc;
pub mod rate_limit;
pub mod replication;
pub mod self_heal;
pub mod web_assets;

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
use zeroize::Zeroizing;

use crate::{
    config::TransportConfig,
    directed::{self, DirectedInbox},
    network::{
        connection_health::ConnectionHealthMonitor,
        coordinator::MiasmaCoordinator,
        environment::EnvironmentSnapshot,
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

pub(crate) type SharingSecretState = Arc<tokio::sync::RwLock<Option<zeroize::Zeroizing<[u8; 32]>>>>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Finalize the same full-content MID used by publish_file while consuming a
/// retrieval stream incrementally. This keeps 100 GB-class verification O(1)
/// in memory.
fn finalize_streamed_mid(
    mut hasher: blake3::Hasher,
    params: DissolutionParams,
) -> crate::crypto::hash::ContentId {
    hasher.update(&params.to_param_bytes());
    crate::crypto::hash::ContentId::from_digest(*hasher.finalize().as_bytes())
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
    /// WSS accept-loop task. Aborted and awaited during daemon shutdown/wipe.
    wss_server_handle: Option<JoinHandle<()>>,
    /// Whether a proxy is configured.
    proxy_configured: bool,
    /// Proxy type string (e.g. "socks5", "http_connect").
    proxy_type: Option<String>,
    /// Port the ObfuscatedQuic server is bound to (0 if not started).
    obfs_quic_port: u16,
    /// ObfuscatedQuic accept-loop task. Aborted and awaited on shutdown/wipe.
    obfs_server_handle: Option<JoinHandle<()>>,
    /// Port the HTTP bridge is bound to (0 if not started).
    #[allow(dead_code)]
    http_bridge_port: u16,
    /// HTTP bridge accept-loop task. Kept so daemon shutdown/distress wipe can
    /// stop accepting new local requests and release its shared state.
    http_bridge_handle: Option<JoinHandle<()>>,
    /// Shared X25519 sharing secret state. Distress wipe replaces the
    /// `Zeroizing` value with `None` after waiting for in-flight users.
    sharing_secret: SharingSecretState,
    /// X25519 sharing public key.
    sharing_pubkey: [u8; 32],
    /// Rate limiter shared with HTTP bridge.
    rate_limiter: Arc<Mutex<rate_limit::RateLimiter>>,
    /// Connection health monitor.
    health_monitor: Arc<Mutex<ConnectionHealthMonitor>>,
    /// Network environment snapshot (periodically updated).
    env_snapshot: Arc<Mutex<EnvironmentSnapshot>>,
    /// Whether Shadowsocks is configured.
    shadowsocks_configured: bool,
    /// Whether Tor is configured.
    tor_configured: bool,
    /// Control-channel token and wipe-challenge state.
    control_auth: Arc<control_auth::ControlAuth>,
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
        mut transport_config: TransportConfig,
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

        // Resolve all fallible daemon-owned security state before spawning any
        // auxiliary server task. A later startup error must not detach a server.
        let parsed_obfs_probe_secret = transport_config
            .parsed_obfuscated_quic_secret()
            .map_err(anyhow::Error::msg)?;
        let preflight_obfs_config = if transport_config.obfuscated_quic_enabled {
            let probe_secret = parsed_obfs_probe_secret
                .as_ref()
                .context("ObfuscatedQuic enabled without a parsed probe secret")?;
            Some(crate::transport::obfuscated::ObfuscatedConfig::new(
                **probe_secret,
                transport_config
                    .obfuscated_quic_sni
                    .as_deref()
                    .unwrap_or("cdn.example.com"),
                transport_config
                    .obfuscated_quic_fallback_url
                    .as_deref()
                    .unwrap_or("https://cdn.example.com"),
                crate::transport::obfuscated::BrowserFingerprint::Chrome124,
            ))
        } else {
            None
        };

        let (sharing_secret, sharing_pubkey) = {
            let master_key_path = data_dir.join("master.key");
            let master_bytes = zeroize::Zeroizing::new(
                std::fs::read(&master_key_path)
                    .with_context(|| format!("cannot read {}", master_key_path.display()))?,
            );
            if master_bytes.len() != 32 {
                anyhow::bail!("{} has wrong length", master_key_path.display());
            }
            let mut master_key = zeroize::Zeroizing::new([0u8; 32]);
            master_key.copy_from_slice(&master_bytes);
            if master_key.iter().all(|byte| *byte == 0) {
                anyhow::bail!("{} is erased/all-zero", master_key_path.display());
            }
            let secret = crate::crypto::keyderive::derive_sharing_key(master_key.as_ref())
                .context("cannot derive directed-sharing key")?;
            let static_secret = x25519_dalek::StaticSecret::from(*secret);
            let pubkey = x25519_dalek::PublicKey::from(&static_secret);
            (
                Arc::new(tokio::sync::RwLock::new(Some(secret))),
                *pubkey.as_bytes(),
            )
        };
        node.set_directed_recipient_pubkey(sharing_pubkey);

        let queue = Arc::new(Mutex::new(ReplicationQueue::load_or_create(&data_dir)?));

        // Consume the serialized Shadowsocks credential exactly once. The
        // runtime transport keeps only a zeroizing decoded PSK.
        let shadowsocks_transport = if transport_config.shadowsocks.enabled {
            let shadowsocks_config = std::mem::take(&mut transport_config.shadowsocks);
            match crate::transport::shadowsocks::ShadowsocksPayloadTransport::new(
                shadowsocks_config,
            ) {
                Ok(transport) => Some(transport),
                Err(e) => {
                    warn!("Shadowsocks config invalid: {e}");
                    None
                }
            }
        } else {
            None
        };
        let shadowsocks_configured = shadowsocks_transport.is_some();

        // Convert serialized proxy credentials into the runtime proxy before
        // zeroizing the config copies. Reject partial/unknown proxy settings
        // instead of silently downgrading them to unauthenticated SOCKS5.
        let proxy_type = transport_config.proxy_type.clone();
        let mut runtime_proxy = match (
            proxy_type.as_deref(),
            transport_config.proxy_addr.as_deref(),
        ) {
            (None, None) => None,
            (None, Some(_)) => anyhow::bail!("proxy address configured without proxy type"),
            (Some(_), None) => anyhow::bail!("proxy type configured without proxy address"),
            (Some("socks5"), Some(addr)) => Some(crate::transport::proxy::ProxyConfig::socks5(
                addr,
                transport_config.proxy_username.take(),
                transport_config.proxy_password.take(),
            )),
            (Some("http-connect"), Some(addr)) | (Some("http_connect"), Some(addr)) => {
                Some(crate::transport::proxy::ProxyConfig::http_connect(
                    addr,
                    transport_config.proxy_username.take(),
                    transport_config.proxy_password.take(),
                ))
            }
            (Some(other), Some(_)) => anyhow::bail!("unsupported proxy type '{other}'"),
        };
        let proxy_configured = runtime_proxy.is_some();

        // The parsed/runtime forms above now own every secret that is actually
        // needed. Erase serialized/base64/hex copies before any server is spawned.
        transport_config.zeroize_secret_copies();

        // 6. Build extra transports based on config.
        let mut extra_transports: Vec<Box<dyn PayloadTransport>> = Vec::new();

        // 6a. WSS share server.
        let wss_tls_enabled = transport_config.wss_tls_enabled;
        let mut wss_config = crate::transport::websocket::WebSocketConfig {
            tls_enabled: wss_tls_enabled,
            ..Default::default()
        };
        // Keep server private-key bytes out of the client transport config.
        // The source PEM buffer is zeroized immediately after server bind.
        let wss_cert_pem = if wss_tls_enabled {
            match transport_config.wss_cert_pem_path.as_deref() {
                Some(cert_path) => Some(std::fs::read(cert_path).context("reading WSS TLS cert")?),
                None => None,
            }
        } else {
            None
        };
        let wss_key_pem = if wss_tls_enabled {
            match transport_config.wss_key_pem_path.as_deref() {
                Some(key_path) => Some(zeroize::Zeroizing::new(
                    std::fs::read(key_path).context("reading WSS TLS key")?,
                )),
                None => None,
            }
        } else {
            None
        };
        // Publish the control port only after every fallible preflight step has
        // succeeded. A failed start must never leave a stale daemon.port file.
        // The control token is written first: clients wait for daemon.port and
        // then read the token, so it must already be there.
        let control_auth = Arc::new(control_auth::ControlAuth::new(
            control_auth::ControlToken::generate(),
        ));
        control_auth::write_token_file(&data_dir, control_auth.token())?;
        if let Err(e) = write_port_file(&data_dir, control_port) {
            control_auth::remove_token_file(&data_dir);
            return Err(e);
        }
        if let Some(ref sni) = transport_config.wss_sni {
            wss_config.sni_override = Some(sni.clone());
        }
        let (wss_port, wss_server_handle) = if wss_tls_enabled {
            let cert_pem: &[u8] = wss_cert_pem.as_deref().unwrap_or_default();
            let key_pem: &[u8] = wss_key_pem
                .as_ref()
                .map(|pem| pem.as_slice())
                .unwrap_or_default();
            match crate::transport::websocket::WssShareServer::bind_tls(
                store.clone(),
                transport_config.wss_port,
                cert_pem,
                key_pem,
            )
            .await
            {
                Ok(server) => {
                    let server = server.with_record_provider(Arc::new(node.dht_handle()));
                    let port = server.port;
                    let handle = tokio::spawn(server.run());
                    info!(
                        wss_port = port,
                        tls = true,
                        "WSS share server started (TLS)"
                    );
                    let mut client_config = wss_config.clone();
                    client_config.port = port;
                    extra_transports.push(Box::new(
                        crate::transport::websocket::WssPayloadTransport::new_with_runtime_proxy(
                            client_config,
                            runtime_proxy.take(),
                        ),
                    ));
                    (port, Some(handle))
                }
                Err(e) => {
                    warn!("WSS TLS share server failed to start: {e}");
                    (0, None)
                }
            }
        } else {
            match crate::transport::websocket::WssShareServer::bind(
                store.clone(),
                transport_config.wss_port,
            )
            .await
            {
                Ok(server) => {
                    let server = server.with_record_provider(Arc::new(node.dht_handle()));
                    let port = server.port;
                    let handle = tokio::spawn(server.run());
                    info!(wss_port = port, "WSS share server started");
                    let mut client_config = wss_config.clone();
                    client_config.port = port;
                    extra_transports.push(Box::new(
                        crate::transport::websocket::WssPayloadTransport::new_with_runtime_proxy(
                            client_config,
                            runtime_proxy.take(),
                        ),
                    ));
                    (port, Some(handle))
                }
                Err(e) => {
                    warn!("WSS share server failed to start: {e}");
                    (0, None)
                }
            }
        };
        drop(wss_key_pem);

        // 6b. ObfuscatedQuic server.
        let mut obfs_quic_port = 0u16;
        let mut obfs_server_handle: Option<JoinHandle<()>> = None;
        if let Some(obfs_config) = preflight_obfs_config {
            match crate::transport::obfuscated::ObfuscatedQuicServer::bind(
                store.clone(),
                0,
                obfs_config.clone(),
            )
            .await
            {
                Ok(server) => {
                    obfs_quic_port = server.port;
                    obfs_server_handle = Some(tokio::spawn(server.run()));
                    info!(port = obfs_quic_port, "ObfuscatedQuic server started");
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

        // 6c. Shadowsocks transport (config-driven, always compiled).
        if let Some(transport) = shadowsocks_transport {
            info!(
                server = ?transport.server_addr(),
                cipher = transport.cipher(),
                "Shadowsocks transport configured"
            );
            extra_transports.push(Box::new(transport));
        }

        // 6d. Tor transport (config-driven, always compiled).
        let tor_configured = transport_config.tor.is_configured();
        if tor_configured {
            match crate::transport::tor::TorPayloadTransport::new(transport_config.tor.clone()) {
                Ok(transport) => {
                    info!(
                        mode = transport.mode_name(),
                        bridges = transport.has_bridges(),
                        "Tor transport configured"
                    );
                    extra_transports.push(Box::new(transport));
                }
                Err(e) => {
                    warn!("Tor config invalid: {e}");
                }
            }
        }

        // 7. Start the coordinator with all transports. All fallible daemon-owned
        // preflight work has already completed before auxiliary task spawn.
        let coord = Arc::new(
            MiasmaCoordinator::start_with_transports(
                node,
                store.clone(),
                listen_addr_strings.clone(),
                extra_transports,
            )
            .await,
        );

        // 8. Create shared rate limiter, health monitor, environment snapshot.
        let rate_limiter = Arc::new(Mutex::new(rate_limit::RateLimiter::default()));
        let health_monitor = Arc::new(Mutex::new(ConnectionHealthMonitor::default()));
        let env_snapshot = Arc::new(Mutex::new(EnvironmentSnapshot::default()));

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        // 10. Bind HTTP bridge for web client access.
        let (http_bridge_port, http_bridge_handle) = match http_bridge::HttpBridge::bind(
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
            sharing_secret.clone(),
            sharing_pubkey,
            data_dir.clone(),
            BridgeLiveState {
                rate_limiter: rate_limiter.clone(),
                health_monitor: health_monitor.clone(),
                env_snapshot: env_snapshot.clone(),
                shadowsocks_configured,
                tor_configured,
                daemon_shutdown_tx: shutdown_tx.clone(),
                control_auth: control_auth.clone(),
            },
        )
        .await
        {
            Ok(bridge) => {
                let port = bridge.port();
                ipc::write_http_port_file(&data_dir, port).ok();
                info!(port, "HTTP bridge started");
                (port, Some(tokio::spawn(bridge.run())))
            }
            Err(e) => {
                warn!("HTTP bridge failed to start: {e}");
                (0, None)
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
            wss_server_handle,
            proxy_configured,
            proxy_type,
            obfs_quic_port,
            obfs_server_handle,
            http_bridge_port,
            http_bridge_handle,
            sharing_secret,
            sharing_pubkey,
            rate_limiter,
            health_monitor,
            env_snapshot,
            shadowsocks_configured,
            tor_configured,
            listener: Some(listener),
            rep_success_rx: Some(rep_rx),
            topology_rx: Some(topo_rx),
            control_auth,
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

    /// Whether the WSS share server terminates TLS itself. `false` means plain
    /// WS, meant to sit behind a tunnel that terminates TLS.
    pub fn wss_tls_enabled(&self) -> bool {
        self.wss_tls_enabled
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
        let ipc_sharing_secret = self.sharing_secret.clone();
        let ipc_sharing_pubkey = self.sharing_pubkey;
        let ipc_data_dir = self.data_dir.clone();
        let ipc_bridge_state = BridgeLiveState {
            rate_limiter: self.rate_limiter.clone(),
            health_monitor: self.health_monitor.clone(),
            env_snapshot: self.env_snapshot.clone(),
            shadowsocks_configured: self.shadowsocks_configured,
            tor_configured: self.tor_configured,
            daemon_shutdown_tx: self.shutdown_tx.clone(),
            control_auth: self.control_auth.clone(),
        };
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
                ipc_bridge_state,
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

        // ── Periodic environment detection task ─────────────────────────────
        let env_coord = coord.clone();
        let env_snapshot = self.env_snapshot.clone();
        let env_handle: JoinHandle<()> = tokio::spawn(async move {
            environment_detector_loop(env_coord, env_snapshot).await;
        });

        // ── Wait for shutdown ─────────────────────────────────────────────────
        shutdown_rx.recv().await;
        info!("daemon shutdown signal received");

        ipc_handle.abort();
        rep_handle.abort();
        env_handle.abort();
        for handle in [
            self.wss_server_handle.take(),
            self.obfs_server_handle.take(),
            self.http_bridge_handle.take(),
        ]
        .into_iter()
        .flatten()
        {
            handle.abort();
            let _ = handle.await;
        }

        coord.shutdown().await;
        remove_port_file(&self.data_dir);
        control_auth::remove_token_file(&self.data_dir);
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
    sharing_secret: SharingSecretState,
    sharing_pubkey: [u8; 32],
    data_dir: PathBuf,
    bridge_state: BridgeLiveState,
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
                let ss = sharing_secret.clone();
                let sp = sharing_pubkey;
                let dd = data_dir.clone();
                let bs = bridge_state.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_ipc_client(stream, c, q, s, la, wp, wt, pc, pt, oq, ss, sp, dd, bs)
                            .await
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
    sharing_secret: SharingSecretState,
    sharing_pubkey: [u8; 32],
    data_dir: PathBuf,
    bridge_state: BridgeLiveState,
) -> Result<()> {
    // Authenticate before anything else is parsed: the first frame must be a
    // small ControlAuth frame carrying the token. Any other first frame, a
    // wrong token, or a slow peer is answered with an error (after a delay
    // that grows with consecutive failures) and disconnected without a
    // request ever being deserialised or processed.
    let auth_result = tokio::time::timeout(
        control_auth::PRE_AUTH_TIMEOUT,
        ipc::read_frame_limited::<ipc::ControlAuth>(&mut stream, control_auth::PRE_AUTH_FRAME_MAX),
    )
    .await;
    let denial = match auth_result {
        Ok(Ok(hello)) => {
            let hello = Zeroizing::new(hello);
            bridge_state.control_auth.check(&hello.token).err()
        }
        // Not an auth frame / oversize / timeout: count it as a failure too.
        _ => Some(
            bridge_state
                .control_auth
                .check("")
                .err()
                .unwrap_or(std::time::Duration::from_millis(100)),
        ),
    };
    if let Some(delay) = denial {
        tokio::time::sleep(delay).await;
        let _ = write_frame(
            &mut stream,
            &ControlResponse::Error(
                "unauthorized: missing or invalid control token (see daemon.token in the data dir)"
                    .into(),
            ),
        )
        .await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
        return Ok(());
    }
    let req: ControlRequest = read_frame(&mut stream).await?;
    let mut resp = process_request(
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
        bridge_state,
    )
    .await;
    let write_result = write_frame(&mut stream, &resp).await;
    resp.zeroize_sensitive_material();
    write_result?;
    Ok(())
}

/// Bridge superhardening live state passed into request processing.
#[derive(Clone)]
pub struct BridgeLiveState {
    pub rate_limiter: Arc<Mutex<rate_limit::RateLimiter>>,
    pub health_monitor: Arc<Mutex<ConnectionHealthMonitor>>,
    pub env_snapshot: Arc<Mutex<EnvironmentSnapshot>>,
    pub shadowsocks_configured: bool,
    pub tor_configured: bool,
    /// Outer daemon lifecycle signal. A successful distress wipe uses this to
    /// terminate IPC/HTTP/network tasks so master-derived identity material in
    /// the libp2p swarm is dropped as part of the wipe boundary.
    pub daemon_shutdown_tx: mpsc::Sender<()>,
    /// Control token (checked on every IPC connection and HTTP bridge request)
    /// and the outstanding `Wipe` confirmation challenge.
    pub control_auth: Arc<control_auth::ControlAuth>,
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
    sharing_secret: SharingSecretState,
    sharing_pubkey: [u8; 32],
    data_dir: PathBuf,
    bridge_state: BridgeLiveState,
) -> ControlResponse {
    match req {
        ControlRequest::Publish {
            data,
            data_shards,
            total_shards,
        } => {
            let data = Zeroizing::new(data);
            let params = DissolutionParams {
                data_shards: data_shards as usize,
                total_shards: total_shards as usize,
            };
            match publish_content(
                data.as_slice(),
                params,
                &coord,
                &queue,
                &store,
                &listen_addrs,
            )
            .await
            {
                Ok(mid) => ControlResponse::Published { mid },
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::PublishFile {
            file_path,
            data_shards,
            total_shards,
        } => {
            let params = DissolutionParams {
                data_shards: data_shards as usize,
                total_shards: total_shards as usize,
            };
            let path = std::path::Path::new(&file_path);
            match coord.dissolve_and_publish_file(path, params).await {
                Ok(mid) => ControlResponse::Published {
                    mid: mid.to_string(),
                },
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::PublishFileProtected {
            file_path,
            data_shards,
            total_shards,
            password,
        } => {
            // Wiped from memory when this arm ends.
            let password = Zeroizing::new(password);
            let params = DissolutionParams {
                data_shards: data_shards as usize,
                total_shards: total_shards as usize,
            };
            let path = std::path::Path::new(&file_path);
            match coord
                .dissolve_and_publish_file_protected(
                    path,
                    params,
                    crate::network::PublishOptions::default(),
                    password.as_str(),
                )
                .await
            {
                Ok(report) => ControlResponse::Published {
                    mid: report.mid.to_string(),
                },
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::TransferStartReceive {
            mid,
            output_path,
            password,
            restart,
            via,
            via_ca_pem,
        } => {
            let password = password.map(Zeroizing::new);
            let output_path = match control_auth::validate_output_path(&output_path) {
                Ok(p) => p,
                Err(e) => return ControlResponse::Error(format!("output path rejected: {e}")),
            };
            // Refuse a bad endpoint list now, with a clear message, rather than
            // starting a job that can only fail.
            let via = crate::transfer::direct::ViaConfig::from_request(via, via_ca_pem);
            if let Some(v) = &via {
                if let Err(e) = v.build_clients() {
                    return ControlResponse::Error(e.to_string());
                }
            }
            match crate::crypto::hash::ContentId::from_str(&mid) {
                Ok(content_id) => {
                    let registry = crate::transfer::jobs::registry_for(&data_dir);
                    let id = registry.start_receive(
                        coord.clone(),
                        content_id,
                        output_path,
                        password,
                        restart,
                        via,
                    );
                    ControlResponse::TransferStarted { id }
                }
                Err(e) => ControlResponse::Error(format!("invalid MID: {e}")),
            }
        }

        ControlRequest::TransferStartPublish {
            file_path,
            data_shards,
            total_shards,
            password,
            restart,
        } => {
            let password = password.map(Zeroizing::new);
            let params = DissolutionParams {
                data_shards: data_shards as usize,
                total_shards: total_shards as usize,
            };
            let registry = crate::transfer::jobs::registry_for(&data_dir);
            let id = registry.start_publish(
                coord.clone(),
                PathBuf::from(file_path),
                params,
                password,
                restart,
            );
            ControlResponse::TransferStarted { id }
        }

        ControlRequest::TransferStatus { id } => {
            match crate::transfer::jobs::registry_for(&data_dir).status(&id) {
                Some(status) => ControlResponse::TransferStatus(status),
                None => ControlResponse::Error(format!("no such transfer: {id}")),
            }
        }

        ControlRequest::TransferList => {
            ControlResponse::TransferList(crate::transfer::jobs::registry_for(&data_dir).list())
        }

        ControlRequest::TransferCancel { id } => {
            if crate::transfer::jobs::registry_for(&data_dir).cancel(&id) {
                ControlResponse::TransferCancelled
            } else {
                ControlResponse::Error(format!("no running transfer: {id}"))
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

        ControlRequest::GetToFile {
            mid,
            data_shards,
            total_shards,
            output_path,
        } => {
            let params = DissolutionParams {
                data_shards: data_shards as usize,
                total_shards: total_shards as usize,
            };
            match crate::crypto::hash::ContentId::from_str(&mid) {
                Ok(content_id) => {
                    match coord
                        .retrieve_from_network_streaming(&content_id, params)
                        .await
                    {
                        Ok(mut stream) => {
                            use futures::StreamExt;
                            use tokio::io::AsyncWriteExt;

                            match tokio::fs::File::create(&output_path).await {
                                Ok(mut file) => {
                                    let mut bytes_written: u64 = 0;
                                    let mut write_err: Option<String> = None;
                                    let mut content_hasher = blake3::Hasher::new();
                                    while let Some(chunk) = stream.next().await {
                                        match chunk {
                                            Ok(bytes) => {
                                                content_hasher.update(&bytes);
                                                match file.write_all(&bytes).await {
                                                    Ok(_) => bytes_written += bytes.len() as u64,
                                                    Err(e) => {
                                                        write_err = Some(format!(
                                                            "cannot write to {output_path}: {e}"
                                                        ));
                                                        break;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                write_err = Some(e.to_string());
                                                break;
                                            }
                                        }
                                    }
                                    // The streaming network path reconstructs and authenticates
                                    // each segment independently, but it intentionally cannot
                                    // verify the full-file MID itself without buffering the
                                    // whole file. Verify the complete plaintext here while the
                                    // bytes are already flowing to disk. A mismatch is a hard
                                    // failure and the partial output is removed below.
                                    if write_err.is_none() {
                                        let actual_mid =
                                            finalize_streamed_mid(content_hasher, params);
                                        if actual_mid != content_id {
                                            write_err = Some(format!(
                                                "streamed retrieval MID mismatch: expected {}, got {}",
                                                content_id.to_string(),
                                                actual_mid.to_string()
                                            ));
                                        }
                                    }

                                    // Explicit flush before declaring success: tokio::fs::File
                                    // writes are dispatched to a blocking-pool thread, so a
                                    // caller reading the file back immediately after this
                                    // response returns is racing that thread unless we wait
                                    // for it here. Caught by CI (not local runs) on a slower/
                                    // more contended runner -- exactly the kind of gap that
                                    // wouldn't show up until the disk I/O is slow enough for
                                    // the read to land first.
                                    if write_err.is_none() {
                                        if let Err(e) = file.flush().await {
                                            write_err =
                                                Some(format!("cannot flush {output_path}: {e}"));
                                        }
                                    }
                                    match write_err {
                                        None => ControlResponse::RetrievedToFile {
                                            output_path,
                                            bytes_written,
                                        },
                                        Some(msg) => {
                                            // A partially-written file on disk would
                                            // silently look like a valid (if short)
                                            // file to anything reading it later --
                                            // unlike the buffered DirectedRetrieveToFile
                                            // path, which only ever writes once
                                            // everything is already reconstructed in
                                            // memory. Remove it rather than leave
                                            // truncated content behind.
                                            drop(file);
                                            let _ = tokio::fs::remove_file(&output_path).await;
                                            ControlResponse::Error(msg)
                                        }
                                    }
                                }
                                Err(e) => ControlResponse::Error(format!(
                                    "cannot create {output_path}: {e}"
                                )),
                            }
                        }
                        Err(e) => ControlResponse::Error(e.to_string()),
                    }
                }
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
            let reconn_metrics = coord.reconnection_metrics().await.unwrap_or_default();
            let dir_relay = coord.directed_relay_stats().await.unwrap_or_default();

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
                path_available_relays: path_stats.available_relays,
                path_relay_prefix_diversity: path_stats.relay_prefix_diversity,
                anonymity_policy: coord.anonymity_policy().to_string(),
                metric_relay_prefix_diversity: outcome.relay_prefix_diversity,
                metric_credentialed_fraction: outcome.credentialed_peer_fraction,
                metric_multi_path_retrievability: outcome.multi_path_retrievability,
                metric_pow_difficulty: outcome.current_pow_difficulty,
                metric_verification_ratio: outcome.verification_ratio,
                metric_rejection_rate: outcome.admission_rejection_rate,
                metric_pseudonym_churn_rate: outcome.pseudonym_churn_rate,
                metric_relay_peers_routable: outcome.relay_peers_routable,
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
                // Directed sharing relay fallback (ADR-010 Part 2)
                directed_direct_sends: dir_relay.direct_sends,
                directed_relay_fallback_attempts: dir_relay.relay_fallback_attempts,
                directed_relay_circuits_registered: dir_relay.relay_circuits_registered,
                directed_no_relay_candidates: dir_relay.no_relay_candidates,
                // Connection health — from live node monitor (fallback to shared mutex)
                connection_quality_score: {
                    match coord.health_snapshot().await {
                        Ok(snap) => snap.quality_score,
                        Err(_) => {
                            let hm = bridge_state.health_monitor.lock().unwrap();
                            hm.average_quality()
                        }
                    }
                },
                dial_backoff_addresses: {
                    match coord.health_snapshot().await {
                        Ok(snap) => snap.backoff_addresses,
                        Err(_) => {
                            let hm = bridge_state.health_monitor.lock().unwrap();
                            hm.backoff.active_count()
                        }
                    }
                },
                stale_addresses_pruned: {
                    match coord.health_snapshot().await {
                        Ok(snap) => snap.addresses_pruned,
                        Err(_) => {
                            let hm = bridge_state.health_monitor.lock().unwrap();
                            hm.pruner.pruned_count
                        }
                    }
                },
                connectivity_degraded: {
                    match coord.health_snapshot().await {
                        Ok(snap) => snap.degraded,
                        Err(_) => {
                            let hm = bridge_state.health_monitor.lock().unwrap();
                            hm.is_degraded(peer_count)
                        }
                    }
                },
                active_transport: coord
                    .transport_stats()
                    .last_selected()
                    .map(|s| s.to_string()),
                fallback_active: coord.transport_stats().is_fallback_active(),
                // Self-healing — from live node flap detector
                flap_damping_active: coord.flap_damping_active().await.unwrap_or(false),
                rate_limit_rejections: {
                    let rl = bridge_state.rate_limiter.lock().unwrap();
                    rl.rejections
                },
                partial_failures: coord.partial_failures().await.unwrap_or_default(),
                // Censorship resistance
                shadowsocks_configured: bridge_state.shadowsocks_configured,
                tor_configured: bridge_state.tor_configured,
                // Network environment — from live snapshot
                network_environment: {
                    let env = bridge_state.env_snapshot.lock().unwrap();
                    env.environment.to_string()
                },
                tls_inspection_detected: {
                    let env = bridge_state.env_snapshot.lock().unwrap();
                    env.capabilities.tls_inspection_detected
                },
                captive_portal_detected: {
                    let env = bridge_state.env_snapshot.lock().unwrap();
                    env.capabilities.captive_portal_detected
                },
                vpn_detected: {
                    let env = bridge_state.env_snapshot.lock().unwrap();
                    env.capabilities.vpn_detected
                },
                // ── Reconnection metrics (single fetch) ──────────────────
                reconnection_attempts: reconn_metrics.attempts,
                reconnection_successes: reconn_metrics.successes,
                reconnection_failures: reconn_metrics.failures,
                reconnection_circuit_breaker_trips: reconn_metrics.circuit_breaker_trips,
                reconnection_recovery_actions: reconn_metrics.recovery_actions_triggered,
            })
        }

        ControlRequest::Wipe => ControlResponse::WipeChallenge {
            nonce: bridge_state.control_auth.issue_wipe_challenge(),
        },

        ControlRequest::WipeConfirm { nonce } => {
            let nonce = Zeroizing::new(nonce);
            if !bridge_state
                .control_auth
                .consume_wipe_challenge(nonce.as_str())
            {
                return ControlResponse::Error(
                    "wipe not confirmed: missing, expired or wrong confirmation nonce".into(),
                );
            }
            // Wipe store key material first, then take the exclusive directed-key
            // lock. The write lock waits for every in-flight send/retrieve read
            // guard before Zeroizing the final shared secret copy.
            let store_result = store.distress_wipe();
            let mut directed_key = sharing_secret.write().await;
            *directed_key = None;
            // Once key erasure starts, the runtime must not remain alive even
            // if a later disk/config cleanup step fails. The detached request
            // handler can still write the final Wiped/Error response.
            let _ = bridge_state.daemon_shutdown_tx.try_send(());
            match store_result {
                Ok(_) => {
                    info!("distress wipe executed; in-memory keys erased; shutting down daemon");
                    ControlResponse::Wiped
                }
                Err(e) => {
                    warn!("distress wipe incomplete; runtime still shutting down: {e}");
                    ControlResponse::Error(format!("wipe incomplete; daemon is shutting down: {e}"))
                }
            }
        }

        // ── Directed sharing ────────────────────────────────────────────
        ControlRequest::SharingKey => {
            let key_guard = sharing_secret.read().await;
            if key_guard.is_none() {
                ControlResponse::Error("directed sharing unavailable after distress wipe".into())
            } else {
                let key = directed::format_sharing_key(&sharing_pubkey);
                let contact =
                    directed::format_sharing_contact(&sharing_pubkey, &coord.peer_id().to_string());
                ControlResponse::SharingKey { key, contact }
            }
        }

        ControlRequest::DirectedSend {
            recipient_contact,
            data,
            password,
            retention_secs,
            filename,
        } => {
            let data = Zeroizing::new(data);
            let password = Zeroizing::new(password);
            let key_guard = sharing_secret.read().await;
            let Some(secret) = key_guard.as_ref() else {
                return ControlResponse::Error(
                    "directed sharing unavailable after distress wipe".into(),
                );
            };
            match process_directed_send(
                &**secret,
                &recipient_contact,
                data.as_slice(),
                password.as_str(),
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
            let password = Zeroizing::new(password);
            // Read the file directly — avoids JSON Vec<u8> bloat over IPC.
            let data = match std::fs::read(&file_path) {
                Ok(d) => Zeroizing::new(d),
                Err(e) => {
                    return ControlResponse::Error(format!("cannot read file {file_path}: {e}"))
                }
            };
            let fname = filename.or_else(|| {
                std::path::Path::new(&file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_owned())
            });
            let key_guard = sharing_secret.read().await;
            let Some(secret) = key_guard.as_ref() else {
                return ControlResponse::Error(
                    "directed sharing unavailable after distress wipe".into(),
                );
            };
            match process_directed_send(
                &**secret,
                &recipient_contact,
                data.as_slice(),
                password.as_str(),
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
        } => {
            let challenge_code = Zeroizing::new(challenge_code);
            match process_directed_confirm(
                &envelope_id,
                challenge_code.as_str(),
                &data_dir,
                &coord,
                &listen_addrs,
            )
            .await
            {
                Ok(_) => ControlResponse::DirectedConfirmed,
                Err(e) => ControlResponse::Error(e.to_string()),
            }
        }

        ControlRequest::DirectedRetrieve {
            envelope_id,
            password,
        } => {
            let password = Zeroizing::new(password);
            let key_guard = sharing_secret.read().await;
            let Some(secret) = key_guard.as_ref() else {
                return ControlResponse::Error(
                    "directed sharing unavailable after distress wipe".into(),
                );
            };
            match process_directed_retrieve(
                &**secret,
                &envelope_id,
                password.as_str(),
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
            let password = Zeroizing::new(password);
            let key_guard = sharing_secret.read().await;
            let Some(secret) = key_guard.as_ref() else {
                return ControlResponse::Error(
                    "directed sharing unavailable after distress wipe".into(),
                );
            };
            match process_directed_retrieve(
                &**secret,
                &envelope_id,
                password.as_str(),
                &coord,
                &data_dir,
            )
            .await
            {
                Ok((data, filename)) => {
                    let data = Zeroizing::new(data);
                    // Write decrypted content to the requested output path.
                    match std::fs::write(&output_path, data.as_slice()) {
                        Ok(_) => ControlResponse::DirectedRetrievedToFile {
                            output_path,
                            filename,
                            bytes_written: data.len() as u64,
                        },
                        Err(e) => {
                            ControlResponse::Error(format!("cannot write to {output_path}: {e}"))
                        }
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
            segment_index: s.segment_index,
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
                                // Save the envelope and bind it to the authenticated
                                // libp2p sender. Follow-up Confirm/Revoke requests are
                                // authorized against this immutable sidecar binding.
                                let id_hex = envelope.id_hex();
                                let peer_id_text = peer_id.to_string();
                                let already_exists = inbox.load_incoming(&id_hex).is_ok();
                                if already_exists {
                                    if inbox.incoming_peer_is_bound(&id_hex, &peer_id_text) {
                                        debug!(%peer_id, id = %id_hex, "duplicate directed invite ignored");
                                    } else {
                                        warn!(%peer_id, id = %id_hex, "directed invite rejected: existing envelope has no matching sender binding");
                                    }
                                } else if let Err(e) = inbox.bind_incoming_peer_id(&id_hex, &peer_id_text) {
                                    warn!(%peer_id, "failed to bind incoming envelope sender: {e}");
                                } else if let Err(e) = inbox.save_incoming(envelope) {
                                    warn!(%peer_id, "failed to save incoming envelope: {e}");
                                } else {
                                    // Generate challenge code and normalize security-sensitive
                                    // state locally instead of trusting sender-supplied counters.
                                    let (code, hash) = directed::generate_challenge();
                                    let code = Zeroizing::new(code);
                                    inbox.save_challenge_code(&id_hex, code.as_str()).unwrap_or_else(|e| {
                                        warn!(id = %id_hex, "failed to save challenge code: {e}");
                                    });
                                    if let Ok(mut env) = inbox.load_incoming(&id_hex) {
                                        env.state = directed::EnvelopeState::ChallengeIssued;
                                        env.challenge_hash = Some(hash);
                                        env.challenge_attempts_remaining = directed::CHALLENGE_MAX_ATTEMPTS;
                                        env.password_attempts_remaining =
                                            directed::challenge::PASSWORD_MAX_ATTEMPTS;
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

// ─── Periodic environment detection ──────────────────────────────────────────

/// Periodically refreshes the network environment snapshot by observing
/// transport outcomes and NAT status from the live coordinator.
///
/// Runs every 5 minutes. Updates the shared `EnvironmentSnapshot` that
/// DaemonStatus and CLI diagnostics read from.
async fn environment_detector_loop(
    coord: Arc<MiasmaCoordinator>,
    env_snapshot: Arc<Mutex<EnvironmentSnapshot>>,
) {
    use crate::network::environment::{EnvironmentSnapshot as EnvSnap, NetworkCapabilities};
    use crate::transport::payload::PayloadTransportKind;

    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
    interval.tick().await; // skip immediate first tick

    loop {
        interval.tick().await;

        // Derive capabilities from observed transport outcomes
        let stats = coord.transport_stats();
        let nat_reachable = coord.nat_publicly_reachable().await.unwrap_or(false);

        let mut caps = NetworkCapabilities::default();

        // If DirectLibp2p (QUIC) has failures and no successes, UDP may be blocked
        let (quic_ok, quic_fail) = stats.kind_stats(PayloadTransportKind::DirectLibp2p);
        if quic_fail > 0 && quic_ok == 0 {
            caps.udp_available = false;
        }

        // If WSS has failures and no successes while others work, port filtering possible
        let (wss_ok, wss_fail) = stats.kind_stats(PayloadTransportKind::WssTunnel);
        if wss_fail > 0 && wss_ok == 0 {
            caps.port_443_available = false;
        }

        // NAT not reachable with no UDP suggests full-tunnel VPN or heavy filtering
        if !nat_reachable && !caps.udp_available {
            // Could be VPN or filtered — check if any transport succeeded
            let (tcp_ok, _) = stats.kind_stats(PayloadTransportKind::TcpDirect);
            if tcp_ok > 0 || wss_ok > 0 {
                // TCP works but UDP doesn't — likely filtered or VPN
                caps.tcp_high_ports_available = tcp_ok > 0;
            }
        }

        let new_snap = EnvSnap::from_capabilities(caps);

        // Only update if environment changed
        let should_log = {
            let current = env_snapshot.lock().unwrap();
            current.environment != new_snap.environment
        };
        if should_log {
            info!(
                old = %env_snapshot.lock().unwrap().environment,
                new = %new_snap.environment,
                "network environment changed"
            );
        }

        *env_snapshot.lock().unwrap() = new_snap;
    }
}

#[cfg(test)]
mod large_file_stream_integrity_tests {
    use super::*;

    #[test]
    fn streamed_mid_matches_chunked_content() {
        let params = DissolutionParams::default();
        let chunks: [&[u8]; 4] = [b"chunk-one-", b"chunk-two-", b"chunk-three-", b"chunk-four"];
        let full = chunks.concat();
        let expected = crate::crypto::hash::ContentId::compute(&full, &params.to_param_bytes());

        let mut hasher = blake3::Hasher::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        let streamed = finalize_streamed_mid(hasher, params);
        assert_eq!(streamed, expected);
    }

    #[test]
    fn streamed_mid_detects_content_change() {
        let params = DissolutionParams::default();
        let expected =
            crate::crypto::hash::ContentId::compute(b"expected", &params.to_param_bytes());

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tampered");
        assert_ne!(finalize_streamed_mid(hasher, params), expected);
    }
}
