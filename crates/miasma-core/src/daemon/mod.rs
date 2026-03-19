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
    network::{
        coordinator::MiasmaCoordinator,
        node::MiasmaNode,
        types::{DhtRecord, ShardLocation, TopologyEvent},
    },
    pipeline::{dissolve, DissolutionParams},
    store::LocalShareStore,
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
        mut node: MiasmaNode,
        store: Arc<LocalShareStore>,
        data_dir: PathBuf,
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

        // 6. Start the coordinator (spawns the libp2p event loop).
        let coord = Arc::new(
            MiasmaCoordinator::start(node, store.clone(), listen_addr_strings.clone()).await,
        );

        // 7. Load the persistent replication queue.
        let queue = Arc::new(Mutex::new(ReplicationQueue::load_or_create(&data_dir)?));

        // 8. Start WSS share server (OS-assigned port for payload transport).
        let wss_port = match crate::transport::websocket::WssShareServer::bind(
            store.clone(),
            0, // OS-assigned port
        )
        .await
        {
            Ok(server) => {
                let port = server.port;
                tokio::spawn(server.run());
                info!(wss_port = port, "WSS share server started");
                port
            }
            Err(e) => {
                warn!("WSS share server failed to start: {e}");
                0
            }
        };

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
        let ipc_handle: JoinHandle<()> = tokio::spawn(async move {
            ipc_server_loop(listener, ipc_coord, ipc_queue, ipc_store, ipc_addrs, ipc_wss_port).await;
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
                tokio::spawn(async move {
                    if let Err(e) = handle_ipc_client(stream, c, q, s, la, wp).await {
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
) -> Result<()> {
    let req: ControlRequest = read_frame(&mut stream).await?;
    let resp = process_request(req, coord, queue, store, listen_addrs, wss_port).await;
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
                    success_count: r.success_count,
                    failure_count: r.failure_count,
                    reason: r.reason,
                })
                .collect();

            ControlResponse::Status(DaemonStatus {
                peer_id: coord.peer_id().to_string(),
                listen_addrs,
                peer_count,
                share_count,
                storage_used_bytes,
                pending_replication,
                replicated_count,
                wss_port,
                transport_readiness,
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
