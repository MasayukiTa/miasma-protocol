/// Background worker — relays UI commands to the miasma daemon via IPC.
///
/// Architecture:
/// ```text
/// UI thread ──(WorkerCmd)──► worker OS thread ──(WorkerResult)──► UI thread
///                mpsc::SyncSender               mpsc::Receiver
///
/// worker OS thread ──(ControlRequest)──► local daemon (TCP loopback)
///                                        ──(ControlResponse)──►
/// ```
///
/// Features:
/// - Auto-detects uninitialized node and reports `NeedsInit`
/// - Auto-launches daemon if not running (with stale port-file detection)
/// - Tracks daemon ownership: if desktop launched it, kills on exit
/// - All operations go through daemon IPC; if daemon not reachable, returns clear error
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc;

use miasma_core::{
    daemon_request, read_port_file, ControlRequest, ControlResponse,
    pipeline::DissolutionParams,
};
use tracing::{info, warn};

// ─── Protocol ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum WorkerCmd {
    /// Dissolve a UTF-8 string.
    DissolveText(String),
    /// Dissolve a file read from disk.
    DissolveFile(PathBuf),
    /// Retrieve content by MID (`miasma:<base58>`).
    Retrieve(String),
    /// Query current daemon status.
    GetStatus,
    /// Initialize node (same semantics as CLI `init`).
    Init,
    /// Start daemon (auto-launch).
    StartDaemon,
    /// Distress-wipe: delete master key → all shares become unreadable.
    Wipe,
}

/// Connection state visible to the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonState {
    /// Node not initialized (no master.key / config.toml).
    NeedsInit,
    /// Node initialized but daemon not running.
    Stopped,
    /// Desktop is launching the daemon, waiting for it to be ready.
    Starting,
    /// Daemon is running and IPC is reachable.
    Connected,
}

#[derive(Debug, Clone)]
pub enum WorkerResult {
    /// Dissolution succeeded: MID string.
    Dissolved { mid: String },
    /// Retrieval succeeded: raw plaintext bytes.
    Retrieved { mid: String, data: Vec<u8> },
    /// Daemon status snapshot.
    Status {
        peer_id: String,
        peer_count: usize,
        share_count: usize,
        used_mb: f64,
        quota_mb: u64,
        pending_replication: usize,
        replicated_count: usize,
        listen_addrs: Vec<String>,
        wss_port: u16,
        wss_tls_enabled: bool,
        proxy_configured: bool,
        proxy_type: Option<String>,
        obfs_quic_port: u16,
        transport_statuses: Vec<TransportStatusInfo>,
    },
    /// Distress wipe complete.
    Wiped,
    /// Daemon connection state changed.
    StateChanged(DaemonState),
    /// Node initialization complete.
    Initialized,
    /// Any error.
    Err(String),
}

/// Transport readiness info for desktop display.
#[derive(Debug, Clone)]
pub struct TransportStatusInfo {
    pub name: String,
    pub available: bool,
    pub selected: bool,
    pub success_count: u64,
    pub failure_count: u64,
    pub session_failures: u64,
    pub data_failures: u64,
    pub last_error: Option<String>,
}

// ─── Handle ───────────────────────────────────────────────────────────────────

/// Owns the channels used to communicate with the worker thread.
pub struct WorkerHandle {
    pub tx: mpsc::SyncSender<WorkerCmd>,
    pub rx: mpsc::Receiver<WorkerResult>,
}

impl WorkerHandle {
    pub fn spawn(data_dir: PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::sync_channel(32);
        let (res_tx, res_rx) = mpsc::sync_channel(64);

        std::thread::Builder::new()
            .name("miasma-worker".into())
            .spawn(move || worker_thread(data_dir, cmd_rx, res_tx))
            .expect("spawn worker thread");

        Self { tx: cmd_tx, rx: res_rx }
    }
}

// ─── Worker thread ────────────────────────────────────────────────────────────

fn worker_thread(
    data_dir: PathBuf,
    rx: mpsc::Receiver<WorkerCmd>,
    tx: mpsc::SyncSender<WorkerResult>,
) {
    // Single-threaded tokio runtime for async daemon IPC calls.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = tx.send(WorkerResult::Err(format!("Failed to start runtime: {e}")));
            return;
        }
    };

    let params = DissolutionParams::default();

    // Track daemon process if we launched it ourselves.
    let mut owned_daemon: Option<Child> = None;

    // On startup: detect node state and attempt auto-connect/launch.
    let initial_state = detect_state(&data_dir, &rt);
    let _ = tx.send(WorkerResult::StateChanged(initial_state.clone()));

    if initial_state == DaemonState::Stopped {
        // Try auto-launching daemon.
        let _ = tx.send(WorkerResult::StateChanged(DaemonState::Starting));
        match auto_launch_daemon(&data_dir, &rt) {
            Ok(child) => {
                owned_daemon = Some(child);
                let _ = tx.send(WorkerResult::StateChanged(DaemonState::Connected));
                // Seed initial status.
                let _ = tx.send(rt.block_on(get_status(&data_dir)));
            }
            Err(e) => {
                warn!("Auto-launch daemon failed: {e}");
                let _ = tx.send(WorkerResult::StateChanged(DaemonState::Stopped));
                let _ = tx.send(WorkerResult::Err(format!(
                    "Could not start daemon automatically: {e}\n\
                     Start manually with: miasma daemon"
                )));
            }
        }
    } else if initial_state == DaemonState::Connected {
        // Already running — seed status.
        let _ = tx.send(rt.block_on(get_status(&data_dir)));
    }

    // Main command loop.
    while let Ok(cmd) = rx.recv() {
        let res = match cmd {
            WorkerCmd::DissolveText(text) => {
                rt.block_on(publish_bytes(text.as_bytes(), &data_dir, params))
            }
            WorkerCmd::DissolveFile(path) => match std::fs::read(&path) {
                Ok(data) => rt.block_on(publish_bytes(&data, &data_dir, params)),
                Err(e) => WorkerResult::Err(format!("Read file: {e}")),
            },
            WorkerCmd::Retrieve(mid_str) => {
                rt.block_on(retrieve_mid(&mid_str, &data_dir, params))
            }
            WorkerCmd::GetStatus => {
                let status = rt.block_on(get_status(&data_dir));
                // Update connection state based on result.
                if matches!(&status, WorkerResult::Err(e) if is_daemon_down(e)) {
                    let _ = tx.send(WorkerResult::StateChanged(DaemonState::Stopped));
                } else if matches!(&status, WorkerResult::Status { .. }) {
                    let _ = tx.send(WorkerResult::StateChanged(DaemonState::Connected));
                }
                status
            }
            WorkerCmd::Init => {
                match do_init(&data_dir) {
                    Ok(()) => {
                        let _ = tx.send(WorkerResult::Initialized);
                        // After init, try to auto-launch daemon.
                        let _ = tx.send(WorkerResult::StateChanged(DaemonState::Starting));
                        match auto_launch_daemon(&data_dir, &rt) {
                            Ok(child) => {
                                owned_daemon = Some(child);
                                let _ = tx.send(WorkerResult::StateChanged(DaemonState::Connected));
                                rt.block_on(get_status(&data_dir))
                            }
                            Err(e) => {
                                let _ = tx.send(WorkerResult::StateChanged(DaemonState::Stopped));
                                WorkerResult::Err(format!(
                                    "Node initialized, but daemon start failed: {e}"
                                ))
                            }
                        }
                    }
                    Err(e) => WorkerResult::Err(format!("Init failed: {e}")),
                }
            }
            WorkerCmd::StartDaemon => {
                let _ = tx.send(WorkerResult::StateChanged(DaemonState::Starting));
                match auto_launch_daemon(&data_dir, &rt) {
                    Ok(child) => {
                        owned_daemon = Some(child);
                        let _ = tx.send(WorkerResult::StateChanged(DaemonState::Connected));
                        rt.block_on(get_status(&data_dir))
                    }
                    Err(e) => {
                        let _ = tx.send(WorkerResult::StateChanged(DaemonState::Stopped));
                        WorkerResult::Err(format!("Daemon start failed: {e}"))
                    }
                }
            }
            WorkerCmd::Wipe => rt.block_on(do_wipe(&data_dir)),
        };

        if tx.send(res).is_err() {
            break; // UI dropped its receiver — exit cleanly.
        }
    }

    // Cleanup: if we own the daemon, kill it on exit.
    if let Some(mut child) = owned_daemon {
        info!("Desktop exiting — stopping owned daemon (pid={})", child.id());
        let _ = child.kill();
        let _ = child.wait();
    }
}

// ─── Node init (same as CLI) ─────────────────────────────────────────────────

/// Initialize node with default parameters. Identical semantics to `miasma init`.
fn do_init(data_dir: &Path) -> anyhow::Result<()> {
    use miasma_core::config::{NetworkConfig, NodeConfig, StorageConfig};
    use miasma_core::LocalShareStore;

    std::fs::create_dir_all(data_dir)
        .map_err(|e| anyhow::anyhow!("cannot create data dir: {e}"))?;

    let config = NodeConfig {
        storage: StorageConfig {
            quota_mb: 10_240,
            bandwidth_mb_day: 1_024,
        },
        network: NetworkConfig {
            listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1".into(),
            bootstrap_peers: vec![],
        },
        transport: Default::default(),
    };
    config.save(data_dir)?;

    // Creates master.key.
    LocalShareStore::open(data_dir, config.storage.quota_mb)?;

    info!("Node initialized at {}", data_dir.display());
    Ok(())
}

// ─── State detection ─────────────────────────────────────────────────────────

/// Check if node is initialized (master.key + config.toml exist).
fn is_node_initialized(data_dir: &Path) -> bool {
    data_dir.join("master.key").exists() && data_dir.join("config.toml").exists()
}

/// Detect current daemon connection state.
fn detect_state(data_dir: &Path, rt: &tokio::runtime::Runtime) -> DaemonState {
    if !is_node_initialized(data_dir) {
        return DaemonState::NeedsInit;
    }

    // Check if daemon.port exists.
    let port = match read_port_file(data_dir) {
        Ok(p) => p,
        Err(_) => return DaemonState::Stopped,
    };

    // Port file exists — try to connect to verify it's not stale.
    match rt.block_on(tokio::time::timeout(
        std::time::Duration::from_secs(3),
        daemon_request(data_dir, ControlRequest::Status),
    )) {
        Ok(Ok(_)) => DaemonState::Connected,
        _ => {
            // Port file is stale — remove it.
            info!("Stale daemon.port (port {port}), removing");
            miasma_core::daemon::ipc::remove_port_file(data_dir);
            DaemonState::Stopped
        }
    }
}

// ─── Auto-launch daemon ──────────────────────────────────────────────────────

/// Find the miasma CLI binary next to the desktop binary.
fn find_miasma_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;

    // Look for miasma.exe (Windows) or miasma (Unix) next to desktop binary.
    let candidate = if cfg!(windows) {
        dir.join("miasma.exe")
    } else {
        dir.join("miasma")
    };
    if candidate.exists() {
        return Some(candidate);
    }

    // Also try PATH.
    which_miasma()
}

/// Search PATH for miasma binary.
fn which_miasma() -> Option<PathBuf> {
    let name = if cfg!(windows) { "miasma.exe" } else { "miasma" };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(name);
            if candidate.is_file() { Some(candidate) } else { None }
        })
    })
}

/// Launch daemon as a background process. Waits up to 10s for port file.
fn auto_launch_daemon(
    data_dir: &Path,
    rt: &tokio::runtime::Runtime,
) -> anyhow::Result<Child> {
    // Safety: check if daemon is already running (avoid duplicates).
    if let Ok(port) = read_port_file(data_dir) {
        if rt.block_on(tokio::time::timeout(
            std::time::Duration::from_secs(2),
            daemon_request(data_dir, ControlRequest::Status),
        )).is_ok() {
            anyhow::bail!("daemon already running on port {port}");
        }
        // Stale port file — remove it.
        miasma_core::daemon::ipc::remove_port_file(data_dir);
    }

    let miasma_exe = find_miasma_exe()
        .ok_or_else(|| anyhow::anyhow!(
            "Cannot find miasma.exe.\n\
             If installed: check that the installation is intact (reinstall if needed).\n\
             If portable: place miasma.exe next to miasma-desktop.exe."
        ))?;

    info!("Auto-launching daemon: {} daemon", miasma_exe.display());

    let child = std::process::Command::new(&miasma_exe)
        .arg("daemon")
        .arg("--data-dir")
        .arg(data_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn daemon: {e}"))?;

    // Wait for daemon to become reachable (port file appears + IPC responds).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("daemon did not become ready within 15 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(300));

        if read_port_file(data_dir).is_err() {
            continue; // Port file not yet written.
        }
        // Port file exists — try IPC.
        if let Ok(Ok(_)) = rt.block_on(tokio::time::timeout(
            std::time::Duration::from_secs(2),
            daemon_request(data_dir, ControlRequest::Status),
        )) {
            info!("Daemon is ready");
            return Ok(child);
        }
    }
}

// ─── IPC helpers ──────────────────────────────────────────────────────────────

async fn publish_bytes(data: &[u8], data_dir: &Path, params: DissolutionParams) -> WorkerResult {
    let req = ControlRequest::Publish {
        data: data.to_vec(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
    };
    match daemon_request(data_dir, req).await {
        Ok(ControlResponse::Published { mid }) => WorkerResult::Dissolved { mid },
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn retrieve_mid(mid_str: &str, data_dir: &Path, params: DissolutionParams) -> WorkerResult {
    let req = ControlRequest::Get {
        mid: mid_str.to_string(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
    };
    match daemon_request(data_dir, req).await {
        Ok(ControlResponse::Retrieved { data }) => {
            WorkerResult::Retrieved { mid: mid_str.to_string(), data }
        }
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn get_status(data_dir: &Path) -> WorkerResult {
    match daemon_request(data_dir, ControlRequest::Status).await {
        Ok(ControlResponse::Status(s)) => {
            // Read config for quota display.
            let quota_mb = miasma_core::NodeConfig::load(data_dir)
                .map(|c| c.storage.quota_mb)
                .unwrap_or(0);

            WorkerResult::Status {
                peer_id: s.peer_id,
                peer_count: s.peer_count,
                share_count: s.share_count,
                used_mb: s.storage_used_bytes as f64 / (1024.0 * 1024.0),
                quota_mb,
                pending_replication: s.pending_replication,
                replicated_count: s.replicated_count,
                listen_addrs: s.listen_addrs,
                wss_port: s.wss_port,
                wss_tls_enabled: s.wss_tls_enabled,
                proxy_configured: s.proxy_configured,
                proxy_type: s.proxy_type,
                obfs_quic_port: s.obfs_quic_port,
                transport_statuses: s
                    .transport_readiness
                    .into_iter()
                    .map(|t| TransportStatusInfo {
                        name: t.name,
                        available: t.available,
                        selected: t.selected,
                        success_count: t.success_count,
                        failure_count: t.failure_count,
                        session_failures: t.session_failures,
                        data_failures: t.data_failures,
                        last_error: t.last_error,
                    })
                    .collect(),
            }
        }
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn do_wipe(data_dir: &Path) -> WorkerResult {
    match daemon_request(data_dir, ControlRequest::Wipe).await {
        Ok(ControlResponse::Wiped) => WorkerResult::Wiped,
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

/// Convert anyhow errors into user-friendly messages.
fn daemon_error(e: &anyhow::Error) -> String {
    let msg = format!("{e:#}");
    if is_daemon_down(&msg) {
        "Daemon not running. Click 'Start Daemon' above to restart it.".to_string()
    } else if msg.contains("Cannot find miasma.exe") {
        msg // Already user-friendly from find_miasma_exe.
    } else if msg.contains("spawn daemon") {
        format!(
            "Could not start the daemon process.\n\
             Check that miasma.exe is not blocked by antivirus or SmartScreen.\n\
             Detail: {msg}"
        )
    } else {
        msg
    }
}

fn is_daemon_down(msg: &str) -> bool {
    msg.contains("daemon.port not found")
        || msg.contains("cannot connect to daemon")
        || msg.contains("Daemon not running")
}
