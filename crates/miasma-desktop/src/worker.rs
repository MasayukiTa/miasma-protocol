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
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc;

use miasma_core::{
    daemon_request, pipeline::DissolutionParams, read_port_file, ControlRequest, ControlResponse,
};
use tracing::{info, warn};
use zeroize::Zeroizing;

// ─── Protocol ─────────────────────────────────────────────────────────────────

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
    /// Import a magnet URI via the bridge subprocess.
    ImportMagnet(String),
    /// Import a .torrent file via the bridge subprocess.
    ImportTorrentFile(PathBuf),
    /// Get sharing key/contact.
    GetSharingKey,
    /// Send a directed share.
    DirectedSend {
        file_path: PathBuf,
        recipient_contact: String,
        password: String,
        retention: String,
    },
    /// Retrieve a directed share.
    DirectedRetrieve {
        envelope_id: String,
        password: String,
    },
    /// Revoke/delete a directed share.
    DirectedRevoke { envelope_id: String },
    /// Submit challenge confirmation for a directed share (sender side).
    DirectedConfirm {
        envelope_id: String,
        challenge_code: String,
    },
    /// List inbox.
    DirectedInbox,
    /// List outbox.
    DirectedOutbox,
    /// Start (or resume, by issuing the same request again) a verified, resumable
    /// receive in the daemon. Returns at once; progress comes from [`Self::TransferPoll`].
    TransferStartReceive {
        mid: String,
        output_path: PathBuf,
        /// `None` when the transfer is not password-protected. Never stored.
        password: Option<String>,
        /// Discard any partial transfer and start over.
        restart: bool,
        /// `wss://` / `ws://` endpoints to fetch from directly instead of the network. Empty for
        /// the ordinary receive. The desktop trusts the operating system's certificate store.
        via: Vec<String>,
    },
    /// Start (or resume) a resumable send of a file in the daemon.
    TransferStartPublish {
        file_path: PathBuf,
        password: Option<String>,
        data_shards: u8,
        total_shards: u8,
        restart: bool,
    },
    /// Resume a stopped send: `k`/`n` are read from its journal so the daemon
    /// sees the same parameters the transfer began with.
    TransferResumePublish {
        file_path: PathBuf,
        password: Option<String>,
    },
    /// Ask the daemon for every transfer (running ones and paused ones left by
    /// an earlier daemon process).
    TransferPoll,
    /// Stop a running transfer at its next safe point; its progress is kept.
    TransferCancel { id: String },
}

impl fmt::Debug for WorkerCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DissolveText(text) => f
                .debug_struct("DissolveText")
                .field("text_len", &text.len())
                .finish(),
            Self::DissolveFile(_) => f.write_str("DissolveFile(<redacted-path>)"),
            Self::Retrieve(mid) => f.debug_tuple("Retrieve").field(mid).finish(),
            Self::GetStatus => f.write_str("GetStatus"),
            Self::Init => f.write_str("Init"),
            Self::StartDaemon => f.write_str("StartDaemon"),
            Self::Wipe => f.write_str("Wipe"),
            Self::ImportMagnet(_) => f.write_str("ImportMagnet(<redacted>)"),
            Self::ImportTorrentFile(_) => f.write_str("ImportTorrentFile(<redacted-path>)"),
            Self::GetSharingKey => f.write_str("GetSharingKey"),
            Self::DirectedSend { retention, .. } => f
                .debug_struct("DirectedSend")
                .field("file_path", &"<redacted>")
                .field("recipient_contact", &"<redacted>")
                .field("password", &"<redacted>")
                .field("retention", retention)
                .finish(),
            Self::DirectedRetrieve { envelope_id, .. } => f
                .debug_struct("DirectedRetrieve")
                .field("envelope_id", envelope_id)
                .field("password", &"<redacted>")
                .finish(),
            Self::DirectedRevoke { envelope_id } => f
                .debug_struct("DirectedRevoke")
                .field("envelope_id", envelope_id)
                .finish(),
            Self::DirectedConfirm { envelope_id, .. } => f
                .debug_struct("DirectedConfirm")
                .field("envelope_id", envelope_id)
                .field("challenge_code", &"<redacted>")
                .finish(),
            Self::DirectedInbox => f.write_str("DirectedInbox"),
            Self::DirectedOutbox => f.write_str("DirectedOutbox"),
            // Paths and passwords are never printed, exactly as for `DirectedSend`.
            Self::TransferStartReceive { mid, restart, .. } => f
                .debug_struct("TransferStartReceive")
                .field("mid", mid)
                .field("output_path", &"<redacted>")
                .field("password", &"<redacted>")
                .field("restart", restart)
                .finish(),
            Self::TransferStartPublish {
                data_shards,
                total_shards,
                restart,
                ..
            } => f
                .debug_struct("TransferStartPublish")
                .field("file_path", &"<redacted>")
                .field("password", &"<redacted>")
                .field("data_shards", data_shards)
                .field("total_shards", total_shards)
                .field("restart", restart)
                .finish(),
            Self::TransferResumePublish { .. } => f
                .debug_struct("TransferResumePublish")
                .field("file_path", &"<redacted>")
                .field("password", &"<redacted>")
                .finish(),
            Self::TransferPoll => f.write_str("TransferPoll"),
            // A send's id embeds the source path.
            Self::TransferCancel { .. } => f.write_str("TransferCancel(<redacted>)"),
        }
    }
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

pub enum WorkerResult {
    /// Dissolution succeeded: MID string.
    Dissolved { mid: String },
    /// Retrieval succeeded: raw plaintext bytes (small/in-memory path).
    Retrieved { mid: String, data: Vec<u8> },
    /// Retrieval succeeded through the streaming file path.
    RetrievedToFile {
        mid: String,
        temp_path: PathBuf,
        bytes_written: u64,
    },
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
    /// Import started — bridge subprocess launched.
    ImportStarted { name: String },
    /// Import complete — content stored, MIDs returned.
    ImportComplete { mids: Vec<String> },
    /// Sharing key/contact retrieved.
    SharingKey { contact: String },
    /// Directed share sent.
    DirectedSent { envelope_id: String },
    /// Directed share retrieved (written to temp file).
    DirectedRetrieved {
        /// Path to the temp file containing decrypted content.
        temp_path: std::path::PathBuf,
        filename: Option<String>,
        bytes_written: u64,
    },
    /// Directed share revoked.
    DirectedRevoked,
    /// Challenge confirmed.
    DirectedConfirmed,
    /// Inbox listing.
    DirectedInboxList(Vec<DirectedInboxItem>),
    /// Outbox listing.
    DirectedOutboxList(Vec<DirectedInboxItem>),
    /// Every transfer the daemon knows (running, and paused from journals).
    TransferList(Vec<miasma_core::transfer::TransferStatus>),
    /// The transfer list could not be read. `daemon_down` means the background
    /// service is not reachable (as opposed to it answering with an error).
    TransferPollFailed { message: String, daemon_down: bool },
    /// The daemon accepted a start request; it now runs the transfer itself.
    TransferStarted { id: String },
    /// The daemon accepted a cancel request.
    TransferCancelRequested,
    /// A start or cancel request was refused or failed.
    TransferError(String),
    /// Any error.
    Err(String),
}

impl fmt::Debug for WorkerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dissolved { mid } => f.debug_struct("Dissolved").field("mid", mid).finish(),
            Self::Retrieved { mid, data } => f
                .debug_struct("Retrieved")
                .field("mid", mid)
                .field("data_len", &data.len())
                .finish(),
            Self::RetrievedToFile {
                mid, bytes_written, ..
            } => f
                .debug_struct("RetrievedToFile")
                .field("mid", mid)
                .field("temp_path", &"<redacted>")
                .field("bytes_written", bytes_written)
                .finish(),
            Self::Status {
                peer_id,
                peer_count,
                share_count,
                used_mb,
                quota_mb,
                pending_replication,
                replicated_count,
                listen_addrs,
                wss_port,
                wss_tls_enabled,
                proxy_configured,
                proxy_type,
                obfs_quic_port,
                transport_statuses,
            } => f
                .debug_struct("Status")
                .field("peer_id", peer_id)
                .field("peer_count", peer_count)
                .field("share_count", share_count)
                .field("used_mb", used_mb)
                .field("quota_mb", quota_mb)
                .field("pending_replication", pending_replication)
                .field("replicated_count", replicated_count)
                .field("listen_addr_count", &listen_addrs.len())
                .field("wss_port", wss_port)
                .field("wss_tls_enabled", wss_tls_enabled)
                .field("proxy_configured", proxy_configured)
                .field("proxy_type", proxy_type)
                .field("obfs_quic_port", obfs_quic_port)
                .field("transport_statuses", transport_statuses)
                .finish(),
            Self::Wiped => f.write_str("Wiped"),
            Self::StateChanged(state) => f.debug_tuple("StateChanged").field(state).finish(),
            Self::Initialized => f.write_str("Initialized"),
            Self::ImportStarted { name } => {
                f.debug_struct("ImportStarted").field("name", name).finish()
            }
            Self::ImportComplete { mids } => f
                .debug_struct("ImportComplete")
                .field("mids", mids)
                .finish(),
            Self::SharingKey { .. } => f.write_str("SharingKey(<redacted>)"),
            Self::DirectedSent { envelope_id } => f
                .debug_struct("DirectedSent")
                .field("envelope_id", envelope_id)
                .finish(),
            Self::DirectedRetrieved { bytes_written, .. } => f
                .debug_struct("DirectedRetrieved")
                .field("temp_path", &"<redacted>")
                .field("filename", &"<redacted>")
                .field("bytes_written", bytes_written)
                .finish(),
            Self::DirectedRevoked => f.write_str("DirectedRevoked"),
            Self::DirectedConfirmed => f.write_str("DirectedConfirmed"),
            Self::DirectedInboxList(items) => f
                .debug_struct("DirectedInboxList")
                .field("items", items)
                .finish(),
            Self::DirectedOutboxList(items) => f
                .debug_struct("DirectedOutboxList")
                .field("items", items)
                .finish(),
            // Transfer names are file paths, so only the count is printed.
            Self::TransferList(list) => f
                .debug_struct("TransferList")
                .field("count", &list.len())
                .finish(),
            Self::TransferPollFailed {
                message,
                daemon_down,
            } => f
                .debug_struct("TransferPollFailed")
                .field("message", message)
                .field("daemon_down", daemon_down)
                .finish(),
            Self::TransferStarted { .. } => f.write_str("TransferStarted(<redacted>)"),
            Self::TransferCancelRequested => f.write_str("TransferCancelRequested"),
            Self::TransferError(message) => f.debug_tuple("TransferError").field(message).finish(),
            Self::Err(message) => f.debug_tuple("Err").field(message).finish(),
        }
    }
}

/// Directed inbox/outbox item for display.
pub struct DirectedInboxItem {
    pub envelope_id: String,
    pub sender_pubkey: String,
    pub sender_peer_id: Option<String>,
    pub recipient_pubkey: String,
    pub state: String,
    pub challenge_code: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub filename: Option<String>,
    pub file_size: u64,
}

impl fmt::Debug for DirectedInboxItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectedInboxItem")
            .field("envelope_id", &self.envelope_id)
            .field("sender_pubkey", &self.sender_pubkey)
            .field("sender_peer_id", &self.sender_peer_id)
            .field("recipient_pubkey", &self.recipient_pubkey)
            .field("state", &self.state)
            .field(
                "challenge_code",
                &self.challenge_code.as_ref().map(|_| "<redacted>"),
            )
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("filename", &self.filename.as_ref().map(|_| "<redacted>"))
            .field("file_size", &self.file_size)
            .finish()
    }
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

        Self {
            tx: cmd_tx,
            rx: res_rx,
        }
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
    // Track launch attempts to cap auto-relaunch retries.
    let mut launch_attempts: u32 = 0;

    // On startup: detect node state and attempt auto-connect/launch.
    let initial_state = detect_state(&data_dir, &rt);
    let _ = tx.send(WorkerResult::StateChanged(initial_state.clone()));

    if initial_state == DaemonState::Stopped {
        // Try auto-launching daemon.
        launch_attempts += 1;
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
            WorkerCmd::DissolveFile(path) => rt.block_on(publish_file(&path, &data_dir, params)),
            WorkerCmd::Retrieve(mid_str) => {
                rt.block_on(retrieve_mid_to_file(&mid_str, &data_dir, params))
            }
            WorkerCmd::GetStatus => {
                let status = rt.block_on(get_status(&data_dir));
                // Update connection state based on result.
                if matches!(&status, WorkerResult::Err(e) if is_daemon_down(e)) {
                    // Auto-reconnect: try relaunch if under retry cap.
                    if launch_attempts < MAX_AUTO_LAUNCHES {
                        launch_attempts += 1;
                        info!("Daemon unreachable — auto-relaunch attempt {launch_attempts}/{MAX_AUTO_LAUNCHES}");
                        let _ = tx.send(WorkerResult::StateChanged(DaemonState::Starting));
                        match auto_launch_daemon(&data_dir, &rt) {
                            Ok(child) => {
                                owned_daemon = Some(child);
                                launch_attempts = 0; // Reset on success.
                                let _ = tx.send(WorkerResult::StateChanged(DaemonState::Connected));
                                rt.block_on(get_status(&data_dir))
                            }
                            Err(e) => {
                                warn!("Auto-relaunch failed: {e}");
                                let _ = tx.send(WorkerResult::StateChanged(DaemonState::Stopped));
                                status
                            }
                        }
                    } else {
                        warn!("Daemon unreachable — auto-relaunch limit reached ({MAX_AUTO_LAUNCHES})");
                        let _ = tx.send(WorkerResult::StateChanged(DaemonState::Stopped));
                        status
                    }
                } else if matches!(&status, WorkerResult::Status { .. }) {
                    let _ = tx.send(WorkerResult::StateChanged(DaemonState::Connected));
                    status
                } else {
                    status
                }
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
                // Manual start resets the auto-launch counter.
                launch_attempts = 0;
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
            WorkerCmd::ImportMagnet(uri) => run_bridge_import(&tx, &data_dir, &["--magnet", &uri]),
            WorkerCmd::ImportTorrentFile(path) => {
                let p = path.to_string_lossy().to_string();
                run_bridge_import(&tx, &data_dir, &["--torrent", &p])
            }
            WorkerCmd::GetSharingKey => rt.block_on(do_sharing_key(&data_dir)),
            WorkerCmd::DirectedSend {
                file_path,
                recipient_contact,
                password,
                retention,
            } => {
                let password = Zeroizing::new(password);
                rt.block_on(do_directed_send(
                    &data_dir,
                    &file_path,
                    &recipient_contact,
                    password.as_str(),
                    &retention,
                ))
            }
            WorkerCmd::DirectedRetrieve {
                envelope_id,
                password,
            } => {
                let password = Zeroizing::new(password);
                rt.block_on(do_directed_retrieve(
                    &data_dir,
                    &envelope_id,
                    password.as_str(),
                ))
            }
            WorkerCmd::DirectedRevoke { envelope_id } => {
                rt.block_on(do_directed_revoke(&data_dir, &envelope_id))
            }
            WorkerCmd::DirectedConfirm {
                envelope_id,
                challenge_code,
            } => {
                let challenge_code = Zeroizing::new(challenge_code);
                rt.block_on(do_directed_confirm(
                    &data_dir,
                    &envelope_id,
                    challenge_code.as_str(),
                ))
            }
            WorkerCmd::DirectedInbox => rt.block_on(do_directed_inbox(&data_dir)),
            WorkerCmd::DirectedOutbox => rt.block_on(do_directed_outbox(&data_dir)),
            WorkerCmd::TransferStartReceive {
                mid,
                output_path,
                password,
                restart,
                via,
            } => {
                let password = password.map(Zeroizing::new);
                rt.block_on(do_transfer_start_receive(
                    &data_dir,
                    &mid,
                    &output_path,
                    password.as_ref().map(|p| p.as_str()),
                    restart,
                    via,
                ))
            }
            WorkerCmd::TransferStartPublish {
                file_path,
                password,
                data_shards,
                total_shards,
                restart,
            } => {
                let password = password.map(Zeroizing::new);
                rt.block_on(do_transfer_start_publish(
                    &data_dir,
                    &file_path,
                    password.as_ref().map(|p| p.as_str()),
                    data_shards,
                    total_shards,
                    restart,
                    true,
                ))
            }
            WorkerCmd::TransferResumePublish {
                file_path,
                password,
            } => {
                let password = password.map(Zeroizing::new);
                let (k, n) = journal_shard_params(&data_dir, &file_path)
                    .unwrap_or((DEFAULT_SEND_K, DEFAULT_SEND_N));
                rt.block_on(do_transfer_start_publish(
                    &data_dir,
                    &file_path,
                    password.as_ref().map(|p| p.as_str()),
                    k,
                    n,
                    false,
                    false,
                ))
            }
            WorkerCmd::TransferPoll => rt.block_on(do_transfer_poll(&data_dir)),
            WorkerCmd::TransferCancel { id } => rt.block_on(do_transfer_cancel(&data_dir, &id)),
        };

        if tx.send(res).is_err() {
            break; // UI dropped its receiver — exit cleanly.
        }
    }

    // Cleanup: if we own the daemon, kill it on exit.
    if let Some(mut child) = owned_daemon {
        info!(
            "Desktop exiting — stopping owned daemon (pid={})",
            child.id()
        );
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
        storage: StorageConfig::default(),
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
    // The timeout must be constructed inside the async block so it has
    // access to the Tokio runtime context (required for timer registration).
    match rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            daemon_request(data_dir, ControlRequest::Status),
        )
        .await
    }) {
        Ok(Ok(ControlResponse::Status(_))) => DaemonState::Connected,
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
    let name = if cfg!(windows) {
        "miasma.exe"
    } else {
        "miasma"
    };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(name);
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

/// Maximum number of auto-launch attempts before giving up.
const MAX_AUTO_LAUNCHES: u32 = 2;
/// How long to wait for the daemon to become reachable after spawn.
const DAEMON_STARTUP_TIMEOUT_SECS: u64 = 30;

/// Launch daemon as a background process. Waits up to 30s for port file.
fn auto_launch_daemon(data_dir: &Path, rt: &tokio::runtime::Runtime) -> anyhow::Result<Child> {
    // Safety: check if daemon is already running (avoid duplicates).
    if let Ok(port) = read_port_file(data_dir) {
        if rt
            .block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    daemon_request(data_dir, ControlRequest::Status),
                )
                .await
            })
            .is_ok()
        {
            anyhow::bail!("daemon already running on port {port}");
        }
        // Stale port file — remove it.
        miasma_core::daemon::ipc::remove_port_file(data_dir);
    }

    let miasma_exe = find_miasma_exe().ok_or_else(|| {
        anyhow::anyhow!(
            "Cannot find miasma backend.\n\
             Reinstall the complete application, keeping the backend next to the desktop executable."
        )
    })?;

    info!("Auto-launching daemon: {} daemon", miasma_exe.display());

    let mut cmd = std::process::Command::new(&miasma_exe);
    cmd.arg("daemon")
        .arg("--data-dir")
        .arg(data_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // On Windows, prevent the daemon from opening a console window.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn daemon: {e}"))?;

    // Wait for daemon to become reachable (port file appears + IPC responds).
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(DAEMON_STARTUP_TIMEOUT_SECS);
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!(
                "daemon did not become ready within {DAEMON_STARTUP_TIMEOUT_SECS} seconds"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(300));

        if read_port_file(data_dir).is_err() {
            continue; // Port file not yet written.
        }
        // Port file exists — try IPC.
        if let Ok(Ok(_)) = rt.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                daemon_request(data_dir, ControlRequest::Status),
            )
            .await
        }) {
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
        Ok(ControlResponse::Retrieved { data }) => WorkerResult::Retrieved {
            mid: mid_str.to_string(),
            data,
        },
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn publish_file(path: &Path, data_dir: &Path, params: DissolutionParams) -> WorkerResult {
    let req = ControlRequest::PublishFile {
        file_path: path.to_string_lossy().into_owned(),
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

fn retrieval_temp_path() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "miasma-retrieve-{}-{nonce}.tmp",
        std::process::id()
    ))
}

async fn retrieve_mid_to_file(
    mid_str: &str,
    data_dir: &Path,
    params: DissolutionParams,
) -> WorkerResult {
    let temp_path = retrieval_temp_path();
    let req = ControlRequest::GetToFile {
        mid: mid_str.to_string(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        output_path: temp_path.to_string_lossy().into_owned(),
    };
    match daemon_request(data_dir, req).await {
        Ok(ControlResponse::RetrievedToFile { bytes_written, .. }) => {
            WorkerResult::RetrievedToFile {
                mid: mid_str.to_string(),
                temp_path,
                bytes_written,
            }
        }
        Ok(ControlResponse::Error(e)) => {
            let _ = std::fs::remove_file(&temp_path);
            WorkerResult::Err(e)
        }
        Ok(other) => {
            let _ = std::fs::remove_file(&temp_path);
            WorkerResult::Err(format!("Unexpected response: {other:?}"))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&temp_path);
            WorkerResult::Err(daemon_error(&e))
        }
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
    match miasma_core::daemon_wipe(data_dir).await {
        Ok(ControlResponse::Wiped) => WorkerResult::Wiped,
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

/// Convert anyhow errors into user-friendly messages with actionable guidance.
fn daemon_error(e: &anyhow::Error) -> String {
    let msg = format!("{e:#}");
    if is_daemon_down(&msg) {
        DAEMON_DOWN_MESSAGE.to_string()
    } else if msg.contains("Cannot find miasma.exe") || msg.contains("Cannot find miasma") {
        "Cannot find the Miasma backend.\n\
         Reinstall the complete application, keeping the backend next to the desktop executable."
            .to_string()
    } else if msg.contains("spawn daemon") && cfg!(target_os = "macos") {
        "Could not start the backend process.\n\
         Try rebuilding or reinstalling the complete Miasma.app bundle."
            .to_string()
    } else if msg.contains("spawn daemon") {
        "Could not start the backend process.\n\
         This can happen if antivirus or SmartScreen is blocking miasma.exe.\n\
         Try: right-click miasma.exe → Properties → Unblock, then restart."
            .to_string()
    } else if msg.contains("did not become ready within") {
        "The backend started but is taking too long to respond.\n\
         This can happen on slower machines or when antivirus is scanning.\n\
         Try waiting a moment and clicking Start again."
            .to_string()
    } else {
        msg
    }
}

// ─── Bridge import ───────────────────────────────────────────────────────────

/// Find the miasma-bridge binary next to the desktop binary or on PATH.
fn find_bridge_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = if cfg!(windows) {
        dir.join("miasma-bridge.exe")
    } else {
        dir.join("miasma-bridge")
    };
    if candidate.exists() {
        return Some(candidate);
    }
    // Search PATH.
    let name = if cfg!(windows) {
        "miasma-bridge.exe"
    } else {
        "miasma-bridge"
    };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let c = dir.join(name);
            if c.is_file() {
                Some(c)
            } else {
                None
            }
        })
    })
}

/// Run bridge subprocess for magnet/torrent import. Sends ImportStarted then
/// waits for exit. On success, parses MIDs from stdout and sends ImportComplete.
fn run_bridge_import(
    tx: &mpsc::SyncSender<WorkerResult>,
    data_dir: &Path,
    args: &[&str],
) -> WorkerResult {
    let bridge_exe = match find_bridge_exe() {
        Some(p) => p,
        None => {
            return WorkerResult::Err(
                "Cannot find miasma-bridge. Ensure it is installed alongside the desktop app."
                    .into(),
            )
        }
    };

    let display_name = if args.first() == Some(&"--magnet") {
        "magnet import"
    } else {
        args.get(1).unwrap_or(&"file")
    };
    let _ = tx.send(WorkerResult::ImportStarted {
        name: display_name.to_string(),
    });

    let mut cmd = std::process::Command::new(&bridge_exe);
    cmd.args(bridge_import_args(args, data_dir))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return WorkerResult::Err(format!("Failed to start bridge: {e}")),
    };

    match child.wait_with_output() {
        Ok(output) => {
            if output.status.success() {
                // Parse MIDs from stdout — bridge prints one MID per line.
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mids = parse_mids_from_stdout(&stdout);
                if mids.is_empty() {
                    warn!("Bridge succeeded but produced no MIDs. stdout: {stdout}");
                }
                WorkerResult::ImportComplete { mids }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                WorkerResult::Err(format!("Bridge exited with error: {}", stderr.trim()))
            }
        }
        Err(e) => WorkerResult::Err(format!("Bridge process error: {e}")),
    }
}

/// Build the argument vector handed to `miasma-bridge`.
///
/// This is one half of a two-sided contract. The bridge's own cross-process
/// test (`crates/miasma-bridge/tests/cli_import_roundtrip.rs`) spawns exactly
/// this shape against the real compiled binary and proves it works end to end;
/// this function pins what the desktop actually sends, so the two halves can't
/// drift apart again. They were completely out of sync before Phase 3 — the
/// desktop sent `--magnet`, the bridge's dispatcher had never heard of it — and
/// nothing caught it because neither side was pinned to the other.
fn bridge_import_args(source: &[&str], data_dir: &Path) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> = source.iter().map(Into::into).collect();
    argv.push("--data-dir".into());
    // Pushed as one OsString, never formatted into a string: a data dir with
    // spaces (the default under `AppData\Local\Programs`) must stay a single
    // argument.
    argv.push(data_dir.as_os_str().to_owned());
    argv
}

/// Extract the MIDs the bridge printed on stdout.
///
/// The bridge indents them under a `[3/3] Dissolved N file(s)` heading, so the
/// `miasma:` test has to run on the *trimmed* line. Trimming only after the
/// filter — as this did originally — matched nothing at all, which meant that
/// even once the bridge's argument dispatch was fixed, every import would still
/// have reported "no MIDs".
fn parse_mids_from_stdout(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("miasma:"))
        .map(str::to_owned)
        .collect()
}

/// What the user is told when the daemon cannot be reached.
const DAEMON_DOWN_MESSAGE: &str = "Not connected. Click the Start button above to restart.\n\
     If the problem persists, try closing all Miasma windows and starting again.";

/// True for a raw "daemon unreachable" error *and* for the message `daemon_error` turns it into.
///
/// The second half matters: `get_status` returns the already-rewritten message, and the
/// auto-relaunch in the `GetStatus` handler tests that message. Matching only the raw wording
/// meant a daemon that died was never noticed: no relaunch, and the header kept saying
/// "Connected" (seen in the running window when a transfer's daemon was killed).
fn is_daemon_down(msg: &str) -> bool {
    msg == DAEMON_DOWN_MESSAGE
        || msg.contains("daemon.port not found")
        || msg.contains("cannot connect to daemon")
        || msg.contains("Daemon not running")
}

// ─── Directed sharing handlers ──────────────────────────────────────────────

async fn do_sharing_key(data_dir: &Path) -> WorkerResult {
    match daemon_request(data_dir, ControlRequest::SharingKey).await {
        Ok(ControlResponse::SharingKey { contact, .. }) => WorkerResult::SharingKey { contact },
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn do_directed_send(
    data_dir: &Path,
    file_path: &Path,
    recipient_contact: &str,
    password: &str,
    retention: &str,
) -> WorkerResult {
    // Validate file exists before sending path to daemon.
    if !file_path.exists() {
        return WorkerResult::Err(format!("File not found: {}", file_path.display()));
    }
    let retention_secs = match parse_retention(retention) {
        Ok(s) => s,
        Err(e) => return WorkerResult::Err(format!("Invalid retention: {e}")),
    };
    // Use file-path variant — daemon reads file directly, no IPC bloat.
    let abs_path = std::fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_owned());
    let req = ControlRequest::DirectedSendFile {
        recipient_contact: recipient_contact.to_owned(),
        file_path: abs_path.to_string_lossy().to_string(),
        password: password.to_owned(),
        retention_secs,
        filename: None,
    };
    match daemon_request(data_dir, req).await {
        Ok(ControlResponse::DirectedSent { envelope_id }) => {
            WorkerResult::DirectedSent { envelope_id }
        }
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn do_directed_retrieve(data_dir: &Path, envelope_id: &str, password: &str) -> WorkerResult {
    // Use file-path variant — daemon writes decrypted content to a temp file,
    // avoiding IPC bloat for large files.
    let tmp_path = std::env::temp_dir().join(format!("miasma-retrieve-{envelope_id}.tmp"));
    let req = ControlRequest::DirectedRetrieveToFile {
        envelope_id: envelope_id.to_owned(),
        password: password.to_owned(),
        output_path: tmp_path.to_string_lossy().to_string(),
    };
    match daemon_request(data_dir, req).await {
        Ok(ControlResponse::DirectedRetrievedToFile {
            filename,
            bytes_written,
            ..
        }) => WorkerResult::DirectedRetrieved {
            temp_path: tmp_path,
            filename,
            bytes_written,
        },
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn do_directed_revoke(data_dir: &Path, envelope_id: &str) -> WorkerResult {
    let req = ControlRequest::DirectedRevoke {
        envelope_id: envelope_id.to_owned(),
    };
    match daemon_request(data_dir, req).await {
        Ok(ControlResponse::DirectedRevoked) => WorkerResult::DirectedRevoked,
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn do_directed_confirm(
    data_dir: &Path,
    envelope_id: &str,
    challenge_code: &str,
) -> WorkerResult {
    let req = ControlRequest::DirectedConfirm {
        envelope_id: envelope_id.to_owned(),
        challenge_code: challenge_code.to_owned(),
    };
    match daemon_request(data_dir, req).await {
        Ok(ControlResponse::DirectedConfirmed) => WorkerResult::DirectedConfirmed,
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

fn map_summary_items(items: Vec<miasma_core::directed::EnvelopeSummary>) -> Vec<DirectedInboxItem> {
    items
        .into_iter()
        .map(|item| DirectedInboxItem {
            envelope_id: item.envelope_id,
            sender_pubkey: item.sender_pubkey,
            sender_peer_id: item.sender_peer_id,
            recipient_pubkey: item.recipient_pubkey,
            state: format!("{:?}", item.state),
            challenge_code: item.challenge_code,
            created_at: item.created_at,
            expires_at: item.expires_at,
            filename: item.filename,
            file_size: item.file_size,
        })
        .collect()
}

async fn do_directed_inbox(data_dir: &Path) -> WorkerResult {
    match daemon_request(data_dir, ControlRequest::DirectedInbox).await {
        Ok(ControlResponse::DirectedInboxList(items)) => {
            WorkerResult::DirectedInboxList(map_summary_items(items))
        }
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn do_directed_outbox(data_dir: &Path) -> WorkerResult {
    match daemon_request(data_dir, ControlRequest::DirectedOutbox).await {
        Ok(ControlResponse::DirectedOutboxList(items)) => {
            WorkerResult::DirectedOutboxList(map_summary_items(items))
        }
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

// ─── Resumable transfers (daemon-side jobs) ─────────────────────────────────
//
// The daemon runs the transfer; these calls only start, list and cancel it, so none of them
// waits for the transfer itself. The requests are the same ones the CLI issues
// (`network-get -o`, `network-publish`, `transfers`, `transfer-cancel`).

/// `miasma network-publish` default (`--data-shards` / `--total-shards`).
pub const DEFAULT_SEND_K: u8 = 10;
pub const DEFAULT_SEND_N: u8 = 20;

async fn do_transfer_start_receive(
    data_dir: &Path,
    mid: &str,
    output_path: &Path,
    password: Option<&str>,
    restart: bool,
    via: Vec<String>,
) -> WorkerResult {
    let abs = miasma_core::daemon::control_auth::absolutize_lexical(output_path);
    let req = ControlRequest::TransferStartReceive {
        mid: mid.trim().to_owned(),
        output_path: abs.to_string_lossy().into_owned(),
        password: password.filter(|p| !p.is_empty()).map(str::to_owned),
        restart,
        via,
        via_ca_pem: None,
    };
    transfer_started(daemon_request(data_dir, req).await)
}

async fn do_transfer_start_publish(
    data_dir: &Path,
    file_path: &Path,
    password: Option<&str>,
    data_shards: u8,
    total_shards: u8,
    restart: bool,
    canonicalize: bool,
) -> WorkerResult {
    // A resume keeps the path the journal recorded; a new send resolves it the way the CLI does,
    // so the same file started from either place is the same transfer.
    let path = if canonicalize {
        if !file_path.exists() {
            return WorkerResult::TransferError(format!("File not found: {}", file_path.display()));
        }
        std::fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_owned())
    } else {
        file_path.to_owned()
    };
    let req = ControlRequest::TransferStartPublish {
        file_path: path.to_string_lossy().into_owned(),
        data_shards,
        total_shards,
        password: password.filter(|p| !p.is_empty()).map(str::to_owned),
        restart,
    };
    transfer_started(daemon_request(data_dir, req).await)
}

fn transfer_started(res: anyhow::Result<ControlResponse>) -> WorkerResult {
    match res {
        Ok(ControlResponse::TransferStarted { id }) => WorkerResult::TransferStarted { id },
        Ok(ControlResponse::Error(e)) => WorkerResult::TransferError(e),
        Ok(other) => WorkerResult::TransferError(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::TransferError(daemon_error(&e)),
    }
}

async fn do_transfer_poll(data_dir: &Path) -> WorkerResult {
    match daemon_request(data_dir, ControlRequest::TransferList).await {
        Ok(ControlResponse::TransferList(list)) => WorkerResult::TransferList(list),
        Ok(ControlResponse::Error(message)) => WorkerResult::TransferPollFailed {
            message,
            daemon_down: false,
        },
        Ok(other) => WorkerResult::TransferPollFailed {
            message: format!("Unexpected response: {other:?}"),
            daemon_down: false,
        },
        Err(e) => WorkerResult::TransferPollFailed {
            daemon_down: is_daemon_down(&format!("{e:#}")),
            message: daemon_error(&e),
        },
    }
}

async fn do_transfer_cancel(data_dir: &Path, id: &str) -> WorkerResult {
    match daemon_request(
        data_dir,
        ControlRequest::TransferCancel { id: id.to_owned() },
    )
    .await
    {
        Ok(ControlResponse::TransferCancelled) => WorkerResult::TransferCancelRequested,
        Ok(ControlResponse::Error(e)) => WorkerResult::TransferError(e),
        Ok(other) => WorkerResult::TransferError(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::TransferError(daemon_error(&e)),
    }
}

/// `(k, n)` a stopped send began with, read from its journal in `<data_dir>/transfers`.
fn journal_shard_params(data_dir: &Path, source: &Path) -> Option<(u8, u8)> {
    use miasma_core::transfer::publish_journal::{publish_journal_path, PublishJournal};
    let path = publish_journal_path(&data_dir.join("transfers"), source);
    let j = PublishJournal::load(&path)?;
    Some((j.header.data_shards, j.header.total_shards))
}

fn parse_retention(s: &str) -> Result<u64, String> {
    let s = s.trim().to_lowercase();
    if let Some(h) = s.strip_suffix('h') {
        h.parse::<u64>()
            .map(|v| v * 3600)
            .map_err(|e| e.to_string())
    } else if let Some(d) = s.strip_suffix('d') {
        d.parse::<u64>()
            .map(|v| v * 86400)
            .map_err(|e| e.to_string())
    } else if let Some(m) = s.strip_suffix('m') {
        m.parse::<u64>().map(|v| v * 60).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bridge_import_args, parse_mids_from_stdout, DirectedInboxItem, WorkerCmd, WorkerResult,
    };
    use std::ffi::OsString;
    use std::path::Path;

    const MAGNET: &str = "magnet:?xt=urn:btih:abcdef0123456789abcdef0123456789abcdef01";

    #[test]
    fn retrieval_temp_path_is_unique_enough_for_sequential_calls() {
        let first = super::retrieval_temp_path();
        std::thread::sleep(std::time::Duration::from_nanos(1));
        let second = super::retrieval_temp_path();
        assert_ne!(first, second);
        assert_eq!(first.extension().and_then(|e| e.to_str()), Some("tmp"));
    }

    #[test]
    fn worker_debug_redacts_sensitive_material() {
        let cmd = WorkerCmd::DirectedSend {
            file_path: std::path::PathBuf::from("C:/private/secret.txt"),
            recipient_contact: "recipient-sensitive".into(),
            password: "password-sensitive".into(),
            retention: "1d".into(),
        };
        let rendered = format!("{cmd:?}");
        assert!(!rendered.contains("C:/private/secret.txt"));
        assert!(!rendered.contains("recipient-sensitive"));
        assert!(!rendered.contains("password-sensitive"));

        let text = WorkerCmd::DissolveText("plaintext-sensitive".into());
        let rendered = format!("{text:?}");
        assert!(!rendered.contains("plaintext-sensitive"));
        assert!(rendered.contains("text_len"));

        let confirm = WorkerCmd::DirectedConfirm {
            envelope_id: "env".into(),
            challenge_code: "ABCD-SECRET".into(),
        };
        let rendered = format!("{confirm:?}");
        assert!(!rendered.contains("ABCD-SECRET"));
    }

    #[test]
    fn a_dead_daemon_is_recognised_after_the_error_has_been_rewritten() {
        // `get_status` returns `daemon_error(..)`, and the GetStatus handler then asks
        // `is_daemon_down` about that text to decide whether to relaunch the daemon.
        for raw in [
            "cannot connect to daemon at 127.0.0.1:49783",
            "daemon.port not found in the data dir",
            "Daemon not running",
        ] {
            let shown = super::daemon_error(&anyhow::anyhow!(raw));
            assert!(super::is_daemon_down(raw), "{raw}");
            assert!(super::is_daemon_down(&shown), "rewritten form of {raw}");
        }
        assert!(!super::is_daemon_down("invalid MID"));
    }

    #[test]
    fn transfer_commands_debug_shows_no_password_or_path() {
        let recv = WorkerCmd::TransferStartReceive {
            mid: "miasma:visible-mid".into(),
            output_path: std::path::PathBuf::from("C:/private/out-secret.iso"),
            password: Some("password-sensitive".into()),
            restart: false,
            via: Vec::new(),
        };
        let rendered = format!("{recv:?}");
        assert!(!rendered.contains("password-sensitive"));
        assert!(!rendered.contains("out-secret"));
        assert!(rendered.contains("miasma:visible-mid"));

        let publish = WorkerCmd::TransferStartPublish {
            file_path: std::path::PathBuf::from("C:/private/src-secret.iso"),
            password: Some("password-sensitive".into()),
            data_shards: 10,
            total_shards: 12,
            restart: false,
        };
        let rendered = format!("{publish:?}");
        assert!(!rendered.contains("password-sensitive"));
        assert!(!rendered.contains("src-secret"));
        assert!(rendered.contains("total_shards: 12"));

        let resume = WorkerCmd::TransferResumePublish {
            file_path: std::path::PathBuf::from("C:/private/src-secret.iso"),
            password: Some("password-sensitive".into()),
        };
        let rendered = format!("{resume:?}");
        assert!(!rendered.contains("password-sensitive"));
        assert!(!rendered.contains("src-secret"));

        // A send's id embeds the source path.
        let cancel = WorkerCmd::TransferCancel {
            id: "send:C:/private/src-secret.iso".into(),
        };
        assert!(!format!("{cancel:?}").contains("src-secret"));
        assert_eq!(format!("{:?}", WorkerCmd::TransferPoll), "TransferPoll");
    }

    #[test]
    fn transfer_results_debug_shows_no_paths() {
        let started = WorkerResult::TransferStarted {
            id: "send:C:/private/src-secret.iso".into(),
        };
        assert!(!format!("{started:?}").contains("src-secret"));

        let status = miasma_core::transfer::TransferStatus {
            mid: "miasma:x".into(),
            kind: miasma_core::transfer::TransferKind::Send,
            name: "C:/private/src-secret.iso".into(),
            phase: miasma_core::transfer::Phase::Transferring,
            state: miasma_core::transfer::TransferState::Running,
            segments_done: 0,
            segments_total: 1,
            bytes_done: 0,
            bytes_total: 1,
            rate_bps: 0.0,
            eta_secs: None,
            elapsed_secs: 0.0,
            fetch_ms: 0,
            decode_ms: 0,
            write_ms: 0,
            pieces_fetched: 0,
            pieces_rejected: 0,
            segment_retries: 0,
            resumed_from_segment: 0,
            last_error: None,
            resumable: false,
        };
        let listed = WorkerResult::TransferList(vec![status]);
        let rendered = format!("{listed:?}");
        assert!(!rendered.contains("src-secret"));
        assert!(rendered.contains("count: 1"));
    }

    #[test]
    fn worker_result_debug_redacts_plaintext_and_directed_metadata() {
        let result = WorkerResult::Retrieved {
            mid: "miasma:test".into(),
            data: b"plaintext-sensitive".to_vec(),
        };
        let rendered = format!("{result:?}");
        assert!(!rendered.contains("plaintext-sensitive"));
        assert!(rendered.contains("data_len: 19"));

        let sharing = WorkerResult::SharingKey {
            contact: "msk:sensitive-contact@peer".into(),
        };
        assert!(!format!("{sharing:?}").contains("sensitive-contact"));

        let directed = WorkerResult::DirectedRetrieved {
            temp_path: std::path::PathBuf::from("C:/private/decrypted.tmp"),
            filename: Some("private-name.txt".into()),
            bytes_written: 42,
        };
        let rendered = format!("{directed:?}");
        assert!(!rendered.contains("C:/private/decrypted.tmp"));
        assert!(!rendered.contains("private-name.txt"));
    }

    #[test]
    fn directed_inbox_item_debug_redacts_challenge_and_filename() {
        let item = DirectedInboxItem {
            envelope_id: "env".into(),
            sender_pubkey: "sender".into(),
            sender_peer_id: Some("peer".into()),
            recipient_pubkey: "recipient".into(),
            state: "ChallengeIssued".into(),
            challenge_code: Some("ABCD-SECRET".into()),
            created_at: 1,
            expires_at: 2,
            filename: Some("private-name.txt".into()),
            file_size: 3,
        };
        let rendered = format!("{item:?}");
        assert!(!rendered.contains("ABCD-SECRET"));
        assert!(!rendered.contains("private-name.txt"));
        assert!(rendered.contains("<redacted>"));
    }

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    /// The exact argv the bridge's cross-process round-trip test spawns.
    #[test]
    fn magnet_import_sends_the_shape_the_bridge_accepts() {
        assert_eq!(
            bridge_import_args(&["--magnet", MAGNET], Path::new("C:/nodes/a")),
            os(&["--magnet", MAGNET, "--data-dir", "C:/nodes/a"])
        );
    }

    #[test]
    fn torrent_import_sends_the_shape_the_bridge_accepts() {
        assert_eq!(
            bridge_import_args(&["--torrent", "C:/dl/x.torrent"], Path::new("C:/nodes/a")),
            os(&["--torrent", "C:/dl/x.torrent", "--data-dir", "C:/nodes/a"])
        );
    }

    /// The installed default data dir sits under `AppData\Local\Programs`, and
    /// a user profile name with a space in it is ordinary. The path has to
    /// survive as one argument.
    #[test]
    fn a_data_dir_with_spaces_stays_a_single_argument() {
        let argv = bridge_import_args(
            &["--magnet", MAGNET],
            Path::new(r"C:\Users\Ada Lovelace\AppData\Roaming\miasma"),
        );
        assert_eq!(argv.len(), 4);
        assert_eq!(
            argv[3],
            OsString::from(r"C:\Users\Ada Lovelace\AppData\Roaming\miasma")
        );
    }

    /// Verbatim shape of what `miasma-bridge dissolve` writes on success —
    /// the MIDs are indented six spaces under the stage heading.
    const BRIDGE_STDOUT: &str = "\
[1/3] Preflight check
      Info hash:    abcdef0123456789abcdef0123456789abcdef01
      Data dir:     C:\\Users\\me\\AppData\\Roaming\\miasma

[2/3] Downloading torrent...

[3/3] Dissolved 2 file(s) into Miasma:
      miasma:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      miasma:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Done. Use 'miasma get <MID>' to retrieve content.
";

    #[test]
    fn indented_mids_are_parsed() {
        assert_eq!(
            parse_mids_from_stdout(BRIDGE_STDOUT),
            vec![
                "miasma:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                "miasma:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            ]
        );
    }

    #[test]
    fn unindented_mids_are_parsed_too() {
        assert_eq!(
            parse_mids_from_stdout("miasma:ZZZZ\n"),
            vec!["miasma:ZZZZ".to_string()]
        );
    }

    #[test]
    fn prose_mentioning_mids_is_not_collected() {
        // Only lines that *are* a MID count; the trailing hint line mentions
        // "miasma" but does not start with the scheme once trimmed.
        assert!(parse_mids_from_stdout(
            "Done. Use 'miasma get <MID>' to retrieve content.\n[2/3] Downloading torrent...\n"
        )
        .is_empty());
    }
}
