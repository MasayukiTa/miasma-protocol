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
/// The worker no longer owns a `LocalShareStore`.  All operations go through
/// the daemon's IPC control plane (`daemon_request`).  If the daemon is not
/// running, every command returns a clear error.
use std::path::PathBuf;
use std::sync::mpsc;

use miasma_core::{
    daemon_request, ControlRequest, ControlResponse,
    pipeline::DissolutionParams,
};

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
    /// Distress-wipe: delete master key → all shares become unreadable.
    Wipe,
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
        pending_replication: usize,
        replicated_count: usize,
        listen_addrs: Vec<String>,
        wss_port: u16,
        wss_tls_enabled: bool,
        proxy_configured: bool,
        proxy_type: Option<String>,
        transport_statuses: Vec<TransportStatusInfo>,
    },
    /// Distress wipe complete.
    Wiped,
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

            WorkerCmd::GetStatus => rt.block_on(get_status(&data_dir)),

            WorkerCmd::Wipe => rt.block_on(do_wipe(&data_dir)),
        };

        if tx.send(res).is_err() {
            break; // UI dropped its receiver — exit cleanly.
        }
    }
}

// ─── IPC helpers ──────────────────────────────────────────────────────────────

const DAEMON_ERR: &str = "Daemon not running. Start with: miasma daemon";

async fn publish_bytes(data: &[u8], data_dir: &PathBuf, params: DissolutionParams) -> WorkerResult {
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

async fn retrieve_mid(mid_str: &str, data_dir: &PathBuf, params: DissolutionParams) -> WorkerResult {
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

async fn get_status(data_dir: &PathBuf) -> WorkerResult {
    match daemon_request(data_dir, ControlRequest::Status).await {
        Ok(ControlResponse::Status(s)) => WorkerResult::Status {
            peer_id: s.peer_id,
            peer_count: s.peer_count,
            share_count: s.share_count,
            used_mb: s.storage_used_bytes as f64 / (1024.0 * 1024.0),
            pending_replication: s.pending_replication,
            replicated_count: s.replicated_count,
            listen_addrs: s.listen_addrs,
            wss_port: s.wss_port,
            wss_tls_enabled: s.wss_tls_enabled,
            proxy_configured: s.proxy_configured,
            proxy_type: s.proxy_type,
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
        },
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

async fn do_wipe(data_dir: &PathBuf) -> WorkerResult {
    match daemon_request(data_dir, ControlRequest::Wipe).await {
        Ok(ControlResponse::Wiped) => WorkerResult::Wiped,
        Ok(ControlResponse::Error(e)) => WorkerResult::Err(e),
        Ok(other) => WorkerResult::Err(format!("Unexpected response: {other:?}")),
        Err(e) => WorkerResult::Err(daemon_error(&e)),
    }
}

/// Convert anyhow errors into user-friendly messages.
/// If the root cause is a missing port file or connection refused, surface
/// the clear "daemon not running" message.
fn daemon_error(e: &anyhow::Error) -> String {
    let msg = format!("{e:#}");
    if msg.contains("daemon.port not found") || msg.contains("cannot connect to daemon") {
        DAEMON_ERR.to_string()
    } else {
        msg
    }
}
