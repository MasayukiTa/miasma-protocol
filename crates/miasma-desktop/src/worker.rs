/// Background worker — runs miasma-core operations off the UI thread.
///
/// Architecture:
/// ```text
/// UI thread ──(WorkerCmd)──► worker OS thread ──(WorkerResult)──► UI thread
///                mpsc::SyncSender               mpsc::Receiver
/// ```
///
/// The worker owns the `LocalShareStore` exclusively (no Mutex needed).
/// All miasma-core calls are synchronous in the worker thread; async retrieval
/// uses a single-threaded tokio runtime created inside the worker.
use std::path::PathBuf;
use std::sync::{mpsc, Arc};

use miasma_core::{
    pipeline::{dissolve, DissolutionParams},
    retrieval::{LocalShareSource, RetrievalCoordinator},
    ContentId, LocalShareStore,
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
    /// Query current share-store metrics.
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
    /// Status snapshot.
    Status { share_count: usize, used_mb: f64, quota_mb: u64 },
    /// Distress wipe complete.
    Wiped,
    /// Any error.
    Err(String),
}

// ─── Handle ───────────────────────────────────────────────────────────────────

/// Owns the channels used to communicate with the worker thread.
pub struct WorkerHandle {
    pub tx: mpsc::SyncSender<WorkerCmd>,
    pub rx: mpsc::Receiver<WorkerResult>,
    /// Initial quota; reflected in status responses.
    pub _quota_mb: u64,
}

impl WorkerHandle {
    pub fn spawn(data_dir: PathBuf, quota_mb: u64) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::sync_channel(32);
        let (res_tx, res_rx) = mpsc::sync_channel(64);

        std::thread::Builder::new()
            .name("miasma-worker".into())
            .spawn(move || worker_thread(data_dir, quota_mb, cmd_rx, res_tx))
            .expect("spawn worker thread");

        Self { tx: cmd_tx, rx: res_rx, _quota_mb: quota_mb }
    }
}

// ─── Worker thread ────────────────────────────────────────────────────────────

fn worker_thread(
    data_dir: PathBuf,
    quota_mb: u64,
    rx: mpsc::Receiver<WorkerCmd>,
    tx: mpsc::SyncSender<WorkerResult>,
) {
    let store = match LocalShareStore::open(&data_dir, quota_mb) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let _ = tx.send(WorkerResult::Err(format!("Store open failed: {e}")));
            return;
        }
    };

    // Single-threaded tokio runtime for async retrieval.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let params = DissolutionParams::default();

    while let Ok(cmd) = rx.recv() {
        let res = match cmd {
            WorkerCmd::DissolveText(text) => dissolve_bytes(text.as_bytes(), &store, params),

            WorkerCmd::DissolveFile(path) => match std::fs::read(&path) {
                Ok(data) => dissolve_bytes(&data, &store, params),
                Err(e) => WorkerResult::Err(format!("Read file: {e}")),
            },

            WorkerCmd::Retrieve(mid_str) => {
                match ContentId::from_str(&mid_str) {
                    Ok(mid) => {
                        let src = LocalShareSource::new(store.clone());
                        let coord = RetrievalCoordinator::new(src);
                        match rt.block_on(coord.retrieve(&mid, params)) {
                            Ok(data) => WorkerResult::Retrieved { mid: mid_str, data },
                            Err(e) => WorkerResult::Err(format!("Retrieve: {e}")),
                        }
                    }
                    Err(e) => WorkerResult::Err(format!("Invalid MID: {e}")),
                }
            }

            WorkerCmd::GetStatus => WorkerResult::Status {
                share_count: store.list().len(),
                used_mb: store.used_bytes() as f64 / (1024.0 * 1024.0),
                quota_mb,
            },

            WorkerCmd::Wipe => match store.distress_wipe() {
                Ok(_) => WorkerResult::Wiped,
                Err(e) => WorkerResult::Err(format!("Wipe: {e}")),
            },

        };

        if tx.send(res).is_err() {
            break; // UI dropped its receiver — exit cleanly.
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn dissolve_bytes(
    data: &[u8],
    store: &Arc<LocalShareStore>,
    params: DissolutionParams,
) -> WorkerResult {
    match dissolve(data, params) {
        Ok((mid, shares)) => {
            for share in &shares {
                if let Err(e) = store.put(share) {
                    return WorkerResult::Err(format!("Store share: {e}"));
                }
            }
            WorkerResult::Dissolved { mid: mid.to_string() }
        }
        Err(e) => WorkerResult::Err(format!("Dissolve: {e}")),
    }
}
