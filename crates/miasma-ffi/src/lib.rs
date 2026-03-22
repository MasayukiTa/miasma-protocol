//! UniFFI bridge — exposes miasma-core to Kotlin/Android.
//!
//! # Architecture
//! All exported functions are **synchronous** at the FFI boundary.
//! Async operations (e.g. `RetrievalCoordinator::retrieve`) are driven by a
//! shared static `tokio` runtime so that the Kotlin layer can call them from
//! any coroutine dispatcher without worrying about runtime lifecycle.
//!
//! # Kotlin bindings generation
//! ```sh
//! # 1. Build for Android targets (requires cargo-ndk + Android NDK):
//! cargo ndk -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs \
//!     build --release -p miasma-ffi
//!
//! # 2. Generate Kotlin bindings from the compiled library:
//! uniffi-bindgen generate \
//!     --library target/debug/libmiasma_ffi.so \
//!     --language kotlin \
//!     --out-dir android/app/src/main/kotlin/dev/miasma/uniffi/
//! ```
//!
//! The generated file will be placed at
//! `android/app/src/main/kotlin/dev/miasma/uniffi/miasma_ffi.kt`.

use std::path::PathBuf;
use std::sync::Arc;

use miasma_core::{
    config::{NetworkConfig, NodeConfig, StorageConfig},
    dissolve,
    store::LocalShareStore,
    ContentId, DissolutionParams, LocalShareSource, MiasmaError, RetrievalCoordinator,
};

// Tell UniFFI to generate the FFI scaffolding for this crate.
uniffi::setup_scaffolding!("miasma_ffi");

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum input size for dissolve (100 MiB).
const MAX_DISSOLVE_SIZE: usize = 100 * 1024 * 1024;

// ─── Static tokio runtime (shared across all FFI calls) ─────────────────────

fn shared_runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}

// ─── Exported types ──────────────────────────────────────────────────────────

/// Node status snapshot returned to the UI.
#[derive(uniffi::Record)]
pub struct NodeStatusFfi {
    /// Number of shares currently in the local store.
    pub share_count: u64,
    /// Storage used in MiB.
    pub used_mb: f64,
    /// Storage quota in MiB.
    pub quota_mb: u64,
    /// Configured listen multiaddr.
    pub listen_addr: String,
    /// Number of bootstrap peers in config.
    pub bootstrap_count: u64,
}

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors surfaced across the FFI boundary to Kotlin.
///
/// Error messages are sanitized to avoid leaking internal paths or system details.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MiasmaFfiError {
    /// Node has not been initialised (no `master.key` / config found).
    #[error("Node not initialised. Call initialize_node first.")]
    NotInitialized { data_dir: String },

    /// Supplied MID string could not be parsed.
    #[error("Invalid content identifier")]
    InvalidMid { reason: String },

    /// Not enough shares available for reconstruction.
    #[error("Insufficient shares: need {need}, found {got}")]
    InsufficientShares { need: u64, got: u64 },

    /// Input data exceeds size limit.
    #[error("Input too large")]
    InputTooLarge { size: u64, max: u64 },

    /// Catch-all for I/O, crypto, and serialization errors.
    #[error("Operation failed")]
    Other { msg: String },
}

impl From<MiasmaError> for MiasmaFfiError {
    fn from(e: MiasmaError) -> Self {
        match e {
            MiasmaError::InvalidMid(_) => MiasmaFfiError::InvalidMid {
                reason: "invalid format".into(),
            },
            MiasmaError::InsufficientShares { need, got } => MiasmaFfiError::InsufficientShares {
                need: need as u64,
                got: got as u64,
            },
            other => {
                tracing::warn!("FFI error: {other}");
                MiasmaFfiError::Other {
                    msg: "internal error".into(),
                }
            }
        }
    }
}

impl From<anyhow::Error> for MiasmaFfiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::warn!("FFI anyhow error: {e}");
        MiasmaFfiError::Other {
            msg: "internal error".into(),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Validate that `data_dir` is a safe path within the app's private storage.
/// Rejects paths containing `..`, absolute paths outside expected prefixes,
/// and symlink traversals.
fn validate_data_dir(data_dir: &str) -> Result<PathBuf, MiasmaFfiError> {
    let path = PathBuf::from(data_dir);

    // Must be absolute.
    if !path.is_absolute() {
        return Err(MiasmaFfiError::Other {
            msg: "data_dir must be an absolute path".into(),
        });
    }

    // Reject path traversal components.
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(MiasmaFfiError::Other {
                msg: "data_dir must not contain '..'".into(),
            });
        }
    }

    // Canonicalize to resolve symlinks (if the path exists).
    let canonical = if path.exists() {
        path.canonicalize().map_err(|_| MiasmaFfiError::Other {
            msg: "failed to canonicalize data_dir".into(),
        })?
    } else {
        path.clone()
    };

    // On Android, the app's private data directory is typically:
    //   /data/data/{package}/files  or  /data/user/{n}/{package}/files
    // We accept any path under /data/ as a reasonable constraint.
    let canonical_str = canonical.to_string_lossy();
    if !canonical_str.starts_with("/data/") && !canonical_str.starts_with("/tmp/") {
        return Err(MiasmaFfiError::Other {
            msg: "data_dir must be within app private storage".into(),
        });
    }

    Ok(canonical)
}

/// Load config and open the share store. Returns `NotInitialized` if the node
/// has not been initialised (`master.key` or `config.toml` missing).
fn open_store(data_dir: &str) -> Result<(NodeConfig, Arc<LocalShareStore>), MiasmaFfiError> {
    let path = validate_data_dir(data_dir)?;
    let master_key_path = path.join("master.key");
    if !master_key_path.exists() {
        return Err(MiasmaFfiError::NotInitialized {
            data_dir: data_dir.to_owned(),
        });
    }
    let config = NodeConfig::load(&path).map_err(|e| {
        tracing::warn!("config load error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to load config".into(),
        }
    })?;
    let store = LocalShareStore::open(&path, config.storage.quota_mb).map_err(|e| {
        tracing::warn!("store open error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to open store".into(),
        }
    })?;
    Ok((config, Arc::new(store)))
}

// ─── Exported functions ───────────────────────────────────────────────────────

/// Initialise a new Miasma node at `data_dir`.
///
/// Creates the data directory, generates a master key, and writes a default
/// config. Idempotent — safe to call again if the node is already initialised.
#[uniffi::export]
pub fn initialize_node(
    data_dir: String,
    storage_mb: u64,
    bandwidth_mb_day: u64,
) -> Result<(), MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    std::fs::create_dir_all(&path).map_err(|e| {
        tracing::warn!("create_dir_all error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to create data directory".into(),
        }
    })?;

    let config = NodeConfig {
        storage: StorageConfig {
            quota_mb: storage_mb,
            bandwidth_mb_day,
        },
        network: NetworkConfig {
            listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1".into(),
            bootstrap_peers: vec![],
        },
        transport: Default::default(),
    };
    config.save(&path).map_err(|e| {
        tracing::warn!("config save error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to save config".into(),
        }
    })?;

    // Opening the store creates master.key if absent.
    LocalShareStore::open(&path, storage_mb).map_err(|e| {
        tracing::warn!("store init error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to initialize store".into(),
        }
    })?;

    Ok(())
}

/// Dissolve raw bytes into encrypted shares and store them locally.
///
/// Returns the Miasma Content ID (MID) string, e.g. `miasma:<base58>`.
/// Default dissolution parameters (k=10, n=20) are used.
#[uniffi::export]
pub fn dissolve_bytes(data_dir: String, data: Vec<u8>) -> Result<String, MiasmaFfiError> {
    // Enforce input size limit to prevent OOM.
    if data.len() > MAX_DISSOLVE_SIZE {
        return Err(MiasmaFfiError::InputTooLarge {
            size: data.len() as u64,
            max: MAX_DISSOLVE_SIZE as u64,
        });
    }
    if data.is_empty() {
        return Err(MiasmaFfiError::Other {
            msg: "empty input".into(),
        });
    }

    let (config, store) = open_store(&data_dir)?;
    let params = DissolutionParams {
        data_shards: 10,
        total_shards: 20,
    };

    let (mid, shares) = dissolve(&data, params).map_err(MiasmaFfiError::from)?;

    for share in &shares {
        store.put(share).map_err(|e| {
            tracing::warn!("share store error: {e}");
            MiasmaFfiError::Other {
                msg: "failed to store share".into(),
            }
        })?;
    }

    let _ = config; // suppress unused warning; quota already enforced by store
    Ok(mid.to_string())
}

/// Retrieve content by MID, reconstructing it entirely in memory.
///
/// Returns the plaintext bytes. Never writes plaintext to disk.
#[uniffi::export]
pub fn retrieve_bytes(data_dir: String, mid_str: String) -> Result<Vec<u8>, MiasmaFfiError> {
    let (_config, store) = open_store(&data_dir)?;

    let mid = ContentId::from_str(&mid_str).map_err(MiasmaFfiError::from)?;
    let params = DissolutionParams {
        data_shards: 10,
        total_shards: 20,
    };

    // Use the shared static runtime instead of creating a new one per call.
    let plaintext = shared_runtime().block_on(async {
        let coord = RetrievalCoordinator::new(LocalShareSource::new(store));
        coord.retrieve(&mid, params).await
    })?;

    Ok(plaintext)
}

/// Return a snapshot of the node's current status.
#[uniffi::export]
pub fn get_node_status(data_dir: String) -> Result<NodeStatusFfi, MiasmaFfiError> {
    let (config, store) = open_store(&data_dir)?;

    let used_bytes = store.used_bytes();
    let _quota_bytes = config.storage.quota_mb * 1024 * 1024;
    let share_count = store.list().len() as u64;

    Ok(NodeStatusFfi {
        share_count,
        used_mb: used_bytes as f64 / 1024.0 / 1024.0,
        quota_mb: config.storage.quota_mb,
        listen_addr: config.network.listen_addr.clone(),
        bootstrap_count: config.network.bootstrap_peers.len() as u64,
    })
}

/// Perform an emergency distress wipe.
///
/// Zeroes and deletes the master key within seconds. All locally stored shares
/// become permanently unreadable. The node directory remains so the app
/// continues to appear normally installed.
///
/// This function is intentionally lenient — it proceeds with deletion even if
/// the node was not fully initialized, to ensure residual files are cleaned.
#[uniffi::export]
pub fn distress_wipe(data_dir: String) -> Result<(), MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;

    // Try to wipe via store (zeroes master.key contents before deleting).
    // If the store can't be opened (e.g., master.key already deleted),
    // proceed with manual cleanup anyway.
    if let Ok((_config, store)) = open_store(&data_dir) {
        let _ = store.distress_wipe();
    }

    // Explicitly delete master.key and Keystore-wrapped blobs.
    // These deletions are best-effort — we don't fail the wipe if some
    // files are already gone.
    let files_to_delete = ["master.key", "master.key.enc", "master.key.iv"];
    for fname in &files_to_delete {
        let fpath = path.join(fname);
        if fpath.exists() {
            // Overwrite with zeros before deleting (defense in depth).
            if let Ok(metadata) = std::fs::metadata(&fpath) {
                let zeros = vec![0u8; metadata.len() as usize];
                let _ = std::fs::write(&fpath, &zeros);
            }
            let _ = std::fs::remove_file(&fpath);
        }
    }

    Ok(())
}
