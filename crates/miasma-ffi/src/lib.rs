//! UniFFI bridge — exposes miasma-core to Kotlin/Android.
//!
//! # Architecture
//! All exported functions are **synchronous** at the FFI boundary.
//! Async operations (e.g. `RetrievalCoordinator::retrieve`) are driven by an
//! in-function `tokio` runtime so that the Kotlin layer can call them from
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
    ContentId, DissolutionParams, MiasmaError,
    LocalShareSource, RetrievalCoordinator,
};

// Tell UniFFI to generate the FFI scaffolding for this crate.
uniffi::setup_scaffolding!("miasma_ffi");

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
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MiasmaFfiError {
    /// Node has not been initialised (no `master.key` / config found).
    #[error("Node not initialised at '{data_dir}'. Call initialize_node first.")]
    NotInitialized { data_dir: String },

    /// Supplied MID string could not be parsed.
    #[error("Invalid MID: {reason}")]
    InvalidMid { reason: String },

    /// Not enough shares available for reconstruction.
    #[error("Insufficient shares: need {need}, found {got}")]
    InsufficientShares { need: u64, got: u64 },

    /// Catch-all for I/O, crypto, and serialization errors.
    #[error("{msg}")]
    Other { msg: String },
}

impl From<MiasmaError> for MiasmaFfiError {
    fn from(e: MiasmaError) -> Self {
        match e {
            MiasmaError::InvalidMid(m) => MiasmaFfiError::InvalidMid { reason: m },
            MiasmaError::InsufficientShares { need, got } => MiasmaFfiError::InsufficientShares {
                need: need as u64,
                got: got as u64,
            },
            other => MiasmaFfiError::Other {
                msg: other.to_string(),
            },
        }
    }
}

impl From<anyhow::Error> for MiasmaFfiError {
    fn from(e: anyhow::Error) -> Self {
        MiasmaFfiError::Other { msg: e.to_string() }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Load config and open the share store. Returns `NotInitialized` if the node
/// has not been initialised (`master.key` or `config.toml` missing).
fn open_store(data_dir: &str) -> Result<(NodeConfig, Arc<LocalShareStore>), MiasmaFfiError> {
    let path = PathBuf::from(data_dir);
    let master_key_path = path.join("master.key");
    if !master_key_path.exists() {
        return Err(MiasmaFfiError::NotInitialized {
            data_dir: data_dir.to_owned(),
        });
    }
    let config = NodeConfig::load(&path).map_err(|e| MiasmaFfiError::Other { msg: e.to_string() })?;
    let store = LocalShareStore::open(&path, config.storage.quota_mb)
        .map_err(|e| MiasmaFfiError::Other { msg: e.to_string() })?;
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
    let path = PathBuf::from(&data_dir);
    std::fs::create_dir_all(&path)
        .map_err(|e| MiasmaFfiError::Other { msg: e.to_string() })?;

    let config = NodeConfig {
        storage: StorageConfig {
            quota_mb: storage_mb,
            bandwidth_mb_day,
        },
        network: NetworkConfig {
            listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1".into(),
            bootstrap_peers: vec![],
        },
    };
    config
        .save(&path)
        .map_err(|e| MiasmaFfiError::Other { msg: e.to_string() })?;

    // Opening the store creates master.key if absent.
    LocalShareStore::open(&path, storage_mb)
        .map_err(|e| MiasmaFfiError::Other { msg: e.to_string() })?;

    Ok(())
}

/// Dissolve raw bytes into encrypted shares and store them locally.
///
/// Returns the Miasma Content ID (MID) string, e.g. `miasma:<base58>`.
/// Default dissolution parameters (k=10, n=20) are used.
#[uniffi::export]
pub fn dissolve_bytes(data_dir: String, data: Vec<u8>) -> Result<String, MiasmaFfiError> {
    let (config, store) = open_store(&data_dir)?;
    let params = DissolutionParams {
        data_shards: 10,
        total_shards: 20,
    };

    let (mid, shares) = dissolve(&data, params).map_err(MiasmaFfiError::from)?;

    for share in &shares {
        store
            .put(share)
            .map_err(|e| MiasmaFfiError::Other { msg: e.to_string() })?;
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

    // RetrievalCoordinator is async — drive it with a dedicated runtime.
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| MiasmaFfiError::Other { msg: e.to_string() })?;

    let plaintext = rt.block_on(async {
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
#[uniffi::export]
pub fn distress_wipe(data_dir: String) -> Result<(), MiasmaFfiError> {
    let (_config, store) = open_store(&data_dir)?;
    store
        .distress_wipe()
        .map_err(|e| MiasmaFfiError::Other { msg: e.to_string() })?;
    Ok(())
}
