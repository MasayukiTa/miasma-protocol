//! UniFFI bridge — exposes miasma-core to Kotlin/Android and Swift/iOS.
//!
//! # Architecture
//! All exported functions are **synchronous** at the FFI boundary.
//! Async operations (e.g. `RetrievalCoordinator::retrieve`) are driven by a
//! shared static `tokio` runtime so that the Kotlin/Swift layer can call them
//! from any coroutine dispatcher without worrying about runtime lifecycle.
//!
//! # Embedded daemon
//! `start_embedded_daemon()` starts a full MiasmaNode + DaemonServer + HTTP
//! bridge within the FFI process.  The HTTP bridge on `127.0.0.1` provides
//! all directed sharing endpoints to both native UI and hosted WebView.
//!
//! # Kotlin bindings generation
//! ```sh
//! # 1. Build for Android targets (requires cargo-ndk + Android NDK):
//! cargo ndk -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs \
//!     build --release -p miasma-ffi
//!
//! # 2. Generate Kotlin bindings with the repository-pinned UniFFI CLI:
//! cargo run -p miasma-ffi --features bindgen-cli --bin miasma-uniffi-bindgen -- \
//!     generate --library --metadata-no-deps --language kotlin \
//!     --config crates/miasma-ffi/uniffi.toml \
//!     --out-dir android/app/src/main/kotlin \
//!     target/aarch64-linux-android/release/libmiasma_ffi.so
//! ```
//!
//! The generated file will be placed at
//! `android/app/src/main/kotlin/dev/miasma/uniffi/miasma_ffi.kt`.

use std::path::PathBuf;
use std::sync::Arc;

use zeroize::Zeroizing;

use miasma_core::{
    config::{NetworkConfig, NodeConfig, StorageConfig},
    daemon::{
        control_auth,
        ipc::{daemon_request, ControlRequest, ControlResponse},
        DaemonServer,
    },
    directed, dissolve,
    network::{node::MiasmaNode, types::NodeType},
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

// ─── Embedded daemon state ───────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::mpsc;

/// State of the embedded daemon (started via `start_embedded_daemon`).
struct EmbeddedDaemon {
    /// Monotonic generation used to avoid an old exiting task clearing a newer daemon.
    generation: u64,
    /// HTTP bridge port on 127.0.0.1.
    http_port: u16,
    /// Peer ID (libp2p).
    peer_id: String,
    /// Sharing contact string (`msk:<base58>@<PeerId>`).
    sharing_contact: String,
    /// Channel to signal daemon shutdown.
    shutdown_tx: mpsc::Sender<()>,
}

/// Global singleton for the embedded daemon.
static EMBEDDED_DAEMON: Mutex<Option<EmbeddedDaemon>> = Mutex::new(None);
static EMBEDDED_DAEMON_GENERATION: AtomicU64 = AtomicU64::new(1);

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

/// Result of a file-path retrieval that kept plaintext out of the FFI byte boundary.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileReceiveResultFfi {
    /// Absolute destination path reported by the daemon.
    pub output_path: String,
    /// Number of plaintext bytes written after full MID verification.
    pub bytes_written: u64,
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
    // On iOS:
    //   /var/mobile/Containers/Data/Application/{UUID}/...
    //   ~/Library/Application Support/miasma/
    // We accept paths under known safe prefixes.
    let canonical_str = canonical.to_string_lossy();
    let allowed = canonical_str.starts_with("/data/")
        || canonical_str.starts_with("/tmp/")
        || canonical_str.starts_with("/var/mobile/")
        || canonical_str.starts_with("/private/var/")
        || canonical_str.contains("/Library/Application Support/");
    if !allowed {
        return Err(MiasmaFfiError::Other {
            msg: "data_dir must be within app private storage".into(),
        });
    }

    Ok(canonical)
}

/// Load config and open the share store. Returns `NotInitialized` if the node
/// has not been initialised (`master.key` or `config.toml` missing).
fn open_store_inner(
    data_dir: &str,
    keep_transport_secrets: bool,
) -> Result<(NodeConfig, Arc<LocalShareStore>), MiasmaFfiError> {
    let path = validate_data_dir(data_dir)?;
    let master_key_path = miasma_core::paths::master_key(&path);
    if !master_key_path.exists() {
        return Err(MiasmaFfiError::NotInitialized {
            data_dir: data_dir.to_owned(),
        });
    }
    let mut config = NodeConfig::load(&path).map_err(|e| {
        tracing::warn!("config load error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to load config".into(),
        }
    })?;
    let store = LocalShareStore::open_with_quotas(
        &path,
        config.storage.quota_mb,
        config.storage.hosted_quota_mb,
    )
    .map_err(|e| {
        tracing::warn!("store open error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to open store".into(),
        }
    })?;
    if !keep_transport_secrets {
        config.transport.zeroize_secret_copies();
    }
    Ok((config, Arc::new(store)))
}

fn open_store(data_dir: &str) -> Result<(NodeConfig, Arc<LocalShareStore>), MiasmaFfiError> {
    open_store_inner(data_dir, false)
}

fn open_store_for_daemon(
    data_dir: &str,
) -> Result<(NodeConfig, Arc<LocalShareStore>), MiasmaFfiError> {
    open_store_inner(data_dir, true)
}

const MAX_MOBILE_BOOTSTRAP_PEERS: usize = 64;
const MAX_MOBILE_BOOTSTRAP_ADDR_LEN: usize = 2_048;

fn normalize_bootstrap_peers(peers: Vec<String>) -> Result<Vec<String>, MiasmaFfiError> {
    let mut normalized = Vec::with_capacity(peers.len().min(MAX_MOBILE_BOOTSTRAP_PEERS));
    for (index, raw) in peers.into_iter().enumerate() {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        if value.len() > MAX_MOBILE_BOOTSTRAP_ADDR_LEN {
            return Err(MiasmaFfiError::Other {
                msg: format!("bootstrap peer {} is too long", index + 1),
            });
        }
        let addr: libp2p::Multiaddr = value.parse().map_err(|_| MiasmaFfiError::Other {
            msg: format!("bootstrap peer {} is not a valid multiaddr", index + 1),
        })?;
        let has_peer_id = addr
            .iter()
            .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)));
        if !has_peer_id {
            return Err(MiasmaFfiError::Other {
                msg: format!("bootstrap peer {} is missing /p2p/<peer-id>", index + 1),
            });
        }
        let canonical = addr.to_string();
        if !normalized.contains(&canonical) {
            if normalized.len() == MAX_MOBILE_BOOTSTRAP_PEERS {
                return Err(MiasmaFfiError::Other {
                    msg: format!("too many bootstrap peers (max {MAX_MOBILE_BOOTSTRAP_PEERS})"),
                });
            }
            normalized.push(canonical);
        }
    }
    Ok(normalized)
}

fn apply_mobile_limits(
    mut config: NodeConfig,
    storage_mb: u64,
    bandwidth_mb_day: u64,
) -> NodeConfig {
    config.storage.quota_mb = storage_mb;
    config.storage.bandwidth_mb_day = bandwidth_mb_day;
    config
}

const DEFAULT_DATA_SHARDS: u8 = 10;
const DEFAULT_TOTAL_SHARDS: u8 = 20;

fn validate_ffi_file_path(
    value: &str,
    field: &'static str,
    require_existing_file: bool,
) -> Result<PathBuf, MiasmaFfiError> {
    let path = control_auth::validate_output_path(value).map_err(|e| {
        tracing::warn!(field, error = %e, "FFI file path rejected");
        MiasmaFfiError::Other {
            msg: format!("{field} must be an absolute path without '..'"),
        }
    })?;
    if require_existing_file && !path.is_file() {
        return Err(MiasmaFfiError::Other {
            msg: format!("{field} must name an existing file"),
        });
    }
    Ok(path)
}

fn daemon_call(
    data_dir: &PathBuf,
    request: ControlRequest,
) -> Result<ControlResponse, MiasmaFfiError> {
    shared_runtime()
        .block_on(daemon_request(data_dir, request))
        .map_err(|e| {
            tracing::warn!("FFI daemon request failed: {e}");
            MiasmaFfiError::Other {
                msg: "daemon is not available".into(),
            }
        })
}

// ─── Exported functions ───────────────────────────────────────────────────────

/// Initialise a new Miasma node at `data_dir`.
///
/// Creates the data directory and master key when absent. On an existing node it
/// only updates the mobile storage/bandwidth limits and preserves the rest of
/// `config.toml`, including bootstrap peers and transport settings.
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

    // Re-running initialization updates mobile quota knobs without destroying
    // the rest of config.toml. In particular, bootstrap peers and transport
    // settings must survive every embedded-daemon restart. New mobile nodes use
    // a store-managed update policy because Google Play/App Store own updates.
    let config_path = miasma_core::paths::config_file(&path);
    let config = if config_path.exists() {
        NodeConfig::load(&path).map_err(|e| {
            tracing::warn!("config load error during initialize: {e}");
            MiasmaFfiError::Other {
                msg: "failed to load existing config".into(),
            }
        })?
    } else {
        NodeConfig {
            storage: StorageConfig::default(),
            network: NetworkConfig {
                listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1".into(),
                bootstrap_peers: vec![],
            },
            transport: Default::default(),
            push: Default::default(),
            chat: Default::default(),
            privacy: Default::default(),
            update: miasma_core::update::UpdateConfig::stealth_preset(),
        }
    };
    let config = apply_mobile_limits(config, storage_mb, bandwidth_mb_day);
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

/// Replace the persisted bootstrap peer list used by the embedded mobile daemon.
///
/// Entries are normalized as libp2p multiaddrs, must include a `/p2p/<peer-id>`
/// component, and are deduplicated while preserving order.
#[uniffi::export]
pub fn set_bootstrap_peers(
    data_dir: String,
    bootstrap_peers: Vec<String>,
) -> Result<(), MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    if !miasma_core::paths::config_file(&path).exists() {
        return Err(MiasmaFfiError::NotInitialized { data_dir });
    }
    let normalized = normalize_bootstrap_peers(bootstrap_peers)?;
    let mut config = NodeConfig::load(&path).map_err(|e| {
        tracing::warn!("config load error while setting bootstrap peers: {e}");
        MiasmaFfiError::Other {
            msg: "failed to load config".into(),
        }
    })?;
    config.network.bootstrap_peers = normalized;
    config.save(&path).map_err(|e| {
        tracing::warn!("config save error while setting bootstrap peers: {e}");
        MiasmaFfiError::Other {
            msg: "failed to save bootstrap peers".into(),
        }
    })
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
        data_shards: DEFAULT_DATA_SHARDS as usize,
        total_shards: DEFAULT_TOTAL_SHARDS as usize,
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
        data_shards: DEFAULT_DATA_SHARDS as usize,
        total_shards: DEFAULT_TOTAL_SHARDS as usize,
    };

    // Use the shared static runtime instead of creating a new one per call.
    let plaintext = shared_runtime().block_on(async {
        let coord = RetrievalCoordinator::new(LocalShareSource::new(store));
        coord.retrieve(&mid, params).await
    })?;

    Ok(plaintext)
}

/// Publish a local file through the running daemon without copying the file
/// contents through UniFFI. The daemon streams dissolution segment by segment.
///
/// `file_path` must be absolute, contain no `..` component, and already exist.
/// The embedded daemon must have been started first.
#[uniffi::export]
pub fn publish_file(data_dir: String, file_path: String) -> Result<String, MiasmaFfiError> {
    let data_path = validate_data_dir(&data_dir)?;
    let file_path = validate_ffi_file_path(&file_path, "file_path", true)?;
    let response = daemon_call(
        &data_path,
        ControlRequest::PublishFile {
            file_path: file_path.to_string_lossy().into_owned(),
            data_shards: DEFAULT_DATA_SHARDS,
            total_shards: DEFAULT_TOTAL_SHARDS,
        },
    )?;
    match response {
        ControlResponse::Published { mid } => Ok(mid),
        ControlResponse::Error(message) => {
            tracing::warn!("daemon publish_file error: {message}");
            Err(MiasmaFfiError::Other {
                msg: "file publish failed".into(),
            })
        }
        _ => Err(MiasmaFfiError::Other {
            msg: "unexpected daemon response".into(),
        }),
    }
}

/// Retrieve a MID through the running daemon and stream verified plaintext
/// directly to `output_path`, avoiding a whole-file `Vec<u8>` crossing UniFFI.
///
/// `output_path` must be absolute and contain no `..` component. The embedded
/// daemon must have been started first.
#[uniffi::export]
pub fn retrieve_to_file(
    data_dir: String,
    mid_str: String,
    output_path: String,
) -> Result<FileReceiveResultFfi, MiasmaFfiError> {
    let data_path = validate_data_dir(&data_dir)?;
    let mid = ContentId::from_str(&mid_str).map_err(MiasmaFfiError::from)?;
    let output_path = validate_ffi_file_path(&output_path, "output_path", false)?;
    let requested_path = output_path.to_string_lossy().into_owned();
    let response = daemon_call(
        &data_path,
        ControlRequest::GetToFile {
            mid: mid.to_string(),
            data_shards: DEFAULT_DATA_SHARDS,
            total_shards: DEFAULT_TOTAL_SHARDS,
            output_path: requested_path,
        },
    )?;
    match response {
        ControlResponse::RetrievedToFile {
            output_path,
            bytes_written,
        } => Ok(FileReceiveResultFfi {
            output_path,
            bytes_written,
        }),
        ControlResponse::Error(message) => {
            tracing::warn!("daemon retrieve_to_file error: {message}");
            Err(MiasmaFfiError::Other {
                msg: "file retrieval failed".into(),
            })
        }
        _ => Err(MiasmaFfiError::Other {
            msg: "unexpected daemon response".into(),
        }),
    }
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
/// If a daemon is running, route the wipe through that daemon first so its
/// in-memory store key, directed-sharing key, and master-derived network runtime
/// are erased/shut down before success is reported. Residual wrapped key blobs
/// and persisted transport secrets are then scrubbed locally.
#[uniffi::export]
pub fn distress_wipe(data_dir: String) -> Result<(), MiasmaFfiError> {
    use miasma_core::daemon::ipc::{daemon_wipe, ControlResponse, PORT_FILE};

    let path = validate_data_dir(&data_dir)?;
    let port_path = path.join(PORT_FILE);
    let embedded_shutdown = {
        let guard = EMBEDDED_DAEMON.lock().unwrap();
        guard.as_ref().map(|daemon| daemon.shutdown_tx.clone())
    };
    let embedded_owned = embedded_shutdown.is_some();
    let mut errors = Vec::<String>::new();
    let mut daemon_wipe_started = false;

    if port_path.exists() {
        let ipc_result = shared_runtime().block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), daemon_wipe(&path)).await
        });
        match ipc_result {
            Ok(Ok(ControlResponse::Wiped)) => daemon_wipe_started = true,
            Ok(Ok(ControlResponse::Error(message))) => {
                // The daemon's Wipe branch always shuts the runtime down after
                // key erasure begins, even when later cleanup is incomplete.
                daemon_wipe_started = true;
                tracing::warn!("daemon distress wipe reported incomplete cleanup: {message}");
                errors.push("daemon reported incomplete wipe cleanup".into());
            }
            Ok(Ok(_)) => errors.push("daemon returned an unexpected wipe response".into()),
            Ok(Err(e)) => {
                tracing::warn!("daemon distress wipe IPC failed: {e}");
                errors.push("could not confirm wipe with running daemon".into());
            }
            Err(_) => {
                tracing::warn!("daemon distress wipe IPC timed out");
                errors.push("daemon wipe timed out".into());
            }
        }
    }

    // If this process owns the daemon but IPC could not start its wipe, stop the
    // runtime before touching the key file directly. Its LocalShareStore and
    // swarm then drop their Zeroizing/master-derived state first.
    if !daemon_wipe_started {
        if let Some(shutdown_tx) = embedded_shutdown {
            let _ = shutdown_tx.try_send(());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while is_daemon_running() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if is_daemon_running() {
                errors.push("embedded daemon did not stop before fallback wipe".into());
            } else {
                // If the only uncertainty was IPC connectivity, confirmed
                // embedded-runtime shutdown resolves that in-memory risk.
                errors.retain(|e| {
                    e != "could not confirm wipe with running daemon"
                        && e != "daemon wipe timed out"
                });
            }
        }
    }

    // No daemon performed the store wipe: erase via a fresh store instance. An
    // unreachable external daemon remains an error even if disk cleanup succeeds,
    // because its in-memory master-derived keys cannot be proven destroyed here.
    if !daemon_wipe_started {
        match open_store(&data_dir) {
            Ok((_config, store)) => {
                if let Err(e) = store.distress_wipe() {
                    tracing::warn!("fallback store distress wipe incomplete: {e}");
                    errors.push("local store wipe incomplete".into());
                }
            }
            Err(e) => tracing::debug!("fallback store open skipped during wipe: {e}"),
        }
    }

    // Scrub persisted transport secrets even when master.key was already absent
    // and LocalShareStore could not be opened.
    let config_path = miasma_core::paths::config_file(&path);
    if config_path.exists() {
        match NodeConfig::load(&path) {
            Ok(mut config) => {
                if config.has_persisted_secrets() {
                    if let Err(e) = config.scrub_credentials(&path) {
                        tracing::warn!("wipe transport-secret scrub failed: {e}");
                        errors.push("transport-secret cleanup failed".into());
                    }
                }
            }
            Err(e) => {
                tracing::warn!("wipe could not parse config for secret scrub: {e}");
                errors.push("transport config could not be scrubbed".into());
            }
        }
    }

    // Platform wrappers can leave encrypted key blobs alongside master.key.
    // Erase-and-remove each one and treat any failure as incomplete wipe.
    for fname in [
        miasma_core::paths::MASTER_KEY.name,
        miasma_core::paths::MASTER_KEY_WRAPPED.name,
        miasma_core::paths::MASTER_KEY_WRAP_IV.name,
    ] {
        let fpath = path.join(fname);
        if !fpath.exists() {
            continue;
        }
        match std::fs::metadata(&fpath) {
            Ok(metadata) => {
                let zeros = vec![0u8; metadata.len() as usize];
                if let Err(e) = std::fs::write(&fpath, &zeros) {
                    tracing::warn!(
                        "wipe overwrite failed for {}: {e}",
                        miasma_core::logging::redact::name(fname)
                    );
                    errors.push(format!("could not overwrite {fname}"));
                    continue;
                }
            }
            Err(e) => {
                tracing::warn!(
                    "wipe metadata failed for {}: {e}",
                    miasma_core::logging::redact::name(fname)
                );
                errors.push(format!("could not inspect {fname}"));
                continue;
            }
        }
        if let Err(e) = std::fs::remove_file(&fpath) {
            tracing::warn!(
                "wipe removal failed for {}: {e}",
                miasma_core::logging::redact::name(fname)
            );
            errors.push(format!("could not remove {fname}"));
        }
    }

    // Daemon Wipe returns its response before the outer run loop necessarily
    // removes daemon.port. Wait for that synchronized runtime-shutdown boundary.
    if daemon_wipe_started {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while (port_path.exists() || (embedded_owned && is_daemon_running()))
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if port_path.exists() || (embedded_owned && is_daemon_running()) {
            errors.push("daemon runtime did not stop after wipe".into());
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        tracing::warn!("distress wipe incomplete: {}", errors.join("; "));
        Err(MiasmaFfiError::Other {
            msg: "distress wipe incomplete".into(),
        })
    }
}

// ??? Directed sharing FFI ???????????????????????????????????????????????????

/// Envelope summary returned to the mobile UI.
#[derive(uniffi::Record)]
pub struct EnvelopeSummaryFfi {
    pub id: String,
    /// Self-asserted sharing key from the envelope.
    pub sender_key: String,
    /// Authenticated sender libp2p PeerId for incoming envelopes.
    pub sender_peer_id: Option<String>,
    pub state: String,
    pub challenge_code: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

fn summary_to_ffi(s: directed::EnvelopeSummary) -> EnvelopeSummaryFfi {
    EnvelopeSummaryFfi {
        id: s.envelope_id,
        sender_key: s.sender_pubkey,
        sender_peer_id: s.sender_peer_id,
        state: format!("{:?}", s.state),
        challenge_code: s.challenge_code,
        created_at: s.created_at,
        expires_at: s.expires_at,
    }
}

fn read_master_key_zeroizing(
    master_key_path: &std::path::Path,
) -> Result<Zeroizing<[u8; 32]>, MiasmaFfiError> {
    let bytes = Zeroizing::new(std::fs::read(master_key_path).map_err(|e| {
        tracing::warn!("read master.key: {e}");
        MiasmaFfiError::Other {
            msg: "failed to read master key".into(),
        }
    })?);
    if bytes.len() != 32 {
        return Err(MiasmaFfiError::Other {
            msg: "invalid master key length".into(),
        });
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    if key.iter().all(|byte| *byte == 0) {
        return Err(MiasmaFfiError::Other {
            msg: "master key is erased/all-zero".into(),
        });
    }
    Ok(key)
}

/// Get this node's sharing key (formatted as `msk:<base58>`).
///
/// The sharing key is derived deterministically from the master key,
/// so it is stable across restarts.
#[uniffi::export]
pub fn get_sharing_key(data_dir: String) -> Result<String, MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    let master_key_path = miasma_core::paths::master_key(&path);
    if !master_key_path.exists() {
        return Err(MiasmaFfiError::NotInitialized {
            data_dir: data_dir.to_owned(),
        });
    }
    let master_key = read_master_key_zeroizing(&master_key_path)?;
    let secret =
        miasma_core::crypto::keyderive::derive_sharing_key(master_key.as_ref()).map_err(|e| {
            MiasmaFfiError::Other {
                msg: format!("{e}"),
            }
        })?;
    let static_secret = x25519_dalek::StaticSecret::from(*secret);
    let pubkey = x25519_dalek::PublicKey::from(&static_secret);
    Ok(directed::format_sharing_key(pubkey.as_bytes()))
}

/// List incoming directed envelopes.
#[uniffi::export]
pub fn list_directed_inbox(data_dir: String) -> Result<Vec<EnvelopeSummaryFfi>, MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    let inbox = directed::DirectedInbox::open(&path).map_err(|e| MiasmaFfiError::Other {
        msg: format!("open inbox: {e}"),
    })?;
    let items = inbox.list_incoming();
    Ok(items.into_iter().map(summary_to_ffi).collect())
}

/// List outgoing directed envelopes.
#[uniffi::export]
pub fn list_directed_outbox(data_dir: String) -> Result<Vec<EnvelopeSummaryFfi>, MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    let inbox = directed::DirectedInbox::open(&path).map_err(|e| MiasmaFfiError::Other {
        msg: format!("open inbox: {e}"),
    })?;
    let items = inbox.list_outgoing();
    Ok(items.into_iter().map(summary_to_ffi).collect())
}

/// Delete a directed envelope from the local inbox.
#[uniffi::export]
pub fn delete_directed_envelope(
    data_dir: String,
    envelope_id: String,
) -> Result<(), MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    let inbox = directed::DirectedInbox::open(&path).map_err(|e| MiasmaFfiError::Other {
        msg: format!("open inbox: {e}"),
    })?;
    // Try incoming first, then outgoing.
    if let Err(e) = inbox.delete_incoming(&envelope_id) {
        inbox
            .delete_outgoing(&envelope_id)
            .map_err(|e2| MiasmaFfiError::Other {
                msg: format!("delete envelope: {e}, {e2}"),
            })?;
    }
    Ok(())
}

// ─── Embedded daemon FFI ────────────────────────────────────────────────────

/// Daemon status returned to mobile UI when the embedded daemon is running.
#[derive(uniffi::Record)]
pub struct EmbeddedDaemonStatus {
    /// HTTP bridge port on 127.0.0.1.
    pub http_port: u16,
    /// libp2p Peer ID.
    pub peer_id: String,
    /// Full sharing contact string (`msk:<base58>@<PeerId>`).
    pub sharing_contact: String,
}

/// Start the embedded daemon with full networking and HTTP bridge.
///
/// This starts a MiasmaNode (libp2p, DHT, peer discovery) and a DaemonServer
/// with HTTP bridge on `127.0.0.1`.  After this call, all directed sharing
/// operations are available via the HTTP bridge at the returned port.
///
/// Idempotent — if already running, returns the existing daemon's status.
///
/// # Arguments
/// * `data_dir` — absolute path to the app's private data directory
/// * `storage_mb` — storage quota in MiB
/// * `bandwidth_mb_day` — bandwidth quota in MiB/day
#[uniffi::export]
pub fn start_embedded_daemon(
    data_dir: String,
    storage_mb: u64,
    bandwidth_mb_day: u64,
) -> Result<EmbeddedDaemonStatus, MiasmaFfiError> {
    // If already running, return existing status.
    {
        let guard = EMBEDDED_DAEMON.lock().unwrap();
        if let Some(ref d) = *guard {
            return Ok(EmbeddedDaemonStatus {
                http_port: d.http_port,
                peer_id: d.peer_id.clone(),
                sharing_contact: d.sharing_contact.clone(),
            });
        }
    }

    let generation = EMBEDDED_DAEMON_GENERATION.fetch_add(1, Ordering::Relaxed);
    let path = validate_data_dir(&data_dir)?;

    // Ensure node is initialised.
    initialize_node(data_dir.clone(), storage_mb, bandwidth_mb_day)?;

    let (mut config, store) = open_store_for_daemon(&data_dir)?;

    // Read master key for node identity.
    let master_key_path = miasma_core::paths::master_key(&path);
    let master_key = read_master_key_zeroizing(&master_key_path)?;

    // Create MiasmaNode with full networking.
    let node =
        MiasmaNode::new(&master_key, NodeType::Full, &config.network.listen_addr).map_err(|e| {
            tracing::warn!("node create error: {e}");
            MiasmaFfiError::Other {
                msg: "failed to create network node".into(),
            }
        })?;

    // Move the transport config into the daemon; do not duplicate persisted
    // secret Strings into a second long-lived config object.
    let mut transport_config = std::mem::take(&mut config.transport);
    // The iroh direct transport (receive by share ID alone) is a desktop feature
    // for now: its battery, background-network and relay behaviour on mobile has
    // not been validated, so the embedded daemon does not start it.
    transport_config.iroh_mode = miasma_core::config::IrohMode::Off;

    // Start DaemonServer (binds IPC + HTTP bridge + transports).
    let rt = shared_runtime();
    let result = rt.block_on(async {
        let server =
            DaemonServer::start_with_transport(node, store, path.clone(), transport_config)
                .await
                .map_err(|e| {
                    tracing::warn!("daemon start error: {e}");
                    MiasmaFfiError::Other {
                        msg: "failed to start daemon".into(),
                    }
                })?;

        let http_port = server.http_bridge_port();
        let peer_id = server.peer_id().to_string();
        let shutdown_handle = server.shutdown_handle();

        // Derive sharing contact for this daemon.
        let sharing_contact = {
            let secret = miasma_core::crypto::keyderive::derive_sharing_key(master_key.as_ref())
                .map_err(|e| MiasmaFfiError::Other {
                    msg: format!("{e}"),
                })?;
            let static_secret = x25519_dalek::StaticSecret::from(*secret);
            let pubkey = x25519_dalek::PublicKey::from(&static_secret);
            directed::format_sharing_contact(pubkey.as_bytes(), &peer_id)
        };

        // Add bootstrap peers from config.
        for addr_str in &config.network.bootstrap_peers {
            if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                let peer_id_opt = addr.iter().find_map(|p| {
                    if let libp2p::multiaddr::Protocol::P2p(pid) = p {
                        Some(pid)
                    } else {
                        None
                    }
                });
                if let Some(pid) = peer_id_opt {
                    let _ = server.add_bootstrap_peer(pid, addr.clone()).await;
                }
            }
        }

        // Bootstrap DHT if we have peers.
        if !config.network.bootstrap_peers.is_empty() {
            let _ = server.bootstrap_dht().await;
        }

        Ok::<_, MiasmaFfiError>((server, http_port, peer_id, sharing_contact, shutdown_handle))
    })?;

    let (server, http_port, peer_id, sharing_contact, shutdown_tx) = result;

    // Publish state before spawning the run task so an immediate task exit can
    // never race ahead of registration. The generation protects a later restart
    // from being cleared by an older task finishing late.
    {
        let mut guard = EMBEDDED_DAEMON.lock().unwrap();
        *guard = Some(EmbeddedDaemon {
            generation,
            http_port,
            peer_id: peer_id.clone(),
            sharing_contact: sharing_contact.clone(),
            shutdown_tx,
        });
    }

    rt.spawn(async move {
        if let Err(e) = server.run().await {
            tracing::warn!("embedded daemon exited: {e}");
        }
        let mut guard = EMBEDDED_DAEMON.lock().unwrap();
        if guard
            .as_ref()
            .is_some_and(|daemon| daemon.generation == generation)
        {
            guard.take();
        }
    });

    tracing::info!(
        http_port,
        peer_id = %peer_id,
        "embedded daemon started"
    );

    Ok(EmbeddedDaemonStatus {
        http_port,
        peer_id,
        sharing_contact,
    })
}

/// Stop the embedded daemon.
///
/// Sends a shutdown signal and clears the daemon state. Safe to call even
/// if no daemon is running.
#[uniffi::export]
pub fn stop_embedded_daemon() {
    let daemon = {
        let mut guard = EMBEDDED_DAEMON.lock().unwrap();
        guard.take()
    };
    if let Some(d) = daemon {
        let _ = d.shutdown_tx.try_send(());
        tracing::info!("embedded daemon stop requested");
    }
}

/// Get the HTTP bridge port of the running embedded daemon.
///
/// Returns 0 if no daemon is running.
#[uniffi::export]
pub fn get_daemon_http_port() -> u16 {
    let guard = EMBEDDED_DAEMON.lock().unwrap();
    guard.as_ref().map(|d| d.http_port).unwrap_or(0)
}

/// Check if the embedded daemon is currently running.
#[uniffi::export]
pub fn is_daemon_running() -> bool {
    let guard = EMBEDDED_DAEMON.lock().unwrap();
    guard.is_some()
}

/// Get the sharing contact string for the running daemon.
///
/// Returns the full `msk:<base58>@<PeerId>` contact that other nodes
/// can use to send directed shares to this device.
/// Returns empty string if no daemon is running.
#[uniffi::export]
pub fn get_sharing_contact() -> String {
    let guard = EMBEDDED_DAEMON.lock().unwrap();
    guard
        .as_ref()
        .map(|d| d.sharing_contact.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod mobile_config_tests {
    use super::*;

    #[test]
    fn bootstrap_peer_normalization_deduplicates_and_trims() {
        let peer = libp2p::PeerId::random();
        let addr = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{peer}");
        let got = normalize_bootstrap_peers(vec![format!("  {addr}  "), addr.clone()]).unwrap();
        assert_eq!(got, vec![addr]);
    }

    #[test]
    fn bootstrap_peer_normalization_rejects_missing_peer_id() {
        let err =
            normalize_bootstrap_peers(vec!["/ip4/127.0.0.1/udp/4001/quic-v1".into()]).unwrap_err();
        assert!(matches!(err, MiasmaFfiError::Other { .. }));
    }

    #[test]
    fn bootstrap_peer_normalization_caps_nonempty_unique_input() {
        let peers = (0..=MAX_MOBILE_BOOTSTRAP_PEERS)
            .map(|i| {
                let peer = libp2p::PeerId::random();
                format!("/ip4/192.0.2.{}/udp/443/quic-v1/p2p/{peer}", (i % 250) + 1)
            })
            .collect();
        assert!(normalize_bootstrap_peers(peers).is_err());
    }

    #[test]
    fn bootstrap_peer_normalization_ignores_blank_lines_before_cap() {
        let blanks = vec![String::new(); MAX_MOBILE_BOOTSTRAP_PEERS + 10];
        assert!(normalize_bootstrap_peers(blanks).unwrap().is_empty());
    }
    #[test]
    fn mobile_limit_update_preserves_network_and_transport_config() {
        let peer = libp2p::PeerId::random();
        let bootstrap = format!("/ip4/192.0.2.1/udp/443/quic-v1/p2p/{peer}");
        let mut config = NodeConfig::default();
        config.network.listen_addr = "/ip4/127.0.0.1/udp/9000/quic-v1".into();
        config.network.bootstrap_peers = vec![bootstrap.clone()];
        config.transport.wss_port = 9443;
        config.storage.hosted_quota_mb = 777;

        let updated = apply_mobile_limits(config, 512, 100);

        assert_eq!(updated.storage.quota_mb, 512);
        assert_eq!(updated.storage.bandwidth_mb_day, 100);
        assert_eq!(updated.storage.hosted_quota_mb, 777);
        assert_eq!(updated.network.bootstrap_peers, vec![bootstrap]);
        assert_eq!(
            updated.network.listen_addr,
            "/ip4/127.0.0.1/udp/9000/quic-v1"
        );
        assert_eq!(updated.transport.wss_port, 9443);
    }

    #[test]
    fn ffi_file_path_requires_absolute_non_traversing_path() {
        let err = validate_ffi_file_path("relative.bin", "output_path", false).unwrap_err();
        assert!(matches!(err, MiasmaFfiError::Other { .. }));

        let traversal = std::env::temp_dir().join("..").join("escape.bin");
        let err =
            validate_ffi_file_path(traversal.to_str().unwrap(), "output_path", false).unwrap_err();
        assert!(matches!(err, MiasmaFfiError::Other { .. }));
    }

    #[test]
    fn ffi_publish_path_requires_existing_file() {
        let missing =
            std::env::temp_dir().join(format!("miasma-ffi-missing-{}", std::process::id()));
        let err = validate_ffi_file_path(missing.to_str().unwrap(), "file_path", true).unwrap_err();
        assert!(matches!(err, MiasmaFfiError::Other { .. }));
    }
}

mod privacy;
pub use privacy::{
    get_privacy_profile, set_privacy_profile, PrivacyProfileApplyResultFfi, PrivacyProfileFfi,
};
