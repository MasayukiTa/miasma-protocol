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
    daemon::DaemonServer,
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

use std::sync::Mutex;
use tokio::sync::mpsc;

/// State of the embedded daemon (started via `start_embedded_daemon`).
struct EmbeddedDaemon {
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

// ─── Directed sharing FFI ───────────────────────────────────────────────────

/// Envelope summary returned to the mobile UI.
#[derive(uniffi::Record)]
pub struct EnvelopeSummaryFfi {
    pub id: String,
    pub sender_key: String,
    pub state: String,
    pub challenge_code: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

fn summary_to_ffi(s: directed::EnvelopeSummary) -> EnvelopeSummaryFfi {
    EnvelopeSummaryFfi {
        id: s.envelope_id,
        sender_key: s.sender_pubkey,
        state: format!("{:?}", s.state),
        challenge_code: s.challenge_code,
        created_at: s.created_at,
        expires_at: s.expires_at,
    }
}

/// Get this node's sharing key (formatted as `msk:<base58>`).
///
/// The sharing key is derived deterministically from the master key,
/// so it is stable across restarts.
#[uniffi::export]
pub fn get_sharing_key(data_dir: String) -> Result<String, MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    let master_key_path = path.join("master.key");
    if !master_key_path.exists() {
        return Err(MiasmaFfiError::NotInitialized {
            data_dir: data_dir.to_owned(),
        });
    }
    let master_key = std::fs::read(&master_key_path).map_err(|e| {
        tracing::warn!("read master.key: {e}");
        MiasmaFfiError::Other {
            msg: "failed to read master key".into(),
        }
    })?;
    if master_key.len() < 32 {
        return Err(MiasmaFfiError::Other {
            msg: "invalid master key".into(),
        });
    }
    let key_array: [u8; 32] = master_key[..32].try_into().unwrap();
    let secret = miasma_core::crypto::keyderive::derive_sharing_key(&key_array).map_err(|e| {
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

    let path = validate_data_dir(&data_dir)?;

    // Ensure node is initialised.
    initialize_node(data_dir.clone(), storage_mb, bandwidth_mb_day)?;

    let (config, store) = open_store(&data_dir)?;

    // Read master key for node identity.
    let master_key_path = path.join("master.key");
    let master_bytes = std::fs::read(&master_key_path).map_err(|e| {
        tracing::warn!("read master.key: {e}");
        MiasmaFfiError::Other {
            msg: "failed to read master key".into(),
        }
    })?;
    let master_key: [u8; 32] = master_bytes[..32].try_into().map_err(|_| {
        MiasmaFfiError::Other {
            msg: "invalid master key length".into(),
        }
    })?;

    // Create MiasmaNode with full networking.
    let node = MiasmaNode::new(&master_key, NodeType::Full, &config.network.listen_addr)
        .map_err(|e| {
            tracing::warn!("node create error: {e}");
            MiasmaFfiError::Other {
                msg: "failed to create network node".into(),
            }
        })?;

    // Start DaemonServer (binds IPC + HTTP bridge + transports).
    let rt = shared_runtime();
    let result = rt.block_on(async {
        let server = DaemonServer::start_with_transport(
            node,
            store,
            path.clone(),
            config.transport.clone(),
        )
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
            let secret = miasma_core::crypto::keyderive::derive_sharing_key(&master_key)
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

        // Spawn the daemon event loop in the background.
        let _daemon_handle = tokio::spawn(async move {
            if let Err(e) = server.run().await {
                tracing::warn!("embedded daemon exited: {e}");
            }
        });

        Ok::<_, MiasmaFfiError>((http_port, peer_id, sharing_contact, shutdown_handle))
    })?;

    let (http_port, peer_id, sharing_contact, shutdown_tx) = result;

    // Store the daemon state.
    {
        let mut guard = EMBEDDED_DAEMON.lock().unwrap();
        *guard = Some(EmbeddedDaemon {
            http_port,
            peer_id: peer_id.clone(),
            sharing_contact: sharing_contact.clone(),
            shutdown_tx,
        });
    }

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
