//! CLI ↔ Daemon control protocol.
//!
//! Transport: TCP loopback, 4-byte LE length-prefixed JSON frames.
//!
//! The daemon binds to `127.0.0.1:0` (OS-assigned port) and writes the
//! bound port number to `<data_dir>/daemon.port`. CLI clients read that
//! file to discover the port, connect, send a request, receive a response,
//! and close the connection.
//!
//! Authentication: the daemon also writes a random per-start control token to
//! `<data_dir>/daemon.token` (see `control_auth`). The first frame of every
//! connection must be a [`ControlAuth`] frame carrying that token; a peer that
//! sends anything else, or a wrong token, gets an error and is disconnected
//! without any request being parsed or processed.

use std::{fmt, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::{Zeroize, Zeroizing};

/// Maximum JSON frame body size (256 MiB).
///
/// Raised from 16 MiB to support large file retrieval via `network-get`.
/// A 100 MB file produces ~370 MB of IPC JSON after base64-encoding shares;
/// 256 MiB covers files up to ~70 MB inline. For larger files, use the
/// HTTP bridge or streaming retrieval API instead.
/// Maximum JSON frame body size (512 MiB).
///
/// JSON-serialised `Vec<u8>` expands ~3.5-4× vs raw bytes, so 100 MB file
/// retrieval produces ~370 MB frames. 512 MiB covers files up to ~140 MB.
const FRAME_MAX: usize = 512 * 1_024 * 1_024;

/// Filename inside the data directory containing the control port number.
pub const PORT_FILE: &str = "daemon.port";

/// Filename inside the data directory containing the HTTP bridge port.
pub const HTTP_PORT_FILE: &str = "daemon.http";

/// Default HTTP bridge port.  Fixed so browsers can discover the daemon
/// without filesystem access.  Configurable via `http_bridge.port` in
/// config.toml.
pub const HTTP_BRIDGE_DEFAULT_PORT: u16 = 17842;

// ─── Wire types ───────────────────────────────────────────────────────────────

/// First frame of every control connection: proves the peer can read the
/// daemon's token file.
#[derive(Serialize, Deserialize)]
pub struct ControlAuth {
    pub token: String,
}

impl Zeroize for ControlAuth {
    fn zeroize(&mut self) {
        self.token.zeroize();
    }
}

impl fmt::Debug for ControlAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlAuth")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Request from a CLI client to the local daemon.
#[derive(Serialize, Deserialize)]
pub enum ControlRequest {
    /// Dissolve `data` into shares and publish a DHT record.
    Publish {
        data: Vec<u8>,
        data_shards: u8,
        total_shards: u8,
    },
    /// Dissolve a file from `file_path` into shares and publish a DHT record.
    ///
    /// The daemon reads the file directly — no IPC size limit.  Uses
    /// streaming per-segment dissolution so files >64 MiB do not require
    /// full-file RAM buffering.  Preferred over `Publish` for large files.
    PublishFile {
        file_path: String,
        data_shards: u8,
        total_shards: u8,
    },
    /// As `PublishFile`, with a password mixed into the content encryption key
    /// (see `transfer::protection`). The receiver must supply the same
    /// password; the MID and every shard alone cannot decrypt the content.
    ///
    /// A separate variant rather than a new field on `PublishFile`, so existing
    /// callers keep constructing `PublishFile` unchanged.
    PublishFileProtected {
        file_path: String,
        data_shards: u8,
        total_shards: u8,
        password: String,
    },
    /// Retrieve content by MID string from the P2P network.
    Get {
        mid: String,
        data_shards: u8,
        total_shards: u8,
    },
    /// Retrieve content by MID string — file-path variant.
    ///
    /// The daemon streams reconstructed segments directly to `output_path`
    /// (`MiasmaCoordinator::retrieve_from_network_streaming`) instead of
    /// buffering the whole file and round-tripping it through a JSON `Vec<u8>`
    /// response. Avoids `Get`'s double-buffering (once in the daemon, once
    /// again as base64-inflated JSON over IPC) and keeps peak RAM at roughly
    /// one segment regardless of file size. Preferred over `Get` for CLI and
    /// desktop callers that have a local output path (`Get` remains for the
    /// stdout-pipe case, which has no path to stream to).
    GetToFile {
        mid: String,
        data_shards: u8,
        total_shards: u8,
        /// Absolute path where reconstructed content should be written.
        output_path: String,
    },
    /// Start (or resume) receiving `mid` into `output_path` as a background
    /// transfer, and return at once with its id.
    ///
    /// Unlike `GetToFile` this is verified piece by piece against the transfer
    /// manifest, is resumable after any interruption (a `<output>.part` file and
    /// a journal are kept), and reports progress through `TransferStatus`. A
    /// password is required exactly when the transfer was published with one.
    TransferStartReceive {
        mid: String,
        /// Absolute path of the finished file. It only appears once the
        /// whole-file MID has been verified.
        output_path: String,
        password: Option<String>,
        /// Discard any partial transfer and start over.
        restart: bool,
        /// `wss://` / `ws://` endpoints to fetch the record and every piece
        /// from instead of the DHT (a sender's WebSocket server behind an
        /// outbound tunnel). Empty: the ordinary network receive. Absent in
        /// requests from older clients, which then behave as before.
        #[serde(default)]
        via: Vec<String>,
        /// Extra CA certificate(s) in PEM text, trusted in addition to the
        /// operating-system store, for the `via` endpoints.
        #[serde(default)]
        via_ca_pem: Option<String>,
    },
    /// Start (or resume) publishing a file as a background transfer, and return
    /// at once with its id. Progress, resume and cancel work as for a receive;
    /// a stopped publish resumes from its journal unless `restart` is set.
    TransferStartPublish {
        file_path: String,
        data_shards: u8,
        total_shards: u8,
        password: Option<String>,
        restart: bool,
    },
    /// Progress of one transfer, by the id `TransferStartReceive` /
    /// `TransferStartPublish` returned.
    TransferStatus { id: String },
    /// Every transfer, including paused ones left by an earlier daemon process.
    TransferList,
    /// Stop a running transfer at its next safe point, keeping it resumable.
    TransferCancel { id: String },
    /// Take one finished (Complete, Failed or Cancelled) transfer off the
    /// dashboard. A running or paused one is refused. A failed/cancelled one
    /// that still holds partial data is refused unless `discard_partial` is set,
    /// which deletes that partial data. A finished receive's output file, a
    /// send's source file and the shares a send published are never touched.
    TransferRemove {
        id: String,
        #[serde(default)]
        discard_partial: bool,
    },
    /// Remove every finished transfer that has no partial data to lose.
    TransferClearFinished,
    /// Return daemon status metrics.
    Status,
    /// Distress-wipe, step 1: ask for a confirmation challenge. Nothing is
    /// destroyed; the daemon answers `WipeChallenge` and remembers the nonce
    /// (single use, short lived).
    Wipe,
    /// Distress-wipe, step 2: destroy the master key so all shares become
    /// unreadable. Only honoured with the nonce the daemon issued for `Wipe`.
    WipeConfirm { nonce: String },

    // ── Directed sharing ────────────────────────────────────────────────
    /// Get this node's sharing key (X25519 pubkey + PeerId).
    SharingKey,

    /// Create and send a directed share to a specific recipient.
    DirectedSend {
        /// Recipient's sharing contact string ("msk:...@PeerId").
        recipient_contact: String,
        /// Raw file data to share.
        data: Vec<u8>,
        /// Password for retrieval gate.
        password: String,
        /// Retention period in seconds.
        retention_secs: u64,
        /// Original filename (optional).
        filename: Option<String>,
    },

    /// Create and send a directed share — file-path variant.
    ///
    /// The daemon reads the file directly from `file_path`, avoiding
    /// JSON `Vec<u8>` serialization bloat over IPC.  Preferred over
    /// `DirectedSend` for CLI and desktop callers that have a local path.
    DirectedSendFile {
        /// Recipient's sharing contact string ("msk:...@PeerId").
        recipient_contact: String,
        /// Absolute path to the file on the local filesystem.
        file_path: String,
        /// Password for retrieval gate.
        password: String,
        /// Retention period in seconds.
        retention_secs: u64,
        /// Original filename override (if None, derived from file_path).
        filename: Option<String>,
    },

    /// Submit the confirmation challenge for a directed share.
    DirectedConfirm {
        /// Hex-encoded envelope ID.
        envelope_id: String,
        /// Challenge code (XXXX-XXXX format).
        challenge_code: String,
    },

    /// Retrieve content from a confirmed directed share.
    DirectedRetrieve {
        /// Hex-encoded envelope ID.
        envelope_id: String,
        /// Password entered by recipient.
        password: String,
    },

    /// Retrieve content — file-path variant.
    ///
    /// The daemon writes decrypted content directly to `output_path`,
    /// avoiding JSON `Vec<u8>` serialization bloat on the response.
    /// Preferred for CLI and desktop callers.
    DirectedRetrieveToFile {
        /// Hex-encoded envelope ID.
        envelope_id: String,
        /// Password entered by recipient.
        password: String,
        /// Absolute path where decrypted content should be written.
        output_path: String,
    },

    /// Revoke a directed share (sender) or delete (recipient).
    DirectedRevoke {
        /// Hex-encoded envelope ID.
        envelope_id: String,
    },

    /// List incoming directed shares (recipient inbox).
    DirectedInbox,

    /// List outgoing directed shares (sender outbox).
    DirectedOutbox,
}

impl fmt::Debug for ControlRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Publish {
                data,
                data_shards,
                total_shards,
            } => f
                .debug_struct("Publish")
                .field("data_len", &data.len())
                .field("data_shards", data_shards)
                .field("total_shards", total_shards)
                .finish(),
            Self::PublishFile {
                data_shards,
                total_shards,
                ..
            } => f
                .debug_struct("PublishFile")
                .field("file_path", &"<redacted>")
                .field("data_shards", data_shards)
                .field("total_shards", total_shards)
                .finish(),
            Self::TransferStartReceive {
                mid,
                password,
                restart,
                via,
                via_ca_pem,
                ..
            } => f
                .debug_struct("TransferStartReceive")
                .field("mid", mid)
                .field("output_path", &"<redacted>")
                .field("password", &password.as_ref().map(|_| "<redacted>"))
                .field("restart", restart)
                .field("via_endpoints", &via.len())
                .field("via_ca_pem", &via_ca_pem.as_ref().map(|_| "<present>"))
                .finish(),
            Self::TransferStartPublish {
                data_shards,
                total_shards,
                password,
                restart,
                ..
            } => f
                .debug_struct("TransferStartPublish")
                .field("file_path", &"<redacted>")
                .field("data_shards", data_shards)
                .field("total_shards", total_shards)
                .field("password", &password.as_ref().map(|_| "<redacted>"))
                .field("restart", restart)
                .finish(),
            Self::TransferStatus { id } => {
                f.debug_struct("TransferStatus").field("id", id).finish()
            }
            Self::TransferList => f.write_str("TransferList"),
            Self::TransferCancel { id } => {
                f.debug_struct("TransferCancel").field("id", id).finish()
            }
            Self::TransferRemove {
                id,
                discard_partial,
            } => f
                .debug_struct("TransferRemove")
                .field("id", id)
                .field("discard_partial", discard_partial)
                .finish(),
            Self::TransferClearFinished => f.write_str("TransferClearFinished"),
            Self::PublishFileProtected {
                data_shards,
                total_shards,
                ..
            } => f
                .debug_struct("PublishFileProtected")
                .field("file_path", &"<redacted>")
                .field("data_shards", data_shards)
                .field("total_shards", total_shards)
                .field("password", &"<redacted>")
                .finish(),
            Self::Get {
                mid,
                data_shards,
                total_shards,
            } => f
                .debug_struct("Get")
                .field("mid", mid)
                .field("data_shards", data_shards)
                .field("total_shards", total_shards)
                .finish(),
            Self::GetToFile {
                mid,
                data_shards,
                total_shards,
                ..
            } => f
                .debug_struct("GetToFile")
                .field("mid", mid)
                .field("data_shards", data_shards)
                .field("total_shards", total_shards)
                .field("output_path", &"<redacted>")
                .finish(),
            Self::Status => f.write_str("Status"),
            Self::Wipe => f.write_str("Wipe"),
            Self::WipeConfirm { .. } => f
                .debug_struct("WipeConfirm")
                .field("nonce", &"<redacted>")
                .finish(),
            Self::SharingKey => f.write_str("SharingKey"),
            Self::DirectedSend {
                data,
                retention_secs,
                filename,
                ..
            } => f
                .debug_struct("DirectedSend")
                .field("recipient_contact", &"<redacted>")
                .field("data_len", &data.len())
                .field("password", &"<redacted>")
                .field("retention_secs", retention_secs)
                .field("filename_configured", &filename.is_some())
                .finish(),
            Self::DirectedSendFile {
                retention_secs,
                filename,
                ..
            } => f
                .debug_struct("DirectedSendFile")
                .field("recipient_contact", &"<redacted>")
                .field("file_path", &"<redacted>")
                .field("password", &"<redacted>")
                .field("retention_secs", retention_secs)
                .field("filename_configured", &filename.is_some())
                .finish(),
            Self::DirectedConfirm { envelope_id, .. } => f
                .debug_struct("DirectedConfirm")
                .field("envelope_id", envelope_id)
                .field("challenge_code", &"<redacted>")
                .finish(),
            Self::DirectedRetrieve { envelope_id, .. } => f
                .debug_struct("DirectedRetrieve")
                .field("envelope_id", envelope_id)
                .field("password", &"<redacted>")
                .finish(),
            Self::DirectedRetrieveToFile { envelope_id, .. } => f
                .debug_struct("DirectedRetrieveToFile")
                .field("envelope_id", envelope_id)
                .field("password", &"<redacted>")
                .field("output_path", &"<redacted>")
                .finish(),
            Self::DirectedRevoke { envelope_id } => f
                .debug_struct("DirectedRevoke")
                .field("envelope_id", envelope_id)
                .finish(),
            Self::DirectedInbox => f.write_str("DirectedInbox"),
            Self::DirectedOutbox => f.write_str("DirectedOutbox"),
        }
    }
}

impl Zeroize for ControlRequest {
    fn zeroize(&mut self) {
        match self {
            Self::Publish { data, .. } => data.zeroize(),
            Self::PublishFileProtected { password, .. } => password.zeroize(),
            Self::TransferStartReceive { password, .. }
            | Self::TransferStartPublish { password, .. } => {
                if let Some(p) = password.as_mut() {
                    p.zeroize();
                }
            }
            Self::WipeConfirm { nonce } => nonce.zeroize(),
            Self::DirectedSend { data, password, .. } => {
                data.zeroize();
                password.zeroize();
            }
            Self::DirectedSendFile { password, .. }
            | Self::DirectedRetrieve { password, .. }
            | Self::DirectedRetrieveToFile { password, .. } => password.zeroize(),
            Self::DirectedConfirm { challenge_code, .. } => challenge_code.zeroize(),
            _ => {}
        }
    }
}

/// Response from the daemon to a CLI client.
#[derive(Serialize, Deserialize)]
pub enum ControlResponse {
    Published {
        mid: String,
    },
    Retrieved {
        data: Vec<u8>,
    },
    /// Content retrieved via `GetToFile` and written directly to disk.
    RetrievedToFile {
        /// Path where the reconstructed content was written.
        output_path: String,
        /// Number of bytes written.
        bytes_written: u64,
    },
    /// A background transfer was started (or was already running).
    TransferStarted {
        id: String,
    },
    TransferStatus(crate::transfer::TransferStatus),
    TransferList(Vec<crate::transfer::TransferStatus>),
    /// The cancel request was accepted; the transfer stops at its next safe point.
    TransferCancelled,
    /// Finished transfers were removed from the dashboard. `kept_partial` counts
    /// finished ones left alone because removing them would delete partial data.
    TransferRemoved {
        removed: u32,
        kept_partial: u32,
    },
    /// A remove was refused, and why.
    TransferRemoveRefused {
        id: String,
        reason: crate::transfer::jobs::RemoveRefusal,
    },
    Status(DaemonStatus),
    /// Distress wipe completed successfully.
    Wiped,
    /// Answer to `Wipe`: the nonce to echo in `WipeConfirm` within its
    /// lifetime. The key is still intact.
    WipeChallenge {
        nonce: String,
    },
    Error(String),

    // ── Directed sharing ────────────────────────────────────────────────
    /// This node's sharing key and contact string.
    SharingKey {
        /// Sharing key ("msk:...").
        key: String,
        /// Full contact string ("msk:...@PeerId").
        contact: String,
    },

    /// Directed share created and invite sent to recipient.
    DirectedSent {
        /// Hex-encoded envelope ID.
        envelope_id: String,
    },

    /// Challenge confirmed — content now retrievable by recipient.
    DirectedConfirmed,

    /// Directed share content retrieved and decrypted.
    DirectedRetrieved {
        /// Decrypted plaintext.
        data: Vec<u8>,
        /// Original filename if provided.
        filename: Option<String>,
    },

    /// Directed share content retrieved and written to a file.
    DirectedRetrievedToFile {
        /// Path where the decrypted content was written.
        output_path: String,
        /// Original filename if provided.
        filename: Option<String>,
        /// Number of bytes written.
        bytes_written: u64,
    },

    /// Directed share revoked/deleted.
    DirectedRevoked,

    /// Inbox listing (incoming directed shares).
    DirectedInboxList(Vec<crate::directed::EnvelopeSummary>),

    /// Outbox listing (outgoing directed shares).
    DirectedOutboxList(Vec<crate::directed::EnvelopeSummary>),
}

impl fmt::Debug for ControlResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Published { mid } => f.debug_struct("Published").field("mid", mid).finish(),
            Self::Retrieved { data } => f
                .debug_struct("Retrieved")
                .field("data_len", &data.len())
                .finish(),
            Self::RetrievedToFile { bytes_written, .. } => f
                .debug_struct("RetrievedToFile")
                .field("output_path", &"<redacted>")
                .field("bytes_written", bytes_written)
                .finish(),
            Self::TransferStarted { id } => {
                f.debug_struct("TransferStarted").field("id", id).finish()
            }
            Self::TransferStatus(status) => f.debug_tuple("TransferStatus").field(status).finish(),
            Self::TransferList(list) => f
                .debug_struct("TransferList")
                .field("count", &list.len())
                .finish(),
            Self::TransferCancelled => f.write_str("TransferCancelled"),
            Self::TransferRemoved {
                removed,
                kept_partial,
            } => f
                .debug_struct("TransferRemoved")
                .field("removed", removed)
                .field("kept_partial", kept_partial)
                .finish(),
            Self::TransferRemoveRefused { id, reason } => f
                .debug_struct("TransferRemoveRefused")
                .field("id", id)
                .field("reason", reason)
                .finish(),
            Self::Status(status) => f.debug_tuple("Status").field(status).finish(),
            Self::Wiped => f.write_str("Wiped"),
            Self::WipeChallenge { .. } => f
                .debug_struct("WipeChallenge")
                .field("nonce", &"<redacted>")
                .finish(),
            Self::Error(message) => f.debug_tuple("Error").field(message).finish(),
            Self::SharingKey { .. } => f
                .debug_struct("SharingKey")
                .field("key", &"<redacted>")
                .field("contact", &"<redacted>")
                .finish(),
            Self::DirectedSent { envelope_id } => f
                .debug_struct("DirectedSent")
                .field("envelope_id", envelope_id)
                .finish(),
            Self::DirectedConfirmed => f.write_str("DirectedConfirmed"),
            Self::DirectedRetrieved { data, filename } => f
                .debug_struct("DirectedRetrieved")
                .field("data_len", &data.len())
                .field("filename_configured", &filename.is_some())
                .finish(),
            Self::DirectedRetrievedToFile {
                filename,
                bytes_written,
                ..
            } => f
                .debug_struct("DirectedRetrievedToFile")
                .field("output_path", &"<redacted>")
                .field("filename_configured", &filename.is_some())
                .field("bytes_written", bytes_written)
                .finish(),
            Self::DirectedRevoked => f.write_str("DirectedRevoked"),
            Self::DirectedInboxList(items) => f
                .debug_struct("DirectedInboxList")
                .field("items", &items.len())
                .finish(),
            Self::DirectedOutboxList(items) => f
                .debug_struct("DirectedOutboxList")
                .field("items", &items.len())
                .finish(),
        }
    }
}

impl ControlResponse {
    /// Erase plaintext response bodies after they have been serialized to IPC.
    pub(super) fn zeroize_sensitive_material(&mut self) {
        match self {
            Self::Retrieved { data } | Self::DirectedRetrieved { data, .. } => data.zeroize(),
            Self::DirectedInboxList(items) | Self::DirectedOutboxList(items) => {
                for item in items {
                    if let Some(code) = item.challenge_code.as_mut() {
                        code.zeroize();
                    }
                }
            }
            _ => {}
        }
    }
}

/// State of the iroh direct transport, as `miasma status` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrohStatus {
    /// `n0` or `custom`.
    pub mode: String,
    /// The endpoint ID (hex), equal to the publisher key in this node's share IDs.
    pub endpoint_id: String,
    /// The home relay this endpoint uses (or last tried), if any.
    pub home_relay: Option<String>,
    /// Whether the relay connection is up.
    pub relay_connected: bool,
    /// Why it is not, when it is not.
    pub last_error: Option<String>,
    /// Whether n0's discovery service is used.
    pub discovery: bool,
}

/// Snapshot of daemon state — returned for `miasma status` and IPC calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// The iroh direct transport; `None` when it is off or not compiled in.
    #[serde(default)]
    pub iroh: Option<IrohStatus>,
    pub peer_id: String,
    pub listen_addrs: Vec<String>,
    pub peer_count: usize,
    pub share_count: usize,
    pub storage_used_bytes: u64,
    pub pending_replication: usize,
    pub replicated_count: usize,
    /// WSS share server port (0 if not running).
    #[serde(default)]
    pub wss_port: u16,
    /// Whether WSS TLS is enabled.
    #[serde(default)]
    pub wss_tls_enabled: bool,
    /// Whether an outbound proxy is configured.
    #[serde(default)]
    pub proxy_configured: bool,
    /// Proxy type string if configured ("socks5" | "http-connect").
    #[serde(default)]
    pub proxy_type: Option<String>,
    /// ObfuscatedQuic server port (0 if not running).
    #[serde(default)]
    pub obfs_quic_port: u16,
    /// Payload transport readiness matrix.
    #[serde(default)]
    pub transport_readiness: Vec<TransportStatus>,
    /// Number of peers that passed PoW admission (Verified tier).
    #[serde(default)]
    pub verified_peers: usize,
    /// Number of peers that completed Identify but not PoW (Observed tier).
    #[serde(default)]
    pub observed_peers: usize,
    /// Cumulative count of peers rejected at any admission stage.
    #[serde(default)]
    pub admission_rejections: u64,
    /// Routing overlay: total peers tracked.
    #[serde(default)]
    pub routing_peers: usize,
    /// Routing overlay: peers flagged as unreliable.
    #[serde(default)]
    pub routing_unreliable: usize,
    /// Routing overlay: unique IP prefixes observed.
    #[serde(default)]
    pub routing_unique_prefixes: usize,
    /// Routing overlay: max peers from a single IP prefix.
    #[serde(default)]
    pub routing_max_prefix_concentration: usize,
    /// Routing overlay: cumulative diversity-based rejections.
    #[serde(default)]
    pub routing_diversity_rejections: u64,
    /// Routing overlay: locally recommended PoW difficulty in bits (diagnostic only).
    #[serde(default)]
    pub routing_pow_difficulty: u8,

    // ── Phase 4b: credential / descriptor / path selection ─────────────
    /// Current trust epoch number.
    #[serde(default)]
    pub credential_epoch: u64,
    /// Number of credentials held in the local wallet.
    #[serde(default)]
    pub credential_held: usize,
    /// Number of known credential issuers.
    #[serde(default)]
    pub credential_issuers: usize,
    /// Total peer descriptors stored.
    #[serde(default)]
    pub descriptor_total: usize,
    /// Relay-capable descriptors stored.
    #[serde(default)]
    pub descriptor_relays: usize,
    /// Number of relay descriptors available for path selection.
    #[serde(default)]
    pub path_available_relays: usize,
    /// Number of unique relay IP prefixes (diversity).
    #[serde(default)]
    pub path_relay_prefix_diversity: usize,
    /// Default anonymity policy name.
    #[serde(default)]
    pub anonymity_policy: String,

    // ── Phase 4b: outcome metrics ────────────────────────────────────────
    /// Relay infrastructure diversity (unique /16 prefixes).
    #[serde(default)]
    pub metric_relay_prefix_diversity: usize,
    /// Fraction of peers with valid credentials.
    #[serde(default)]
    pub metric_credentialed_fraction: f64,
    /// Multi-path content retrievability estimate (0.0–1.0).
    #[serde(default)]
    pub metric_multi_path_retrievability: f64,
    /// Locally recommended PoW difficulty (bits); admission may enforce a different floor.
    #[serde(default)]
    pub metric_pow_difficulty: u8,
    /// Peer verification ratio (verified / total).
    #[serde(default)]
    pub metric_verification_ratio: f64,
    /// Admission rejection rate.
    #[serde(default)]
    pub metric_rejection_rate: f64,
    /// Pseudonym churn rate (fraction of pseudonyms new this epoch).
    #[serde(default)]
    pub metric_pseudonym_churn_rate: f64,
    /// Relay peers routable for circuit construction.
    #[serde(default)]
    pub metric_relay_peers_routable: usize,
    /// Stale descriptors in store.
    #[serde(default)]
    pub metric_stale_descriptors: usize,
    /// Descriptor store utilisation (0.0–1.0).
    #[serde(default)]
    pub metric_descriptor_utilisation: f64,
    /// Number of relay peers with onion pubkeys (enables per-hop encrypted retrieval).
    #[serde(default)]
    pub metric_onion_relay_peers: usize,
    /// Whether this node is publicly reachable (AutoNAT).
    #[serde(default)]
    pub nat_publicly_reachable: bool,

    // ── Retrieval tracking ──────────────────────────────────────────────
    /// Direct retrieval attempts.
    #[serde(default)]
    pub retrieval_direct_attempts: u64,
    /// Direct retrieval successes.
    #[serde(default)]
    pub retrieval_direct_successes: u64,
    /// Opportunistic retrieval attempts.
    #[serde(default)]
    pub retrieval_opportunistic_attempts: u64,
    /// Opportunistic relay successes (relay path worked).
    #[serde(default)]
    pub retrieval_opportunistic_relay_successes: u64,
    /// Opportunistic direct fallbacks (relay failed, direct worked).
    #[serde(default)]
    pub retrieval_opportunistic_direct_fallbacks: u64,
    /// Required anonymity retrieval attempts.
    #[serde(default)]
    pub retrieval_required_attempts: u64,
    /// Required anonymity onion successes.
    #[serde(default)]
    pub retrieval_required_onion_successes: u64,
    /// Required anonymity relay (non-onion) successes.
    #[serde(default)]
    pub retrieval_required_relay_successes: u64,
    /// Required anonymity failures.
    #[serde(default)]
    pub retrieval_required_failures: u64,
    /// Rendezvous retrieval attempts.
    #[serde(default)]
    pub retrieval_rendezvous_attempts: u64,
    /// Rendezvous retrieval successes.
    #[serde(default)]
    pub retrieval_rendezvous_successes: u64,
    /// Rendezvous retrieval failures.
    #[serde(default)]
    pub retrieval_rendezvous_failures: u64,
    /// Rendezvous fallbacks to direct (no intro points).
    #[serde(default)]
    pub retrieval_rendezvous_direct_fallbacks: u64,
    /// Rendezvous + onion (content-blind) attempts.
    #[serde(default)]
    pub retrieval_rendezvous_onion_attempts: u64,
    /// Rendezvous + onion successes.
    #[serde(default)]
    pub retrieval_rendezvous_onion_successes: u64,
    /// Rendezvous + onion failures.
    #[serde(default)]
    pub retrieval_rendezvous_onion_failures: u64,
    /// Opportunistic: onion-encrypted successes.
    #[serde(default)]
    pub retrieval_opportunistic_onion_successes: u64,
    /// Opportunistic: onion+rendezvous successes.
    #[serde(default)]
    pub retrieval_opportunistic_onion_rendezvous_successes: u64,
    /// Opportunistic: rendezvous-relay successes.
    #[serde(default)]
    pub retrieval_opportunistic_rendezvous_successes: u64,
    /// Active relay probes sent.
    #[serde(default)]
    pub relay_probes_sent: u64,
    /// Active relay probes succeeded (nonce matched).
    #[serde(default)]
    pub relay_probes_succeeded: u64,
    /// Active relay probes failed.
    #[serde(default)]
    pub relay_probes_failed: u64,
    /// Forwarding verification probes sent.
    #[serde(default)]
    pub forwarding_probes_sent: u64,
    /// Forwarding verification probes succeeded.
    #[serde(default)]
    pub forwarding_probes_succeeded: u64,
    /// Forwarding verification probes failed.
    #[serde(default)]
    pub forwarding_probes_failed: u64,
    /// Pre-retrieval probe sweeps executed.
    #[serde(default)]
    pub pre_retrieval_probes_run: u64,

    // ── Rendezvous and relay trust ──────────────────────────────────────
    /// Number of peers with Rendezvous reachability descriptors.
    #[serde(default)]
    pub rendezvous_peers: usize,
    /// Relay peers at Claimed trust tier.
    #[serde(default)]
    pub relay_tier_claimed: usize,
    /// Relay peers at Observed trust tier.
    #[serde(default)]
    pub relay_tier_observed: usize,
    /// Relay peers at Verified trust tier.
    #[serde(default)]
    pub relay_tier_verified: usize,
    /// Relays with fresh (within 300s) probe evidence.
    #[serde(default)]
    pub probe_cache_fresh: usize,
    /// Relays with forwarding verification evidence.
    #[serde(default)]
    pub forwarding_verified_relays: usize,

    // ── Directed sharing relay fallback (ADR-010 Part 2) ─────────────────
    /// Directed requests sent via direct (already-connected) path.
    #[serde(default)]
    pub directed_direct_sends: u64,
    /// Directed requests where relay circuit fallback was attempted.
    #[serde(default)]
    pub directed_relay_fallback_attempts: u64,
    /// Total relay circuit addresses registered for directed fallback.
    #[serde(default)]
    pub directed_relay_circuits_registered: u64,
    /// Directed requests where no relay candidates were available.
    #[serde(default)]
    pub directed_no_relay_candidates: u64,

    // ── Connection health (Phase 1: bridge superhardening) ──────────────
    /// Overall connection quality score (0.0–1.0).
    #[serde(default)]
    pub connection_quality_score: f64,
    /// Number of addresses currently in dial backoff.
    #[serde(default)]
    pub dial_backoff_addresses: usize,
    /// Total addresses pruned as stale since startup.
    #[serde(default)]
    pub stale_addresses_pruned: u64,
    /// Whether connectivity is considered degraded.
    #[serde(default)]
    pub connectivity_degraded: bool,
    /// Currently active (most recently successful) transport name.
    #[serde(default)]
    pub active_transport: Option<String>,
    /// Whether the system is operating in fallback mode (not using primary transport).
    #[serde(default)]
    pub fallback_active: bool,

    // ── Self-healing (Phase 2) ──────────────────────────────────────────
    /// Whether network flap damping is active.
    #[serde(default)]
    pub flap_damping_active: bool,
    /// Number of rate-limited requests since startup.
    #[serde(default)]
    pub rate_limit_rejections: u64,
    /// Current partial failure conditions (e.g., "relay-only mode", "no peers").
    #[serde(default)]
    pub partial_failures: Vec<String>,

    // ── Censorship resistance (Phases 3-4) ──────────────────────────────
    /// Whether Shadowsocks transport is configured.
    #[serde(default)]
    pub shadowsocks_configured: bool,
    /// Whether Tor transport is configured.
    #[serde(default)]
    pub tor_configured: bool,

    // ── Network environment (Phase 5) ───────────────────────────────────
    /// Detected network environment.
    #[serde(default)]
    pub network_environment: String,
    /// Whether TLS inspection was detected.
    #[serde(default)]
    pub tls_inspection_detected: bool,
    /// Whether a captive portal was detected.
    #[serde(default)]
    pub captive_portal_detected: bool,
    /// Whether a VPN was detected.
    #[serde(default)]
    pub vpn_detected: bool,

    // ── Reconnection (Track B wiring) ───────────────────────────────────
    /// Total reconnection attempts.
    #[serde(default)]
    pub reconnection_attempts: u64,
    /// Successful reconnections.
    #[serde(default)]
    pub reconnection_successes: u64,
    /// Failed reconnection attempts.
    #[serde(default)]
    pub reconnection_failures: u64,
    /// Circuit breaker trips (peer abandoned).
    #[serde(default)]
    pub reconnection_circuit_breaker_trips: u64,
    /// Recovery actions dispatched from partial failures.
    #[serde(default)]
    pub reconnection_recovery_actions: u64,
}

/// Per-transport readiness info for IPC/CLI display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportStatus {
    pub name: String,
    pub available: bool,
    /// Was this transport used for the most recent successful fetch?
    #[serde(default)]
    pub selected: bool,
    pub success_count: u64,
    pub failure_count: u64,
    /// Session-phase failures (connection refused, timeout, TLS handshake).
    #[serde(default)]
    pub session_failures: u64,
    /// Data-phase failures (connected but transfer failed).
    #[serde(default)]
    pub data_failures: u64,
    /// Most recent error message for this transport.
    #[serde(default)]
    pub last_error: Option<String>,
    pub reason: Option<String>,
}

// ─── Frame helpers ────────────────────────────────────────────────────────────

/// Serialize `value` to JSON and write a 4-byte LE length-prefixed frame.
pub async fn write_frame(stream: &mut TcpStream, value: &impl Serialize) -> Result<()> {
    let body = Zeroizing::new(serde_json::to_vec(value).context("frame serialize")?);
    let len = body.len() as u32;
    stream
        .write_all(&len.to_le_bytes())
        .await
        .context("write frame length")?;
    stream
        .write_all(body.as_slice())
        .await
        .context("write frame body")?;
    Ok(())
}

/// Read a 4-byte LE length-prefixed JSON frame and deserialize it.
pub async fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T> {
    read_frame_limited(stream, FRAME_MAX).await
}

/// As [`read_frame`], with a caller-chosen size cap (used for the small,
/// pre-authentication first frame).
pub async fn read_frame_limited<T: for<'de> Deserialize<'de>>(
    stream: &mut TcpStream,
    max: usize,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read frame length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        bail!("IPC frame too large: {len} bytes (max {max})");
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    stream
        .read_exact(buf.as_mut_slice())
        .await
        .context("read frame body")?;
    serde_json::from_slice(buf.as_slice()).context("frame deserialize")
}

// ─── Port file helpers ────────────────────────────────────────────────────────

/// Write the daemon control port to `<data_dir>/daemon.port`.
pub fn write_port_file(data_dir: &Path, port: u16) -> Result<()> {
    std::fs::write(data_dir.join(PORT_FILE), port.to_string()).context("write daemon.port")
}

/// Remove `<data_dir>/daemon.port` (called on daemon exit).
pub fn remove_port_file(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join(PORT_FILE));
}

/// Write the HTTP bridge port to `<data_dir>/daemon.http`.
pub fn write_http_port_file(data_dir: &Path, port: u16) -> Result<()> {
    std::fs::write(data_dir.join(HTTP_PORT_FILE), port.to_string()).context("write daemon.http")
}

/// Remove `<data_dir>/daemon.http` (called on daemon exit).
pub fn remove_http_port_file(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join(HTTP_PORT_FILE));
}

/// Read and parse the control port.  Returns a descriptive error if the file
/// is absent (i.e. the daemon is not running).
pub fn read_port_file(data_dir: &Path) -> Result<u16> {
    let path = data_dir.join(PORT_FILE);
    let s = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "daemon.port not found — is the miasma daemon running?\n  (looked in {})",
            path.display()
        )
    })?;
    s.trim()
        .parse::<u16>()
        .context("daemon.port contains an invalid port number")
}

// ─── Client helper ────────────────────────────────────────────────────────────

/// Connect to the local daemon, send one request, and return the response.
///
/// Reads `<data_dir>/daemon.token` and presents it as the first frame. The
/// request (and with it any password it carries) is wiped once it has been
/// written, whether or not the write succeeded.
pub async fn daemon_request(data_dir: &Path, req: ControlRequest) -> Result<ControlResponse> {
    let mut req = Zeroizing::new(req);
    let token = super::control_auth::read_token_file(data_dir)?;
    let port = read_port_file(data_dir)?;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .with_context(|| {
            format!(
                "cannot connect to daemon on 127.0.0.1:{port} — \
                 is the miasma daemon still running?"
            )
        })?;
    let mut hello = Zeroizing::new(ControlAuth {
        token: token.as_str().to_owned(),
    });
    let hello_result = write_frame(&mut stream, &*hello).await;
    hello.zeroize();
    let write_result = match hello_result {
        Ok(()) => write_frame(&mut stream, &*req).await,
        Err(e) => Err(e),
    };
    req.zeroize();
    write_result?;
    let resp: ControlResponse = read_frame(&mut stream).await?;
    Ok(resp)
}

/// Distress-wipe through the two-step confirmation exchange: `Wipe` returns a
/// daemon-issued challenge, `WipeConfirm` echoes it. Returns the final
/// response (`Wiped` or `Error`).
pub async fn daemon_wipe(data_dir: &Path) -> Result<ControlResponse> {
    match daemon_request(data_dir, ControlRequest::Wipe).await? {
        ControlResponse::WipeChallenge { nonce } => {
            daemon_request(data_dir, ControlRequest::WipeConfirm { nonce }).await
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod debug_redaction_tests {
    use super::*;

    #[test]
    fn control_request_debug_redacts_secret_and_payload() {
        let request = ControlRequest::DirectedSend {
            recipient_contact: "recipient-sensitive".into(),
            data: b"plaintext-sensitive".to_vec(),
            password: "password-sensitive".into(),
            retention_secs: 60,
            filename: Some("private-name.txt".into()),
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("DirectedSend"));
        assert!(rendered.contains("data_len: 19"));
        assert!(!rendered.contains("recipient-sensitive"));
        assert!(!rendered.contains("plaintext-sensitive"));
        assert!(!rendered.contains("password-sensitive"));
        assert!(!rendered.contains("private-name.txt"));
    }

    #[test]
    fn control_response_debug_redacts_plaintext_and_sharing_identity() {
        let retrieved = ControlResponse::DirectedRetrieved {
            data: b"plaintext-sensitive".to_vec(),
            filename: Some("private-name.txt".into()),
        };
        let rendered = format!("{retrieved:?}");
        assert!(rendered.contains("DirectedRetrieved"));
        assert!(rendered.contains("data_len: 19"));
        assert!(!rendered.contains("plaintext-sensitive"));
        assert!(!rendered.contains("private-name.txt"));

        let sharing = ControlResponse::SharingKey {
            key: "msk:sensitive-key".into(),
            contact: "msk:sensitive-key@peer".into(),
        };
        let rendered = format!("{sharing:?}");
        assert!(!rendered.contains("sensitive-key"));
    }
}

#[cfg(test)]
mod secret_lifetime_tests {
    use super::*;

    #[test]
    fn control_request_zeroizes_sensitive_material() {
        let mut password_req = ControlRequest::DirectedRetrieve {
            envelope_id: "id".into(),
            password: "super-secret".into(),
        };
        password_req.zeroize();
        match password_req {
            ControlRequest::DirectedRetrieve { password, .. } => assert!(password.is_empty()),
            _ => unreachable!(),
        }

        let mut challenge_req = ControlRequest::DirectedConfirm {
            envelope_id: "id".into(),
            challenge_code: "1234-5678".into(),
        };
        challenge_req.zeroize();
        match challenge_req {
            ControlRequest::DirectedConfirm { challenge_code, .. } => {
                assert!(challenge_code.is_empty())
            }
            _ => unreachable!(),
        }

        let mut publish_req = ControlRequest::Publish {
            data: vec![1, 2, 3, 4],
            data_shards: 2,
            total_shards: 3,
        };
        publish_req.zeroize();
        match publish_req {
            ControlRequest::Publish { data, .. } => assert!(data.is_empty()),
            _ => unreachable!(),
        }

        let mut response = ControlResponse::DirectedRetrieved {
            data: vec![9, 8, 7],
            filename: None,
        };
        response.zeroize_sensitive_material();
        match response {
            ControlResponse::DirectedRetrieved { data, .. } => assert!(data.is_empty()),
            _ => unreachable!(),
        }
    }
}
