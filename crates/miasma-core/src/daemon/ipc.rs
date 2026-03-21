//! CLI ↔ Daemon control protocol.
//!
//! Transport: TCP loopback, 4-byte LE length-prefixed JSON frames.
//!
//! The daemon binds to `127.0.0.1:0` (OS-assigned port) and writes the
//! bound port number to `<data_dir>/daemon.port`. CLI clients read that
//! file to discover the port, connect, send a request, receive a response,
//! and close the connection.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Maximum JSON frame body size (16 MiB).
const FRAME_MAX: usize = 16 * 1_024 * 1_024;

/// Filename inside the data directory containing the control port number.
pub const PORT_FILE: &str = "daemon.port";

// ─── Wire types ───────────────────────────────────────────────────────────────

/// Request from a CLI client to the local daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlRequest {
    /// Dissolve `data` into shares and publish a DHT record.
    Publish {
        data: Vec<u8>,
        data_shards: u8,
        total_shards: u8,
    },
    /// Retrieve content by MID string from the P2P network.
    Get {
        mid: String,
        data_shards: u8,
        total_shards: u8,
    },
    /// Return daemon status metrics.
    Status,
    /// Distress-wipe: destroy the master key so all shares become unreadable.
    Wipe,
}

/// Response from the daemon to a CLI client.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlResponse {
    Published { mid: String },
    Retrieved { data: Vec<u8> },
    Status(DaemonStatus),
    /// Distress wipe completed successfully.
    Wiped,
    Error(String),
}

/// Snapshot of daemon state — returned for `miasma status` and IPC calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
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
    /// Routing overlay: current PoW difficulty in bits.
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
    /// Descriptors carrying a BBS+ proof.
    #[serde(default)]
    pub descriptor_bbs_credentialed: usize,
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
    /// Fraction of peers using pseudonymous descriptors.
    #[serde(default)]
    pub metric_pseudonymous_fraction: f64,
    /// Multi-path content retrievability estimate (0.0–1.0).
    #[serde(default)]
    pub metric_multi_path_retrievability: f64,
    /// Current PoW difficulty (bits).
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
    /// BBS+-credentialed descriptors (within-epoch unlinkability).
    #[serde(default)]
    pub metric_bbs_credentialed: usize,
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
    let body = serde_json::to_vec(value).context("frame serialize")?;
    let len = body.len() as u32;
    stream.write_all(&len.to_le_bytes()).await.context("write frame length")?;
    stream.write_all(&body).await.context("write frame body")?;
    Ok(())
}

/// Read a 4-byte LE length-prefixed JSON frame and deserialize it.
pub async fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("read frame length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > FRAME_MAX {
        bail!("IPC frame too large: {len} bytes (max {FRAME_MAX})");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.context("read frame body")?;
    serde_json::from_slice(&buf).context("frame deserialize")
}

// ─── Port file helpers ────────────────────────────────────────────────────────

/// Write the daemon control port to `<data_dir>/daemon.port`.
pub fn write_port_file(data_dir: &Path, port: u16) -> Result<()> {
    std::fs::write(data_dir.join(PORT_FILE), port.to_string())
        .context("write daemon.port")
}

/// Remove `<data_dir>/daemon.port` (called on daemon exit).
pub fn remove_port_file(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join(PORT_FILE));
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
    s.trim().parse::<u16>().context("daemon.port contains an invalid port number")
}

// ─── Client helper ────────────────────────────────────────────────────────────

/// Connect to the local daemon, send one request, and return the response.
pub async fn daemon_request(data_dir: &Path, req: ControlRequest) -> Result<ControlResponse> {
    let port = read_port_file(data_dir)?;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .with_context(|| {
            format!(
                "cannot connect to daemon on 127.0.0.1:{port} — \
                 is the miasma daemon still running?"
            )
        })?;
    write_frame(&mut stream, &req).await?;
    let resp: ControlResponse = read_frame(&mut stream).await?;
    Ok(resp)
}
