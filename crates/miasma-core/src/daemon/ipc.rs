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

/// Maximum JSON frame body size (256 MiB).
const FRAME_MAX: usize = 256 * 1_024 * 1_024;

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
}

/// Response from the daemon to a CLI client.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlResponse {
    Published { mid: String },
    Retrieved { data: Vec<u8> },
    Status(DaemonStatus),
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
            "daemon.port not found — is `miasma daemon` running?\n  (looked in {})",
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
                 is `miasma daemon` still running?"
            )
        })?;
    write_frame(&mut stream, &req).await?;
    let resp: ControlResponse = read_frame(&mut stream).await?;
    Ok(resp)
}
