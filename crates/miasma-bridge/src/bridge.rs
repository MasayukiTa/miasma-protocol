/// BitTorrent → Miasma bridge — Phase 2 (Task 15).
///
/// # Protocol flow
/// ```text
/// magnet:?xt=urn:btih:<info_hash>
///   │
///   ▼ dht_get_peers (UDP BEP-5)
/// [peer_addr, ...]
///   │
///   ▼ fetch_ut_metadata (TCP BEP-10 + BEP-9)
/// torrent info dict (bencoded)
///   │
///   ▼ parse info dict → Vec<(filename, size)>
///   │
///   ▼ download_piece_by_piece (TCP BEP-3)
/// Vec<(filename, Vec<u8>)>
///   │
///   ▼ miasma_core::pipeline::dissolve each file
/// Vec<MID>
/// ```
use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context};
use directories::UserDirs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use miasma_core::{pipeline::dissolve, pipeline::DissolutionParams, LocalShareStore};

use crate::bencode::{self, Value};

// ─── Constants ───────────────────────────────────────────────────────────────

const DHT_BOOTSTRAP: &[&str] = &[
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
];

// Extension protocol flag byte 5 bit 4 (supports BEP-10).
const EXT_FLAG: u8 = 0x10;
// ut_metadata extension ID we advertise.
const UT_METADATA_ID: u8 = 3;
const INBOX_MARKER: &str = ".miasma-bridge-inbox";
const PROCESSED_DIR: &str = ".processed";

#[derive(Debug, Clone)]
pub struct TorrentInspection {
    pub info_hash_hex: String,
    pub display_name: Option<String>,
    pub peer_count: usize,
    pub files: Vec<(String, u64)>,
    pub total_bytes: u64,
}

/// Safety options for torrent downloads.
#[derive(Debug, Clone)]
pub struct DownloadSafetyOpts {
    /// Hard limit in bytes.  If the torrent's total payload exceeds this,
    /// the download is refused unless `confirm_download` is set.
    /// Default: 100 MiB.
    pub max_total_bytes: u64,
    /// When true, proceed even if the torrent exceeds `max_total_bytes`.
    pub confirm_download: bool,
}

impl Default for DownloadSafetyOpts {
    fn default() -> Self {
        Self {
            max_total_bytes: 100 * 1024 * 1024, // 100 MiB
            confirm_download: false,
        }
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Dissolve a torrent identified by `info_hash` into Miasma.
///
/// 1. Discover peers via DHT.
/// 2. Fetch torrent metadata (ut_metadata extension).
/// 3. **Preflight**: print file list and total size; refuse if over the
///    safety limit unless `opts.confirm_download` is set.
/// 4. Download each file in the torrent.
/// 5. Dissolve each file into the local share store.
///
/// Returns the list of MID strings produced.
pub async fn dissolve_torrent(
    info_hash: &[u8; 20],
    display_name: Option<&str>,
    data_dir: &std::path::Path,
    quota_mb: u64,
    opts: &DownloadSafetyOpts,
) -> anyhow::Result<Vec<String>> {
    let store = Arc::new(
        LocalShareStore::open(data_dir, quota_mb).context("open share store")?,
    );

    info!(
        "Dissolving torrent {} ({})",
        hex::encode(info_hash),
        display_name.unwrap_or("unknown")
    );

    // 1. Find peers.
    let peers = dht_get_peers(info_hash)
        .await
        .context("DHT get_peers")?;

    if peers.is_empty() {
        bail!(
            "No peers found for info_hash {}. The torrent may be too new or too old.",
            hex::encode(info_hash)
        );
    }
    info!("Found {} peers", peers.len());

    // 2. Fetch metadata (preflight — no payload downloaded yet).
    let info_dict_bytes = fetch_info_dict_from_peers(&peers, info_hash).await?;
    let file_entries = parse_info_dict(&info_dict_bytes)?;
    let total_bytes: u64 = file_entries.iter().map(|(_, s)| *s).sum();

    // 3. Print preflight report.
    info!("Torrent has {} file(s), {} bytes total", file_entries.len(), total_bytes);
    for (name, size) in &file_entries {
        info!("  {size:>12}  {name}");
    }

    // 4. Enforce safety limit.
    if total_bytes > opts.max_total_bytes && !opts.confirm_download {
        bail!(
            "Torrent total size ({}) exceeds safety limit ({} bytes).\n\
             To proceed anyway, re-run with --confirm-download or increase --max-total-bytes.",
            format_bytes(total_bytes),
            opts.max_total_bytes
        );
    }

    // 5. Download each file and dissolve it.
    let params = DissolutionParams::default();
    let mut mids = Vec::new();

    for (filename, size) in &file_entries {
        info!("  Fetching {} ({} bytes)…", filename, size);
        let data = download_file(&peers, info_hash, filename, *size, &info_dict_bytes)
            .await
            .with_context(|| format!("download {filename}"))?;

        match dissolve(&data, params) {
            Ok((mid, shares)) => {
                let mid_str = mid.to_string();
                for share in &shares {
                    store.put(share).context("store share")?;
                }
                info!("    -> {mid_str}");
                mids.push(mid_str);
            }
            Err(e) => warn!("Dissolution failed for {filename}: {e}"),
        }
    }

    Ok(mids)
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

/// Inspect a torrent via the public BitTorrent network without downloading its
/// payload files. Useful for safely verifying magnet reachability.
pub async fn inspect_torrent(
    info_hash: &[u8; 20],
    display_name: Option<&str>,
) -> anyhow::Result<TorrentInspection> {
    let peers = dht_get_peers(info_hash)
        .await
        .context("DHT get_peers")?;
    if peers.is_empty() {
        bail!(
            "No peers found for info_hash {}. The torrent may be too new or too old.",
            hex::encode(info_hash)
        );
    }

    let info_dict_bytes = fetch_info_dict_from_peers(&peers, info_hash).await?;
    let files = parse_info_dict(&info_dict_bytes)?;
    let total_bytes = files.iter().map(|(_, size)| *size).sum();

    Ok(TorrentInspection {
        info_hash_hex: hex::encode(info_hash),
        display_name: display_name.map(str::to_owned),
        peer_count: peers.len(),
        files,
        total_bytes,
    })
}

/// Initialize a dedicated bridge inbox directory with an explicit marker file.
pub fn init_inbox(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create inbox dir {}", dir.display()))?;
    let marker_path = dir.join(INBOX_MARKER);
    if !marker_path.exists() {
        std::fs::write(
            &marker_path,
            concat!(
                "This directory is explicitly approved as a miasma-bridge inbox.\n",
                "Only drop files here that you want the bridge daemon to import.\n",
                "Do not point the bridge at Downloads/Desktop/Documents directly.\n",
            ),
        )
        .with_context(|| format!("write inbox marker {}", marker_path.display()))?;
    }
    std::fs::create_dir_all(dir.join(PROCESSED_DIR))
        .with_context(|| format!("create processed dir {}", dir.display()))?;
    Ok(())
}

// ─── DHT get_peers ────────────────────────────────────────────────────────────

/// Send DHT `get_peers` to bootstrap nodes and collect peer socket addresses.
async fn dht_get_peers(info_hash: &[u8; 20]) -> anyhow::Result<Vec<SocketAddr>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind UDP")?;
    let our_id = random_20_bytes();
    let tid = b"aa";

    let query = bencode::encode(&Value::Dict({
        let mut d = BTreeMap::new();
        d.insert(b"t".to_vec(), Value::Bytes(tid.to_vec()));
        d.insert(b"y".to_vec(), Value::Bytes(b"q".to_vec()));
        d.insert(b"q".to_vec(), Value::Bytes(b"get_peers".to_vec()));
        d.insert(b"a".to_vec(), Value::Dict({
            let mut a = BTreeMap::new();
            a.insert(b"id".to_vec(), Value::Bytes(our_id.to_vec()));
            a.insert(b"info_hash".to_vec(), Value::Bytes(info_hash.to_vec()));
            a
        }));
        d
    }));

    let mut peers: Vec<SocketAddr> = Vec::new();
    let mut buf = vec![0u8; 4096];

    for node in DHT_BOOTSTRAP {
        let addrs: Vec<SocketAddr> = match node.to_socket_addrs() {
            Ok(a) => a.collect(),
            Err(e) => { debug!("DNS {node}: {e}"); continue; }
        };
        for addr in addrs {
            if let Err(e) = sock.send_to(&query, addr).await {
                debug!("UDP send to {addr}: {e}");
                continue;
            }
            match timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _from))) => {
                    peers.extend(parse_compact_peers(&buf[..n]));
                }
                Ok(Err(e)) => debug!("UDP recv from {addr}: {e}"),
                Err(_) => debug!("DHT timeout from {addr}"),
            }
        }
        if peers.len() >= 20 { break; }
    }

    Ok(peers)
}

/// Parse compact peer list from a DHT `get_peers` response.
/// Compact format: 6 bytes per peer (4 bytes IP + 2 bytes port).
fn parse_compact_peers(data: &[u8]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if let Ok((v, _)) = bencode::decode(data) {
        // Try r.values (compact peer list) and r.nodes
        if let Some(resp) = v.dict_get(b"r") {
            if let Some(values) = resp.dict_get(b"values") {
                if let Some(list) = values.as_list() {
                    for item in list {
                        if let Some(bytes) = item.as_bytes() {
                            if let Some(addr) = decode_compact_6(bytes) {
                                out.push(addr);
                            }
                        }
                    }
                } else if let Some(bytes) = values.as_bytes() {
                    // Sometimes encoded as one flat bytes string
                    for chunk in bytes.chunks_exact(6) {
                        if let Some(addr) = decode_compact_6(chunk) {
                            out.push(addr);
                        }
                    }
                }
            }
        }
    }
    out
}

fn decode_compact_6(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < 6 { return None; }
    let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
    if port == 0 { return None; }
    Some(SocketAddr::from((ip, port)))
}

// ─── ut_metadata fetch ────────────────────────────────────────────────────────

/// Try each peer in turn until we successfully fetch the info dict.
async fn fetch_info_dict_from_peers(
    peers: &[SocketAddr],
    info_hash: &[u8; 20],
) -> anyhow::Result<Vec<u8>> {
    for &peer in peers.iter().take(10) {
        match timeout(
            Duration::from_secs(15),
            fetch_ut_metadata(peer, info_hash),
        )
        .await
        {
            Ok(Ok(bytes)) => {
                info!("Got metadata ({} bytes) from {peer}", bytes.len());
                return Ok(bytes);
            }
            Ok(Err(e)) => debug!("Peer {peer} metadata fail: {e}"),
            Err(_) => debug!("Peer {peer} metadata timeout"),
        }
    }
    bail!("Could not fetch metadata from any peer")
}

/// Connect to a peer, do BT handshake + extension, then fetch ut_metadata.
async fn fetch_ut_metadata(
    peer: SocketAddr,
    info_hash: &[u8; 20],
) -> anyhow::Result<Vec<u8>> {
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(peer))
        .await
        .context("connect timeout")?
        .context("TCP connect")?;

    // ── Handshake ───────────────────────────────────────────────────────────
    let our_id = random_20_bytes();
    let mut handshake = Vec::with_capacity(68);
    handshake.push(19u8);
    handshake.extend_from_slice(b"BitTorrent protocol");
    // Extension bytes: byte 5 = 0x10 (extension protocol, BEP-10)
    let mut ext_bytes = [0u8; 8];
    ext_bytes[5] = EXT_FLAG;
    handshake.extend_from_slice(&ext_bytes);
    handshake.extend_from_slice(info_hash);
    handshake.extend_from_slice(&our_id);

    stream.write_all(&handshake).await.context("send handshake")?;

    // Read remote handshake (68 bytes)
    let mut rbuf = [0u8; 68];
    timeout(Duration::from_secs(10), stream.read_exact(&mut rbuf))
        .await
        .context("handshake timeout")?
        .context("read handshake")?;

    // Verify protocol string
    if &rbuf[1..20] != b"BitTorrent protocol" {
        bail!("Not a BT peer");
    }
    // Check extension support
    if rbuf[25] & EXT_FLAG == 0 {
        bail!("Peer does not support extension protocol");
    }

    // ── Extension handshake (BEP-10) ────────────────────────────────────────
    let ext_hs_payload = bencode::encode(&Value::Dict({
        let mut d = BTreeMap::new();
        d.insert(b"m".to_vec(), Value::Dict({
            let mut m = BTreeMap::new();
            m.insert(b"ut_metadata".to_vec(), Value::Int(UT_METADATA_ID as i64));
            m
        }));
        d
    }));

    send_msg(&mut stream, 20, &[0], &ext_hs_payload).await?;

    // Read extension handshake response.
    let (msg_id, payload) = recv_msg(&mut stream).await?;
    if msg_id != 20 {
        bail!("Expected ext handshake (20), got {msg_id}");
    }
    // payload[0] = 0 (handshake ext_id), rest is bencoded dict
    if payload.is_empty() { bail!("Empty ext handshake"); }

    let (hs_dict, _) = bencode::decode(&payload[1..])
        .map_err(|e| anyhow::anyhow!("parse ext hs: {e}"))?;
    let peer_ut_meta_id = hs_dict
        .dict_get(b"m")
        .and_then(|m: &Value| m.dict_get(b"ut_metadata"))
        .and_then(|v: &Value| v.as_int())
        .ok_or_else(|| anyhow::anyhow!("Peer does not advertise ut_metadata"))? as u8;

    let metadata_size = hs_dict
        .dict_get(b"metadata_size")
        .and_then(|v: &Value| v.as_int())
        .unwrap_or(0) as usize;

    if metadata_size == 0 || metadata_size > 10 * 1024 * 1024 {
        bail!("Implausible metadata_size: {metadata_size}");
    }

    // ── Request metadata pieces (BEP-9) ─────────────────────────────────────
    let piece_size = 16_384usize;
    let num_pieces = (metadata_size + piece_size - 1) / piece_size;
    let mut pieces: Vec<Option<Vec<u8>>> = vec![None; num_pieces];

    for i in 0..num_pieces {
        let req = bencode::encode(&Value::Dict({
            let mut d = BTreeMap::new();
            d.insert(b"msg_type".to_vec(), Value::Int(0)); // request
            d.insert(b"piece".to_vec(), Value::Int(i as i64));
            d
        }));
        send_msg(&mut stream, 20, &[peer_ut_meta_id], &req).await?;
    }

    // Receive pieces (may arrive out of order, mixed with other messages).
    for _ in 0..(num_pieces * 4) {
        let (msg_id, payload) = match recv_msg(&mut stream).await {
            Ok(p) => p,
            Err(_) => break,
        };
        if msg_id != 20 || payload.is_empty() { continue; }
        if payload[0] != peer_ut_meta_id { continue; }

        // Decode the dict prefix to find piece index and data offset.
        let (dict, rest) = match bencode::decode(&payload[1..]) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let msg_type = dict.dict_get(b"msg_type").and_then(|v| v.as_int()).unwrap_or(-1);
        let piece_idx = dict.dict_get(b"piece").and_then(|v| v.as_int()).unwrap_or(-1) as usize;

        if msg_type != 1 || piece_idx >= num_pieces { continue; } // data = 1

        // Data follows the dict (the raw metadata bytes for this piece).
        let data_start = payload.len() - rest.len();
        let piece_data = payload[1 + data_start..].to_vec();
        pieces[piece_idx] = Some(piece_data);

        if pieces.iter().all(|p| p.is_some()) {
            break;
        }
    }

    if pieces.iter().any(|p| p.is_none()) {
        bail!("Incomplete metadata: missing pieces");
    }

    let mut assembled = Vec::with_capacity(metadata_size);
    for piece in pieces.into_iter().flatten() {
        assembled.extend(piece);
    }
    assembled.truncate(metadata_size);

    Ok(assembled)
}

// ─── Info dict parsing ────────────────────────────────────────────────────────

/// Parse a bencoded info dict → Vec<(relative_path, size_bytes)>.
fn parse_info_dict(info_bytes: &[u8]) -> anyhow::Result<Vec<(String, u64)>> {
    let (info, _) = bencode::decode(info_bytes).map_err(|e| anyhow::anyhow!(e))?;

    let mut files = Vec::new();

    if let Some(f) = info.dict_get(b"files") {
        // Multi-file torrent.
        let name = info
            .dict_get(b"name")
            .and_then(|v| v.as_bytes())
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("torrent");

        for entry in f.as_list().ok_or_else(|| anyhow::anyhow!("files not a list"))? {
            let size = entry
                .dict_get(b"length")
                .and_then(|v| v.as_int())
                .ok_or_else(|| anyhow::anyhow!("file missing length"))? as u64;

            let path_parts = entry
                .dict_get(b"path")
                .and_then(|v| v.as_list())
                .ok_or_else(|| anyhow::anyhow!("file missing path"))?;

            let mut path = name.to_owned();
            for part in path_parts {
                if let Some(p) = part.as_bytes().and_then(|b| std::str::from_utf8(b).ok()) {
                    path.push('/');
                    path.push_str(p);
                }
            }
            files.push((path, size));
        }
    } else {
        // Single-file torrent.
        let name = info
            .dict_get(b"name")
            .and_then(|v| v.as_bytes())
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("file")
            .to_owned();
        let size = info
            .dict_get(b"length")
            .and_then(|v| v.as_int())
            .ok_or_else(|| anyhow::anyhow!("missing length in info dict"))? as u64;
        files.push((name, size));
    }

    Ok(files)
}

// ─── File download ────────────────────────────────────────────────────────────

/// Download a specific file from peers using the BT piece protocol.
///
/// For Phase 2: this is a simplified implementation that requests pieces
/// sequentially from the first cooperative peer.
async fn download_file(
    peers: &[SocketAddr],
    info_hash: &[u8; 20],
    _filename: &str,
    size: u64,
    info_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // Extract piece info from the info dict.
    let (info, _) = bencode::decode(info_bytes).map_err(|e| anyhow::anyhow!(e))?;
    let piece_length = info
        .dict_get(b"piece length")
        .and_then(|v| v.as_int())
        .ok_or_else(|| anyhow::anyhow!("missing piece length"))? as usize;

    let pieces_hash = info
        .dict_get(b"pieces")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("missing pieces"))?.to_owned();

    let num_pieces = (size as usize + piece_length - 1) / piece_length;

    // Try each peer until we get a full download.
    for &peer in peers.iter().take(10) {
        match timeout(
            Duration::from_secs(300), // 5 min per file
            download_from_peer(peer, info_hash, num_pieces, piece_length, size as usize),
        )
        .await
        {
            Ok(Ok(data)) => {
                // Verify SHA1 of each piece.
                if verify_pieces(&data, &pieces_hash, piece_length) {
                    return Ok(data);
                } else {
                    warn!("Piece verification failed for peer {peer}");
                }
            }
            Ok(Err(e)) => debug!("Download from {peer}: {e}"),
            Err(_) => debug!("Download timeout from {peer}"),
        }
    }

    bail!("Could not download file from any peer")
}

async fn download_from_peer(
    peer: SocketAddr,
    info_hash: &[u8; 20],
    num_pieces: usize,
    piece_length: usize,
    total_size: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(peer).await.context("TCP connect")?;
    let our_id = random_20_bytes();

    // Handshake (same as ut_metadata).
    let mut handshake = Vec::with_capacity(68);
    handshake.push(19u8);
    handshake.extend_from_slice(b"BitTorrent protocol");
    let ext_bytes = [0u8; 8];
    handshake.extend_from_slice(&ext_bytes);
    handshake.extend_from_slice(info_hash);
    handshake.extend_from_slice(&our_id);
    stream.write_all(&handshake).await?;

    let mut rbuf = [0u8; 68];
    stream.read_exact(&mut rbuf).await?;
    if &rbuf[1..20] != b"BitTorrent protocol" { bail!("Not a BT peer"); }

    // Send interested + unchoke.
    send_msg(&mut stream, 2, &[], &[]).await?; // interested
    // Wait for unchoke (msg_id 1) or bitfield.
    for _ in 0..10 {
        let (msg_id, _) = recv_msg(&mut stream).await?;
        if msg_id == 1 { break; } // unchoke
        if msg_id == 5 { continue; } // bitfield — wait for unchoke
    }

    // Download pieces.
    let block_size = 16_384usize;
    let mut data = vec![0u8; total_size];

    for piece_idx in 0..num_pieces {
        let piece_begin = piece_idx * piece_length;
        let piece_end = (piece_begin + piece_length).min(total_size);
        let this_piece_len = piece_end - piece_begin;
        let mut offset = 0usize;

        while offset < this_piece_len {
            let this_block = (this_piece_len - offset).min(block_size);
            // Request: piece index (4) + begin (4) + length (4)
            let mut req = [0u8; 12];
            req[0..4].copy_from_slice(&(piece_idx as u32).to_be_bytes());
            req[4..8].copy_from_slice(&(offset as u32).to_be_bytes());
            req[8..12].copy_from_slice(&(this_block as u32).to_be_bytes());
            send_msg(&mut stream, 6, &[], &req).await?; // request

            loop {
                let (msg_id, payload) = recv_msg(&mut stream).await?;
                if msg_id != 7 { continue; } // piece = 7
                if payload.len() < 8 { continue; }
                let recv_piece = u32::from_be_bytes(payload[0..4].try_into().unwrap()) as usize;
                let recv_begin = u32::from_be_bytes(payload[4..8].try_into().unwrap()) as usize;
                if recv_piece != piece_idx || recv_begin != offset { continue; }
                let block_data = &payload[8..];
                let dst_start = piece_begin + offset;
                let dst_end = (dst_start + block_data.len()).min(total_size);
                data[dst_start..dst_end].copy_from_slice(&block_data[..dst_end - dst_start]);
                offset += block_data.len();
                break;
            }
        }
    }

    Ok(data)
}

/// Verify pieces using SHA1 hashes from the info dict.
fn verify_pieces(data: &[u8], pieces_hash: &[u8], piece_length: usize) -> bool {
    if pieces_hash.len() % 20 != 0 { return false; }
    let num_pieces = pieces_hash.len() / 20;

    for (i, expected) in pieces_hash.chunks(20).enumerate() {
        let start = i * piece_length;
        let end = (start + piece_length).min(data.len());
        if start >= data.len() { break; }
        let actual = sha1_of(&data[start..end]);
        if actual != expected {
            return false;
        }
    }
    let _ = num_pieces; // suppress warning
    true
}

fn sha1_of(data: &[u8]) -> [u8; 20] {
    // Minimal SHA1 — use the SHA-2 crate which is already a workspace dep.
    // SHA1 is NOT in sha2, so we implement a tiny wrapper here.
    // Note: sha1 is only used for verifying BT pieces, not for security.
    sha1_compress(data)
}

/// Minimal SHA1 (FIPS 180-4) — used only for BT piece verification.
fn sha1_compress(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Pad message.
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19  => ((b & c) | ((!b) & d),   0x5A827999u32),
                20..=39 => (b ^ c ^ d,               0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _       => (b ^ c ^ d,               0xCA62C1D6u32),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e)
                         .wrapping_add(k).wrapping_add(w[i]);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, &val) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

// ─── BT message helpers ───────────────────────────────────────────────────────

/// Send a BT message: `<len:4><msg_id:1><prefix><payload>`.
async fn send_msg(
    stream: &mut TcpStream,
    msg_id: u8,
    prefix: &[u8],
    payload: &[u8],
) -> anyhow::Result<()> {
    let len = 1 + prefix.len() + payload.len();
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    buf.push(msg_id);
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(payload);
    stream.write_all(&buf).await.context("send_msg")
}

/// Receive one BT message, returns `(msg_id, payload)`.
async fn recv_msg(stream: &mut TcpStream) -> anyhow::Result<(u8, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    timeout(Duration::from_secs(30), stream.read_exact(&mut len_buf))
        .await
        .context("recv len timeout")?
        .context("recv len")?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 { return Ok((0, vec![])); } // keep-alive
    if len > 10 * 1024 * 1024 { bail!("Message too large: {len}"); }

    let mut payload = vec![0u8; len];
    timeout(Duration::from_secs(30), stream.read_exact(&mut payload))
        .await
        .context("recv payload timeout")?
        .context("recv payload")?;

    let msg_id = payload[0];
    Ok((msg_id, payload[1..].to_vec()))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn random_20_bytes() -> [u8; 20] {
    let mut arr = [0u8; 20];
    // Use a deterministic "random" based on current time for the peer ID.
    // Good enough for our purposes (not a security primitive).
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    arr[..8].copy_from_slice(&(t as u64).to_le_bytes());
    arr[8..12].copy_from_slice(b"-MI-"); // Miasma client identifier
    arr
}

// ─── Directory watcher (daemon mode) ─────────────────────────────────────────

/// Watch `watch_dir` for new files and dissolve them into Miasma.
///
/// This is the daemon mode: the user configures their BT client to download
/// to `watch_dir`, and this daemon dissolves completed files automatically.
pub async fn watch_and_dissolve(
    watch_dir: &std::path::Path,
    data_dir: &std::path::Path,
    quota_mb: u64,
) -> anyhow::Result<()> {
    use tokio::time::sleep;

    validate_inbox_dir(watch_dir, data_dir)?;

    let store = Arc::new(
        LocalShareStore::open(data_dir, quota_mb).context("open share store")?,
    );
    let params = DissolutionParams::default();

    info!("Bridge daemon watching {} for new files…", watch_dir.display());
    let mut seen = seed_seen_files(watch_dir)?;

    loop {
        for path in scan_new_inbox_files(watch_dir, &mut seen)? {
            // Small delay to avoid dissolving a partially-written file.
            sleep(Duration::from_secs(2)).await;
            match std::fs::read(&path) {
                Ok(data) => match dissolve(&data, params) {
                    Ok((mid, shares)) => {
                        for share in &shares {
                            let _ = store.put(share);
                        }
                        archive_imported_file(watch_dir, &path)?;
                        info!(
                            "Dissolved {} → {}",
                            path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("?"),
                            mid.to_string()
                        );
                    }
                    Err(e) => warn!("Dissolution failed for {}: {e}", path.display()),
                },
                Err(e) => warn!("Read failed for {}: {e}", path.display()),
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

fn validate_inbox_dir(watch_dir: &Path, data_dir: &Path) -> anyhow::Result<()> {
    let watch_dir = std::fs::canonicalize(watch_dir)
        .with_context(|| format!("canonicalize inbox dir {}", watch_dir.display()))?;
    let data_dir = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());

    if !watch_dir.is_dir() {
        bail!("inbox path is not a directory: {}", watch_dir.display());
    }
    if watch_dir == data_dir || watch_dir.starts_with(&data_dir) || data_dir.starts_with(&watch_dir)
    {
        bail!(
            "refusing unsafe inbox path {} because it overlaps the Miasma data directory {}",
            watch_dir.display(),
            data_dir.display()
        );
    }
    if watch_dir.parent().is_none() {
        bail!("refusing filesystem root as inbox: {}", watch_dir.display());
    }

    if let Some(user_dirs) = UserDirs::new() {
        let dangerous_dirs = [
            Some(user_dirs.home_dir()),
            user_dirs.desktop_dir(),
            user_dirs.document_dir(),
            user_dirs.download_dir(),
            user_dirs.audio_dir(),
            user_dirs.picture_dir(),
            user_dirs.public_dir(),
            user_dirs.video_dir(),
        ];
        for dangerous in dangerous_dirs.into_iter().flatten() {
            if let Ok(canon) = std::fs::canonicalize(dangerous) {
                if canon == watch_dir {
                    bail!(
                        "refusing unsafe inbox path {}. Create a dedicated inbox with `miasma-bridge init-inbox <dir>` instead",
                        watch_dir.display()
                    );
                }
            }
        }
    }

    let marker = watch_dir.join(INBOX_MARKER);
    if !marker.exists() {
        bail!(
            "inbox {} is missing {}. Run `miasma-bridge init-inbox <dir>` first",
            watch_dir.display(),
            INBOX_MARKER
        );
    }

    Ok(())
}

fn seed_seen_files(watch_dir: &Path) -> anyhow::Result<std::collections::HashSet<PathBuf>> {
    let mut seen = std::collections::HashSet::new();
    let entries = std::fs::read_dir(watch_dir).context("read inbox dir")?;
    for entry in entries.flatten() {
        let path = entry.path();
        if is_importable_file(&path)? {
            seen.insert(path);
        }
    }
    Ok(seen)
}

fn scan_new_inbox_files(
    watch_dir: &Path,
    seen: &mut std::collections::HashSet<PathBuf>,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut new_files = Vec::new();
    let entries = std::fs::read_dir(watch_dir).context("read inbox dir")?;
    for entry in entries.flatten() {
        let path = entry.path();
        if is_importable_file(&path)? && !seen.contains(&path) {
            seen.insert(path.clone());
            new_files.push(path);
        }
    }
    Ok(new_files)
}

fn is_importable_file(path: &Path) -> anyhow::Result<bool> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    if name == INBOX_MARKER || name == PROCESSED_DIR {
        return Ok(false);
    }

    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("read metadata for {}", path.display()))?;
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return Ok(false);
    }
    Ok(file_type.is_file())
}

fn archive_imported_file(inbox_dir: &Path, path: &Path) -> anyhow::Result<()> {
    let processed_dir = inbox_dir.join(PROCESSED_DIR);
    std::fs::create_dir_all(&processed_dir)
        .with_context(|| format!("create processed dir {}", processed_dir.display()))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("imported path has no filename: {}", path.display()))?;
    let mut dest = processed_dir.join(file_name);
    if dest.exists() {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("imported");
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let suffix = format!(
            "-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        let unique = if ext.is_empty() {
            format!("{stem}{suffix}")
        } else {
            format!("{stem}{suffix}.{ext}")
        };
        dest = processed_dir.join(unique);
    }

    std::fs::rename(path, &dest).or_else(|_| {
        std::fs::copy(path, &dest)?;
        std::fs::remove_file(path)
    })
    .with_context(|| {
        format!(
            "move imported file {} to {}",
            path.display(),
            dest.display()
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sha1_empty() {
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
            0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
            0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(sha1_compress(&[]), expected);
    }

    #[test]
    fn sha1_abc() {
        // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
            0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
            0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(sha1_compress(b"abc"), expected);
    }

    #[test]
    fn parse_single_file_info_dict() {
        // Build a minimal bencoded info dict for a single file.
        let info = Value::Dict({
            let mut d = BTreeMap::new();
            d.insert(b"name".to_vec(), Value::Bytes(b"test.txt".to_vec()));
            d.insert(b"length".to_vec(), Value::Int(1024));
            d.insert(b"piece length".to_vec(), Value::Int(262144));
            d.insert(b"pieces".to_vec(), Value::Bytes(vec![0u8; 20]));
            d
        });
        let bytes = bencode::encode(&info);
        let files = parse_info_dict(&bytes).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "test.txt");
        assert_eq!(files[0].1, 1024);
    }

    #[test]
    fn parse_multi_file_info_dict() {
        let info = Value::Dict({
            let mut d = BTreeMap::new();
            d.insert(b"name".to_vec(), Value::Bytes(b"album".to_vec()));
            d.insert(b"piece length".to_vec(), Value::Int(262144));
            d.insert(b"pieces".to_vec(), Value::Bytes(vec![0u8; 40]));
            d.insert(b"files".to_vec(), Value::List(vec![
                Value::Dict({
                    let mut f = BTreeMap::new();
                    f.insert(b"length".to_vec(), Value::Int(512));
                    f.insert(b"path".to_vec(), Value::List(vec![
                        Value::Bytes(b"track1.flac".to_vec()),
                    ]));
                    f
                }),
                Value::Dict({
                    let mut f = BTreeMap::new();
                    f.insert(b"length".to_vec(), Value::Int(768));
                    f.insert(b"path".to_vec(), Value::List(vec![
                        Value::Bytes(b"track2.flac".to_vec()),
                    ]));
                    f
                }),
            ]));
            d
        });
        let bytes = bencode::encode(&info);
        let files = parse_info_dict(&bytes).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].0, "album/track1.flac");
        assert_eq!(files[1].1, 768);
    }

    #[test]
    fn init_inbox_creates_marker_and_processed_dir() {
        let dir = tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        init_inbox(&inbox).unwrap();
        assert!(inbox.join(INBOX_MARKER).exists());
        assert!(inbox.join(PROCESSED_DIR).is_dir());
    }

    #[test]
    fn format_bytes_human_readable() {
        assert_eq!(format_bytes(500), "500 bytes");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn safety_opts_default_is_100mib() {
        let opts = DownloadSafetyOpts::default();
        assert_eq!(opts.max_total_bytes, 100 * 1024 * 1024);
        assert!(!opts.confirm_download);
    }

    #[test]
    fn validate_inbox_rejects_missing_marker() {
        let root = tempdir().unwrap();
        let inbox = root.path().join("inbox");
        let data = root.path().join("data");
        std::fs::create_dir_all(&inbox).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let err = validate_inbox_dir(&inbox, &data).unwrap_err().to_string();
        assert!(err.contains(INBOX_MARKER));
    }

    #[test]
    fn scan_new_inbox_ignores_symlinks_and_processed_dir() {
        let root = tempdir().unwrap();
        let inbox = root.path().join("inbox");
        init_inbox(&inbox).unwrap();
        let file = inbox.join("hello.txt");
        std::fs::write(&file, b"hello").unwrap();
        std::fs::create_dir_all(inbox.join("nested")).unwrap();

        #[cfg(windows)]
        {
            let _ = std::os::windows::fs::symlink_file(&file, inbox.join("hello-link.txt"));
        }
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&file, inbox.join("hello-link.txt"));
        }

        let mut seen = seed_seen_files(&inbox).unwrap();
        assert!(seen.contains(&file));

        let later = inbox.join("later.bin");
        std::fs::write(&later, b"world").unwrap();
        let new_files = scan_new_inbox_files(&inbox, &mut seen).unwrap();
        assert_eq!(new_files, vec![later]);
    }
}
