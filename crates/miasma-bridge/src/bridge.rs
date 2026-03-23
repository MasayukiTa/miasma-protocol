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
use crate::torrent::{MiasmaSession, TorrentConfig};

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

/// How the torrent metadata was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMethod {
    /// Peers found via UDP BEP-5 DHT, metadata via BEP-9 ut_metadata.
    Dht,
    /// Peers found via HTTP tracker announce, metadata via BEP-9 ut_metadata.
    HttpTracker,
    /// Metadata parsed from a .torrent file downloaded from the web.
    /// No peer connectivity was established — **payload transport is NOT proven**.
    TorrentFile { source: String },
}

impl std::fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dht => write!(f, "DHT (BEP-5 UDP)"),
            Self::HttpTracker => write!(f, "HTTP tracker announce"),
            Self::TorrentFile { source } => write!(f, ".torrent file ({source})"),
        }
    }
}

/// Per-strategy status from the discovery attempt.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryAttempts {
    pub dht: StrategyResult,
    pub http_tracker: StrategyResult,
    pub torrent_file: StrategyResult,
}

/// Outcome of a single discovery strategy.
#[derive(Debug, Clone, Default)]
pub enum StrategyResult {
    #[default]
    NotAttempted,
    Success {
        detail: String,
    },
    Failed {
        reason: String,
    },
}

impl std::fmt::Display for StrategyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAttempted => write!(f, "not attempted"),
            Self::Success { detail } => write!(f, "OK ({detail})"),
            Self::Failed { reason } => write!(f, "FAILED ({reason})"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TorrentInspection {
    pub info_hash_hex: String,
    pub display_name: Option<String>,
    pub peer_count: usize,
    pub files: Vec<(String, u64)>,
    pub total_bytes: u64,
    /// Which method successfully retrieved metadata.
    pub method: DiscoveryMethod,
    /// Status of each discovery strategy attempted.
    pub attempts: DiscoveryAttempts,
}

/// Safety and transport options for torrent downloads.
#[derive(Debug, Clone)]
pub struct DownloadSafetyOpts {
    /// Hard limit in bytes.  If the torrent's total payload exceeds this,
    /// the download is refused unless `confirm_download` is set.
    /// Default: 100 MiB.
    pub max_total_bytes: u64,
    /// When true, proceed even if the torrent exceeds `max_total_bytes`.
    pub confirm_download: bool,
    /// SOCKS5 proxy URL for all BT connections (e.g. "socks5://127.0.0.1:9050").
    pub proxy_url: Option<String>,
    /// Enable seeding after download completes. Default: false.
    pub seed_enabled: bool,
    /// Upload rate limit in bits/sec. 0 = unlimited.
    pub upload_rate_limit_bps: u32,
    /// Download rate limit in bits/sec. 0 = unlimited.
    pub download_rate_limit_bps: u32,
}

impl Default for DownloadSafetyOpts {
    fn default() -> Self {
        Self {
            max_total_bytes: 100 * 1024 * 1024, // 100 MiB
            confirm_download: false,
            proxy_url: None,
            seed_enabled: false,
            upload_rate_limit_bps: 0,
            download_rate_limit_bps: 0,
        }
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Dissolve a torrent identified by `info_hash` into Miasma.
///
/// Uses librqbit for full BT protocol download (multi-peer, choking, piece
/// selection), then dissolves each downloaded file into the local share store.
///
/// 1. Create librqbit session with safety limits.
/// 2. Download the torrent from the existing BT swarm.
/// 3. Dissolve each downloaded file into the local share store.
///
/// Returns the list of MID strings produced.
pub async fn dissolve_torrent(
    info_hash: &[u8; 20],
    display_name: Option<&str>,
    data_dir: &std::path::Path,
    quota_mb: u64,
    opts: &DownloadSafetyOpts,
) -> anyhow::Result<Vec<String>> {
    let store = Arc::new(LocalShareStore::open(data_dir, quota_mb).context("open share store")?);

    let ih_hex = hex::encode(info_hash);
    let name = display_name.unwrap_or("unknown");
    info!("Dissolving torrent {ih_hex} ({name}) via librqbit");

    // Build magnet URI from info_hash + display_name.
    let mut magnet = format!("magnet:?xt=urn:btih:{ih_hex}");
    if let Some(dn) = display_name {
        magnet.push_str("&dn=");
        magnet.push_str(&urlencoded(dn));
    }

    // Configure librqbit session with safety limits and transport options.
    let torrent_config = TorrentConfig {
        output_dir: data_dir.join("bridge-downloads"),
        seed_enabled: opts.seed_enabled,
        upload_rate_limit_bps: opts.upload_rate_limit_bps,
        download_rate_limit_bps: opts.download_rate_limit_bps,
        proxy_url: opts.proxy_url.clone(),
        max_total_bytes: if opts.confirm_download {
            0
        } else {
            opts.max_total_bytes
        },
        ..Default::default()
    };

    let session = MiasmaSession::new(torrent_config)
        .await
        .context("create librqbit session")?;

    // Download with progress logging.
    let result = session
        .download_magnet(
            &magnet,
            Some(|progress: crate::torrent::DownloadProgress| {
                if progress.total_bytes > 0 {
                    let pct =
                        (progress.downloaded_bytes as f64 / progress.total_bytes as f64) * 100.0;
                    info!(
                        "  {:.1}% ({}/{} bytes) peers={} speed={:.2} Mbps",
                        pct,
                        progress.downloaded_bytes,
                        progress.total_bytes,
                        progress.peers,
                        progress.download_speed_mbps,
                    );
                }
            }),
        )
        .await
        .context("librqbit download")?;

    info!(
        "Downloaded {} file(s), {} bytes total",
        result.files.len(),
        result.total_bytes
    );

    // Dissolve each downloaded file.
    let params = DissolutionParams::default();
    let mut mids = Vec::new();

    for file in &result.files {
        info!("  Dissolving {} ({} bytes)…", file.path, file.size);
        let data = tokio::fs::read(&file.disk_path)
            .await
            .with_context(|| format!("read downloaded file {}", file.disk_path.display()))?;

        match dissolve(&data, params) {
            Ok((mid, shares)) => {
                let mid_str = mid.to_string();
                for share in &shares {
                    store.put(share).context("store share")?;
                }
                info!("    -> {mid_str}");
                mids.push(mid_str);
            }
            Err(e) => warn!("Dissolution failed for {}: {e}", file.path),
        }
    }

    // Clean up session (stop seeding, release resources).
    session.shutdown().await;

    Ok(mids)
}

/// Simple URL encoding for display name in magnet URIs.
fn urlencoded(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

#[allow(dead_code)]
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
///
/// Uses a multi-strategy approach:
/// 1. **DHT** (UDP BEP-5) — works on open networks
/// 2. **HTTP tracker announce** — works when UDP is blocked but HTTP is open
/// 3. **.torrent download** — fetches .torrent from archive.org/web, works
///    even behind aggressive DPI that blocks all BT-specific traffic
pub async fn inspect_torrent(
    info_hash: &[u8; 20],
    display_name: Option<&str>,
) -> anyhow::Result<TorrentInspection> {
    let ih_hex = hex::encode(info_hash);
    let mut attempts = DiscoveryAttempts::default();

    // ── Strategy 1: DHT get_peers (UDP, best-case scenario) ─────────────
    let mut peers = Vec::new();
    match dht_get_peers(info_hash).await {
        Ok(p) if !p.is_empty() => {
            info!("DHT: found {} peers", p.len());
            attempts.dht = StrategyResult::Success {
                detail: format!("{} peers", p.len()),
            };
            peers = p;
        }
        Ok(_) => {
            info!("DHT: no peers found, trying HTTP tracker fallback");
            attempts.dht = StrategyResult::Failed {
                reason: "0 peers returned".into(),
            };
        }
        Err(e) => {
            info!("DHT failed ({e}), trying HTTP tracker fallback");
            attempts.dht = StrategyResult::Failed {
                reason: format!("{e:#}"),
            };
        }
    }

    // If DHT succeeded and we can fetch metadata, return early.
    if !peers.is_empty() {
        if let Ok(result) = try_metadata_from_peers(
            &ih_hex,
            display_name,
            &peers,
            info_hash,
            DiscoveryMethod::Dht,
            &attempts,
        )
        .await
        {
            return Ok(result);
        }
        // Metadata fetch failed despite having peers — record and continue.
        attempts.dht = StrategyResult::Failed {
            reason: format!("{} peers found but metadata fetch failed", peers.len()),
        };
        peers.clear();
    }

    // ── Strategy 2: HTTP tracker announce (TCP) ─────────────────────────
    match http_tracker_get_peers(info_hash).await {
        Ok(p) if !p.is_empty() => {
            info!("HTTP tracker: found {} peers", p.len());
            attempts.http_tracker = StrategyResult::Success {
                detail: format!("{} peers", p.len()),
            };
            peers = p;
        }
        Ok(_) => {
            info!("HTTP tracker: no peers returned");
            attempts.http_tracker = StrategyResult::Failed {
                reason: "0 peers from all trackers".into(),
            };
        }
        Err(e) => {
            info!("HTTP tracker failed: {e}");
            attempts.http_tracker = StrategyResult::Failed {
                reason: format!("{e:#}"),
            };
        }
    }

    if !peers.is_empty() {
        if let Ok(result) = try_metadata_from_peers(
            &ih_hex,
            display_name,
            &peers,
            info_hash,
            DiscoveryMethod::HttpTracker,
            &attempts,
        )
        .await
        {
            return Ok(result);
        }
        attempts.http_tracker = StrategyResult::Failed {
            reason: format!("{} peers found but metadata fetch failed", peers.len()),
        };
    }

    // ── Strategy 3: .torrent file from web (works behind aggressive DPI) ──
    info!("No peers via DHT/tracker. Trying .torrent download fallback...");
    match fetch_torrent_file_from_web(info_hash).await {
        Ok((torrent_bytes, source)) => {
            let files = parse_torrent_file_info(&torrent_bytes)?;
            let total_bytes = files.iter().map(|(_, size)| *size).sum();

            attempts.torrent_file = StrategyResult::Success {
                detail: format!("{} bytes from {source}", torrent_bytes.len()),
            };

            Ok(TorrentInspection {
                info_hash_hex: ih_hex,
                display_name: display_name.map(str::to_owned),
                peer_count: 0,
                files,
                total_bytes,
                method: DiscoveryMethod::TorrentFile { source },
                attempts,
            })
        }
        Err(e) => {
            attempts.torrent_file = StrategyResult::Failed {
                reason: format!("{e:#}"),
            };
            bail!(
                "All discovery methods failed for {ih_hex}.\n  \
                 DHT:          {}\n  \
                 HTTP tracker: {}\n  \
                 .torrent:     {}",
                attempts.dht,
                attempts.http_tracker,
                attempts.torrent_file,
            );
        }
    }
}

/// Helper: given discovered peers, try to fetch metadata and build a result.
async fn try_metadata_from_peers(
    ih_hex: &str,
    display_name: Option<&str>,
    peers: &[SocketAddr],
    info_hash: &[u8; 20],
    method: DiscoveryMethod,
    attempts: &DiscoveryAttempts,
) -> anyhow::Result<TorrentInspection> {
    let info_dict_bytes = fetch_info_dict_from_peers(peers, info_hash).await?;
    let files = parse_info_dict(&info_dict_bytes)?;
    let total_bytes = files.iter().map(|(_, size)| *size).sum();

    Ok(TorrentInspection {
        info_hash_hex: ih_hex.to_owned(),
        display_name: display_name.map(str::to_owned),
        peer_count: peers.len(),
        files,
        total_bytes,
        method,
        attempts: attempts.clone(),
    })
}

/// Initialize a dedicated bridge inbox directory with an explicit marker file.
pub fn init_inbox(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create inbox dir {}", dir.display()))?;
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

// ─── DHT ping (connectivity check) ──────────────────────────────────────────

/// Ping all DHT bootstrap nodes and return which ones responded.
/// This is a pure connectivity test — no info_hash needed.
pub async fn dht_ping() -> anyhow::Result<Vec<(String, SocketAddr, Vec<u8>)>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind UDP")?;
    let our_id = random_20_bytes();
    let tid = b"pn";

    let query = bencode::encode(&Value::Dict({
        let mut d = BTreeMap::new();
        d.insert(b"t".to_vec(), Value::Bytes(tid.to_vec()));
        d.insert(b"y".to_vec(), Value::Bytes(b"q".to_vec()));
        d.insert(b"q".to_vec(), Value::Bytes(b"ping".to_vec()));
        d.insert(
            b"a".to_vec(),
            Value::Dict({
                let mut a = BTreeMap::new();
                a.insert(b"id".to_vec(), Value::Bytes(our_id.to_vec()));
                a
            }),
        );
        d
    }));

    let mut results = Vec::new();
    let mut buf = vec![0u8; 4096];

    for node in DHT_BOOTSTRAP {
        let addrs: Vec<SocketAddr> = match node.to_socket_addrs() {
            Ok(a) => a.collect(),
            Err(e) => {
                info!("DNS {node}: {e}");
                continue;
            }
        };
        for addr in addrs {
            if let Err(e) = sock.send_to(&query, addr).await {
                info!("  ping UDP send to {addr}: {e}");
                continue;
            }
            match timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    // Parse response to extract remote node ID.
                    let node_id = if let Ok((v, _)) = bencode::decode(&buf[..n]) {
                        v.dict_get(b"r")
                            .and_then(|r| r.dict_get(b"id"))
                            .and_then(|id| id.as_bytes())
                            .map(|b| b.to_vec())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    results.push((node.to_string(), from, node_id));
                }
                Ok(Err(e)) => info!("  ping recv from {addr}: {e}"),
                Err(_) => info!("  ping timeout from {addr} (5s)"),
            }
        }
    }

    Ok(results)
}

// ─── Multi-strategy peer discovery ───────────────────────────────────────────

/// Discover peers using all available strategies.
#[allow(dead_code)]
async fn discover_peers(info_hash: &[u8; 20]) -> anyhow::Result<Vec<SocketAddr>> {
    // Strategy 1: DHT
    let mut peers = match dht_get_peers(info_hash).await {
        Ok(p) if !p.is_empty() => {
            info!("DHT: found {} peers", p.len());
            return Ok(p);
        }
        Ok(_) => {
            info!("DHT: no peers found, trying HTTP tracker fallback");
            Vec::new()
        }
        Err(e) => {
            info!("DHT failed ({e}), trying HTTP tracker fallback");
            Vec::new()
        }
    };

    // Strategy 2: HTTP tracker
    match http_tracker_get_peers(info_hash).await {
        Ok(p) if !p.is_empty() => {
            info!("HTTP tracker: found {} peers", p.len());
            peers = p;
        }
        Ok(_) => info!("HTTP tracker: no peers returned"),
        Err(e) => info!("HTTP tracker failed: {e}"),
    }

    Ok(peers)
}

// ─── DHT get_peers (iterative BEP-5 lookup) ─────────────────────────────────

/// Maximum iterations for iterative DHT lookup.
const DHT_MAX_ITERATIONS: usize = 10;
/// Maximum nodes to query per iteration (Kademlia alpha).
const DHT_ALPHA: usize = 8;
/// Per-iteration response collection timeout in seconds.
const DHT_QUERY_TIMEOUT_SECS: u64 = 4;

/// A DHT node with its ID (for XOR-distance sorting).
#[derive(Clone)]
struct DhtNode {
    id: [u8; 20],
    addr: SocketAddr,
}

/// XOR distance between two 20-byte keys.
fn xor_distance(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut d = [0u8; 20];
    for i in 0..20 {
        d[i] = a[i] ^ b[i];
    }
    d
}

/// Iterative BEP-5 get_peers lookup with XOR-distance sorting.
///
/// 1. Query bootstrap nodes with `get_peers(info_hash)`
/// 2. Bootstrap nodes return `nodes` (compact 26-byte entries: 20-byte id + 6-byte addr)
/// 3. Sort discovered nodes by XOR distance to info_hash
/// 4. Query the closest unqueried nodes
/// 5. Repeat until we find `values` (actual torrent peers) or exhaust iterations
async fn dht_get_peers(info_hash: &[u8; 20]) -> anyhow::Result<Vec<SocketAddr>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind UDP")?;
    let our_id = random_20_bytes();

    let mut peers: Vec<SocketAddr> = Vec::new();
    let mut queried: std::collections::HashSet<SocketAddr> = std::collections::HashSet::new();
    // Candidates sorted by XOR distance to info_hash.
    let mut candidates: Vec<DhtNode> = Vec::new();

    // Seed with bootstrap nodes (unknown node ID, use zeros — they'll be
    // queried first anyway since we have nothing better).
    for node in DHT_BOOTSTRAP {
        let addrs: Vec<SocketAddr> = match node.to_socket_addrs() {
            Ok(a) => a.collect(),
            Err(e) => {
                debug!("DNS {node}: {e}");
                continue;
            }
        };
        for addr in addrs {
            candidates.push(DhtNode {
                id: [0u8; 20],
                addr,
            });
        }
    }

    let mut buf = vec![0u8; 4096];
    let mut tid_counter: u16 = 0;

    for iteration in 0..DHT_MAX_ITERATIONS {
        // Sort candidates by XOR distance to info_hash (closest first).
        candidates
            .sort_by(|a, b| xor_distance(&a.id, info_hash).cmp(&xor_distance(&b.id, info_hash)));

        // Pick up to ALPHA closest nodes we haven't queried yet.
        let batch: Vec<DhtNode> = candidates
            .iter()
            .filter(|n| !queried.contains(&n.addr))
            .take(DHT_ALPHA)
            .cloned()
            .collect();

        if batch.is_empty() {
            debug!("DHT iteration {iteration}: all candidates already queried");
            break;
        }

        debug!(
            "DHT iteration {iteration}: querying {} nodes (total queried={}, peers={}, candidates={})",
            batch.len(),
            queried.len(),
            peers.len(),
            candidates.len()
        );

        // Send get_peers to all batch nodes.
        for node in &batch {
            queried.insert(node.addr);
            tid_counter = tid_counter.wrapping_add(1);
            let tid = tid_counter.to_be_bytes();

            let query = bencode::encode(&Value::Dict({
                let mut d = BTreeMap::new();
                d.insert(b"t".to_vec(), Value::Bytes(tid.to_vec()));
                d.insert(b"y".to_vec(), Value::Bytes(b"q".to_vec()));
                d.insert(b"q".to_vec(), Value::Bytes(b"get_peers".to_vec()));
                d.insert(
                    b"a".to_vec(),
                    Value::Dict({
                        let mut a = BTreeMap::new();
                        a.insert(b"id".to_vec(), Value::Bytes(our_id.to_vec()));
                        a.insert(b"info_hash".to_vec(), Value::Bytes(info_hash.to_vec()));
                        a
                    }),
                );
                d
            }));

            if let Err(e) = sock.send_to(&query, node.addr).await {
                debug!("  UDP send to {}: {e}", node.addr);
            }
        }

        // Collect responses (wait for all with a deadline).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(DHT_QUERY_TIMEOUT_SECS);
        let mut responses = 0;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    responses += 1;
                    let (found_peers, found_nodes) = parse_get_peers_response_with_ids(&buf[..n]);

                    if !found_peers.is_empty() {
                        debug!("  got {} peers from {from}", found_peers.len());
                        peers.extend(&found_peers);
                    }
                    if !found_nodes.is_empty() {
                        debug!("  got {} closer nodes from {from}", found_nodes.len());
                        // Add new candidates (dedup by addr).
                        for node in found_nodes {
                            if !candidates.iter().any(|c| c.addr == node.addr) {
                                candidates.push(node);
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    // On Windows, ICMP port-unreachable triggers WSAECONNRESET
                    // (os error 10054) on the UDP socket. This is harmless —
                    // just means one node was unreachable. Continue collecting.
                    debug!("  UDP recv error (continuing): {e}");
                }
                Err(_) => break, // deadline
            }
        }

        info!(
            "DHT iteration {}: {} responses, {} peers, {} candidates remaining",
            iteration,
            responses,
            peers.len(),
            candidates
                .iter()
                .filter(|n| !queried.contains(&n.addr))
                .count()
        );

        // If we found enough peers, stop.
        if peers.len() >= 30 {
            break;
        }
    }

    // Deduplicate peers.
    peers.sort();
    peers.dedup();

    Ok(peers)
}

/// Parse a DHT `get_peers` response, returning (values_peers, closer_nodes).
///
/// BEP-5 response contains either:
///  - `r.values`: list of compact 6-byte peer addresses (peers with the torrent)
///  - `r.nodes`: compact 26-byte node info (20-byte id + 6-byte addr) for closer DHT nodes
///
/// A response may contain both.
///
/// Returns `DhtNode`s (with their 20-byte node IDs) so the caller can sort by
/// XOR distance.
fn parse_get_peers_response_with_ids(data: &[u8]) -> (Vec<SocketAddr>, Vec<DhtNode>) {
    let mut peers = Vec::new();
    let mut nodes = Vec::new();

    let (v, _) = match bencode::decode(data) {
        Ok(p) => p,
        Err(_) => return (peers, nodes),
    };

    let resp = match v.dict_get(b"r") {
        Some(r) => r,
        None => return (peers, nodes),
    };

    // Parse `values` — compact 6-byte peer addrs (peers that have the torrent).
    if let Some(values) = resp.dict_get(b"values") {
        if let Some(list) = values.as_list() {
            for item in list {
                if let Some(bytes) = item.as_bytes() {
                    if let Some(addr) = decode_compact_6(bytes) {
                        peers.push(addr);
                    }
                }
            }
        } else if let Some(bytes) = values.as_bytes() {
            for chunk in bytes.chunks_exact(6) {
                if let Some(addr) = decode_compact_6(chunk) {
                    peers.push(addr);
                }
            }
        }
    }

    // Parse `nodes` — compact 26-byte entries (20-byte node_id + 6-byte addr).
    // Bootstrap nodes return `nodes`, not `values`. We recursively query these
    // closer nodes, sorting by XOR distance to converge on the target.
    if let Some(nodes_val) = resp.dict_get(b"nodes") {
        if let Some(bytes) = nodes_val.as_bytes() {
            for chunk in bytes.chunks_exact(26) {
                let mut id = [0u8; 20];
                id.copy_from_slice(&chunk[..20]);
                if let Some(addr) = decode_compact_6(&chunk[20..26]) {
                    nodes.push(DhtNode { id, addr });
                }
            }
        }
    }

    (peers, nodes)
}

fn decode_compact_6(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < 6 {
        return None;
    }
    let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
    if port == 0 {
        return None;
    }
    Some(SocketAddr::from((ip, port)))
}

// ─── HTTP tracker fallback ────────────────────────────────────────────────────

/// Well-known HTTP/HTTPS trackers on standard ports.
/// These are tried as a fallback when UDP DHT is blocked.
const HTTP_TRACKERS: &[&str] = &[
    // archive.org tracker (port 6969, often blocked by DPI)
    "http://bt1.archive.org:6969/announce",
    "http://bt2.archive.org:6969/announce",
    // Common HTTP trackers on port 80/443
    "http://tracker.openbittorrent.com:80/announce",
    "http://tracker.opentrackr.org:1337/announce",
];

/// Try HTTP tracker announce to discover peers.
/// Sends a minimal BEP-3 HTTP tracker request.
async fn http_tracker_get_peers(info_hash: &[u8; 20]) -> anyhow::Result<Vec<SocketAddr>> {
    let mut all_peers = Vec::new();

    for tracker_url in HTTP_TRACKERS {
        match timeout(
            Duration::from_secs(8),
            http_tracker_announce(tracker_url, info_hash),
        )
        .await
        {
            Ok(Ok(peers)) => {
                info!("HTTP tracker {tracker_url}: {} peers", peers.len());
                all_peers.extend(peers);
                if all_peers.len() >= 30 {
                    break;
                }
            }
            Ok(Err(e)) => debug!("HTTP tracker {tracker_url}: {e}"),
            Err(_) => debug!("HTTP tracker {tracker_url}: timeout"),
        }
    }

    all_peers.sort();
    all_peers.dedup();
    Ok(all_peers)
}

/// Send a raw HTTP GET tracker announce via TCP.
/// We implement HTTP/1.1 manually to avoid depending on an HTTP client library.
async fn http_tracker_announce(
    tracker_url: &str,
    info_hash: &[u8; 20],
) -> anyhow::Result<Vec<SocketAddr>> {
    // Parse URL
    let url = tracker_url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// trackers supported"))?;
    let (host_port, path) = url
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid tracker URL"))?;
    let path = format!("/{path}");

    // Resolve host
    let addr: SocketAddr = host_port
        .to_socket_addrs()
        .context("DNS resolve")?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses for {host_port}"))?;

    // URL-encode info_hash
    let ih_encoded: String = info_hash.iter().map(|b| format!("%{b:02X}")).collect();
    let peer_id = "-MI0001-000000000000";

    let request = format!(
        "GET {path}?info_hash={ih_encoded}&peer_id={peer_id}&port=6881\
         &uploaded=0&downloaded=0&left=1&compact=1&numwant=50 HTTP/1.1\r\n\
         Host: {host_port}\r\nConnection: close\r\n\r\n"
    );

    let mut stream = TcpStream::connect(addr).await.context("TCP connect")?;
    stream
        .write_all(request.as_bytes())
        .await
        .context("send request")?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .context("read response")?;

    // Find the body after \r\n\r\n
    let body_start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(0);
    let body = &response[body_start..];

    // Parse bencoded tracker response
    let (resp, _) = bencode::decode(body).map_err(|e| anyhow::anyhow!("bencode: {e}"))?;

    // Check for error
    if let Some(err) = resp.dict_get(b"failure reason") {
        if let Some(msg) = err.as_bytes() {
            bail!("tracker: {}", String::from_utf8_lossy(msg));
        }
    }

    // Parse compact peers
    let mut peers = Vec::new();
    if let Some(peers_val) = resp.dict_get(b"peers") {
        if let Some(bytes) = peers_val.as_bytes() {
            // Compact format: 6 bytes per peer (4 IP + 2 port)
            for chunk in bytes.chunks_exact(6) {
                if let Some(addr) = decode_compact_6(chunk) {
                    peers.push(addr);
                }
            }
        }
    }

    Ok(peers)
}

// ─── .torrent file fallback ──────────────────────────────────────────────────

/// Attempt to download a .torrent file from well-known web sources.
/// This is the last resort when both DHT and HTTP trackers are blocked.
/// archive.org is often accessible even behind aggressive corporate firewalls.
/// Returns `(torrent_bytes, source_description)`.
async fn fetch_torrent_file_from_web(info_hash: &[u8; 20]) -> anyhow::Result<(Vec<u8>, String)> {
    let ih_hex = hex::encode(info_hash);
    info!("Trying to fetch .torrent file for {ih_hex} from web sources...");

    // Source 1: torrent cache sites (may be blocked by DPI)
    let cache_sources = [format!("https://itorrents.org/torrent/{ih_hex}.torrent")];

    for url in &cache_sources {
        match timeout(Duration::from_secs(15), https_get(url)).await {
            Ok(Ok(body)) if body.len() > 20 && body.starts_with(b"d") => {
                info!("Downloaded .torrent ({} bytes) from {url}", body.len());
                return Ok((body, url.clone()));
            }
            Ok(Ok(_)) => debug!(".torrent from {url}: not a valid torrent"),
            Ok(Err(e)) => debug!(".torrent from {url}: {e}"),
            Err(_) => debug!(".torrent from {url}: timeout"),
        }
    }

    // Source 2: archive.org — search by btih, then download the .torrent
    // archive.org is categorized as "education" by most firewalls, not "P2P"
    info!("Trying archive.org btih search...");
    match timeout(Duration::from_secs(15), archive_org_torrent(&ih_hex)).await {
        Ok(Ok(body)) => return Ok((body, "archive.org".into())),
        Ok(Err(e)) => debug!("archive.org: {e}"),
        Err(_) => debug!("archive.org: timeout"),
    }

    bail!("Could not download .torrent file from any web source")
}

/// Search archive.org for a torrent by info hash, then download its .torrent.
async fn archive_org_torrent(ih_hex: &str) -> anyhow::Result<Vec<u8>> {
    // Step 1: Search for the item by btih
    let search_url = format!(
        "https://archive.org/advancedsearch.php?q=btih%3A{ih_hex}&output=json&rows=1&fl[]=identifier"
    );
    let search_body = https_get(&search_url).await.context("archive.org search")?;

    // Parse JSON response to extract identifier
    let search_text = std::str::from_utf8(&search_body).context("search response not UTF-8")?;

    // Simple JSON extraction — find "identifier":"<value>"
    let identifier = search_text
        .find("\"identifier\":\"")
        .and_then(|start| {
            let rest = &search_text[start + 14..];
            rest.find('"').map(|end| &rest[..end])
        })
        .ok_or_else(|| anyhow::anyhow!("no archive.org item found for btih {ih_hex}"))?;

    info!("archive.org: found item '{identifier}' for btih {ih_hex}");

    // Step 2: Download the .torrent file
    let torrent_url =
        format!("https://archive.org/download/{identifier}/{identifier}_archive.torrent");
    let torrent_bytes = https_get(&torrent_url)
        .await
        .context("download .torrent from archive.org")?;

    if torrent_bytes.len() < 20 || !torrent_bytes.starts_with(b"d") {
        bail!("archive.org: downloaded file is not a valid .torrent");
    }

    info!(
        "Downloaded .torrent ({} bytes) from archive.org/{identifier}",
        torrent_bytes.len()
    );
    Ok(torrent_bytes)
}

/// Minimal HTTPS GET using raw TCP + rustls (if available) or falling back
/// to spawning curl as a subprocess.
async fn https_get(url: &str) -> anyhow::Result<Vec<u8>> {
    // Use curl subprocess — it handles TLS, redirects, and proxy settings
    // automatically, and is available on Windows 10+.
    let output = tokio::process::Command::new("curl")
        .args(["-skL", "--connect-timeout", "10", "-o", "-", url])
        .output()
        .await
        .context("spawn curl")?;

    if !output.status.success() {
        bail!("curl failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Check for GlobalProtect block pages
    if (output.stdout.starts_with(b"<html") || output.stdout.starts_with(b"<!DOCTYPE"))
        && output.stdout.windows(14).any(|w| w == b"Web Page Block")
    {
        bail!("blocked by firewall");
    }

    Ok(output.stdout)
}

/// Parse a full .torrent file (bencoded with outer `d` wrapper) to extract
/// the file list from the `info` dict.
fn parse_torrent_file_info(torrent_bytes: &[u8]) -> anyhow::Result<Vec<(String, u64)>> {
    let (torrent, _) =
        bencode::decode(torrent_bytes).map_err(|e| anyhow::anyhow!("bencode: {e}"))?;

    let info = torrent
        .dict_get(b"info")
        .ok_or_else(|| anyhow::anyhow!("missing info dict in .torrent"))?;

    // Re-encode the info dict so we can parse it with our existing function
    let info_bytes = bencode::encode(info);
    parse_info_dict(&info_bytes)
}

// ─── ut_metadata fetch ────────────────────────────────────────────────────────

/// Try peers until we successfully fetch the info dict.
///
/// Attempts up to 30 peers sequentially (with 8s timeout each) to keep total
/// wall-clock time reasonable while giving enough chances to hit a responsive
/// peer.
async fn fetch_info_dict_from_peers(
    peers: &[SocketAddr],
    info_hash: &[u8; 20],
) -> anyhow::Result<Vec<u8>> {
    for (i, &peer) in peers.iter().take(30).enumerate() {
        debug!(
            "Trying metadata from peer {}/{}: {peer}",
            i + 1,
            peers.len().min(30)
        );
        match timeout(Duration::from_secs(8), fetch_ut_metadata(peer, info_hash)).await {
            Ok(Ok(bytes)) => {
                info!("Got metadata ({} bytes) from {peer}", bytes.len());
                return Ok(bytes);
            }
            Ok(Err(e)) => debug!("Peer {peer} metadata fail: {e}"),
            Err(_) => debug!("Peer {peer} metadata timeout"),
        }
    }
    bail!("Could not fetch metadata from any of {} peers", peers.len())
}

/// Connect to a peer, do BT handshake + extension, then fetch ut_metadata.
async fn fetch_ut_metadata(peer: SocketAddr, info_hash: &[u8; 20]) -> anyhow::Result<Vec<u8>> {
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

    stream
        .write_all(&handshake)
        .await
        .context("send handshake")?;

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
        d.insert(
            b"m".to_vec(),
            Value::Dict({
                let mut m = BTreeMap::new();
                m.insert(b"ut_metadata".to_vec(), Value::Int(UT_METADATA_ID as i64));
                m
            }),
        );
        d
    }));

    send_msg(&mut stream, 20, &[0], &ext_hs_payload).await?;

    // Read extension handshake response.
    let (msg_id, payload) = recv_msg(&mut stream).await?;
    if msg_id != 20 {
        bail!("Expected ext handshake (20), got {msg_id}");
    }
    // payload[0] = 0 (handshake ext_id), rest is bencoded dict
    if payload.is_empty() {
        bail!("Empty ext handshake");
    }

    let (hs_dict, _) =
        bencode::decode(&payload[1..]).map_err(|e| anyhow::anyhow!("parse ext hs: {e}"))?;
    let peer_ut_meta_id = hs_dict
        .dict_get(b"m")
        .and_then(|m: &Value| m.dict_get(b"ut_metadata"))
        .and_then(|v: &Value| v.as_int())
        .ok_or_else(|| anyhow::anyhow!("Peer does not advertise ut_metadata"))?
        as u8;

    let metadata_size = hs_dict
        .dict_get(b"metadata_size")
        .and_then(|v: &Value| v.as_int())
        .unwrap_or(0) as usize;

    if metadata_size == 0 || metadata_size > 10 * 1024 * 1024 {
        bail!("Implausible metadata_size: {metadata_size}");
    }

    // ── Request metadata pieces (BEP-9) ─────────────────────────────────────
    let piece_size = 16_384usize;
    let num_pieces = metadata_size.div_ceil(piece_size);
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
        if msg_id != 20 || payload.is_empty() {
            continue;
        }
        if payload[0] != peer_ut_meta_id {
            continue;
        }

        // Decode the dict prefix to find piece index and data offset.
        let (dict, rest) = match bencode::decode(&payload[1..]) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let msg_type = dict
            .dict_get(b"msg_type")
            .and_then(|v| v.as_int())
            .unwrap_or(-1);
        let piece_idx = dict
            .dict_get(b"piece")
            .and_then(|v| v.as_int())
            .unwrap_or(-1) as usize;

        if msg_type != 1 || piece_idx >= num_pieces {
            continue;
        } // data = 1

        // `rest` is the raw metadata bytes for this piece (everything after
        // the bencoded dict in the extension payload).
        let piece_data = rest.to_vec();
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

        for entry in f
            .as_list()
            .ok_or_else(|| anyhow::anyhow!("files not a list"))?
        {
            let size = entry
                .dict_get(b"length")
                .and_then(|v| v.as_int())
                .ok_or_else(|| anyhow::anyhow!("file missing length"))?
                as u64;

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
        let size =
            info.dict_get(b"length")
                .and_then(|v| v.as_int())
                .ok_or_else(|| anyhow::anyhow!("missing length in info dict"))? as u64;
        files.push((name, size));
    }

    Ok(files)
}

// ─── File download (legacy, superseded by librqbit) ──────────────────────────

#[allow(dead_code)]
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
        .ok_or_else(|| anyhow::anyhow!("missing pieces"))?
        .to_owned();

    let num_pieces = (size as usize).div_ceil(piece_length);

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

#[allow(dead_code)]
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
    if &rbuf[1..20] != b"BitTorrent protocol" {
        bail!("Not a BT peer");
    }

    // Send interested + unchoke.
    send_msg(&mut stream, 2, &[], &[]).await?; // interested
                                               // Wait for unchoke (msg_id 1) or bitfield.
    for _ in 0..10 {
        let (msg_id, _) = recv_msg(&mut stream).await?;
        if msg_id == 1 {
            break;
        } // unchoke
        if msg_id == 5 {
            continue;
        } // bitfield — wait for unchoke
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
                if msg_id != 7 {
                    continue;
                } // piece = 7
                if payload.len() < 8 {
                    continue;
                }
                let recv_piece = u32::from_be_bytes(payload[0..4].try_into().unwrap()) as usize;
                let recv_begin = u32::from_be_bytes(payload[4..8].try_into().unwrap()) as usize;
                if recv_piece != piece_idx || recv_begin != offset {
                    continue;
                }
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

#[allow(dead_code)]
/// Verify pieces using SHA1 hashes from the info dict.
fn verify_pieces(data: &[u8], pieces_hash: &[u8], piece_length: usize) -> bool {
    if !pieces_hash.len().is_multiple_of(20) {
        return false;
    }
    let num_pieces = pieces_hash.len() / 20;

    for (i, expected) in pieces_hash.chunks(20).enumerate() {
        let start = i * piece_length;
        let end = (start + piece_length).min(data.len());
        if start >= data.len() {
            break;
        }
        let actual = sha1_of(&data[start..end]);
        if actual != expected {
            return false;
        }
    }
    let _ = num_pieces; // suppress warning
    true
}

#[allow(dead_code)]
fn sha1_of(data: &[u8]) -> [u8; 20] {
    // Minimal SHA1 — use the SHA-2 crate which is already a workspace dep.
    // SHA1 is NOT in sha2, so we implement a tiny wrapper here.
    // Note: sha1 is only used for verifying BT pieces, not for security.
    sha1_compress(data)
}

/// Minimal SHA1 (FIPS 180-4) — used only for BT piece verification.
#[allow(dead_code)]
fn sha1_compress(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Pad message.
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        #[allow(clippy::needless_range_loop)]
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, &val) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
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
    if len == 0 {
        return Ok((0, vec![]));
    } // keep-alive
    if len > 10 * 1024 * 1024 {
        bail!("Message too large: {len}");
    }

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

    let store = Arc::new(LocalShareStore::open(data_dir, quota_mb).context("open share store")?);
    let params = DissolutionParams::default();

    info!(
        "Bridge daemon watching {} for new files…",
        watch_dir.display()
    );
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
                            path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
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
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
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
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("imported");
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

    std::fs::rename(path, &dest)
        .or_else(|_| {
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
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(sha1_compress(&[]), expected);
    }

    #[test]
    fn sha1_abc() {
        // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
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
            d.insert(
                b"files".to_vec(),
                Value::List(vec![
                    Value::Dict({
                        let mut f = BTreeMap::new();
                        f.insert(b"length".to_vec(), Value::Int(512));
                        f.insert(
                            b"path".to_vec(),
                            Value::List(vec![Value::Bytes(b"track1.flac".to_vec())]),
                        );
                        f
                    }),
                    Value::Dict({
                        let mut f = BTreeMap::new();
                        f.insert(b"length".to_vec(), Value::Int(768));
                        f.insert(
                            b"path".to_vec(),
                            Value::List(vec![Value::Bytes(b"track2.flac".to_vec())]),
                        );
                        f
                    }),
                ]),
            );
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

    // ── XOR distance ──────────────────────────────────────────────────────

    #[test]
    fn xor_distance_identity_is_zero() {
        let a = [0x08; 20];
        let d = xor_distance(&a, &a);
        assert_eq!(d, [0u8; 20]);
    }

    #[test]
    fn xor_distance_ordering() {
        let target = [
            0x08, 0xAD, 0xA5, 0xA7, 0xA6, 0x18, 0x3A, 0xAE, 0x1E, 0x09, 0xD8, 0x31, 0xDF, 0x67,
            0x48, 0xD5, 0x66, 0x09, 0x5A, 0x10,
        ];
        let close = [
            0x08, 0xAD, 0xA5, 0xA7, 0xA6, 0x18, 0x3A, 0xAE, 0x1E, 0x09, 0xD8, 0x31, 0xDF, 0x67,
            0x48, 0xD5, 0x66, 0x09, 0x5A, 0x11,
        ]; // differs in last bit
        let far = [
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let d_close = xor_distance(&close, &target);
        let d_far = xor_distance(&far, &target);
        assert!(d_close < d_far);
    }

    // ── get_peers response parsing ───────────────────────────────────────

    #[test]
    fn parse_get_peers_response_with_ids_parses_nodes() {
        // Build a mock BEP-5 response with r.nodes (26-byte compact entries).
        let mut nodes_bytes = Vec::new();
        // Node 1: id = [0x01; 20], addr = 10.0.0.1:6881
        nodes_bytes.extend_from_slice(&[0x01; 20]);
        nodes_bytes.extend_from_slice(&[10, 0, 0, 1]);
        nodes_bytes.extend_from_slice(&6881u16.to_be_bytes());
        // Node 2: id = [0x02; 20], addr = 10.0.0.2:51413
        nodes_bytes.extend_from_slice(&[0x02; 20]);
        nodes_bytes.extend_from_slice(&[10, 0, 0, 2]);
        nodes_bytes.extend_from_slice(&51413u16.to_be_bytes());

        let resp = Value::Dict({
            let mut d = BTreeMap::new();
            d.insert(b"t".to_vec(), Value::Bytes(b"ab".to_vec()));
            d.insert(b"y".to_vec(), Value::Bytes(b"r".to_vec()));
            d.insert(
                b"r".to_vec(),
                Value::Dict({
                    let mut r = BTreeMap::new();
                    r.insert(b"id".to_vec(), Value::Bytes(vec![0xAA; 20]));
                    r.insert(b"nodes".to_vec(), Value::Bytes(nodes_bytes));
                    r
                }),
            );
            d
        });

        let encoded = bencode::encode(&resp);
        let (peers, nodes) = parse_get_peers_response_with_ids(&encoded);
        assert!(peers.is_empty());
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].id, [0x01; 20]);
        assert_eq!(nodes[0].addr.port(), 6881);
        assert_eq!(nodes[1].id, [0x02; 20]);
        assert_eq!(nodes[1].addr.port(), 51413);
    }

    #[test]
    fn parse_get_peers_response_with_ids_parses_values() {
        // Build a BEP-5 response with r.values (list of 6-byte compact peers).
        let resp = Value::Dict({
            let mut d = BTreeMap::new();
            d.insert(b"t".to_vec(), Value::Bytes(b"ab".to_vec()));
            d.insert(b"y".to_vec(), Value::Bytes(b"r".to_vec()));
            d.insert(
                b"r".to_vec(),
                Value::Dict({
                    let mut r = BTreeMap::new();
                    r.insert(b"id".to_vec(), Value::Bytes(vec![0xBB; 20]));
                    r.insert(
                        b"values".to_vec(),
                        Value::List(vec![
                            // 192.168.1.1:8080
                            Value::Bytes(vec![192, 168, 1, 1, 0x1F, 0x90]),
                            // 10.0.0.5:6881
                            Value::Bytes(vec![10, 0, 0, 5, 0x1A, 0xE1]),
                        ]),
                    );
                    r
                }),
            );
            d
        });

        let encoded = bencode::encode(&resp);
        let (peers, nodes) = parse_get_peers_response_with_ids(&encoded);
        assert_eq!(peers.len(), 2);
        assert!(nodes.is_empty());
        assert_eq!(peers[0].port(), 8080);
        assert_eq!(peers[1].port(), 6881);
    }

    // ── .torrent file parsing ────────────────────────────────────────────

    #[test]
    fn parse_torrent_file_info_extracts_files() {
        // Build a minimal .torrent file (outer dict with "info" key).
        let torrent = Value::Dict({
            let mut d = BTreeMap::new();
            d.insert(
                b"announce".to_vec(),
                Value::Bytes(b"http://tracker.example.com/announce".to_vec()),
            );
            d.insert(
                b"info".to_vec(),
                Value::Dict({
                    let mut info = BTreeMap::new();
                    info.insert(b"name".to_vec(), Value::Bytes(b"movie".to_vec()));
                    info.insert(b"piece length".to_vec(), Value::Int(262144));
                    info.insert(b"pieces".to_vec(), Value::Bytes(vec![0u8; 40]));
                    info.insert(
                        b"files".to_vec(),
                        Value::List(vec![
                            Value::Dict({
                                let mut f = BTreeMap::new();
                                f.insert(b"length".to_vec(), Value::Int(1_000_000));
                                f.insert(
                                    b"path".to_vec(),
                                    Value::List(vec![Value::Bytes(b"video.mp4".to_vec())]),
                                );
                                f
                            }),
                            Value::Dict({
                                let mut f = BTreeMap::new();
                                f.insert(b"length".to_vec(), Value::Int(500));
                                f.insert(
                                    b"path".to_vec(),
                                    Value::List(vec![
                                        Value::Bytes(b"subs".to_vec()),
                                        Value::Bytes(b"en.srt".to_vec()),
                                    ]),
                                );
                                f
                            }),
                        ]),
                    );
                    info
                }),
            );
            d
        });

        let bytes = bencode::encode(&torrent);
        let files = parse_torrent_file_info(&bytes).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].0, "movie/video.mp4");
        assert_eq!(files[0].1, 1_000_000);
        assert_eq!(files[1].0, "movie/subs/en.srt");
        assert_eq!(files[1].1, 500);
    }

    #[test]
    fn parse_torrent_file_info_rejects_missing_info() {
        let torrent = Value::Dict({
            let mut d = BTreeMap::new();
            d.insert(
                b"announce".to_vec(),
                Value::Bytes(b"http://tracker.example.com/announce".to_vec()),
            );
            d
        });
        let bytes = bencode::encode(&torrent);
        assert!(parse_torrent_file_info(&bytes).is_err());
    }

    // ── HTTP tracker response parsing ────────────────────────────────────

    #[test]
    fn http_tracker_response_compact_peers() {
        // Simulate a tracker response with compact peers.
        let resp = Value::Dict({
            let mut d = BTreeMap::new();
            d.insert(b"interval".to_vec(), Value::Int(1800));
            // 2 peers: 1.2.3.4:80 + 5.6.7.8:443
            let mut peers_bytes = Vec::new();
            peers_bytes.extend_from_slice(&[1, 2, 3, 4, 0, 80]);
            peers_bytes.extend_from_slice(&[5, 6, 7, 8, 1, 0xBB]);
            d.insert(b"peers".to_vec(), Value::Bytes(peers_bytes));
            d
        });

        let body = bencode::encode(&resp);
        // Wrap in a fake HTTP response.
        let mut http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n".to_vec();
        http_resp.extend_from_slice(&body);

        // Parse body manually (same logic as http_tracker_announce)
        let body_start = http_resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .unwrap();
        let body = &http_resp[body_start..];
        let (parsed, _) = bencode::decode(body).unwrap();

        let mut peers = Vec::new();
        if let Some(peers_val) = parsed.dict_get(b"peers") {
            if let Some(bytes) = peers_val.as_bytes() {
                for chunk in bytes.chunks_exact(6) {
                    if let Some(addr) = decode_compact_6(chunk) {
                        peers.push(addr);
                    }
                }
            }
        }
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].port(), 80);
        assert_eq!(peers[1].port(), 443);
    }

    // ── Firewall block detection ─────────────────────────────────────────

    #[test]
    fn detect_firewall_block_page() {
        let block_page = b"<html>\r\n<head>\r\n<title>Web Page Blocked</title>";
        assert!(block_page.windows(14).any(|w| w == b"Web Page Block"));

        let normal_html = b"<html><head><title>Hello World</title></head></html>";
        assert!(!normal_html.windows(14).any(|w| w == b"Web Page Block"));
    }

    // ── Discovery types ──────────────────────────────────────────────────

    #[test]
    fn discovery_method_display() {
        assert_eq!(format!("{}", DiscoveryMethod::Dht), "DHT (BEP-5 UDP)");
        assert_eq!(
            format!(
                "{}",
                DiscoveryMethod::TorrentFile {
                    source: "archive.org".into()
                }
            ),
            ".torrent file (archive.org)"
        );
    }

    #[test]
    fn strategy_result_display() {
        let ok = StrategyResult::Success {
            detail: "42 peers".into(),
        };
        assert!(format!("{ok}").contains("42 peers"));

        let fail = StrategyResult::Failed {
            reason: "timeout".into(),
        };
        assert!(format!("{fail}").contains("FAILED"));
        assert!(format!("{fail}").contains("timeout"));

        let na = StrategyResult::NotAttempted;
        assert_eq!(format!("{na}"), "not attempted");
    }

    // ── scan_new_inbox ───────────────────────────────────────────────────

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
