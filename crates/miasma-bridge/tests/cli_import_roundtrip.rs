//! Real cross-process round trip through the compiled `miasma-bridge` binary.
//!
//! Everything else in this crate is a synthetic unit test: bencode round trips,
//! magnet string parsing, argument parsing. Nothing had ever moved a byte over
//! an actual BitTorrent connection, which is why the desktop app's Import
//! Magnet / Import Torrent File buttons could be broken for their entire
//! existence without a single test noticing.
//!
//! This test closes that hole end to end, on loopback only:
//!
//! ```text
//!   in-process librqbit seeder  ──BitTorrent/TCP──►  miasma-bridge.exe
//!        (holds payload.bin)                          (real subprocess)
//!             ▲                                              │
//!             │ compact peer address                         │ dissolve
//!             │                                              ▼
//!      stub HTTP tracker  ◄──announce──                 local share store
//!                                                            │
//!                                                            ▼
//!                                              MID on stdout == MID of the
//!                                              original bytes
//! ```
//!
//! The MID is a content address, so asserting that the bridge printed the MID
//! of the *original* payload proves the exact bytes made it across the wire,
//! through dissolution, and into the store — not merely that the process exited
//! zero.
//!
//! Peer discovery goes through a stub HTTP tracker rather than the public DHT:
//! that keeps the test hermetic (no outbound traffic is required for it to
//! pass) while still exercising librqbit's real announce path, which is how the
//! trackers in a user's magnet actually get used.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use librqbit::{
    create_torrent, AddTorrent, AddTorrentOptions, CreateTorrentOptions, Session, SessionOptions,
};
use miasma_core::pipeline::{dissolve, DissolutionParams};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How long the bridge subprocess gets to finish the whole download +
/// dissolve cycle before the test gives up on it.
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(120);

/// Payload size — several pieces' worth, so this is a real multi-piece
/// transfer rather than a single-block special case.
const PAYLOAD_LEN: usize = 200 * 1024;
const PIECE_LEN: u32 = 32 * 1024;

// ─── Test 1: `--magnet` (desktop's Import Magnet) ────────────────────────────

/// The desktop app spawns `miasma-bridge.exe --magnet <uri> --data-dir <dir>`.
/// The dispatcher used to reject that with `Unknown command`, so this path had
/// never once run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn magnet_flag_downloads_and_dissolves() {
    let fx = Fixture::start().await;

    let magnet = format!(
        "magnet:?xt=urn:btih:{}&dn=payload.bin&tr={}",
        fx.info_hash_hex,
        urlencode(&fx.tracker_url)
    );

    let out = fx.run_bridge(&["--magnet", &magnet]).await;
    assert_bridge_produced_payload_mid(&out, &fx);
}

// ─── Test 2: `--torrent` (desktop's Import Torrent File) ─────────────────────

/// Same for `miasma-bridge.exe --torrent <path> --data-dir <dir>`. This path
/// additionally had no implementation at all behind it: `download_torrent_file`
/// existed but was marked `#[allow(dead_code)]` because nothing called it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn torrent_file_flag_downloads_and_dissolves() {
    let fx = Fixture::start().await;

    let torrent_path = fx.torrent_path.to_string_lossy().to_string();
    let out = fx.run_bridge(&["--torrent", &torrent_path]).await;
    assert_bridge_produced_payload_mid(&out, &fx);
}

// ─── Test 3: positional `.torrent` argument ──────────────────────────────────

/// `miasma-bridge dissolve <path.torrent>` — the same source kind reached
/// through the documented subcommand rather than the desktop's flag form.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dissolve_accepts_a_positional_torrent_file() {
    let fx = Fixture::start().await;

    let torrent_path = fx.torrent_path.to_string_lossy().to_string();
    let out = fx.run_bridge(&["dissolve", &torrent_path]).await;
    assert_bridge_produced_payload_mid(&out, &fx);
}

// ─── Assertions ──────────────────────────────────────────────────────────────

fn assert_bridge_produced_payload_mid(out: &BridgeOutput, fx: &Fixture) {
    assert!(
        out.status_success,
        "bridge exited with failure\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.stdout, out.stderr
    );

    // Parse exactly the way miasma-desktop's worker does: trim first, then
    // test the scheme. The bridge indents MIDs under its stage heading.
    let mids: Vec<&str> = out
        .stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("miasma:"))
        .collect();

    assert_eq!(
        mids,
        vec![fx.expected_mid.as_str()],
        "bridge did not report the MID of the payload it was supposed to fetch\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        out.stdout,
        out.stderr
    );

    // The shares really landed on disk in the data dir we handed the bridge.
    let store_dir = fx.data_dir.join("shares");
    assert!(
        store_dir.is_dir(),
        "no share store was created under {}",
        fx.data_dir.display()
    );
    let share_count = std::fs::read_dir(&store_dir)
        .expect("read share dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .count();
    assert!(
        share_count >= DissolutionParams::default().total_shards,
        "expected at least {} share files in {}, found {share_count}",
        DissolutionParams::default().total_shards,
        store_dir.display()
    );
}

// ─── Fixture ─────────────────────────────────────────────────────────────────

struct Fixture {
    /// Kept alive so the temp tree outlives the test body.
    _tmp: tempfile::TempDir,
    data_dir: PathBuf,
    torrent_path: PathBuf,
    info_hash_hex: String,
    tracker_url: String,
    expected_mid: String,
    /// Seeder session; stopped in `Drop` order along with the rest.
    _seeder: std::sync::Arc<Session>,
    _tracker: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn start() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let seed_dir = tmp.path().join("seed");
        let data_dir = tmp.path().join("node");
        std::fs::create_dir_all(&seed_dir).expect("create seed dir");
        std::fs::create_dir_all(&data_dir).expect("create data dir");

        // ── Payload ─────────────────────────────────────────────────────────
        let payload = deterministic_payload(PAYLOAD_LEN);
        let payload_path = seed_dir.join("payload.bin");
        std::fs::write(&payload_path, &payload).expect("write payload");

        // The MID the bridge must arrive at, computed from the original bytes.
        let (expected_mid, _) =
            dissolve(&payload, DissolutionParams::default()).expect("dissolve payload locally");
        let expected_mid = expected_mid.to_string();

        // ── Torrent metadata ────────────────────────────────────────────────
        let created = create_torrent(
            &payload_path,
            CreateTorrentOptions {
                name: Some("payload.bin"),
                piece_length: Some(PIECE_LEN),
            },
        )
        .await
        .expect("create torrent");
        let info_hash_hex = hex::encode(created.info_hash().0);
        let bare_torrent = created.as_bytes().expect("serialize torrent").to_vec();

        // ── Seeder ──────────────────────────────────────────────────────────
        // DHT off: this side only ever needs to accept the one inbound
        // connection the tracker points at it.
        let listen_from = probe_free_port();
        let seeder = Session::new_with_opts(
            seed_dir.clone(),
            SessionOptions {
                disable_dht: true,
                disable_dht_persistence: true,
                listen_port_range: Some(listen_from..listen_from + 50),
                ..Default::default()
            },
        )
        .await
        .expect("start seeder session");

        let handle = seeder
            .add_torrent(
                AddTorrent::from_bytes(bare_torrent.clone()),
                Some(AddTorrentOptions {
                    overwrite: true,
                    ..Default::default()
                }),
            )
            .await
            .expect("seeder add_torrent")
            .into_handle()
            .expect("seeder torrent handle");

        // The payload is already on disk, so this is just a hash check.
        tokio::time::timeout(Duration::from_secs(60), handle.wait_until_completed())
            .await
            .expect("seeder did not finish checking the payload in time")
            .expect("seeder completion");

        let seed_port = seeder
            .tcp_listen_port()
            .expect("seeder should be listening for peers");
        let seed_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, seed_port));

        // ── Stub tracker ────────────────────────────────────────────────────
        let (tracker_port, tracker) = spawn_stub_tracker(seed_addr).await;
        let tracker_url = format!("http://127.0.0.1:{tracker_port}/announce");

        // ── .torrent file carrying that tracker ─────────────────────────────
        let torrent_path = tmp.path().join("payload.torrent");
        std::fs::write(
            &torrent_path,
            with_announce(&bare_torrent, &tracker_url).expect("splice announce"),
        )
        .expect("write .torrent");

        Self {
            _tmp: tmp,
            data_dir,
            torrent_path,
            info_hash_hex,
            tracker_url,
            expected_mid,
            _seeder: seeder,
            _tracker: tracker,
        }
    }

    /// Run the real compiled binary with `--data-dir` pointed at this fixture.
    async fn run_bridge(&self, args: &[&str]) -> BridgeOutput {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_miasma-bridge"));
        cmd.args(args)
            .arg("--data-dir")
            .arg(&self.data_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env("RUST_LOG", "miasma_bridge=debug")
            .kill_on_drop(true);

        // librqbit talks to the tracker through reqwest, which honours the
        // ambient proxy environment. A corporate proxy would swallow the
        // loopback announce, so strip it for the child.
        for var in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            cmd.env_remove(var);
        }
        cmd.env("NO_PROXY", "127.0.0.1,localhost");

        let child = cmd.spawn().expect("spawn miasma-bridge");
        let output = tokio::time::timeout(BRIDGE_TIMEOUT, child.wait_with_output())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "miasma-bridge {args:?} did not finish within {}s",
                    BRIDGE_TIMEOUT.as_secs()
                )
            })
            .expect("collect bridge output");

        BridgeOutput {
            status_success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

struct BridgeOutput {
    status_success: bool,
    stdout: String,
    stderr: String,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Reproducible pseudo-random bytes — a constant-filled payload would compress
/// into a single trivial piece pattern and prove less about the transfer.
fn deterministic_payload(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u64 = 0x5DEE_CE66_D000_0001;
    while out.len() < len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Insert an `announce` key into a serialized .torrent.
///
/// `librqbit::create_torrent` omits `announce` entirely (it serializes `None`
/// as absent), so the bencoded root dict starts straight at `4:info`.
/// `"announce"` sorts before every other key a .torrent carries, so prepending
/// it keeps the dict correctly ordered.
fn with_announce(torrent: &[u8], announce_url: &str) -> Option<Vec<u8>> {
    if torrent.first() != Some(&b'd') {
        return None;
    }
    let mut out = Vec::with_capacity(torrent.len() + announce_url.len() + 24);
    out.push(b'd');
    out.extend_from_slice(b"8:announce");
    out.extend_from_slice(format!("{}:", announce_url.len()).as_bytes());
    out.extend_from_slice(announce_url.as_bytes());
    out.extend_from_slice(&torrent[1..]);
    Some(out)
}

/// Percent-encode a tracker URL for use in a magnet's `tr=` parameter.
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Ask the OS for a port, then hand it back — librqbit takes a range and picks
/// the first one it can bind, so a momentarily-stale hint is harmless.
fn probe_free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("probe port")
        .local_addr()
        .expect("probe addr")
        .port()
}

/// A tracker that knows exactly one peer and announces it to anyone who asks.
///
/// Returns the port it bound and the task serving it.
async fn spawn_stub_tracker(peer: SocketAddr) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind stub tracker");
    let port = listener.local_addr().expect("tracker addr").port();
    let body = announce_response(peer);

    let task = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                // Drain the request line/headers. The answer does not depend on
                // them, but reading avoids resetting the client's connection.
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;

                let head = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            });
        }
    });

    (port, task)
}

/// Bencoded BEP-3 announce response with one compact peer.
fn announce_response(peer: SocketAddr) -> Vec<u8> {
    let v4 = match peer {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => panic!("stub tracker is IPv4-only"),
    };

    let mut out = Vec::new();
    // Keys in sorted order: complete, incomplete, interval, peers.
    out.extend_from_slice(b"d8:completei1e10:incompletei0e8:intervali60e5:peers6:");
    out.extend_from_slice(&v4.ip().octets());
    out.extend_from_slice(&v4.port().to_be_bytes());
    out.push(b'e');
    out
}
