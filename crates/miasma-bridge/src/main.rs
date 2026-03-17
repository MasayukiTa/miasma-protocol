/// miasma-bridge CLI — BitTorrent ↔ Miasma bridge (Phase 2, Task 15).
///
/// # Usage
/// ```text
/// # Dissolve a torrent's files into Miasma (DHT + peer-wire download):
/// miasma-bridge dissolve \
///   --data-dir ~/.miasma \
///   "magnet:?xt=urn:btih:aabb...&dn=example"
///
/// # Retrieve a MID and re-seed it as a torrent (Phase 2 stub):
/// miasma-bridge retrieve \
///   --data-dir ~/.miasma \
///   "miasma:<base58>"
///
/// # Start the bridge daemon (watches a directory for new files):
/// miasma-bridge daemon \
///   --data-dir ~/.miasma \
///   --quota 100G \
///   --watch-dir ~/Downloads
/// ```
#[allow(dead_code)]
mod index;
mod bencode;
mod bridge;
mod pipeline;

use std::path::PathBuf;

use tracing::{error, info};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "miasma_bridge=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "dissolve"    => cmd_dissolve(&args[2..]),
        "retrieve"    => cmd_retrieve(&args[2..]),
        "daemon"      => cmd_daemon(&args[2..]),
        "--help" | "-h" => print_usage(),
        other => {
            eprintln!("Unknown command: {other}");
            print_usage();
            std::process::exit(1);
        }
    }
}

// ─── Commands ─────────────────────────────────────────────────────────────────

fn cmd_dissolve(args: &[String]) {
    let (data_dir, rest) = parse_data_dir(args);
    if rest.is_empty() {
        eprintln!("Usage: miasma-bridge dissolve --data-dir <dir> <magnet-uri>");
        std::process::exit(1);
    }
    let magnet = &rest[0];

    let info = match pipeline::MagnetInfo::parse(magnet) {
        Ok(i) => i,
        Err(e) => {
            error!("Failed to parse magnet link: {e}");
            std::process::exit(1);
        }
    };

    let ih_hex = hex::encode(info.info_hash);
    let name = info.display_name.as_deref().unwrap_or("unknown");
    info!("Dissolving torrent: hash={ih_hex}, name={name}");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let quota_mb = parse_quota_mb_from_args(args);

    match rt.block_on(bridge::dissolve_torrent(
        &info.info_hash,
        info.display_name.as_deref(),
        &data_dir,
        quota_mb,
    )) {
        Ok(mids) => {
            println!("Dissolved {} file(s):", mids.len());
            for mid in &mids {
                println!("  {mid}");
            }
        }
        Err(e) => {
            error!("Dissolution failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_retrieve(args: &[String]) {
    let (data_dir, rest) = parse_data_dir(args);
    if rest.is_empty() {
        eprintln!("Usage: miasma-bridge retrieve --data-dir <dir> <MID>");
        std::process::exit(1);
    }
    let mid = &rest[0];
    info!(
        "Retrieve stub: would fetch {mid} from Miasma and re-seed as torrent (data_dir={}).",
        data_dir.display()
    );
    println!("Phase 2 stub: retrieve {mid} from Miasma.");
}

fn cmd_daemon(args: &[String]) {
    let (data_dir, rest) = parse_data_dir(args);
    let watch_dir = rest.windows(2)
        .find(|w| w[0] == "--watch-dir")
        .map(|w| PathBuf::from(&w[1]));
    let quota_mb = parse_quota_mb_from_args(args);

    let watch_dir = match watch_dir {
        Some(d) => d,
        None => {
            eprintln!("Usage: miasma-bridge daemon --watch-dir <dir> [--quota 100G]");
            std::process::exit(1);
        }
    };

    info!(
        "Bridge daemon: data_dir={}, quota={}M, watch={}",
        data_dir.display(), quota_mb, watch_dir.display()
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    if let Err(e) = rt.block_on(bridge::watch_and_dissolve(&watch_dir, &data_dir, quota_mb)) {
        error!("Daemon error: {e}");
        std::process::exit(1);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn parse_data_dir(args: &[String]) -> (PathBuf, Vec<String>) {
    let default_dir = directories::ProjectDirs::from("dev", "miasma", "miasma")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".miasma"));

    let mut data_dir = default_dir;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--data-dir" && i + 1 < args.len() {
            data_dir = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    (data_dir, rest)
}

fn parse_quota_mb_from_args(args: &[String]) -> u64 {
    args.windows(2)
        .find(|w| w[0] == "--quota")
        .map(|w| parse_size_mb(&w[1]))
        .unwrap_or(102_400) // 100 GiB default
}

fn parse_size_mb(s: &str) -> u64 {
    if let Some(g) = s.strip_suffix('G').or_else(|| s.strip_suffix("GB")) {
        return g.parse::<u64>().unwrap_or(100) * 1024;
    }
    if let Some(m) = s.strip_suffix('M').or_else(|| s.strip_suffix("MB")) {
        return m.parse::<u64>().unwrap_or(102400);
    }
    s.parse::<u64>().unwrap_or(102400)
}

fn print_usage() {
    println!(concat!(
        "miasma-bridge — BitTorrent ↔ Miasma bridge\n",
        "\n",
        "Commands:\n",
        "  dissolve  Dissolve a torrent's files into Miasma\n",
        "            (uses DHT peer discovery + BT peer wire protocol)\n",
        "  retrieve  Retrieve a MID and re-seed as torrent [Phase 2 stub]\n",
        "  daemon    Watch a directory for new files and auto-dissolve them\n",
        "\n",
        "Options:\n",
        "  --data-dir <dir>    Node data directory\n",
        "  --quota <size>      Storage quota (e.g. 100G, 512M)\n",
        "  --watch-dir <dir>   Directory to watch for new files (daemon mode)\n",
        "\n",
        "Examples:\n",
        "  miasma-bridge dissolve \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge daemon --watch-dir C:\\\\Downloads\n",
    ));
}
