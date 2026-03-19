/// miasma-bridge CLI - BitTorrent <-> Miasma bridge.
///
/// Usage examples:
/// ```text
/// # Inspect a magnet via DHT + metadata only:
/// miasma-bridge inspect --data-dir ~/.miasma "magnet:?xt=urn:btih:..."
///
/// # Dissolve a torrent's files into Miasma:
/// miasma-bridge dissolve --data-dir ~/.miasma "magnet:?xt=urn:btih:..."
///
/// # Create a dedicated inbox approved for bridge daemon imports:
/// miasma-bridge init-inbox C:\MiasmaInbox
///
/// # Start the bridge daemon against that inbox:
/// miasma-bridge daemon --data-dir ~/.miasma --inbox-dir C:\MiasmaInbox
/// ```
#[allow(dead_code)]
mod index;
mod bencode;
mod bridge;
mod pipeline;

use std::path::PathBuf;

use tracing::{error, info, warn};

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
        "inspect" => cmd_inspect(&args[2..]),
        "dissolve" => cmd_dissolve(&args[2..]),
        "init-inbox" => cmd_init_inbox(&args[2..]),
        "retrieve" => cmd_retrieve(&args[2..]),
        "daemon" => cmd_daemon(&args[2..]),
        "--help" | "-h" => print_usage(),
        other => {
            eprintln!("Unknown command: {other}");
            print_usage();
            std::process::exit(1);
        }
    }
}

fn cmd_inspect(args: &[String]) {
    let (_data_dir, rest) = parse_data_dir(args);
    if rest.is_empty() {
        eprintln!("Usage: miasma-bridge inspect --data-dir <dir> <magnet-uri>");
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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    match rt.block_on(bridge::inspect_torrent(
        &info.info_hash,
        info.display_name.as_deref(),
    )) {
        Ok(report) => {
            println!("Magnet reachable on BitTorrent network");
            println!("  Info hash:    {}", report.info_hash_hex);
            println!(
                "  Display name: {}",
                report.display_name.as_deref().unwrap_or("unknown")
            );
            println!("  Peers found:  {}", report.peer_count);
            println!("  Files:        {}", report.files.len());
            println!("  Total bytes:  {}", report.total_bytes);
            for (name, size) in report.files {
                println!("    {size:>10}  {name}");
            }
        }
        Err(e) => {
            error!("Inspect failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_dissolve(args: &[String]) {
    let (data_dir, rest) = parse_data_dir(args);
    let magnet = rest.iter().find(|a| !a.starts_with("--"));
    let magnet = match magnet {
        Some(m) => m.clone(),
        None => {
            eprintln!(
                "Usage: miasma-bridge dissolve [--max-total-bytes <N>] [--confirm-download] <magnet-uri>"
            );
            std::process::exit(1);
        }
    };

    let info = match pipeline::MagnetInfo::parse(&magnet) {
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
    let safety_opts = parse_safety_opts(args);

    match rt.block_on(bridge::dissolve_torrent(
        &info.info_hash,
        info.display_name.as_deref(),
        &data_dir,
        quota_mb,
        &safety_opts,
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

fn cmd_init_inbox(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: miasma-bridge init-inbox <dir>");
        std::process::exit(1);
    }

    let dir = PathBuf::from(&args[0]);
    if let Err(e) = bridge::init_inbox(&dir) {
        error!("Failed to initialize inbox: {e}");
        std::process::exit(1);
    }

    println!("Initialized bridge inbox:");
    println!("  {}", dir.display());
    println!("Only files dropped into this directory will be auto-imported.");
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
    let inbox_dir = parse_inbox_dir(&rest);
    let quota_mb = parse_quota_mb_from_args(args);

    let inbox_dir = match inbox_dir {
        Some(dir) => dir,
        None => {
            eprintln!("Usage: miasma-bridge daemon --inbox-dir <dir> [--quota 100G]");
            std::process::exit(1);
        }
    };

    info!(
        "Bridge daemon: data_dir={}, quota={}M, inbox={}",
        data_dir.display(),
        quota_mb,
        inbox_dir.display()
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    if let Err(e) = rt.block_on(bridge::watch_and_dissolve(&inbox_dir, &data_dir, quota_mb)) {
        error!("Daemon error: {e}");
        std::process::exit(1);
    }
}

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

fn parse_inbox_dir(args: &[String]) -> Option<PathBuf> {
    let mut i = 0;
    while i + 1 < args.len() {
        if args[i] == "--inbox-dir" {
            return Some(PathBuf::from(&args[i + 1]));
        }
        if args[i] == "--watch-dir" {
            warn!("--watch-dir is deprecated; use --inbox-dir for a dedicated safe inbox");
            return Some(PathBuf::from(&args[i + 1]));
        }
        i += 1;
    }
    None
}

fn parse_quota_mb_from_args(args: &[String]) -> u64 {
    args.windows(2)
        .find(|w| w[0] == "--quota")
        .map(|w| parse_size_mb(&w[1]))
        .unwrap_or(102_400)
}

fn parse_safety_opts(args: &[String]) -> bridge::DownloadSafetyOpts {
    let mut opts = bridge::DownloadSafetyOpts::default();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--confirm-download" {
            opts.confirm_download = true;
        } else if args[i] == "--max-total-bytes" && i + 1 < args.len() {
            opts.max_total_bytes = parse_size_bytes(&args[i + 1]);
            i += 1;
        }
        i += 1;
    }
    opts
}

fn parse_size_bytes(s: &str) -> u64 {
    if let Some(g) = s.strip_suffix('G').or_else(|| s.strip_suffix("GiB")) {
        return g.parse::<u64>().unwrap_or(100) * 1024 * 1024 * 1024;
    }
    if let Some(m) = s.strip_suffix('M').or_else(|| s.strip_suffix("MiB")) {
        return m.parse::<u64>().unwrap_or(100) * 1024 * 1024;
    }
    if let Some(k) = s.strip_suffix('K').or_else(|| s.strip_suffix("KiB")) {
        return k.parse::<u64>().unwrap_or(100) * 1024;
    }
    s.parse::<u64>().unwrap_or(100 * 1024 * 1024)
}

fn parse_size_mb(s: &str) -> u64 {
    if let Some(g) = s.strip_suffix('G').or_else(|| s.strip_suffix("GB")) {
        return g.parse::<u64>().unwrap_or(100) * 1024;
    }
    if let Some(m) = s.strip_suffix('M').or_else(|| s.strip_suffix("MB")) {
        return m.parse::<u64>().unwrap_or(102_400);
    }
    s.parse::<u64>().unwrap_or(102_400)
}

fn print_usage() {
    println!(concat!(
        "miasma-bridge - BitTorrent <-> Miasma bridge\n",
        "\n",
        "Commands:\n",
        "  inspect     Probe a magnet via DHT + metadata without downloading payload files\n",
        "  dissolve    Dissolve a torrent's files into Miasma (preflight size check)\n",
        "  init-inbox  Create a dedicated inbox approved for bridge daemon imports\n",
        "  retrieve    Retrieve a MID and re-seed as torrent [Phase 2 stub]\n",
        "  daemon      Watch a dedicated inbox for new files and auto-dissolve them\n",
        "\n",
        "Options:\n",
        "  --data-dir <dir>           Node data directory\n",
        "  --quota <size>             Storage quota (e.g. 100G, 512M)\n",
        "  --inbox-dir <dir>          Dedicated inbox directory to watch for new files\n",
        "  --max-total-bytes <size>   Safety limit for dissolve (default: 100M)\n",
        "  --confirm-download         Proceed even if torrent exceeds safety limit\n",
        "\n",
        "Examples:\n",
        "  miasma-bridge inspect \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge dissolve \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge dissolve --max-total-bytes 500M \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge dissolve --confirm-download \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge init-inbox C:\\\\MiasmaInbox\n",
        "  miasma-bridge daemon --inbox-dir C:\\\\MiasmaInbox\n",
    ));
}
