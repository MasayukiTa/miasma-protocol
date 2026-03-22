mod bencode;
mod bridge;
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
mod pipeline;
mod torrent;

use std::path::PathBuf;

use tracing::{error, info, warn};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_daemon = args.get(1).map(|s| s.as_str()) == Some("daemon");

    // For daemon mode, set up file logging. For short-lived commands, stderr only.
    if is_daemon {
        let (data_dir, _) = parse_data_dir(if args.len() > 2 { &args[2..] } else { &[] });
        let _ = std::fs::create_dir_all(&data_dir);
        let file_appender = tracing_appender::rolling::daily(&data_dir, "bridge.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        {
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            let filter = tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| "miasma_bridge=info".parse().unwrap());
            let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
            let file_layer = tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false);
            tracing_subscriber::registry()
                .with(filter)
                .with(stderr_layer)
                .with(file_layer)
                .init();
        }
        std::mem::forget(_guard);
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "miasma_bridge=info".into()),
            )
            .init();
    }
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "dht-ping" => cmd_dht_ping(),
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

fn cmd_dht_ping() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    println!("Pinging DHT bootstrap nodes...");
    match rt.block_on(bridge::dht_ping()) {
        Ok(results) => {
            if results.is_empty() {
                println!("No responses. UDP 6881 may be blocked.");
                std::process::exit(1);
            }
            println!("{} node(s) responded:", results.len());
            for (name, addr, node_id) in &results {
                println!(
                    "  {} ({}) — node_id: {}",
                    name,
                    addr,
                    if node_id.is_empty() {
                        "(none)".to_string()
                    } else {
                        hex::encode(node_id)
                    }
                );
            }
            println!("DHT connectivity: OK");
        }
        Err(e) => {
            error!("DHT ping failed: {e}");
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
            println!("Torrent metadata retrieved");
            println!("  Info hash:    {}", report.info_hash_hex);
            println!(
                "  Display name: {}",
                report.display_name.as_deref().unwrap_or("unknown")
            );
            println!("  Method:       {}", report.method);
            println!("  Peers found:  {}", report.peer_count);
            println!("  Files:        {}", report.files.len());
            println!("  Total bytes:  {}", report.total_bytes);
            for (name, size) in &report.files {
                println!("    {size:>10}  {name}");
            }
            // Show discovery strategy results
            println!();
            println!("Discovery attempts:");
            println!("  DHT:          {}", report.attempts.dht);
            println!("  HTTP tracker: {}", report.attempts.http_tracker);
            println!("  .torrent:     {}", report.attempts.torrent_file);

            // Warn if metadata was obtained without peer connectivity
            if report.peer_count == 0 {
                println!();
                println!("NOTE: Metadata obtained from .torrent file, not from peers.");
                println!("      Payload download is NOT possible without peer connectivity.");
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
    let magnet = find_dissolve_magnet_arg(&rest);
    let magnet = match magnet {
        Some(m) => m.to_owned(),
        None => {
            eprintln!(
                "Usage: miasma-bridge dissolve [options] <magnet-uri>\n\
                 Options: --max-total-bytes <N> --confirm-download --proxy <url>\n\
                 \x20        --seed/--no-seed --upload-limit <bps> --download-limit <bps>"
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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let quota_mb = parse_quota_mb_from_args(args);
    let safety_opts = parse_safety_opts(args);

    // ── Stage 1: Preflight ──────────────────────────────────────────────
    println!("[1/3] Preflight check");
    println!("      Info hash:    {ih_hex}");
    println!("      Display name: {name}");
    println!("      Data dir:     {}", data_dir.display());
    println!(
        "      Size limit:   {}",
        if safety_opts.confirm_download {
            "unlimited (--confirm-download)".to_string()
        } else {
            format_bytes_human(safety_opts.max_total_bytes)
        }
    );
    if let Some(ref proxy) = safety_opts.proxy_url {
        println!("      Proxy:        {proxy}");
    } else {
        println!("      Proxy:        none (direct connection)");
    }
    println!(
        "      Seeding:      {}",
        if safety_opts.seed_enabled {
            "ENABLED — you will upload to peers after download"
        } else {
            "disabled (default)"
        }
    );
    if safety_opts.upload_rate_limit_bps > 0 {
        println!(
            "      Upload limit: {}",
            format_bytes_human(safety_opts.upload_rate_limit_bps as u64)
        );
    }
    if safety_opts.download_rate_limit_bps > 0 {
        println!(
            "      Down limit:   {}",
            format_bytes_human(safety_opts.download_rate_limit_bps as u64)
        );
    }
    println!();

    // ── Stage 2: Download ────────────────────────────────────────────────
    println!("[2/3] Downloading torrent...");
    info!("Dissolving torrent: hash={ih_hex}, name={name}");

    match rt.block_on(bridge::dissolve_torrent(
        &info.info_hash,
        info.display_name.as_deref(),
        &data_dir,
        quota_mb,
        &safety_opts,
    )) {
        Ok(mids) => {
            // ── Stage 3: Result ──────────────────────────────────────────
            println!();
            println!("[3/3] Dissolved {} file(s) into Miasma:", mids.len());
            for mid in &mids {
                println!("      {mid}");
            }
            println!();
            println!("Done. Use 'miasma get <MID>' to retrieve content.");
        }
        Err(e) => {
            println!();
            eprintln!("[3/3] FAILED: {e}");
            if format!("{e}").contains("too large") {
                eprintln!();
                eprintln!("The torrent exceeds the safety size limit.");
                eprintln!("To override, re-run with --confirm-download");
                eprintln!("or increase with --max-total-bytes <size>");
            }
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
    info!("Log file: {}/bridge.log.*", data_dir.display());

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
        match args[i].as_str() {
            "--confirm-download" => {
                opts.confirm_download = true;
            }
            "--max-total-bytes" if i + 1 < args.len() => {
                opts.max_total_bytes = parse_size_bytes(&args[i + 1]);
                i += 1;
            }
            "--proxy" if i + 1 < args.len() => {
                opts.proxy_url = Some(args[i + 1].clone());
                i += 1;
            }
            "--seed" => {
                opts.seed_enabled = true;
            }
            "--no-seed" => {
                opts.seed_enabled = false;
            }
            "--upload-limit" if i + 1 < args.len() => {
                opts.upload_rate_limit_bps = parse_size_bytes(&args[i + 1]) as u32;
                i += 1;
            }
            "--download-limit" if i + 1 < args.len() => {
                opts.download_rate_limit_bps = parse_size_bytes(&args[i + 1]) as u32;
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    opts
}

fn find_dissolve_magnet_arg<'a>(args: &'a [String]) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--confirm-download" | "--seed" | "--no-seed" => {
                i += 1;
            }
            "--max-total-bytes" | "--proxy" | "--upload-limit" | "--download-limit" => {
                i += 2;
            }
            other if !other.starts_with("--") => return Some(other),
            _ => i += 1,
        }
    }
    None
}

fn format_bytes_human(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
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
        "  dht-ping    Test UDP connectivity to DHT bootstrap nodes\n",
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
        "  --proxy <url>              SOCKS5 proxy for BT connections (e.g. socks5://127.0.0.1:9050)\n",
        "  --seed / --no-seed         Enable/disable seeding after download (default: no-seed)\n",
        "  --upload-limit <bps>       Upload rate limit (e.g. 1M, 500K). 0 = unlimited\n",
        "  --download-limit <bps>     Download rate limit (e.g. 10M, 1M). 0 = unlimited\n",
        "\n",
        "Examples:\n",
        "  miasma-bridge inspect \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge dissolve \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge dissolve --max-total-bytes 500M \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge dissolve --proxy socks5://127.0.0.1:9050 \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge dissolve --download-limit 5M --no-seed \"magnet:?xt=urn:btih:...\"\n",
        "  miasma-bridge init-inbox C:\\\\MiasmaInbox\n",
        "  miasma-bridge daemon --inbox-dir C:\\\\MiasmaInbox\n",
        "\n",
        "Safe defaults:\n",
        "  - Seeding is DISABLED by default (--no-seed). No data is uploaded.\n",
        "  - Download size limit: 100 MiB. Override with --max-total-bytes or --confirm-download.\n",
        "  - No proxy by default. Use --proxy for SOCKS5.\n",
        "  - Upload rate capped at 1 bps when seeding disabled (effectively zero upload).\n",
        "\n",
        "Validation with a small legal torrent:\n",
        "  1. Find a small (<10 MiB) Creative Commons torrent\n",
        "  2. miasma-bridge dissolve --max-total-bytes 10M \"magnet:?xt=urn:btih:<hash>\"\n",
        "  3. Verify: preflight shows size limit, download completes, MIDs printed\n",
        "  4. miasma get <MID> -o retrieved.file  (verify content matches)\n",
    ));
}

#[cfg(test)]
mod tests {
    use super::find_dissolve_magnet_arg;

    #[test]
    fn dissolve_magnet_arg_skips_flag_values() {
        let args = vec![
            "--max-total-bytes".to_string(),
            "500M".to_string(),
            "--proxy".to_string(),
            "socks5://127.0.0.1:9050".to_string(),
            "--seed".to_string(),
            "magnet:?xt=urn:btih:abcdef0123456789abcdef0123456789abcdef01".to_string(),
        ];

        let magnet = find_dissolve_magnet_arg(&args);
        assert_eq!(
            magnet,
            Some("magnet:?xt=urn:btih:abcdef0123456789abcdef0123456789abcdef01")
        );
    }

    #[test]
    fn dissolve_magnet_arg_returns_none_when_only_flags_are_present() {
        let args = vec![
            "--max-total-bytes".to_string(),
            "500M".to_string(),
            "--no-seed".to_string(),
            "--download-limit".to_string(),
            "1M".to_string(),
        ];

        assert_eq!(find_dissolve_magnet_arg(&args), None);
    }
}
