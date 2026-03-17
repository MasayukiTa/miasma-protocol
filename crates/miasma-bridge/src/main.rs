/// miasma-bridge CLI — BitTorrent ↔ Miasma bridge (Phase 2, Task 15).
///
/// # Usage
/// ```
/// # Bridge a torrent (magnet → dissolve all files into Miasma):
/// miasma-bridge dissolve \
///   --data-dir ~/.miasma \
///   "magnet:?xt=urn:btih:aabb...&dn=example"
///
/// # Retrieve a MID and re-seed it as a torrent:
/// miasma-bridge retrieve \
///   --data-dir ~/.miasma \
///   "miasma:<base58>"
///
/// # Start the bridge daemon (watches for new torrents, auto-dissolves):
/// miasma-bridge daemon \
///   --data-dir ~/.miasma \
///   --quota 100G \
///   --watch-dir ~/Downloads
/// ```
#[allow(dead_code)]
mod index;
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
        "dissolve" => cmd_dissolve(&args[2..]),
        "retrieve" => cmd_retrieve(&args[2..]),
        "daemon"   => cmd_daemon(&args[2..]),
        "--help" | "-h" => { print_usage(); }
        other => {
            eprintln!("Unknown command: {other}");
            print_usage();
            std::process::exit(1);
        }
    }
}

fn cmd_dissolve(args: &[String]) {
    let (_data_dir, rest) = parse_data_dir(args);
    if rest.is_empty() {
        eprintln!("Usage: miasma-bridge dissolve --data-dir <dir> <magnet-uri>");
        std::process::exit(1);
    }
    let magnet = &rest[0];

    match pipeline::MagnetInfo::parse(magnet) {
        Ok(info) => {
            let ih_hex = hex::encode(info.info_hash);
            info!("Parsed magnet: info_hash={ih_hex}, name={:?}", info.display_name);
            // Phase 2: fetch torrent metadata via librqbit, dissolve each file.
            println!("Phase 2 stub: would dissolve torrent {ih_hex} into Miasma.");
        }
        Err(e) => {
            error!("Failed to parse magnet link: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_retrieve(args: &[String]) {
    let (_data_dir, rest) = parse_data_dir(args);
    if rest.is_empty() {
        eprintln!("Usage: miasma-bridge retrieve --data-dir <dir> <MID>");
        std::process::exit(1);
    }
    let mid = &rest[0];
    info!("Retrieve stub: would fetch {mid} from Miasma and re-seed as torrent.");
    println!("Phase 2 stub: retrieve {mid} from Miasma.");
}

fn cmd_daemon(args: &[String]) {
    let (data_dir, rest) = parse_data_dir(args);
    let watch_dir = rest.windows(2)
        .find(|w| w[0] == "--watch-dir")
        .map(|w| PathBuf::from(&w[1]));
    let quota = rest.windows(2)
        .find(|w| w[0] == "--quota")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "100G".into());

    info!(
        "Bridge daemon starting: data_dir={}, quota={quota}, watch={:?}",
        data_dir.display(), watch_dir
    );
    // Phase 2: start tokio runtime, watch watch_dir for .torrent files,
    // dissolve new files, update BtMiasmaIndex.
    println!("Phase 2 stub: daemon would start here.");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

fn print_usage() {
    println!(concat!(
        "miasma-bridge — BitTorrent ↔ Miasma bridge (Phase 2)\n",
        "\n",
        "Commands:\n",
        "  dissolve  Dissolve a torrent's contents into Miasma\n",
        "  retrieve  Retrieve a MID and re-seed as torrent\n",
        "  daemon    Run the bridge daemon\n",
        "\n",
        "Options:\n",
        "  --data-dir <dir>   Node data directory\n",
        "  --quota <size>     Storage quota (e.g. 100G)\n",
        "  --watch-dir <dir>  Directory to watch for .torrent files (daemon only)\n",
    ));
}
