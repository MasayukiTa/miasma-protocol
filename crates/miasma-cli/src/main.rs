use std::{
    io::{self, Write as _},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::sync::Arc;

use miasma_core::{
    config::{default_data_dir, NodeConfig},
    dissolve, retrieve,
    store::LocalShareStore,
    DissolutionParams, MiasmaNode, NodeType,
};
use tracing::info;
use zeroize::Zeroizing;

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "miasma",
    about = "Miasma Protocol — censorship-resistant decentralized file sharing",
    version
)]
struct Cli {
    /// Override the data directory (default: platform-specific ~/.local/share/miasma).
    #[arg(long, env = "MIASMA_DATA_DIR", global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Miasma node (creates data directory, master key, config).
    Init {
        /// Storage quota for held shares, in MiB (desktop default: 10240).
        #[arg(long, default_value = "10240")]
        storage_mb: u64,
        /// Outbound bandwidth quota for serving shares, in MiB/day.
        #[arg(long, default_value = "1024")]
        bandwidth_mb_day: u64,
        /// Listen multiaddr.
        #[arg(long, default_value = "/ip4/0.0.0.0/udp/0/quic-v1")]
        listen_addr: String,
    },

    /// Dissolve a file into the Miasma network.
    ///
    /// Encrypts, erasure-codes, and distributes the file as shares.
    /// Prints the Miasma Content ID (MID) to stdout.
    ///
    /// Phase 1: shares are stored locally. Network distribution is added in Task 3.
    Dissolve {
        /// Path to the file to dissolve.
        path: PathBuf,
        /// Number of data shards (k). Retrieve requires ≥k shares.
        #[arg(long, default_value = "10")]
        data_shards: usize,
        /// Total shards (n). n - k recovery shards provide redundancy.
        #[arg(long, default_value = "20")]
        total_shards: usize,
    },

    /// Retrieve and reconstruct content by its Miasma Content ID (MID).
    ///
    /// Phase 1: retrieves from local share store only.
    Get {
        /// Miasma Content ID (format: `miasma:<base58>`).
        mid: String,
        /// Write reconstructed content to this file path.
        /// If omitted, writes to stdout.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
        /// Number of data shards (k) used during dissolution.
        #[arg(long, default_value = "10")]
        data_shards: usize,
        /// Total shards (n) used during dissolution.
        #[arg(long, default_value = "20")]
        total_shards: usize,
    },

    /// Show node status (peer ID, storage usage, config summary).
    Status,

    /// Emergency wipe — zero and delete the master key within seconds.
    ///
    /// All locally stored shares become immediately and permanently unreadable.
    /// The node can still be reinstalled and appear to function normally.
    Wipe {
        /// Required: explicit confirmation flag.
        #[arg(long)]
        confirm: bool,
    },

    /// Get or set configuration values.
    Config {
        /// Config key to read or write (e.g. `storage.quota_mb`).
        #[arg(long)]
        key: Option<String>,
        /// Value to set. If omitted, prints current value.
        #[arg(long)]
        value: Option<String>,
    },

    /// Run node in daemon mode (foreground, systemd-compatible).
    ///
    /// Starts the libp2p swarm and serves shares to the network.
    /// Send SIGTERM / Ctrl-C to shut down gracefully.
    Daemon {
        /// Bootstrap peer multiaddrs (repeatable).
        #[arg(long)]
        bootstrap: Vec<String>,
    },

    /// Dissolve a file and publish it to the P2P network via Kademlia DHT.
    ///
    /// Shares are stored locally; run `daemon` to serve them long-term.
    /// Prints the Miasma Content ID (MID) to stdout.
    NetworkPublish {
        /// Path to the file to dissolve and publish.
        path: PathBuf,
        /// Number of data shards (k).
        #[arg(long, default_value = "10")]
        data_shards: usize,
        /// Total shards (n).
        #[arg(long, default_value = "20")]
        total_shards: usize,
        /// Bootstrap peer multiaddrs (repeatable).
        #[arg(long)]
        bootstrap: Vec<String>,
    },

    /// Retrieve and reconstruct content from the P2P network by MID.
    NetworkGet {
        /// Miasma Content ID (format: `miasma:<base58>`).
        mid: String,
        /// Write reconstructed content to this file. If omitted, writes to stdout.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
        /// Number of data shards (k) used during dissolution.
        #[arg(long, default_value = "10")]
        data_shards: usize,
        /// Total shards (n) used during dissolution.
        #[arg(long, default_value = "20")]
        total_shards: usize,
        /// Bootstrap peer multiaddrs (repeatable).
        #[arg(long)]
        bootstrap: Vec<String>,
    },
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Logging: MIASMA_LOG or default to info.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MIASMA_LOG")
                .unwrap_or_else(|_| "miasma=info,miasma_core=info".parse().unwrap()),
        )
        .init();

    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);

    match cli.command {
        Commands::Init {
            storage_mb,
            bandwidth_mb_day,
            listen_addr,
        } => cmd_init(&data_dir, storage_mb, bandwidth_mb_day, &listen_addr),

        Commands::Dissolve {
            path,
            data_shards,
            total_shards,
        } => cmd_dissolve(&data_dir, &path, data_shards, total_shards),

        Commands::Get {
            mid,
            output,
            data_shards,
            total_shards,
        } => cmd_get(&data_dir, &mid, output.as_deref(), data_shards, total_shards),

        Commands::Status => cmd_status(&data_dir).await,

        Commands::Wipe { confirm } => cmd_wipe(&data_dir, confirm),

        Commands::Config { key, value } => cmd_config(&data_dir, key.as_deref(), value.as_deref()),

        Commands::Daemon { bootstrap } => cmd_daemon(&data_dir, &bootstrap).await,

        Commands::NetworkPublish {
            path,
            data_shards,
            total_shards,
            bootstrap,
        } => cmd_network_publish(&data_dir, &path, data_shards, total_shards, &bootstrap).await,

        Commands::NetworkGet {
            mid,
            output,
            data_shards,
            total_shards,
            bootstrap,
        } => cmd_network_get(&data_dir, &mid, output.as_deref(), data_shards, total_shards, &bootstrap).await,
    }
}

// ─── Command implementations ──────────────────────────────────────────────────

fn cmd_init(
    data_dir: &std::path::Path,
    storage_mb: u64,
    bandwidth_mb_day: u64,
    listen_addr: &str,
) -> Result<()> {
    use miasma_core::config::{NetworkConfig, StorageConfig};

    // Create data directory and initialise config.
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("cannot create data dir: {}", data_dir.display()))?;

    let config = NodeConfig {
        storage: StorageConfig {
            quota_mb: storage_mb,
            bandwidth_mb_day,
        },
        network: NetworkConfig {
            listen_addr: listen_addr.into(),
            bootstrap_peers: vec![],
        },
    };
    config.save(data_dir).context("cannot save config")?;

    // Initialise the local store (creates master.key).
    LocalShareStore::open(data_dir, storage_mb).context("cannot initialise share store")?;

    println!("✓ Miasma node initialised");
    println!("  Data dir:         {}", data_dir.display());
    println!("  Storage quota:    {} MiB", storage_mb);
    println!("  Bandwidth quota:  {} MiB/day", bandwidth_mb_day);
    println!("  Listen addr:      {listen_addr}");
    println!();
    println!("Run `miasma daemon` to start the node.");
    Ok(())
}

fn cmd_dissolve(
    data_dir: &std::path::Path,
    path: &std::path::Path,
    data_shards: usize,
    total_shards: usize,
) -> Result<()> {
    let config = NodeConfig::load(data_dir).context("cannot load config")?;
    let store = LocalShareStore::open(data_dir, config.storage.quota_mb)
        .context("cannot open share store")?;

    // Read input file.
    let plaintext = std::fs::read(path)
        .with_context(|| format!("cannot read file: {}", path.display()))?;

    let params = DissolutionParams {
        data_shards,
        total_shards,
    };

    eprintln!(
        "Dissolving {} ({} bytes) k={} n={} …",
        path.display(),
        plaintext.len(),
        data_shards,
        total_shards
    );

    let (mid, shares) = dissolve(&plaintext, params).context("dissolution failed")?;
    let mid_str = mid.to_string();

    // Store all shares locally (Phase 1 — network distribution in Task 3).
    let mut stored = 0usize;
    for share in &shares {
        store.put(share).context("cannot store share")?;
        stored += 1;
    }

    // Print MID to stdout (machine-parseable).
    println!("{mid_str}");
    eprintln!(
        "✓ Dissolved into {stored} shares. Retrieve with: miasma get {mid_str}"
    );
    Ok(())
}

fn cmd_get(
    data_dir: &std::path::Path,
    mid_str: &str,
    output: Option<&std::path::Path>,
    data_shards: usize,
    total_shards: usize,
) -> Result<()> {
    use miasma_core::crypto::hash::ContentId;

    let config = NodeConfig::load(data_dir).context("cannot load config")?;
    let store = LocalShareStore::open(data_dir, config.storage.quota_mb)
        .context("cannot open share store")?;

    let mid = ContentId::from_str(mid_str)
        .with_context(|| format!("invalid MID: {mid_str}"))?;

    let params = DissolutionParams {
        data_shards,
        total_shards,
    };

    // Collect all stored shares and filter by MID prefix (coarse check).
    let mut shares = Vec::new();
    for addr in store.list() {
        match store.get(&addr) {
            Ok(share) if share.mid_prefix == mid.prefix() => shares.push(share),
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("cannot read share {addr}: {e}");
            }
        }
        if shares.len() >= total_shards {
            break;
        }
    }

    if shares.len() < data_shards {
        bail!(
            "insufficient shares: need {}, found {} locally. \
            Phase 1: only local shares supported. \
            Run `miasma dissolve` on this machine first.",
            data_shards,
            shares.len()
        );
    }

    eprintln!("Retrieving {} (found {} shares locally) …", mid_str, shares.len());

    // Reconstruct in memory — plaintext never touches disk until verified.
    let plaintext = retrieve(&mid, &shares, params).context("retrieval failed")?;

    // Write output.
    match output {
        Some(path) => {
            std::fs::write(path, &plaintext)
                .with_context(|| format!("cannot write output: {}", path.display()))?;
            eprintln!("✓ Written to {}", path.display());
        }
        None => {
            io::stdout()
                .write_all(&plaintext)
                .context("cannot write to stdout")?;
        }
    }
    Ok(())
}

async fn cmd_status(data_dir: &std::path::Path) -> Result<()> {
    // Try daemon IPC first; fall back to local config if daemon not running.
    if let Ok(resp) = {
        use miasma_core::{daemon_request, ControlRequest};
        daemon_request(data_dir, ControlRequest::Status).await
    } {
        use miasma_core::ControlResponse;
        if let ControlResponse::Status(s) = resp {
            println!("Miasma Daemon Status");
            println!("  Peer ID:             {}", s.peer_id);
            for addr in &s.listen_addrs {
                println!("  Listen addr:         {addr}/p2p/{}", s.peer_id);
            }
            println!("  Connected peers:     {}", s.peer_count);
            println!("  Shares stored:       {}", s.share_count);
            println!(
                "  Storage used:        {:.1} MiB",
                s.storage_used_bytes as f64 / 1024.0 / 1024.0
            );
            println!("  Pending replication: {}", s.pending_replication);
            println!("  Replicated items:    {}", s.replicated_count);
            if s.wss_port > 0 {
                println!("  WSS share server:    127.0.0.1:{}", s.wss_port);
            }

            // Payload transport readiness matrix.
            if !s.transport_readiness.is_empty() {
                println!();
                println!("  Payload Transport Readiness:");
                for t in &s.transport_readiness {
                    let status = if t.available { "AVAILABLE" } else { "UNAVAILABLE" };
                    print!(
                        "    {:<20} {:<12} success={} failure={}",
                        t.name, status, t.success_count, t.failure_count
                    );
                    if let Some(ref reason) = t.reason {
                        print!("  ({reason})");
                    }
                    println!();
                }
            }
            return Ok(());
        }
    }
    // Fallback: no daemon running
    let config = NodeConfig::load(data_dir).context("cannot load config")?;
    let store = LocalShareStore::open(data_dir, config.storage.quota_mb)
        .context("cannot open share store")?;
    println!("Miasma Node Status (daemon not running)");
    println!("  Data dir:      {}", data_dir.display());
    println!("  Shares stored: {}", store.list().len());
    println!(
        "  Storage used:  {:.1} MiB / {} MiB",
        store.used_bytes() as f64 / 1024.0 / 1024.0,
        config.storage.quota_mb
    );
    Ok(())
}

fn cmd_wipe(data_dir: &std::path::Path, confirm: bool) -> Result<()> {
    if !confirm {
        eprintln!(
            "ERROR: This command is irreversible. All stored shares will become unreadable.\n\
            Re-run with --confirm to proceed: miasma wipe --confirm"
        );
        std::process::exit(1);
    }

    let config = NodeConfig::load(data_dir).unwrap_or_default();
    let store = LocalShareStore::open(data_dir, config.storage.quota_mb)
        .context("cannot open share store")?;

    let t0 = std::time::Instant::now();
    store.distress_wipe().context("wipe failed")?;
    let elapsed = t0.elapsed();

    eprintln!(
        "✓ Distress wipe complete in {:.0}ms. Master key deleted.",
        elapsed.as_millis()
    );
    eprintln!("  All {} locally stored shares are permanently unreadable.", store.list().len());
    Ok(())
}

fn cmd_config(
    data_dir: &std::path::Path,
    key: Option<&str>,
    value: Option<&str>,
) -> Result<()> {
    let mut config = NodeConfig::load(data_dir).context("cannot load config")?;

    match (key, value) {
        (None, _) => {
            // Print all config.
            let raw = toml::to_string_pretty(&config)
                .context("cannot serialize config")?;
            print!("{raw}");
        }
        (Some(k), None) => {
            // Read a specific key.
            match k {
                "storage.quota_mb" => println!("{}", config.storage.quota_mb),
                "storage.bandwidth_mb_day" => println!("{}", config.storage.bandwidth_mb_day),
                "network.listen_addr" => println!("{}", config.network.listen_addr),
                _ => bail!("unknown config key: {k}"),
            }
        }
        (Some(k), Some(v)) => {
            // Write a specific key.
            match k {
                "storage.quota_mb" => {
                    config.storage.quota_mb = v.parse().context("expected integer")?;
                }
                "storage.bandwidth_mb_day" => {
                    config.storage.bandwidth_mb_day = v.parse().context("expected integer")?;
                }
                "network.listen_addr" => {
                    config.network.listen_addr = v.into();
                }
                _ => bail!("unknown config key: {k}"),
            }
            config.save(data_dir).context("cannot save config")?;
            println!("✓ {k} = {v}");
        }
    }
    Ok(())
}

async fn cmd_daemon(data_dir: &std::path::Path, bootstrap_addrs: &[String]) -> Result<()> {
    use miasma_core::DaemonServer;

    let config = NodeConfig::load(data_dir).context("cannot load config")?;

    let master_key_path = data_dir.join("master.key");
    if !master_key_path.exists() {
        bail!("Node not initialised. Run `miasma init` first.");
    }
    let master_bytes = std::fs::read(&master_key_path).context("cannot read master.key")?;
    let master_key: Zeroizing<[u8; 32]> = Zeroizing::new(
        master_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("master.key has wrong length"))?,
    );

    let store = Arc::new(
        LocalShareStore::open(data_dir, config.storage.quota_mb)
            .context("cannot open share store")?,
    );

    let node = MiasmaNode::new(&*master_key, NodeType::Full, &config.network.listen_addr)
        .context("cannot create node")?;

    let server = DaemonServer::start(node, store, data_dir.to_owned())
        .await
        .context("daemon start failed")?;

    // Print peer ID and bootstrap addresses.
    eprintln!("Peer ID: {}", server.peer_id());
    eprintln!("Bootstrap addresses for other nodes:");
    for addr in server.listen_addrs() {
        eprintln!("  {addr}/p2p/{}", server.peer_id());
    }
    eprintln!("IPC control port: {}", server.control_port());
    eprintln!();

    // Add bootstrap peers from CLI flags and config.
    let all_bootstrap: Vec<&str> = config
        .network
        .bootstrap_peers
        .iter()
        .map(|s| s.as_str())
        .chain(bootstrap_addrs.iter().map(|s| s.as_str()))
        .collect();
    let has_bootstrap = add_bootstrap_peers_to_server(&server, &all_bootstrap).await;
    if has_bootstrap {
        server.bootstrap_dht().await.context("DHT bootstrap failed")?;
    }

    eprintln!("Daemon running. Press Ctrl-C to stop.");

    // Graceful shutdown on Ctrl-C.
    let shutdown = server.shutdown_handle();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received Ctrl-C, shutting down...");
        let _ = shutdown.send(()).await;
    });

    server.run().await.context("daemon error")?;
    Ok(())
}

// ─── Shared bootstrap helper ──────────────────────────────────────────────────

/// Parse multiaddr bootstrap peers and register them with the daemon server.
async fn add_bootstrap_peers_to_server(
    server: &miasma_core::DaemonServer,
    addrs: &[&str],
) -> bool {
    use libp2p::multiaddr::Protocol;
    let mut added = false;
    for addr_str in addrs {
        match addr_str.parse::<libp2p::Multiaddr>() {
            Ok(mut addr) => {
                let maybe_peer_id: Option<libp2p::PeerId> = addr.iter().find_map(|proto| {
                    if let Protocol::P2p(id) = proto { Some(id) } else { None }
                });
                match maybe_peer_id {
                    Some(peer_id) => {
                        if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
                            addr.pop();
                        }
                        if server.add_bootstrap_peer(peer_id, addr).await.is_ok() {
                            added = true;
                        }
                    }
                    None => eprintln!(
                        "Warning: bootstrap addr '{addr_str}' missing /p2p/<peer-id> — skipping"
                    ),
                }
            }
            Err(e) => eprintln!("Warning: invalid bootstrap addr '{addr_str}': {e}"),
        }
    }
    added
}

// ─── network-publish ──────────────────────────────────────────────────────────

async fn cmd_network_publish(
    data_dir: &std::path::Path,
    path: &std::path::Path,
    data_shards: usize,
    total_shards: usize,
    _bootstrap_addrs: &[String],  // ignored: daemon handles bootstrap
) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    let plaintext = std::fs::read(path)
        .with_context(|| format!("cannot read file: {}", path.display()))?;

    eprintln!(
        "Publishing {} ({} bytes) via local daemon...",
        path.display(),
        plaintext.len()
    );

    let req = ControlRequest::Publish {
        data: plaintext,
        data_shards: data_shards as u8,
        total_shards: total_shards as u8,
    };

    match daemon_request(data_dir, req).await? {
        ControlResponse::Published { mid } => {
            println!("{mid}");
            eprintln!("Published. MID: {mid}");
            eprintln!("  Retrieve: miasma network-get {mid} -o output.bin");
            Ok(())
        }
        ControlResponse::Error(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
}

// ─── network-get ─────────────────────────────────────────────────────────────

async fn cmd_network_get(
    data_dir: &std::path::Path,
    mid_str: &str,
    output: Option<&std::path::Path>,
    data_shards: usize,
    total_shards: usize,
    _bootstrap_addrs: &[String],  // ignored: daemon handles bootstrap
) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    eprintln!("Requesting {mid_str} from local daemon...");

    let req = ControlRequest::Get {
        mid: mid_str.to_owned(),
        data_shards: data_shards as u8,
        total_shards: total_shards as u8,
    };

    match daemon_request(data_dir, req).await? {
        ControlResponse::Retrieved { data } => {
            match output {
                Some(path) => {
                    std::fs::write(path, &data)
                        .with_context(|| format!("cannot write output: {}", path.display()))?;
                    eprintln!("Written to {}", path.display());
                }
                None => {
                    use std::io::Write as _;
                    io::stdout().write_all(&data).context("cannot write to stdout")?;
                }
            }
            Ok(())
        }
        ControlResponse::Error(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
}
