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

    /// Export a full diagnostic report for troubleshooting.
    ///
    /// Collects node config, daemon status, transport readiness, storage,
    /// and recent errors into a single text or JSON report.
    Diagnostics {
        /// Output as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
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

    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);

    // Logging: MIASMA_LOG or default to info.
    // Daemon mode logs to both stderr and a file in the data directory.
    let filter = tracing_subscriber::EnvFilter::try_from_env("MIASMA_LOG")
        .unwrap_or_else(|_| "miasma=info,miasma_core=info".parse().unwrap());

    let is_daemon = matches!(cli.command, Commands::Daemon { .. });
    if is_daemon {
        let log_dir = data_dir.clone();
        let _ = std::fs::create_dir_all(&log_dir);
        let file_appender = tracing_appender::rolling::daily(&log_dir, "daemon.log");
        // Truncate old logs: keep recent file only (daily roller creates new files).
        cleanup_old_logs(&log_dir, "daemon.log", 3);
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false);
        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
        // Keep _guard alive for the duration of main by leaking it.
        // This is intentional: the guard must outlive all tracing calls.
        std::mem::forget(_guard);
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .init();
    }

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

        Commands::Diagnostics { json } => cmd_diagnostics(&data_dir, json).await,

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
        transport: Default::default(),
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
                let tls_tag = if s.wss_tls_enabled { " (TLS)" } else { " (plain WS)" };
                println!("  WSS share server:    127.0.0.1:{}{}", s.wss_port, tls_tag);
            }
            if s.obfs_quic_port > 0 {
                println!("  ObfuscatedQuic:      127.0.0.1:{}", s.obfs_quic_port);
            }
            if s.proxy_configured {
                println!("  Outbound proxy:      {} (configured)", s.proxy_type.as_deref().unwrap_or("unknown"));
            }

            // Payload transport readiness matrix.
            if !s.transport_readiness.is_empty() {
                println!();
                println!("  Payload Transport Readiness:");
                for t in &s.transport_readiness {
                    let status = if t.available { "AVAILABLE" } else { "UNAVAIL " };
                    let sel = if t.selected { " [SELECTED]" } else { "" };
                    print!(
                        "    {:<20} {:<9} success={:<4} fail={:<4} (session={} data={}){sel}",
                        t.name, status, t.success_count, t.failure_count,
                        t.session_failures, t.data_failures,
                    );
                    if let Some(ref err) = t.last_error {
                        print!("  last: {err}");
                    }
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

async fn cmd_diagnostics(data_dir: &std::path::Path, json_out: bool) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    let version = env!("CARGO_PKG_VERSION");
    let config_ok = NodeConfig::load(data_dir);
    let has_config = config_ok.is_ok();
    let key_path = data_dir.join("master.key");
    let key_exists = key_path.exists();

    // Store info.
    let (share_count, storage_used) = if let Ok(ref config) = config_ok {
        if let Ok(store) = LocalShareStore::open(data_dir, config.storage.quota_mb) {
            (store.list().len(), store.used_bytes())
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };

    // Daemon IPC.
    let daemon_resp = daemon_request(data_dir, ControlRequest::Status).await;
    let daemon_status = match daemon_resp {
        Ok(ControlResponse::Status(s)) => Some(s),
        _ => None,
    };

    if json_out {
        let mut report = serde_json::Map::new();
        report.insert("version".into(), serde_json::json!(version));
        report.insert("data_dir".into(), serde_json::json!(data_dir.display().to_string()));
        report.insert("config_exists".into(), serde_json::json!(has_config));
        report.insert("master_key_exists".into(), serde_json::json!(key_exists));
        // Log file location.
        let log_glob = data_dir.join("daemon.log.*");
        report.insert("log_file".into(), serde_json::json!(log_glob.display().to_string()));
        report.insert("share_count".into(), serde_json::json!(share_count));
        report.insert("storage_used_bytes".into(), serde_json::json!(storage_used));

        if let Ok(ref config) = config_ok {
            report.insert("storage_quota_mb".into(), serde_json::json!(config.storage.quota_mb));
            report.insert("listen_addr".into(), serde_json::json!(config.network.listen_addr));
        }

        report.insert("daemon_running".into(), serde_json::json!(daemon_status.is_some()));

        if let Some(ref s) = daemon_status {
            report.insert("peer_id".into(), serde_json::json!(s.peer_id));
            report.insert("peer_count".into(), serde_json::json!(s.peer_count));
            report.insert("listen_addrs".into(), serde_json::json!(s.listen_addrs));
            report.insert("pending_replication".into(), serde_json::json!(s.pending_replication));
            report.insert("replicated_count".into(), serde_json::json!(s.replicated_count));
            report.insert("wss_port".into(), serde_json::json!(s.wss_port));
            report.insert("wss_tls_enabled".into(), serde_json::json!(s.wss_tls_enabled));
            report.insert("obfs_quic_port".into(), serde_json::json!(s.obfs_quic_port));
            report.insert("proxy_configured".into(), serde_json::json!(s.proxy_configured));
            report.insert("proxy_type".into(), serde_json::json!(s.proxy_type));

            let transports: Vec<serde_json::Value> = s.transport_readiness.iter().map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "available": t.available,
                    "selected": t.selected,
                    "success_count": t.success_count,
                    "failure_count": t.failure_count,
                    "session_failures": t.session_failures,
                    "data_failures": t.data_failures,
                    "last_error": t.last_error,
                    "reason": t.reason,
                })
            }).collect();
            report.insert("transport_readiness".into(), serde_json::json!(transports));
        }

        let obj = serde_json::Value::Object(report);
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    } else {
        println!("Miasma Diagnostics Report");
        println!("=========================");
        println!("Version:         {version}");
        println!("Data dir:        {}", data_dir.display());
        println!("Config exists:   {has_config}");
        println!("Master key:      {}", if key_exists { "present" } else { "MISSING" });
        println!("Daemon log:      {}/daemon.log.*", data_dir.display());

        if let Ok(ref config) = config_ok {
            println!("Storage quota:   {} MiB", config.storage.quota_mb);
            println!("Listen addr:     {}", config.network.listen_addr);
        }

        println!("Shares stored:   {share_count}");
        println!("Storage used:    {:.1} MiB", storage_used as f64 / 1024.0 / 1024.0);

        println!();
        let daemon_running = daemon_status.is_some();
        println!("Daemon:          {}", if daemon_running { "RUNNING" } else { "NOT RUNNING" });

        if let Some(ref s) = daemon_status {
            println!("Peer ID:         {}", s.peer_id);
            println!("Connected peers: {}", s.peer_count);
            println!("Replication:     {} done, {} pending", s.replicated_count, s.pending_replication);
            if s.wss_port > 0 {
                let tls_tag = if s.wss_tls_enabled { " (TLS)" } else { "" };
                println!("WSS server:      :{}{tls_tag}", s.wss_port);
            }
            if s.obfs_quic_port > 0 {
                println!("ObfuscatedQuic:  :{}", s.obfs_quic_port);
            }
            if s.proxy_configured {
                println!("Proxy:           {}", s.proxy_type.as_deref().unwrap_or("?"));
            }

            if !s.transport_readiness.is_empty() {
                println!();
                println!("Transport Readiness:");
                for t in &s.transport_readiness {
                    let status = if t.available { "AVAIL" } else { "UNAVL" };
                    let sel_tag = if t.selected { " [SELECTED]" } else { "" };
                    print!("  {:<20} {status} ok={} fail={}{sel_tag}", t.name, t.success_count, t.failure_count);
                    if let Some(ref err) = t.last_error {
                        print!("  last_err: {err}");
                    }
                    println!();
                }
            }
        }

        println!();
        println!("(Copy this output for troubleshooting. Use --json for machine-readable format.)");
    }

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
                "transport.wss_tls_enabled" => println!("{}", config.transport.wss_tls_enabled),
                "transport.wss_sni" => println!("{}", config.transport.wss_sni.as_deref().unwrap_or("")),
                "transport.proxy_type" => println!("{}", config.transport.proxy_type.as_deref().unwrap_or("")),
                "transport.proxy_addr" => println!("{}", config.transport.proxy_addr.as_deref().unwrap_or("")),
                "transport.obfuscated_quic_enabled" => println!("{}", config.transport.obfuscated_quic_enabled),
                "transport.obfuscated_quic_sni" => println!("{}", config.transport.obfuscated_quic_sni.as_deref().unwrap_or("")),
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
                "transport.wss_tls_enabled" => {
                    config.transport.wss_tls_enabled = v.parse().context("expected bool")?;
                }
                "transport.wss_sni" => {
                    config.transport.wss_sni = if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.proxy_type" => {
                    config.transport.proxy_type = if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.proxy_addr" => {
                    config.transport.proxy_addr = if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.proxy_username" => {
                    config.transport.proxy_username = if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.proxy_password" => {
                    config.transport.proxy_password = if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.obfuscated_quic_enabled" => {
                    config.transport.obfuscated_quic_enabled = v.parse().context("expected bool")?;
                }
                "transport.obfuscated_quic_sni" => {
                    config.transport.obfuscated_quic_sni = if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.obfuscated_quic_secret" => {
                    config.transport.obfuscated_quic_secret = if v.is_empty() { None } else { Some(v.into()) };
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

    let server = DaemonServer::start_with_transport(
        node, store, data_dir.to_owned(), config.transport.clone(),
    )
        .await
        .context("daemon start failed")?;

    // Print peer ID and bootstrap addresses.
    eprintln!("Peer ID: {}", server.peer_id());
    eprintln!("Bootstrap addresses for other nodes:");
    for addr in server.listen_addrs() {
        eprintln!("  {addr}/p2p/{}", server.peer_id());
    }
    eprintln!("IPC control port: {}", server.control_port());
    eprintln!("Log file: {}/daemon.log.*", data_dir.display());
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

// ─── Log file cleanup ───────────────────────────────────────────────────────

/// Remove old log files beyond `keep` count. Matches files starting with `prefix`.
fn cleanup_old_logs(dir: &std::path::Path, prefix: &str, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut logs: Vec<(std::path::PathBuf, std::time::SystemTime)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(prefix))
                .unwrap_or(false)
        })
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            Some((e.path(), meta.modified().unwrap_or(std::time::UNIX_EPOCH)))
        })
        .collect();

    if logs.len() <= keep {
        return;
    }

    // Sort newest-first, then remove the oldest.
    logs.sort_by(|a, b| b.1.cmp(&a.1));
    for (path, _) in logs.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
}
