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
use zeroize::{Zeroize, Zeroizing};

mod i18n;
use i18n::{Lang, Msg};

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

    /// Language of the messages: en or ja. Default: env MIASMA_LANG, else the OS language, else en.
    #[arg(long, global = true, value_name = "en|ja", value_parser = i18n::parse_lang_arg)]
    lang: Option<Lang>,

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
        /// Protect the content with a password read from the first line of FILE.
        ///
        /// The password is an encryption factor: the receiver needs it in
        /// addition to the MID, and the MID plus every shard cannot decrypt
        /// without it. It is never taken from the command line, where it would
        /// show in process listings and shell history.
        #[arg(long, value_name = "FILE", conflicts_with = "password_stdin")]
        password_file: Option<PathBuf>,
        /// Read the password from the first line of standard input.
        #[arg(long)]
        password_stdin: bool,
        /// Discard any earlier partial publish of this file and start over. By
        /// default a publish that was interrupted resumes from the last finished
        /// segment (the source file must be unchanged).
        #[arg(long)]
        restart: bool,
        /// Start the publish in the daemon and return at once. Watch it with
        /// `miasma transfers`; the MID is shown there once the file is hashed.
        #[arg(long)]
        no_wait: bool,
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

    // ── Directed sharing ──────────────────────────────────────────────
    /// Show this node's sharing key and contact string.
    ///
    /// Share the contact string with people who want to send you files.
    /// Format: msk:<base58-pubkey>@<PeerId>
    SharingKey,

    /// Send a file to a specific recipient using directed private sharing.
    ///
    /// The file is encrypted with the recipient's public key and a password,
    /// then dissolved into the Miasma network. The recipient must confirm
    /// with a challenge code and provide the password to retrieve.
    Send {
        /// Path to the file to send.
        path: PathBuf,
        /// Recipient's sharing contact string (msk:...@PeerId).
        #[arg(long)]
        to: String,
        /// Password the recipient must provide to retrieve the content.
        #[arg(long)]
        password: String,
        /// Retention period (e.g. "24h", "7d", "30d"). Default: 7 days.
        #[arg(long, default_value = "7d")]
        retention: String,
    },

    /// Submit a confirmation challenge code for a received directed share.
    ///
    /// After receiving a directed share, a challenge code is generated.
    /// Share this code with the sender through a side channel.
    /// The sender submits it here to confirm delivery.
    Confirm {
        /// Hex-encoded envelope ID.
        envelope_id: String,
        /// Challenge code (XXXX-XXXX format).
        #[arg(long)]
        code: String,
    },

    /// Retrieve content from a confirmed directed share.
    ///
    /// Requires the password set by the sender.
    Receive {
        /// Hex-encoded envelope ID.
        envelope_id: String,
        /// Password set by the sender.
        #[arg(long)]
        password: String,
        /// Write decrypted content to this file. If omitted, uses original filename or stdout.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Revoke a directed share (as sender) or delete it (as recipient).
    ///
    /// Performs cryptographic deletion: discards key material so content
    /// is permanently unreadable. Underlying network shards are cleaned up
    /// on a best-effort basis — this is NOT guaranteed physical deletion.
    Revoke {
        /// Hex-encoded envelope ID.
        envelope_id: String,
    },

    /// List incoming directed shares (your inbox).
    Inbox,

    /// List outgoing directed shares (your outbox).
    Outbox,

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
        /// The password, read from the first line of FILE. Required exactly when
        /// the content was published with `--password-file` / `--password-stdin`.
        #[arg(long, value_name = "FILE", conflicts_with = "password_stdin")]
        password_file: Option<PathBuf>,
        /// Read the password from the first line of standard input.
        #[arg(long)]
        password_stdin: bool,
        /// Discard any partial transfer and start over. By default a transfer
        /// that was interrupted (Ctrl-C, crash, lost holder) resumes.
        #[arg(long)]
        restart: bool,
        /// Start the transfer in the daemon and return at once. Watch it with
        /// `miasma transfers`.
        #[arg(long)]
        no_wait: bool,
    },

    /// List transfers: running, paused, and finished, including ones an earlier
    /// daemon process left behind (those can be resumed by running the same
    /// `network-get` again).
    Transfers,

    /// Stop a running transfer at its next safe point. The partial file is kept
    /// and the transfer can be resumed.
    TransferCancel {
        /// The MID of the transfer (`miasma:<base58>`).
        mid: String,
    },

    /// Measure what a redundancy setting (k of n) costs and buys, on this machine.
    ///
    /// Runs the real dissolve and recover code in memory for each setting and
    /// prints a table: bytes stored per byte of file, throughput, and whether
    /// losing exactly n-k pieces is survivable while n-k+1 fails cleanly. Nothing
    /// touches the network. Storage factor and loss tolerance are exact anywhere;
    /// throughput needs a `--release` build on the machine that will do the transfer.
    RedundancyBench {
        /// Megabytes (MiB) of data to run each setting over.
        #[arg(long, default_value = "256")]
        size_mib: usize,
        /// Settings to compare, as `k/n` (repeatable). Default: 10/10 10/11 10/12 10/15 10/20.
        #[arg(long, value_name = "K/N")]
        preset: Vec<String>,
        /// Also write every share to a real share store under this directory, so
        /// local disk speed and at-rest encryption are part of the measurement.
        #[arg(long, value_name = "DIR")]
        store_dir: Option<PathBuf>,
    },

    /// Probe WebSocket/WSS connectivity to a URL.
    ///
    /// Connects via TCP (+ TLS for wss:// or https://) and performs a WebSocket
    /// upgrade. Useful for verifying that a restrictive network (corporate VPN,
    /// GFW) passes WebSocket traffic on port 443.
    ///
    /// Exit 0 = connection established (TCP + WS upgrade succeeded).
    /// Exit 1 = connection failed (timeout, TCP reset, TLS error, etc.).
    ///
    /// Examples:
    ///   miasma wss-probe wss://abc.trycloudflare.com
    ///   miasma wss-probe ws://127.0.0.1:8080
    WssProbe {
        /// WebSocket URL to probe.
        /// Accepted schemes: ws://, wss://, http://, https://
        url: String,
        /// Connect + handshake timeout in seconds. Default: 15.
        #[arg(long, default_value = "15")]
        timeout_secs: u64,
        /// Custom CA certificate PEM file for self-signed server certs.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Skip TLS certificate verification (for testing through MITM proxies).
        /// WARNING: insecure — use only for connectivity testing, never for production.
        #[arg(long)]
        skip_tls_verify: bool,
    },
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(l) = cli.lang {
        i18n::set_lang(l);
    }

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
        let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
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
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    // Stamp version for future upgrade detection.
    if data_dir.join("config.toml").exists() {
        miasma_core::config::stamp_version(&data_dir, env!("CARGO_PKG_VERSION"));
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
        } => cmd_get(
            &data_dir,
            &mid,
            output.as_deref(),
            data_shards,
            total_shards,
        ),

        Commands::Status => cmd_status(&data_dir).await,

        Commands::Wipe { confirm } => cmd_wipe(&data_dir, confirm).await,

        Commands::Config { key, value } => cmd_config(&data_dir, key.as_deref(), value.as_deref()),

        Commands::Daemon { bootstrap } => cmd_daemon(&data_dir, &bootstrap).await,

        Commands::Diagnostics { json } => cmd_diagnostics(&data_dir, json).await,

        Commands::SharingKey => cmd_sharing_key(&data_dir).await,
        Commands::Send {
            path,
            to,
            password,
            retention,
        } => cmd_send(&data_dir, &path, &to, &password, &retention).await,
        Commands::Confirm { envelope_id, code } => {
            cmd_confirm(&data_dir, &envelope_id, &code).await
        }
        Commands::Receive {
            envelope_id,
            password,
            output,
        } => cmd_receive(&data_dir, &envelope_id, &password, output.as_deref()).await,
        Commands::Revoke { envelope_id } => cmd_revoke(&data_dir, &envelope_id).await,
        Commands::Inbox => cmd_inbox(&data_dir).await,
        Commands::Outbox => cmd_outbox(&data_dir).await,

        Commands::NetworkPublish {
            path,
            data_shards,
            total_shards,
            bootstrap,
            password_file,
            password_stdin,
            restart,
            no_wait,
        } => {
            let password = read_transfer_password(password_file.as_deref(), password_stdin)?;
            cmd_network_publish(
                &data_dir,
                &path,
                data_shards,
                total_shards,
                &bootstrap,
                password.as_ref().map(|p| p.as_str()),
                restart,
                no_wait,
            )
            .await
        }

        Commands::NetworkGet {
            mid,
            output,
            data_shards,
            total_shards,
            bootstrap,
            password_file,
            password_stdin,
            restart,
            no_wait,
        } => {
            let password = read_transfer_password(password_file.as_deref(), password_stdin)?;
            cmd_network_get(
                &data_dir,
                &mid,
                output.as_deref(),
                data_shards,
                total_shards,
                &bootstrap,
                password.as_ref().map(|p| p.as_str()),
                restart,
                no_wait,
            )
            .await
        }

        Commands::Transfers => cmd_transfers(&data_dir).await,
        Commands::TransferCancel { mid } => cmd_transfer_cancel(&data_dir, &mid).await,
        Commands::RedundancyBench {
            size_mib,
            preset,
            store_dir,
        } => cmd_redundancy_bench(size_mib, &preset, store_dir.as_deref()),

        Commands::WssProbe {
            url,
            timeout_secs,
            ca_cert,
            skip_tls_verify,
        } => cmd_wss_probe(&url, timeout_secs, ca_cert.as_deref(), skip_tls_verify).await,
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
    let mut config = NodeConfig::load(data_dir).context("cannot load config")?;
    let quota_mb = config.storage.quota_mb;
    config.transport.zeroize_secret_copies();
    let store = LocalShareStore::open(data_dir, quota_mb).context("cannot open share store")?;

    // Read input file.
    let plaintext =
        std::fs::read(path).with_context(|| format!("cannot read file: {}", path.display()))?;

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
    eprintln!("✓ Dissolved into {stored} shares. Retrieve with: miasma get {mid_str}");
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

    let mut config = NodeConfig::load(data_dir).context("cannot load config")?;
    let quota_mb = config.storage.quota_mb;
    config.transport.zeroize_secret_copies();
    let store = LocalShareStore::open(data_dir, quota_mb).context("cannot open share store")?;

    let mid = ContentId::from_str(mid_str).with_context(|| format!("invalid MID: {mid_str}"))?;

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

    eprintln!(
        "Retrieving {} (found {} shares locally) …",
        mid_str,
        shares.len()
    );

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
                let tls_tag = if s.wss_tls_enabled {
                    " (TLS)"
                } else {
                    " (plain WS)"
                };
                println!("  WSS share server:    127.0.0.1:{}{}", s.wss_port, tls_tag);
            }
            if s.obfs_quic_port > 0 {
                println!("  ObfuscatedQuic:      127.0.0.1:{}", s.obfs_quic_port);
            }
            if s.proxy_configured {
                println!(
                    "  Outbound proxy:      {} (configured)",
                    s.proxy_type.as_deref().unwrap_or("unknown")
                );
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
                        t.name,
                        status,
                        t.success_count,
                        t.failure_count,
                        t.session_failures,
                        t.data_failures,
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
    let mut config = NodeConfig::load(data_dir).context("cannot load config")?;
    let quota_mb = config.storage.quota_mb;
    config.transport.zeroize_secret_copies();
    let store = LocalShareStore::open(data_dir, quota_mb).context("cannot open share store")?;
    println!("Miasma Node Status (daemon not running)");
    println!("  Data dir:      {}", data_dir.display());
    println!("  Shares stored: {}", store.list().len());
    println!(
        "  Storage used:  {:.1} MiB / {} MiB",
        store.used_bytes() as f64 / 1024.0 / 1024.0,
        quota_mb
    );
    Ok(())
}

async fn cmd_diagnostics(data_dir: &std::path::Path, json_out: bool) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    let version = env!("CARGO_PKG_VERSION");
    let config_info = NodeConfig::load(data_dir).map(|mut config| {
        let info = (config.storage.quota_mb, config.network.listen_addr.clone());
        config.transport.zeroize_secret_copies();
        info
    });
    let has_config = config_info.is_ok();
    let key_path = data_dir.join("master.key");
    let key_exists = key_path.exists();

    // Store info.
    let (share_count, storage_used) = if let Ok((quota_mb, _)) = &config_info {
        if let Ok(store) = LocalShareStore::open(data_dir, *quota_mb) {
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
        report.insert(
            "data_dir".into(),
            serde_json::json!(data_dir.display().to_string()),
        );
        report.insert("config_exists".into(), serde_json::json!(has_config));
        report.insert("master_key_exists".into(), serde_json::json!(key_exists));
        // Log file location.
        let log_glob = data_dir.join("daemon.log.*");
        report.insert(
            "log_file".into(),
            serde_json::json!(log_glob.display().to_string()),
        );
        report.insert("share_count".into(), serde_json::json!(share_count));
        report.insert("storage_used_bytes".into(), serde_json::json!(storage_used));

        if let Ok((quota_mb, listen_addr)) = &config_info {
            report.insert("storage_quota_mb".into(), serde_json::json!(quota_mb));
            report.insert("listen_addr".into(), serde_json::json!(listen_addr));
        }

        report.insert(
            "daemon_running".into(),
            serde_json::json!(daemon_status.is_some()),
        );

        if let Some(ref s) = daemon_status {
            report.insert("peer_id".into(), serde_json::json!(s.peer_id));
            report.insert("peer_count".into(), serde_json::json!(s.peer_count));
            report.insert("listen_addrs".into(), serde_json::json!(s.listen_addrs));
            report.insert(
                "pending_replication".into(),
                serde_json::json!(s.pending_replication),
            );
            report.insert(
                "replicated_count".into(),
                serde_json::json!(s.replicated_count),
            );
            report.insert("wss_port".into(), serde_json::json!(s.wss_port));
            report.insert(
                "wss_tls_enabled".into(),
                serde_json::json!(s.wss_tls_enabled),
            );
            report.insert("obfs_quic_port".into(), serde_json::json!(s.obfs_quic_port));
            report.insert(
                "proxy_configured".into(),
                serde_json::json!(s.proxy_configured),
            );
            report.insert("proxy_type".into(), serde_json::json!(s.proxy_type));

            let transports: Vec<serde_json::Value> = s
                .transport_readiness
                .iter()
                .map(|t| {
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
                })
                .collect();
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
        println!(
            "Master key:      {}",
            if key_exists { "present" } else { "MISSING" }
        );
        println!("Daemon log:      {}/daemon.log.*", data_dir.display());

        if let Ok((quota_mb, listen_addr)) = &config_info {
            println!("Storage quota:   {quota_mb} MiB");
            println!("Listen addr:     {listen_addr}");
        }

        println!("Shares stored:   {share_count}");
        println!(
            "Storage used:    {:.1} MiB",
            storage_used as f64 / 1024.0 / 1024.0
        );

        println!();
        let daemon_running = daemon_status.is_some();
        println!(
            "Daemon:          {}",
            if daemon_running {
                "RUNNING"
            } else {
                "NOT RUNNING"
            }
        );

        if let Some(ref s) = daemon_status {
            println!("Peer ID:         {}", s.peer_id);
            println!("Connected peers: {}", s.peer_count);
            println!(
                "Replication:     {} done, {} pending",
                s.replicated_count, s.pending_replication
            );
            if s.wss_port > 0 {
                let tls_tag = if s.wss_tls_enabled { " (TLS)" } else { "" };
                println!("WSS server:      :{}{tls_tag}", s.wss_port);
            }
            if s.obfs_quic_port > 0 {
                println!("ObfuscatedQuic:  :{}", s.obfs_quic_port);
            }
            if s.proxy_configured {
                println!(
                    "Proxy:           {}",
                    s.proxy_type.as_deref().unwrap_or("?")
                );
            }

            if !s.transport_readiness.is_empty() {
                println!();
                println!("Transport Readiness:");
                for t in &s.transport_readiness {
                    let status = if t.available { "AVAIL" } else { "UNAVL" };
                    let sel_tag = if t.selected { " [SELECTED]" } else { "" };
                    print!(
                        "  {:<20} {status} ok={} fail={}{sel_tag}",
                        t.name, t.success_count, t.failure_count
                    );
                    if let Some(ref err) = t.last_error {
                        print!("  last_err: {err}");
                    }
                    println!();
                }
            }

            // Trust & anonymity subsystem.
            println!();
            println!("Trust & Anonymity:");
            println!("  Verified peers:   {}", s.verified_peers);
            println!("  Observed peers:   {}", s.observed_peers);
            println!("  Rejections:       {}", s.admission_rejections);
            println!("  Credential epoch: {}", s.credential_epoch);
            println!("  Credentials held: {}", s.credential_held);
            println!("  Known issuers:    {}", s.credential_issuers);
            println!(
                "  Descriptors:      {} total, {} relays",
                s.descriptor_total, s.descriptor_relays
            );
            println!("  Anonymity policy: {}", s.anonymity_policy);

            // Outcome metrics.
            println!();
            println!("Network Health Metrics:");
            println!(
                "  Relay diversity:       {} /16 prefixes",
                s.metric_relay_prefix_diversity
            );
            println!("  Relay peers routable:  {}", s.metric_relay_peers_routable);
            println!(
                "  Multi-path score:      {:.1}%",
                s.metric_multi_path_retrievability * 100.0
            );
            println!(
                "  Credentialed peers:    {:.1}%",
                s.metric_credentialed_fraction * 100.0
            );
            println!(
                "  Pseudonym churn:       {:.1}%",
                s.metric_pseudonym_churn_rate * 100.0
            );
            println!(
                "  Verification ratio:    {:.1}%",
                s.metric_verification_ratio * 100.0
            );
            println!("  PoW difficulty:        {} bits", s.metric_pow_difficulty);
            println!(
                "  Rejection rate:        {:.1}%",
                s.metric_rejection_rate * 100.0
            );
            println!("  Stale descriptors:     {}", s.metric_stale_descriptors);
            println!(
                "  Descriptor store:      {:.1}% full",
                s.metric_descriptor_utilisation * 100.0
            );
            println!(
                "  Onion relay peers:     {} (content-blind retrieval {})",
                s.metric_onion_relay_peers,
                if s.metric_onion_relay_peers >= 2 {
                    "available"
                } else {
                    "unavailable"
                }
            );
            println!(
                "  NAT status:            {} (can_relay: {})",
                if s.nat_publicly_reachable {
                    "public"
                } else {
                    "private/unknown"
                },
                if s.nat_publicly_reachable {
                    "yes"
                } else {
                    "no"
                }
            );

            // Rendezvous and relay trust
            println!("  Rendezvous peers:      {}", s.rendezvous_peers);
            println!(
                "  Relay trust tiers:     claimed={} observed={} verified={}",
                s.relay_tier_claimed, s.relay_tier_observed, s.relay_tier_verified
            );
            println!(
                "  Relay trust evidence:  {} probed (fresh), {} forwarding-verified",
                s.probe_cache_fresh, s.forwarding_verified_relays
            );

            // Directed sharing relay fallback
            let total_directed = s.directed_direct_sends
                + s.directed_relay_fallback_attempts
                + s.directed_no_relay_candidates;
            if total_directed > 0 {
                println!();
                println!("Directed Sharing (control plane):");
                println!("  Direct sends:          {}", s.directed_direct_sends);
                println!(
                    "  Relay fallback:        {} attempts, {} circuits registered",
                    s.directed_relay_fallback_attempts, s.directed_relay_circuits_registered
                );
                if s.directed_no_relay_candidates > 0 {
                    println!(
                        "  No relay candidates:   {}",
                        s.directed_no_relay_candidates
                    );
                }
            }

            // Connection health
            println!();
            println!("Connection Health:");
            println!(
                "  Quality score:         {:.1}%",
                s.connection_quality_score * 100.0
            );
            println!("  Dial backoff addrs:    {}", s.dial_backoff_addresses);
            println!("  Stale addrs pruned:    {}", s.stale_addresses_pruned);
            println!(
                "  Connectivity:          {}",
                if s.connectivity_degraded {
                    "DEGRADED"
                } else {
                    "healthy"
                }
            );
            if let Some(ref transport) = s.active_transport {
                println!("  Active transport:      {}", transport);
            }
            if s.fallback_active {
                println!("  Fallback mode:         ACTIVE (not using primary transport)");
            }
            if s.flap_damping_active {
                println!("  Flap damping:          ACTIVE (suppressing reconnections)");
            }
            if s.rate_limit_rejections > 0 {
                println!("  Rate limit rejections: {}", s.rate_limit_rejections);
            }
            if !s.partial_failures.is_empty() {
                println!("  Partial failures:      {}", s.partial_failures.join(", "));
            }
            if s.reconnection_attempts > 0 {
                println!();
                println!("Reconnection:");
                println!("  Attempts:              {}", s.reconnection_attempts);
                println!("  Successes:             {}", s.reconnection_successes);
                println!("  Failures:              {}", s.reconnection_failures);
                if s.reconnection_circuit_breaker_trips > 0 {
                    println!(
                        "  Circuit breaker trips: {}",
                        s.reconnection_circuit_breaker_trips
                    );
                }
                if s.reconnection_recovery_actions > 0 {
                    println!(
                        "  Recovery actions:      {}",
                        s.reconnection_recovery_actions
                    );
                }
            }

            // Censorship resistance transports
            if s.shadowsocks_configured || s.tor_configured {
                println!();
                println!("Censorship Resistance:");
                println!(
                    "  Shadowsocks:           {}",
                    if s.shadowsocks_configured {
                        "configured"
                    } else {
                        "not configured"
                    }
                );
                println!(
                    "  Tor:                   {}",
                    if s.tor_configured {
                        "configured"
                    } else {
                        "not configured"
                    }
                );
            }

            // Network environment
            if s.network_environment != "unknown" {
                println!();
                println!("Network Environment:");
                println!("  Detected:              {}", s.network_environment);
                if s.tls_inspection_detected {
                    println!("  TLS inspection:        DETECTED (corporate proxy/ZTNA)");
                }
                if s.captive_portal_detected {
                    println!("  Captive portal:        DETECTED (authentication required)");
                }
                if s.vpn_detected {
                    println!("  VPN:                   DETECTED");
                }
            }

            let total_retrievals = s.retrieval_direct_attempts
                + s.retrieval_opportunistic_attempts
                + s.retrieval_required_attempts
                + s.retrieval_rendezvous_attempts;
            if total_retrievals > 0 {
                println!();
                println!("Retrieval Tracking:");
                println!(
                    "  Direct:        {}/{} succeeded",
                    s.retrieval_direct_successes, s.retrieval_direct_attempts
                );
                println!(
                    "  Opportunistic: {}/{} attempts",
                    {
                        s.retrieval_opportunistic_onion_rendezvous_successes
                            + s.retrieval_opportunistic_onion_successes
                            + s.retrieval_opportunistic_rendezvous_successes
                            + s.retrieval_opportunistic_relay_successes
                            + s.retrieval_opportunistic_direct_fallbacks
                    },
                    s.retrieval_opportunistic_attempts
                );
                println!(
                    "    onion+rendezvous (content-blind+NAT): {}",
                    s.retrieval_opportunistic_onion_rendezvous_successes
                );
                println!(
                    "    onion (content-blind):                {}",
                    s.retrieval_opportunistic_onion_successes
                );
                println!(
                    "    rendezvous relay (IP-only+NAT):       {}",
                    s.retrieval_opportunistic_rendezvous_successes
                );
                println!(
                    "    relay circuit (IP-only):              {}",
                    s.retrieval_opportunistic_relay_successes
                );
                println!(
                    "    direct fallback:                      {}",
                    s.retrieval_opportunistic_direct_fallbacks
                );
                println!(
                    "  Required:      {}/{} (onion: {}, relay: {}, failed: {})",
                    s.retrieval_required_onion_successes + s.retrieval_required_relay_successes,
                    s.retrieval_required_attempts,
                    s.retrieval_required_onion_successes,
                    s.retrieval_required_relay_successes,
                    s.retrieval_required_failures
                );
                println!(
                    "  Rendezvous:    {}/{} (failed: {}, direct fallback: {})",
                    s.retrieval_rendezvous_successes,
                    s.retrieval_rendezvous_attempts,
                    s.retrieval_rendezvous_failures,
                    s.retrieval_rendezvous_direct_fallbacks
                );
                if s.retrieval_rendezvous_onion_attempts > 0 {
                    println!(
                        "  Rendezvous+Onion (content-blind): {}/{} (failed: {})",
                        s.retrieval_rendezvous_onion_successes,
                        s.retrieval_rendezvous_onion_attempts,
                        s.retrieval_rendezvous_onion_failures
                    );
                }
            }

            // Active relay probe and forwarding verification stats.
            if s.relay_probes_sent > 0 || s.forwarding_probes_sent > 0 {
                println!();
                println!("Relay Verification:");
                println!(
                    "  Reachability probes:   {} sent, {} ok, {} fail",
                    s.relay_probes_sent, s.relay_probes_succeeded, s.relay_probes_failed
                );
                println!(
                    "  Forwarding probes:     {} sent, {} ok, {} fail",
                    s.forwarding_probes_sent,
                    s.forwarding_probes_succeeded,
                    s.forwarding_probes_failed
                );
                println!("  Pre-retrieval sweeps:  {}", s.pre_retrieval_probes_run);
            }
        }

        println!();
        println!("(Copy this output for troubleshooting. Use --json for machine-readable format.)");
    }

    Ok(())
}

async fn cmd_wipe(data_dir: &std::path::Path, confirm: bool) -> Result<()> {
    use miasma_core::daemon::ipc::PORT_FILE;
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    if !confirm {
        eprintln!(
            "ERROR: This command is irreversible. All stored shares will become unreadable.\n\
            Re-run with --confirm to proceed: miasma wipe --confirm"
        );
        std::process::exit(1);
    }

    let t0 = std::time::Instant::now();
    let port_path = data_dir.join(PORT_FILE);
    if port_path.exists() {
        match daemon_request(data_dir, ControlRequest::Wipe).await {
            Ok(ControlResponse::Wiped) => {}
            Ok(ControlResponse::Error(e)) => {
                bail!("wipe incomplete; daemon is shutting down: {e}");
            }
            Ok(other) => bail!("unexpected daemon wipe response: {other:?}"),
            Err(e) => bail!(
                "daemon.port exists but wipe IPC failed; refusing disk-only wipe while a daemon may still hold keys: {e}"
            ),
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while port_path.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        if port_path.exists() {
            bail!("wipe response received but daemon runtime did not stop within 5s");
        }
    } else {
        let mut config = NodeConfig::load(data_dir).unwrap_or_default();
        let quota_mb = config.storage.quota_mb;
        config.transport.zeroize_secret_copies();
        let store = LocalShareStore::open(data_dir, quota_mb).context("cannot open share store")?;
        store.distress_wipe().context("wipe failed")?;
    }

    eprintln!(
        "Distress wipe complete in {:.0}ms. Key material erased and daemon stopped.",
        t0.elapsed().as_millis()
    );
    Ok(())
}

fn cmd_config(data_dir: &std::path::Path, key: Option<&str>, value: Option<&str>) -> Result<()> {
    let mut config = NodeConfig::load(data_dir).context("cannot load config")?;
    let result = cmd_config_loaded(data_dir, &mut config, key, value);
    config.transport.zeroize_secret_copies();
    result
}

fn cmd_config_loaded(
    data_dir: &std::path::Path,
    config: &mut NodeConfig,
    key: Option<&str>,
    value: Option<&str>,
) -> Result<()> {
    match (key, value) {
        (None, _) => {
            // Never serialize persisted secrets to stdout. Move them out rather
            // than cloning them into a redacted copy, then restore so the common
            // zeroize-at-exit path can erase the original buffers.
            let proxy_username = config.transport.proxy_username.take();
            let proxy_password = config.transport.proxy_password.take();
            let obfs_secret = config.transport.obfuscated_quic_secret.take();
            let shadowsocks_password = config.transport.shadowsocks.password.take();
            let raw_result = toml::to_string_pretty(&*config);
            config.transport.proxy_username = proxy_username;
            config.transport.proxy_password = proxy_password;
            config.transport.obfuscated_quic_secret = obfs_secret;
            config.transport.shadowsocks.password = shadowsocks_password;
            let raw = Zeroizing::new(raw_result.context("cannot serialize config")?);
            print!("{}", raw.as_str());
            eprintln!("# persisted secret fields are omitted from config output");
        }
        (Some(k), None) => {
            // Read a specific key.
            match k {
                "storage.quota_mb" => println!("{}", config.storage.quota_mb),
                "storage.bandwidth_mb_day" => println!("{}", config.storage.bandwidth_mb_day),
                "network.listen_addr" => println!("{}", config.network.listen_addr),
                "network.bootstrap_peers" => {
                    for peer in &config.network.bootstrap_peers {
                        println!("{peer}");
                    }
                }
                "transport.wss_tls_enabled" => println!("{}", config.transport.wss_tls_enabled),
                "transport.wss_sni" => {
                    println!("{}", config.transport.wss_sni.as_deref().unwrap_or(""))
                }
                "transport.proxy_type" => {
                    println!("{}", config.transport.proxy_type.as_deref().unwrap_or(""))
                }
                "transport.proxy_addr" => {
                    println!("{}", config.transport.proxy_addr.as_deref().unwrap_or(""))
                }
                "transport.obfuscated_quic_enabled" => {
                    println!("{}", config.transport.obfuscated_quic_enabled)
                }
                "transport.obfuscated_quic_sni" => println!(
                    "{}",
                    config
                        .transport
                        .obfuscated_quic_sni
                        .as_deref()
                        .unwrap_or("")
                ),
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
                "network.bootstrap_peers" => {
                    if v.is_empty() {
                        config.network.bootstrap_peers.clear();
                    } else {
                        config.network.bootstrap_peers.push(v.into());
                    }
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
                    config.transport.proxy_username =
                        if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.proxy_password" => {
                    config.transport.proxy_password =
                        if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.obfuscated_quic_enabled" => {
                    config.transport.obfuscated_quic_enabled =
                        v.parse().context("expected bool")?;
                }
                "transport.obfuscated_quic_sni" => {
                    config.transport.obfuscated_quic_sni =
                        if v.is_empty() { None } else { Some(v.into()) };
                }
                "transport.obfuscated_quic_secret" => {
                    config.transport.obfuscated_quic_secret =
                        if v.is_empty() { None } else { Some(v.into()) };
                }
                _ => bail!("unknown config key: {k}"),
            }
            config.save(data_dir).context("cannot save config")?;
            let is_secret = matches!(
                k,
                "transport.proxy_username"
                    | "transport.proxy_password"
                    | "transport.obfuscated_quic_secret"
            );
            if is_secret {
                println!("configured {k} = <redacted>");
            } else {
                println!("configured {k} = {v}");
            }
        }
    }
    Ok(())
}

async fn cmd_daemon(data_dir: &std::path::Path, bootstrap_addrs: &[String]) -> Result<()> {
    use miasma_core::DaemonServer;

    let mut config = NodeConfig::load(data_dir).context("cannot load config")?;

    let master_key_path = data_dir.join("master.key");
    if !master_key_path.exists() {
        bail!("Node not initialised. Run `miasma init` first.");
    }
    let master_bytes =
        Zeroizing::new(std::fs::read(&master_key_path).context("cannot read master.key")?);
    if master_bytes.len() != 32 {
        bail!("master.key has wrong length");
    }
    let mut master_key = Zeroizing::new([0u8; 32]);
    master_key.copy_from_slice(&master_bytes);
    if master_key.iter().all(|byte| *byte == 0) {
        bail!("master.key is erased/all-zero");
    }

    let store = Arc::new(
        LocalShareStore::open(data_dir, config.storage.quota_mb)
            .context("cannot open share store")?,
    );

    let node = MiasmaNode::new(&master_key, NodeType::Full, &config.network.listen_addr)
        .context("cannot create node")?;

    let transport_config = std::mem::take(&mut config.transport);
    let server =
        DaemonServer::start_with_transport(node, store, data_dir.to_owned(), transport_config)
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
        server
            .bootstrap_dht()
            .await
            .context("DHT bootstrap failed")?;
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
async fn add_bootstrap_peers_to_server(server: &miasma_core::DaemonServer, addrs: &[&str]) -> bool {
    use libp2p::multiaddr::Protocol;
    let mut added = false;
    for addr_str in addrs {
        match addr_str.parse::<libp2p::Multiaddr>() {
            Ok(mut addr) => {
                let maybe_peer_id: Option<libp2p::PeerId> = addr.iter().find_map(|proto| {
                    if let Protocol::P2p(id) = proto {
                        Some(id)
                    } else {
                        None
                    }
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

// ─── Directed sharing commands ────────────────────────────────────────────────

async fn cmd_sharing_key(data_dir: &std::path::Path) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    match daemon_request(data_dir, ControlRequest::SharingKey).await? {
        ControlResponse::SharingKey { key, contact } => {
            println!("Sharing key:     {key}");
            println!("Sharing contact: {contact}");
            eprintln!();
            eprintln!("Share your contact string with people who want to send you files.");
        }
        ControlResponse::Error(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

fn parse_retention(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();
    if let Some(h) = s.strip_suffix('h') {
        let hours: u64 = h.parse().context("invalid hours")?;
        Ok(hours * 3600)
    } else if let Some(d) = s.strip_suffix('d') {
        let days: u64 = d.parse().context("invalid days")?;
        Ok(days * 86400)
    } else if let Some(m) = s.strip_suffix('m') {
        let mins: u64 = m.parse().context("invalid minutes")?;
        Ok(mins * 60)
    } else {
        // Try parsing as raw seconds.
        s.parse::<u64>()
            .context("invalid retention: use e.g. '24h', '7d', or seconds")
    }
}

async fn cmd_send(
    data_dir: &std::path::Path,
    path: &std::path::Path,
    to: &str,
    password: &str,
    retention: &str,
) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    // Validate the file exists and get its size for display, but don't read it —
    // the daemon reads it directly via DirectedSendFile, avoiding IPC bloat.
    let meta = std::fs::metadata(path)
        .with_context(|| format!("cannot access file: {}", path.display()))?;
    let retention_secs = parse_retention(retention)?;

    eprintln!(
        "Sending {} ({} bytes) to {} …",
        path.display(),
        meta.len(),
        to
    );

    // Canonicalize path so the daemon can find it regardless of cwd.
    let abs_path = std::fs::canonicalize(path)
        .with_context(|| format!("cannot resolve path: {}", path.display()))?;

    let req = ControlRequest::DirectedSendFile {
        recipient_contact: to.to_owned(),
        file_path: abs_path.to_string_lossy().to_string(),
        password: password.to_owned(),
        retention_secs,
        filename: None, // daemon derives from file_path
    };

    match daemon_request(data_dir, req).await? {
        ControlResponse::DirectedSent { envelope_id } => {
            println!("{envelope_id}");
            eprintln!("✓ Directed share created.");
            eprintln!("  Envelope ID: {envelope_id}");
            eprintln!("  Waiting for recipient to generate a challenge code.");
            eprintln!("  Then confirm with: miasma confirm {envelope_id} --code XXXX-XXXX");
        }
        ControlResponse::Error(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

async fn cmd_confirm(data_dir: &std::path::Path, envelope_id: &str, code: &str) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    eprintln!("Submitting challenge code for {envelope_id} …");

    let req = ControlRequest::DirectedConfirm {
        envelope_id: envelope_id.to_owned(),
        challenge_code: code.to_owned(),
    };

    match daemon_request(data_dir, req).await? {
        ControlResponse::DirectedConfirmed => {
            eprintln!("✓ Challenge confirmed. Recipient can now retrieve the content.");
        }
        ControlResponse::Error(e) => bail!("challenge failed: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

async fn cmd_receive(
    data_dir: &std::path::Path,
    envelope_id: &str,
    password: &str,
    output: Option<&std::path::Path>,
) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    eprintln!("Retrieving directed share {envelope_id} …");

    // If we have an output path (explicit or can be derived later), use the
    // file-path variant so the daemon writes directly — avoids IPC bloat.
    if let Some(out) = output {
        let abs_out = if out.is_absolute() {
            out.to_owned()
        } else {
            std::env::current_dir().unwrap_or_default().join(out)
        };
        let req = ControlRequest::DirectedRetrieveToFile {
            envelope_id: envelope_id.to_owned(),
            password: password.to_owned(),
            output_path: abs_out.to_string_lossy().to_string(),
        };
        match daemon_request(data_dir, req).await? {
            ControlResponse::DirectedRetrievedToFile {
                output_path,
                bytes_written,
                ..
            } => {
                eprintln!("✓ Written {bytes_written} bytes to {output_path}");
            }
            ControlResponse::Error(e) => bail!("retrieval failed: {e}"),
            other => bail!("unexpected response: {other:?}"),
        }
        return Ok(());
    }

    // No explicit output — try to get the filename from the daemon, then decide.
    // We need to use a temp file as the target so we can learn the original
    // filename before choosing the final destination.
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("miasma-retrieve-{envelope_id}.tmp"));
    let req = ControlRequest::DirectedRetrieveToFile {
        envelope_id: envelope_id.to_owned(),
        password: password.to_owned(),
        output_path: tmp_path.to_string_lossy().to_string(),
    };
    match daemon_request(data_dir, req).await? {
        ControlResponse::DirectedRetrievedToFile {
            filename,
            bytes_written,
            ..
        } => {
            if let Some(fname) = &filename {
                // Move from temp to final filename in current directory.
                let final_path = PathBuf::from(fname);
                std::fs::rename(&tmp_path, &final_path)
                    .or_else(|_| {
                        // rename can fail across filesystems; fall back to copy+delete.
                        std::fs::copy(&tmp_path, &final_path).map(|_| ())?;
                        std::fs::remove_file(&tmp_path).ok();
                        Ok::<(), std::io::Error>(())
                    })
                    .with_context(|| format!("cannot write output: {}", final_path.display()))?;
                eprintln!(
                    "✓ Written {bytes_written} bytes to {}",
                    final_path.display()
                );
            } else {
                // No filename — dump temp file contents to stdout.
                let data = std::fs::read(&tmp_path).context("read temp file")?;
                std::fs::remove_file(&tmp_path).ok();
                io::stdout()
                    .write_all(&data)
                    .context("cannot write to stdout")?;
            }
        }
        ControlResponse::Error(e) => {
            std::fs::remove_file(&tmp_path).ok();
            bail!("retrieval failed: {e}");
        }
        other => {
            std::fs::remove_file(&tmp_path).ok();
            bail!("unexpected response: {other:?}");
        }
    }
    Ok(())
}

async fn cmd_revoke(data_dir: &std::path::Path, envelope_id: &str) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    eprintln!("Revoking directed share {envelope_id} …");

    let req = ControlRequest::DirectedRevoke {
        envelope_id: envelope_id.to_owned(),
    };

    match daemon_request(data_dir, req).await? {
        ControlResponse::DirectedRevoked => {
            eprintln!("✓ Directed share revoked. Key material discarded.");
            eprintln!("  Content is cryptographically deleted (not guaranteed physical deletion).");
        }
        ControlResponse::Error(e) => bail!("revoke failed: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

async fn cmd_inbox(data_dir: &std::path::Path) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    match daemon_request(data_dir, ControlRequest::DirectedInbox).await? {
        ControlResponse::DirectedInboxList(mut items) => {
            if items.is_empty() {
                println!("Inbox is empty.");
                return Ok(());
            }
            println!(
                "Directed Inbox ({} item{})",
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            );
            println!();
            for item in &items {
                let age = format_age(item.created_at);
                let expires = format_age(item.expires_at);
                println!("  ID:          {}", item.envelope_id);
                println!(
                    "  From peer:   {}",
                    item.sender_peer_id.as_deref().unwrap_or("<legacy/unbound>")
                );
                println!("  Claimed key: {}", item.sender_pubkey);
                println!("  State:       {:?}", item.state);
                println!("  Created:   {age}");
                println!("  Expires:   {expires}");
                if let Some(ref code) = item.challenge_code {
                    println!("  Challenge: {code}");
                    eprintln!("  → Share this code with the sender for confirmation.");
                }
                println!();
            }
            for item in &mut items {
                if let Some(code) = item.challenge_code.as_mut() {
                    code.zeroize();
                }
            }
        }
        ControlResponse::Error(e) => bail!("inbox error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

async fn cmd_outbox(data_dir: &std::path::Path) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    match daemon_request(data_dir, ControlRequest::DirectedOutbox).await? {
        ControlResponse::DirectedOutboxList(items) => {
            if items.is_empty() {
                println!("Outbox is empty.");
                return Ok(());
            }
            println!(
                "Directed Outbox ({} item{})",
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            );
            println!();
            for item in &items {
                let age = format_age(item.created_at);
                let expires = format_age(item.expires_at);
                println!("  ID:        {}", item.envelope_id);
                println!("  To:        {}", item.recipient_pubkey);
                println!("  State:     {:?}", item.state);
                println!("  Created:   {age}");
                println!("  Expires:   {expires}");
                println!();
            }
        }
        ControlResponse::Error(e) => bail!("outbox error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

fn format_age(epoch_secs: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if epoch_secs == 0 {
        return "unknown".into();
    }
    if epoch_secs > now {
        let diff = epoch_secs - now;
        if diff < 3600 {
            format!("in {}m", diff / 60)
        } else if diff < 86400 {
            format!("in {}h", diff / 3600)
        } else {
            format!("in {}d", diff / 86400)
        }
    } else {
        let diff = now - epoch_secs;
        if diff < 60 {
            "just now".into()
        } else if diff < 3600 {
            format!("{}m ago", diff / 60)
        } else if diff < 86400 {
            format!("{}h ago", diff / 3600)
        } else {
            format!("{}d ago", diff / 86400)
        }
    }
}

// ─── network-publish ──────────────────────────────────────────────────────────

/// Read a transfer password from a file or from stdin: the first line, without
/// its line ending. Never from argv, where it would show in process listings.
///
/// Only the line ending is stripped; spaces are part of the password.
fn read_transfer_password(
    file: Option<&std::path::Path>,
    from_stdin: bool,
) -> Result<Option<Zeroizing<String>>> {
    let raw = match (file, from_stdin) {
        (Some(path), _) => Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
            Msg::CannotReadPasswordFile {
                path: path.display().to_string(),
            }
            .t()
        })?),
        (None, true) => {
            let mut line = Zeroizing::new(String::new());
            std::io::stdin()
                .read_line(&mut line)
                .with_context(|| Msg::CannotReadPasswordStdin.t())?;
            line
        }
        (None, false) => return Ok(None),
    };
    let first = raw.lines().next().unwrap_or("");
    if first.is_empty() {
        bail!("{}", Msg::PasswordEmpty.t());
    }
    Ok(Some(Zeroizing::new(first.to_owned())))
}

async fn cmd_network_publish(
    data_dir: &std::path::Path,
    path: &std::path::Path,
    data_shards: usize,
    total_shards: usize,
    _bootstrap_addrs: &[String], // ignored: daemon handles bootstrap
    password: Option<&str>,
    restart: bool,
    no_wait: bool,
) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    // The daemon reads the file itself and publishes it segment by segment, so
    // files of any size work without full-file RAM buffering or IPC size limits.
    // It runs as a background transfer: progress is readable, a stop (Ctrl-C,
    // crash, out of disk) can be resumed, and the CLI disconnecting changes nothing.
    let abs_path = std::fs::canonicalize(path).with_context(|| {
        Msg::CannotResolvePath {
            path: path.display().to_string(),
        }
        .t()
    })?;
    let file_len = std::fs::metadata(&abs_path).map(|m| m.len()).unwrap_or(0);

    let id = match daemon_request(
        data_dir,
        ControlRequest::TransferStartPublish {
            file_path: abs_path.to_string_lossy().into_owned(),
            data_shards: data_shards as u8,
            total_shards: total_shards as u8,
            password: password.map(str::to_owned),
            restart,
        },
    )
    .await?
    {
        ControlResponse::TransferStarted { id } => id,
        ControlResponse::Error(e) => return Err(daemon_error(e)),
        other => return Err(unexpected_response(&other)),
    };

    eprintln!(
        "{}",
        Msg::PublishStart {
            path: abs_path.display().to_string(),
            size: human_bytes(file_len),
        }
        .t()
    );
    eprintln!(
        "{}",
        Msg::PublishParams {
            k: data_shards,
            n: total_shards,
            factor: total_shards as f64 / data_shards.max(1) as f64,
        }
        .t()
    );
    eprintln!("{}", Msg::RunAgainToWatch.t());
    if no_wait {
        eprintln!("{}", Msg::StartedCheckWith.t());
        return Ok(());
    }

    let status = watch_transfer(data_dir, &id).await?;
    println!("{}", status.mid);
    eprintln!(
        "{}",
        Msg::Published {
            mid: status.mid.clone()
        }
        .t()
    );
    // Elapsed includes hashing the file and, on a resume, only this session.
    if status.elapsed_secs > 0.0 {
        eprintln!(
            "{}",
            Msg::PublishedStats {
                size: human_bytes(file_len),
                secs: status.elapsed_secs,
                avg: human_bytes((file_len as f64 / status.elapsed_secs) as u64),
            }
            .t()
        );
    }
    if password.is_some() {
        eprintln!("{}", Msg::PasswordProtectedNote.t());
    }
    eprintln!(
        "{}",
        Msg::RetrieveHint {
            mid: status.mid.clone()
        }
        .t()
    );
    Ok(())
}

// ─── network-get ─────────────────────────────────────────────────────────────

async fn cmd_network_get(
    data_dir: &std::path::Path,
    mid_str: &str,
    output: Option<&std::path::Path>,
    data_shards: usize,
    total_shards: usize,
    _bootstrap_addrs: &[String], // ignored: daemon handles bootstrap
    password: Option<&str>,
    restart: bool,
    no_wait: bool,
) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    // To a file: a background transfer in the daemon, verified piece by piece,
    // resumable, with progress. (The daemon still serves the older `GetToFile`
    // for callers that want the single blocking request.)
    if let Some(path) = output {
        return cmd_network_get_transfer(data_dir, mid_str, path, password, restart, no_wait).await;
    }
    if password.is_some() {
        bail!("{}", Msg::PasswordOnlyToFile.t());
    }

    eprintln!("Requesting {mid_str} from local daemon...");

    // No output path: there is nothing to stream to, so use the byte-returning `Get`.
    let req = ControlRequest::Get {
        mid: mid_str.to_owned(),
        data_shards: data_shards as u8,
        total_shards: total_shards as u8,
    };

    match daemon_request(data_dir, req).await? {
        ControlResponse::Retrieved { data } => {
            use std::io::Write as _;
            io::stdout()
                .write_all(&data)
                .context("cannot write to stdout")?;
            Ok(())
        }
        ControlResponse::Error(e) => Err(daemon_error(e)),
        other => Err(unexpected_response(&other)),
    }
}

// ─── transfers (background receive, progress, resume) ────────────────────────

/// `1.5 GiB`, `312 MiB`, `4 KiB`, `17 B`.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn human_duration(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// One line describing a transfer's progress, in the process language.
fn format_progress(s: &miasma_core::transfer::TransferStatus) -> String {
    format_progress_in(s, i18n::lang())
}

/// One line describing a transfer's progress. Pure, so it can be tested. The
/// fields and their order are the same in every language.
fn format_progress_in(s: &miasma_core::transfer::TransferStatus, lang: Lang) -> String {
    use miasma_core::transfer::{Phase, TransferKind};

    match s.phase {
        Phase::Preparing => {
            return match s.kind {
                TransferKind::Receive => Msg::LookingUpRecord.text(lang),
                TransferKind::Send => Msg::PreparingSend.text(lang),
            }
        }
        Phase::Hashing => {
            return Msg::Hashing {
                done: human_bytes(s.bytes_done),
                total: human_bytes(s.bytes_total),
            }
            .text(lang)
        }
        Phase::Verifying => {
            let done = human_bytes(s.bytes_done);
            return match s.kind {
                TransferKind::Receive => Msg::VerifyingPartialFile { done }.text(lang),
                TransferKind::Send => Msg::VerifyingPublished { done }.text(lang),
            };
        }
        Phase::Finalizing => {
            return match s.kind {
                TransferKind::Receive => Msg::CheckingWholeFile.text(lang),
                TransferKind::Send => Msg::AnnouncingRecord.text(lang),
            }
        }
        _ => {}
    }

    let pct = if s.bytes_total > 0 {
        (s.bytes_done as f64 / s.bytes_total as f64 * 100.0).min(100.0)
    } else if s.segments_total > 0 {
        s.segments_done as f64 / s.segments_total as f64 * 100.0
    } else {
        0.0
    };
    let width = 24usize;
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let bar: String = "#".repeat(filled.min(width)) + &"-".repeat(width - filled.min(width));

    let size = if s.bytes_total > 0 {
        format!(
            "{} / {}",
            human_bytes(s.bytes_done),
            human_bytes(s.bytes_total)
        )
    } else {
        human_bytes(s.bytes_done)
    };
    let rate = if s.rate_bps > 0.0 {
        format!("{}/s", human_bytes(s.rate_bps as u64))
    } else {
        "-".to_owned()
    };
    let eta = s.eta_secs.map_or("--:--:--".to_owned(), human_duration);

    // Where the time is going: what the speed experiment needs to read off.
    let spent = (s.fetch_ms + s.decode_ms + s.write_ms).max(1) as f64;
    let split = match s.kind {
        TransferKind::Receive => Msg::SplitReceive {
            fetch: s.fetch_ms as f64 / spent * 100.0,
            decode: s.decode_ms as f64 / spent * 100.0,
            write: s.write_ms as f64 / spent * 100.0,
        },
        // For a send `fetch_ms` is store + push, `decode_ms` is encrypt + RS + SSS.
        TransferKind::Send => Msg::SplitSend {
            store_push: s.fetch_ms as f64 / spent * 100.0,
            dissolve: s.decode_ms as f64 / spent * 100.0,
        },
    }
    .text(lang);
    let seg = Msg::SegmentProgress {
        done: s.segments_done,
        total: s.segments_total,
    }
    .text(lang);
    let eta = Msg::Eta { eta }.text(lang);

    let mut line = format!("[{bar}] {pct:5.1}%  {seg}  {size}  {rate}  {eta}  ({split})");
    if s.pieces_rejected > 0 {
        line.push_str("  ");
        line.push_str(
            &Msg::RejectedPieces {
                n: s.pieces_rejected,
            }
            .text(lang),
        );
    }
    if s.segment_retries > 0 {
        line.push_str("  ");
        line.push_str(
            &Msg::Retries {
                n: s.segment_retries,
            }
            .text(lang),
        );
    }
    line
}

/// A daemon's `ControlResponse::Error`, as an error a person can read.
fn daemon_error(e: String) -> anyhow::Error {
    anyhow::anyhow!("{}", Msg::DaemonError { e }.t())
}

fn unexpected_response(other: &dyn std::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!(
        "{}",
        Msg::UnexpectedResponse {
            debug: format!("{other:?}")
        }
        .t()
    )
}

/// Poll a transfer until it stops, drawing one updating progress line. Returns
/// the final status of a completed transfer; any other end is an error whose
/// message says how to continue.
async fn watch_transfer(
    data_dir: &std::path::Path,
    id: &str,
) -> Result<miasma_core::transfer::TransferStatus> {
    use miasma_core::transfer::TransferState;
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    let mut last_line_len = 0usize;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let status = match daemon_request(
            data_dir,
            ControlRequest::TransferStatus { id: id.to_owned() },
        )
        .await?
        {
            ControlResponse::TransferStatus(s) => s,
            ControlResponse::Error(e) => return Err(daemon_error(e)),
            other => return Err(unexpected_response(&other)),
        };

        let line = format_progress(&status);
        // Overwrite the previous line in place. Padding is by terminal columns:
        // a Japanese line is wider than its character count.
        let width = i18n::display_width(&line);
        eprint!(
            "\r{line}{}",
            " ".repeat(last_line_len.saturating_sub(width))
        );
        last_line_len = last_line_len.max(width);

        match status.state {
            TransferState::Running => continue,
            TransferState::Complete => {
                eprintln!();
                return Ok(status);
            }
            TransferState::Paused => {
                eprintln!();
                bail!(
                    "{}",
                    Msg::Paused {
                        reason: status.last_error.clone()
                    }
                    .t()
                );
            }
            TransferState::Cancelled => {
                eprintln!();
                bail!("{}", Msg::Cancelled.t());
            }
            TransferState::Failed => {
                eprintln!();
                bail!(
                    "{}",
                    Msg::TransferFailed {
                        reason: status.last_error.clone()
                    }
                    .t()
                );
            }
        }
    }
}

async fn cmd_network_get_transfer(
    data_dir: &std::path::Path,
    mid_str: &str,
    path: &std::path::Path,
    password: Option<&str>,
    restart: bool,
    no_wait: bool,
) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    let abs_path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };

    let id = match daemon_request(
        data_dir,
        ControlRequest::TransferStartReceive {
            mid: mid_str.to_owned(),
            output_path: abs_path.to_string_lossy().into_owned(),
            password: password.map(str::to_owned),
            restart,
        },
    )
    .await?
    {
        ControlResponse::TransferStarted { id } => id,
        ControlResponse::Error(e) => return Err(daemon_error(e)),
        other => return Err(unexpected_response(&other)),
    };

    eprintln!("{}", Msg::Receiving { id: id.clone() }.t());
    eprintln!(
        "{}",
        Msg::ReceiveTo {
            path: abs_path.display().to_string()
        }
        .t()
    );
    eprintln!("{}", Msg::ReceiveKeepsGoing.t());
    if no_wait {
        eprintln!("{}", Msg::StartedCheckWith.t());
        return Ok(());
    }

    let status = watch_transfer(data_dir, &id).await?;
    eprintln!(
        "{}",
        Msg::ReceiveDone {
            size: human_bytes(status.bytes_done),
            secs: status.elapsed_secs,
            path: abs_path.display().to_string(),
        }
        .t()
    );
    // This session only: a resumed transfer's earlier segments are not counted.
    if status.rate_bps > 0.0 {
        eprintln!(
            "{}",
            Msg::ReceiveStats {
                rate: human_bytes(status.rate_bps as u64),
                fetch_ms: status.fetch_ms,
                decode_ms: status.decode_ms,
                write_ms: status.write_ms,
            }
            .t()
        );
    }
    Ok(())
}

/// Parse `k/n`, e.g. `10/12`.
fn parse_preset(s: &str) -> Result<(usize, usize)> {
    let (k, n) = s
        .split_once('/')
        .with_context(|| Msg::PresetNotKOverN { s: s.to_owned() }.t())?;
    let k: usize = k
        .trim()
        .parse()
        .with_context(|| Msg::PresetBadK { s: s.to_owned() }.t())?;
    let n: usize = n
        .trim()
        .parse()
        .with_context(|| Msg::PresetBadN { s: s.to_owned() }.t())?;
    if k == 0 || n < k || n > 255 {
        bail!("{}", Msg::PresetOutOfRange { s: s.to_owned() }.t());
    }
    Ok((k, n))
}

fn cmd_redundancy_bench(
    size_mib: usize,
    presets: &[String],
    store_dir: Option<&std::path::Path>,
) -> Result<()> {
    use miasma_core::transfer::bench::{run_redundancy_bench, DEFAULT_PRESETS};

    let presets: Vec<(usize, usize)> = if presets.is_empty() {
        DEFAULT_PRESETS.to_vec()
    } else {
        presets
            .iter()
            .map(|p| parse_preset(p))
            .collect::<Result<_>>()?
    };

    if cfg!(debug_assertions) {
        eprintln!("{}", Msg::BenchDebugBuildNote.t());
    }
    eprintln!(
        "{}",
        Msg::BenchRunning {
            count: presets.len(),
            size_mib,
            store_dir: store_dir.map(|d| d.display().to_string()),
        }
        .t()
    );

    let rows = run_redundancy_bench(size_mib, &presets, store_dir)?;
    println!("{}", i18n::format_bench_table(&rows, i18n::lang()));

    // Where the time goes on the first segment, per setting.
    println!("{}", Msg::BenchStageTimes.t());
    for r in &rows {
        println!(
            "  {}/{}: {:.1} ms / {:.1} ms / {:.2} ms",
            r.data_shards,
            r.total_shards,
            r.stage_encrypt.as_secs_f64() * 1e3,
            r.stage_reed_solomon.as_secs_f64() * 1e3,
            r.stage_shamir.as_secs_f64() * 1e3
        );
    }
    Ok(())
}

async fn cmd_transfers(data_dir: &std::path::Path) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    let list = match daemon_request(data_dir, ControlRequest::TransferList).await? {
        ControlResponse::TransferList(l) => l,
        ControlResponse::Error(e) => return Err(daemon_error(e)),
        other => return Err(unexpected_response(&other)),
    };
    if list.is_empty() {
        eprintln!("{}", Msg::NoTransfers.t());
        return Ok(());
    }
    for s in &list {
        println!("{}", transfer_heading(s));
        println!(
            "  {}  {}",
            Msg::State { state: s.state }.t(),
            format_progress(s)
        );
        if let Some(e) = &s.last_error {
            println!(
                "  {}",
                Msg::LastError {
                    e: i18n::localize_daemon_error(e, i18n::lang())
                }
                .t()
            );
        }
        if s.resumable {
            println!(
                "  {}",
                Msg::Resumable {
                    hint: resume_hint(s)
                }
                .t()
            );
        }
    }
    Ok(())
}

/// First line of a transfer in `miasma transfers`: which way it goes and what it is.
fn transfer_heading(s: &miasma_core::transfer::TransferStatus) -> String {
    transfer_heading_in(s, i18n::lang())
}

fn transfer_heading_in(s: &miasma_core::transfer::TransferStatus, lang: Lang) -> String {
    use miasma_core::transfer::TransferKind;
    match s.kind {
        TransferKind::Receive => Msg::HeadingReceive {
            mid: s.mid.clone(),
            name: s.name.clone(),
        },
        TransferKind::Send if s.mid.is_empty() => Msg::HeadingSendHashing {
            name: s.name.clone(),
        },
        TransferKind::Send => Msg::HeadingSend {
            name: s.name.clone(),
            mid: s.mid.clone(),
        },
    }
    .text(lang)
}

/// The command that resumes a paused transfer.
fn resume_hint(s: &miasma_core::transfer::TransferStatus) -> String {
    resume_hint_in(s, i18n::lang())
}

fn resume_hint_in(s: &miasma_core::transfer::TransferStatus, lang: Lang) -> String {
    use miasma_core::transfer::TransferKind;
    match s.kind {
        TransferKind::Receive => Msg::ResumeHintReceive {
            mid: s.mid.clone(),
            name: s.name.clone(),
        },
        TransferKind::Send => Msg::ResumeHintSend {
            name: s.name.clone(),
        },
    }
    .text(lang)
}

async fn cmd_transfer_cancel(data_dir: &std::path::Path, mid: &str) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    match daemon_request(
        data_dir,
        ControlRequest::TransferCancel { id: mid.to_owned() },
    )
    .await?
    {
        ControlResponse::TransferCancelled => {
            eprintln!("{}", Msg::CancelRequested.t());
            Ok(())
        }
        ControlResponse::Error(e) => bail!("{}", Msg::CancelError { e }.t()),
        other => Err(unexpected_response(&other)),
    }
}

// ─── wss-probe ───────────────────────────────────────────────────────────────

/// Probe WebSocket connectivity to a URL.
///
/// Distinguishes between:
/// - Session-phase failure: TCP connect / TLS handshake / WS upgrade failed
///   → transport is blocked (GlobalProtect, GFW, firewall)
/// - Data-phase failure:  WS connected but share not found / bad response
///   → transport is functional, server just doesn't have the dummy shard
///
/// Exit 0 on session success (or data-phase error → connection itself worked).
/// Exit 1 on session failure.
async fn cmd_wss_probe(
    url: &str,
    timeout_secs: u64,
    ca_cert: Option<&std::path::Path>,
    skip_tls_verify: bool,
) -> Result<()> {
    use miasma_core::transport::{
        payload::{PayloadTransport, TransportPhase},
        websocket::{WebSocketConfig, WssPayloadTransport},
    };
    use std::time::Instant;

    let is_tls = url.starts_with("wss://") || url.starts_with("https://");

    if skip_tls_verify && is_tls {
        eprintln!("WARNING: TLS certificate verification is DISABLED (--skip-tls-verify).");
        eprintln!("         Use only for connectivity testing, never for production.");
    }

    // Load optional custom CA cert (for self-signed server certs).
    let custom_ca_pem = if let Some(path) = ca_cert {
        Some(
            std::fs::read(path)
                .with_context(|| format!("cannot read CA cert: {}", path.display()))?,
        )
    } else {
        None
    };

    let config = WebSocketConfig {
        tls_enabled: is_tls,
        custom_ca_pem,
        accept_invalid_certs: skip_tls_verify,
        connect_timeout_ms: timeout_secs * 1000,
        read_timeout_ms: timeout_secs * 1000,
        write_timeout_ms: timeout_secs * 1000,
        idle_timeout_ms: timeout_secs * 1000 * 2,
        ..WebSocketConfig::default()
    };

    let transport = WssPayloadTransport::new(config);

    let scheme = if is_tls { "WSS (TLS)" } else { "WS (plain)" };
    eprintln!("Probing {scheme} connection to: {url}");
    eprintln!("Timeout: {timeout_secs}s");

    let start = Instant::now();

    // Use an all-zeros dummy MID. The server will respond "share not found"
    // (data-phase error) if the connection works, or a session-phase error if
    // the transport itself is blocked.
    let result = transport.fetch_share(url, [0u8; 32], 0, 0).await;
    let elapsed = start.elapsed();

    match result {
        Ok(_) => {
            eprintln!(
                "\n✓ PASS — WSS connected and server returned a valid response ({elapsed:.2?})"
            );
            eprintln!("  TCP + WebSocket upgrade: OK");
            eprintln!("  This transport path is NOT blocked.");
        }
        Err(ref e) if e.phase == TransportPhase::Session => {
            eprintln!("\n✗ FAIL — connection blocked at transport layer ({elapsed:.2?})");
            eprintln!("  Error: {}", e.message);
            eprintln!("  Conclusion: TCP 443 / WebSocket is blocked on this network.");
            bail!("WSS probe failed (session): {}", e.message);
        }
        Err(ref e) => {
            // Data-phase error = connection worked, server just doesn't have shard 0
            eprintln!("\n✓ PASS — WSS connection established ({elapsed:.2?})");
            eprintln!("  TCP + WebSocket upgrade: OK");
            eprintln!(
                "  Server response (data-phase, expected for probe): {}",
                e.message
            );
            eprintln!("  Conclusion: this transport path IS functional.");
        }
    }

    Ok(())
}

// ─── Log file cleanup ───────────────────────────────────────────────────────

/// Remove old log files beyond `keep` count. Matches files starting with `prefix`.
fn cleanup_old_logs(dir: &std::path::Path, prefix: &str, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
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

#[cfg(test)]
mod transfer_password_tests {
    use super::read_transfer_password;

    fn file_with(contents: &str) -> tempfile::TempPath {
        let path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn no_source_means_no_password() {
        assert!(read_transfer_password(None, false).unwrap().is_none());
    }

    #[test]
    fn only_the_line_ending_is_stripped() {
        let unix = file_with("hunter2\n");
        let windows = file_with("hunter2\r\n");
        let bare = file_with("hunter2");
        for p in [&unix, &windows, &bare] {
            let got = read_transfer_password(Some(p.as_ref()), false)
                .unwrap()
                .unwrap();
            assert_eq!(got.as_str(), "hunter2");
        }
    }

    #[test]
    fn spaces_are_part_of_the_password() {
        let p = file_with("  two words and a trailing space \n");
        let got = read_transfer_password(Some(p.as_ref()), false)
            .unwrap()
            .unwrap();
        assert_eq!(got.as_str(), "  two words and a trailing space ");
    }

    #[test]
    fn only_the_first_line_is_used() {
        let p = file_with("first\nsecond\n");
        let got = read_transfer_password(Some(p.as_ref()), false)
            .unwrap()
            .unwrap();
        assert_eq!(got.as_str(), "first");
    }

    #[test]
    fn an_empty_password_is_refused() {
        for body in ["", "\n", "\r\n"] {
            let p = file_with(body);
            assert!(
                read_transfer_password(Some(p.as_ref()), false).is_err(),
                "{body:?} must be refused"
            );
        }
    }

    #[test]
    fn a_missing_file_is_an_error_not_no_password() {
        let missing = std::path::Path::new("definitely/not/here.txt");
        assert!(read_transfer_password(Some(missing), false).is_err());
    }
}

#[cfg(test)]
mod transfer_progress_tests {
    use super::{format_progress_in, human_bytes, human_duration, Lang};
    use miasma_core::transfer::{Phase, TransferKind, TransferState, TransferStatus};

    /// These tests pin the English wording, whatever language the machine
    /// running them is set to.
    fn format_progress(s: &TransferStatus) -> String {
        format_progress_in(s, Lang::En)
    }

    /// The digits of a line, in order, as separate numbers: what a person
    /// comparing the English and Japanese lines would line up.
    fn numbers(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        for c in line.chars() {
            if c.is_ascii_digit() {
                cur.push(c);
            } else if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    #[test]
    fn the_japanese_line_carries_the_same_numbers_in_the_same_order() {
        let mut cases = Vec::new();
        cases.push(status());
        let mut s = status();
        s.pieces_rejected = 3;
        s.segment_retries = 2;
        cases.push(s);
        let mut s = status();
        s.kind = TransferKind::Send;
        s.fetch_ms = 7_000;
        s.decode_ms = 3_000;
        s.write_ms = 0;
        cases.push(s);
        let mut s = status();
        s.bytes_total = 0;
        s.eta_secs = None;
        s.rate_bps = 0.0;
        cases.push(s);
        for kind in [TransferKind::Receive, TransferKind::Send] {
            for phase in [
                Phase::Preparing,
                Phase::Hashing,
                Phase::Verifying,
                Phase::Finalizing,
            ] {
                let mut s = status();
                s.kind = kind;
                s.phase = phase;
                s.bytes_done = 5 * 1024 * 1024 * 1024;
                cases.push(s);
            }
        }
        for s in &cases {
            let en = format_progress_in(s, Lang::En);
            let ja = format_progress_in(s, Lang::Ja);
            assert_ne!(en, ja, "{:?}/{:?} is not translated", s.kind, s.phase);
            assert_eq!(numbers(&en), numbers(&ja), "\nen: {en}\nja: {ja}");
            // Units are kept as they are.
            for unit in ["GiB", "MiB/s", "ETA"] {
                assert_eq!(en.contains(unit), ja.contains(unit), "{unit}: {ja}");
            }
        }
    }

    #[test]
    fn the_japanese_running_line_has_the_same_fields_in_the_same_order() {
        let ja = format_progress_in(&status(), Lang::Ja);
        let at = |needle: &str| {
            ja.find(needle)
                .unwrap_or_else(|| panic!("{needle:?} missing: {ja}"))
        };
        let order = [
            at("42.2%"),
            at("セグメント 27/64"),
            at("1.7 GiB / 4.0 GiB"),
            at("85.0 MiB/s"),
            at("ETA 00:00:42"),
            at("取得 60% 復元 8% 書き込み 32%"),
        ];
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{ja}");
    }

    fn status() -> TransferStatus {
        TransferStatus {
            mid: "miasma:x".into(),
            kind: TransferKind::Receive,
            name: "out.bin".into(),
            phase: Phase::Transferring,
            state: TransferState::Running,
            segments_done: 27,
            segments_total: 64,
            bytes_done: 27 * 64 * 1024 * 1024,
            bytes_total: 64 * 64 * 1024 * 1024,
            rate_bps: 85.0 * 1_048_576.0,
            eta_secs: Some(42),
            elapsed_secs: 20.0,
            fetch_ms: 6_000,
            decode_ms: 800,
            write_ms: 3_200,
            pieces_fetched: 270,
            pieces_rejected: 0,
            segment_retries: 0,
            resumed_from_segment: 0,
            last_error: None,
            resumable: false,
        }
    }

    #[test]
    fn sizes_are_binary_and_human() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(17), "17 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(64 * 1024 * 1024), "64.0 MiB");
        assert_eq!(human_bytes(100 * 1024 * 1024 * 1024), "100.0 GiB");
    }

    #[test]
    fn durations_are_hh_mm_ss() {
        assert_eq!(human_duration(0), "00:00:00");
        assert_eq!(human_duration(42), "00:00:42");
        assert_eq!(human_duration(3_725), "01:02:05");
    }

    #[test]
    fn a_running_transfer_shows_percent_segments_size_rate_eta_and_where_time_goes() {
        let line = format_progress(&status());
        assert!(line.contains("42.2%"), "{line}");
        assert!(line.contains("seg 27/64"), "{line}");
        assert!(line.contains("1.7 GiB / 4.0 GiB"), "{line}");
        assert!(line.contains("85.0 MiB/s"), "{line}");
        assert!(line.contains("ETA 00:00:42"), "{line}");
        assert!(line.contains("fetch 60% decode 8% write 32%"), "{line}");
        assert!(!line.contains("rejected"), "{line}");
        assert!(!line.contains("retries"), "{line}");
    }

    #[test]
    fn rejected_pieces_and_retries_are_called_out_only_when_they_happen() {
        let mut s = status();
        s.pieces_rejected = 3;
        s.segment_retries = 2;
        let line = format_progress(&s);
        assert!(line.contains("rejected pieces: 3"), "{line}");
        assert!(line.contains("retries: 2"), "{line}");
    }

    #[test]
    fn other_phases_say_what_is_happening_instead_of_a_bar() {
        let mut s = status();
        s.phase = Phase::Preparing;
        assert!(format_progress(&s).contains("looking up"));
        s.phase = Phase::Verifying;
        assert!(format_progress(&s).contains("verifying"));
        s.phase = Phase::Finalizing;
        assert!(format_progress(&s).contains("MID"));
    }

    #[test]
    fn hashing_and_sending_have_their_own_wording() {
        let mut s = status();
        s.kind = TransferKind::Send;
        s.phase = Phase::Hashing;
        s.bytes_done = 5 * 1024 * 1024 * 1024;
        s.bytes_total = 100 * 1024 * 1024 * 1024;
        let line = format_progress(&s);
        assert!(line.contains("hashing"), "{line}");
        assert!(line.contains("5.0 GiB / 100.0 GiB"), "{line}");

        s.phase = Phase::Transferring;
        s.bytes_done = 25 * 1024 * 1024 * 1024;
        s.fetch_ms = 7_000;
        s.decode_ms = 3_000;
        s.write_ms = 0;
        let line = format_progress(&s);
        assert!(line.contains("store+push 70% dissolve 30%"), "{line}");
        assert!(!line.contains("fetch"), "a send does not fetch: {line}");

        s.phase = Phase::Finalizing;
        assert!(format_progress(&s).contains("announcing"));
        s.phase = Phase::Verifying;
        assert!(format_progress(&s).contains("already published"));
    }

    #[test]
    fn an_unknown_total_still_renders() {
        // A legacy record has no manifest, so no byte total.
        let mut s = status();
        s.bytes_total = 0;
        let line = format_progress(&s);
        assert!(line.contains("seg 27/64"), "{line}");
        assert!(line.contains("1.7 GiB"), "{line}");
    }

    #[test]
    fn a_complete_transfer_is_a_full_bar_and_never_over_100() {
        let mut s = status();
        s.bytes_done = s.bytes_total + 12345;
        let line = format_progress(&s);
        assert!(line.contains("100.0%"), "{line}");
        assert!(line.contains(&"#".repeat(24)), "{line}");
    }
}

#[cfg(test)]
mod transfers_listing {
    use super::{resume_hint_in, transfer_heading_in, Lang};
    use miasma_core::transfer::{Phase, TransferKind, TransferState, TransferStatus};

    // The English wording is what these tests pin, whatever the machine's language.
    fn transfer_heading(s: &TransferStatus) -> String {
        transfer_heading_in(s, Lang::En)
    }
    fn resume_hint(s: &TransferStatus) -> String {
        resume_hint_in(s, Lang::En)
    }

    fn status(kind: TransferKind, mid: &str, name: &str) -> TransferStatus {
        TransferStatus {
            mid: mid.into(),
            kind,
            name: name.into(),
            phase: Phase::Transferring,
            state: TransferState::Paused,
            segments_done: 1,
            segments_total: 3,
            bytes_done: 1,
            bytes_total: 3,
            rate_bps: 0.0,
            eta_secs: None,
            elapsed_secs: 0.0,
            fetch_ms: 0,
            decode_ms: 0,
            write_ms: 0,
            pieces_fetched: 0,
            pieces_rejected: 0,
            segment_retries: 0,
            resumed_from_segment: 0,
            last_error: None,
            resumable: true,
        }
    }

    #[test]
    fn a_receive_is_headed_by_its_mid_and_output() {
        let s = status(TransferKind::Receive, "miasma:abc", "D:/recv/file.bin");
        assert_eq!(
            transfer_heading(&s),
            "receive  miasma:abc  ->  D:/recv/file.bin"
        );
        let hint = resume_hint(&s);
        assert!(
            hint.contains("network-get miasma:abc -o D:/recv/file.bin"),
            "{hint}"
        );
    }

    #[test]
    fn a_send_is_headed_by_its_file_and_shows_the_mid_once_known() {
        let hashing = status(TransferKind::Send, "", "/data/big.bin");
        assert_eq!(transfer_heading(&hashing), "send     /data/big.bin");
        let known = status(TransferKind::Send, "miasma:xyz", "/data/big.bin");
        assert_eq!(
            transfer_heading(&known),
            "send     /data/big.bin  (miasma:xyz)"
        );
        let hint = resume_hint(&known);
        assert!(hint.contains("network-publish /data/big.bin"), "{hint}");
    }

    #[test]
    fn in_japanese_the_ids_and_the_command_are_unchanged() {
        let s = status(TransferKind::Receive, "miasma:abc", "D:/recv/file.bin");
        let heading = transfer_heading_in(&s, Lang::Ja);
        assert!(
            heading.contains("miasma:abc") && heading.contains("D:/recv/file.bin"),
            "{heading}"
        );
        assert!(!heading.starts_with("receive"), "{heading}");
        let hint = resume_hint_in(&s, Lang::Ja);
        assert!(
            hint.contains("`miasma network-get miasma:abc -o D:/recv/file.bin`"),
            "{hint}"
        );
        let send = status(TransferKind::Send, "", "/data/big.bin");
        assert!(resume_hint_in(&send, Lang::Ja).contains("`miasma network-publish /data/big.bin`"));
    }
}

#[cfg(test)]
mod redundancy_bench_args {
    use super::parse_preset;

    #[test]
    fn k_over_n_parses_with_or_without_spaces() {
        assert_eq!(parse_preset("10/12").unwrap(), (10, 12));
        assert_eq!(parse_preset(" 10 / 20 ").unwrap(), (10, 20));
        assert_eq!(parse_preset("10/10").unwrap(), (10, 10));
    }

    #[test]
    fn nonsense_is_refused_with_a_reason() {
        for bad in [
            "", "10", "10/", "/12", "a/b", "0/5", "12/10", "10/300", "10-12",
        ] {
            assert!(parse_preset(bad).is_err(), "{bad:?} must be refused");
        }
    }
}
