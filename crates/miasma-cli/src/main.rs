use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "miasma", about = "Miasma Protocol CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a Miasma node (storage/bandwidth config)
    Init {
        /// Storage quota in MB
        #[arg(long, default_value = "10240")]
        storage_mb: u64,
        /// Bandwidth quota in MB/day
        #[arg(long, default_value = "1024")]
        bandwidth_mb_day: u64,
    },
    /// Dissolve a file into the Miasma network
    Dissolve {
        /// Path to the file to dissolve
        path: String,
    },
    /// Retrieve content by MID
    Get {
        /// Miasma Content ID (miasma:<base58>)
        mid: String,
    },
    /// Show node status
    Status,
    /// Emergency wipe (zeroes all local key material within 5 seconds)
    Wipe {
        /// Required confirmation flag
        #[arg(long)]
        confirm: bool,
    },
    /// Manage node configuration
    Config {
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        value: Option<String>,
    },
    /// Run in daemon mode (systemd compatible)
    Daemon,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("miasma=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { storage_mb, bandwidth_mb_day } => {
            println!("Initializing Miasma node...");
            println!("  Storage quota:    {} MB", storage_mb);
            println!("  Bandwidth quota:  {} MB/day", bandwidth_mb_day);
            println!("[TODO] Phase 1 implementation pending");
        }
        Commands::Dissolve { path } => {
            println!("Dissolving file: {}", path);
            println!("[TODO] Phase 1 implementation pending");
        }
        Commands::Get { mid } => {
            println!("Retrieving MID: {}", mid);
            println!("[TODO] Phase 1 implementation pending");
        }
        Commands::Status => {
            println!("Miasma node status");
            println!("[TODO] Phase 1 implementation pending");
        }
        Commands::Wipe { confirm } => {
            if !confirm {
                eprintln!("ERROR: --confirm flag required for wipe. This operation is irreversible.");
                std::process::exit(1);
            }
            println!("EMERGENCY WIPE initiated...");
            println!("[TODO] Phase 1 implementation pending");
        }
        Commands::Config { key, value } => {
            match (key, value) {
                (Some(k), Some(v)) => println!("Setting {} = {}", k, v),
                (Some(k), None) => println!("Getting {}", k),
                _ => println!("Usage: miasma config --key <key> [--value <value>]"),
            }
            println!("[TODO] Phase 1 implementation pending");
        }
        Commands::Daemon => {
            println!("Starting Miasma daemon...");
            println!("[TODO] Phase 1 implementation pending");
        }
    }

    Ok(())
}
