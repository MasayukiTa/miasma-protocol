// Prevent console window on Windows when launched as a GUI app.
#![cfg_attr(windows, windows_subsystem = "windows")]

//! miasma-desktop — Cross-platform GUI (daemon-centric IPC).
//!
//! # Architecture
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  eframe window (egui immediate-mode)             │
//! │  ┌───────────────────────────────────────────┐   │
//! │  │  MiasmaApp                                │   │
//! │  │  [Store] [Retrieve] [Status] [Settings]   │   │
//! │  └───────────────────────────────────────────┘   │
//! │                                                  │
//! │  worker OS thread ── IPC ──► local daemon        │
//! │      mpsc channels (WorkerCmd / WorkerResult)    │
//! └──────────────────────────────────────────────────┘
//! ```

mod app;
pub mod locale;
pub mod variant;
mod worker;

/// What triggered this launch — normal startup, or a file/URI association.
#[derive(Debug, Clone)]
pub enum LaunchIntent {
    /// Normal launch (no special args).
    Normal,
    /// Launched with a `magnet:` URI (e.g., from browser or shell).
    Magnet(String),
    /// Launched with a `.torrent` file path (e.g., from Explorer "Open with").
    TorrentFile(std::path::PathBuf),
}

/// Parse command-line arguments for launch intent.
///
/// Scans for magnet URIs and .torrent file paths after skipping the executable
/// name and any `--mode` / `--mode <value>` arguments.
fn parse_launch_intent() -> LaunchIntent {
    for arg in std::env::args().skip(1) {
        // Skip known flags.
        if arg == "--mode" || arg == "easy" || arg == "technical" {
            continue;
        }
        if arg.starts_with("magnet:") {
            return LaunchIntent::Magnet(arg);
        }
        let path = std::path::Path::new(&arg);
        if path.extension().and_then(|e| e.to_str()) == Some("torrent") && path.exists() {
            return LaunchIntent::TorrentFile(path.to_path_buf());
        }
    }
    LaunchIntent::Normal
}

fn main() -> eframe::Result<()> {
    // Logging: stderr + file in data dir.
    let data_dir = miasma_core::default_data_dir();
    let _ = std::fs::create_dir_all(&data_dir);
    let file_appender = tracing_appender::rolling::daily(&data_dir, "desktop.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let filter = tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
            .unwrap_or_else(|_| "miasma_desktop=info,miasma_core=info".parse().unwrap());
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
    }

    // Stamp version for future upgrade detection.
    miasma_core::config::stamp_version(&data_dir, env!("CARGO_PKG_VERSION"));

    // Resolve product mode: CLI arg > env var > persisted prefs > default.
    let prefs = variant::DesktopPrefs::load(&data_dir);
    let cli_mode = variant::parse_cli_mode();
    let mode = variant::resolve_mode(cli_mode, &prefs);
    let locale = prefs.locale;

    // Parse launch intent (magnet URI or .torrent file).
    let intent = parse_launch_intent();

    let version = env!("CARGO_PKG_VERSION");
    let title = match mode {
        variant::ProductMode::Technical => format!("Miasma v{version} (Technical Beta)"),
        variant::ProductMode::Easy => format!("Miasma v{version}"),
    };

    // Embedded 32x32 RGBA icon for the window titlebar and taskbar.
    let icon_rgba = include_bytes!("../assets/icon-32x32.rgba");
    let icon_data = egui::IconData {
        rgba: icon_rgba.to_vec(),
        width: 32,
        height: 32,
    };

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 680.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title(title)
            .with_icon(std::sync::Arc::new(icon_data)),
        ..Default::default()
    };

    eframe::run_native(
        "Miasma",
        native_options,
        Box::new(move |cc| Box::new(app::MiasmaApp::new(cc, mode, locale, intent))),
    )
}
