/// miasma-desktop — Cross-platform GUI (daemon-centric IPC).
///
/// # Architecture
/// ```text
/// ┌──────────────────────────────────────────────────┐
/// │  eframe window (egui immediate-mode)             │
/// │  ┌───────────────────────────────────────────┐   │
/// │  │  MiasmaApp                                │   │
/// │  │  [Dissolve] [Retrieve] [Status] [Settings]│   │
/// │  └───────────────────────────────────────────┘   │
/// │                                                  │
/// │  worker OS thread ── IPC ──► local daemon        │
/// │      mpsc channels (WorkerCmd / WorkerResult)    │
/// └──────────────────────────────────────────────────┘
/// ```
mod app;
mod worker;

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

    let version = env!("CARGO_PKG_VERSION");
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 680.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title(format!("Miasma v{version}")),
        ..Default::default()
    };

    eframe::run_native(
        "Miasma",
        native_options,
        Box::new(|cc| Box::new(app::MiasmaApp::new(cc))),
    )
}
