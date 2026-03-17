/// miasma-desktop — Cross-platform GUI (Phase 3, Task 22).
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
/// │  worker OS thread ← miasma-core (local store)    │
/// │      mpsc channels (WorkerCmd / WorkerResult)     │
/// └──────────────────────────────────────────────────┘
/// ```
mod app;
mod worker;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "miasma_desktop=info".into()),
        )
        .init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 680.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title("Miasma"),
        ..Default::default()
    };

    eframe::run_native(
        "Miasma",
        native_options,
        Box::new(|cc| Box::new(app::MiasmaApp::new(cc))),
    )
}
