/// miasma-desktop — Cross-platform GUI (Phase 3, Task 22).
///
/// # Architecture
/// The desktop GUI uses **egui** (immediate-mode, no Electron, no WebView):
///
/// ```text
/// ┌─────────────────────────────────┐
/// │       eframe window             │
/// │  ┌─────────────────────────┐    │
/// │  │  MiasmaApp (egui)        │    │
/// │  │  ┌──────┬──────┬──────┐ │    │
/// │  │  │Dissolve│Retrieve│Status│   │
/// │  │  └──────┴──────┴──────┘ │    │
/// │  └─────────────────────────┘    │
/// │  Tokio runtime (background)     │
/// │  ↕ miasma-core FFI              │
/// └─────────────────────────────────┘
/// ```
///
/// # Phase 3 implementation plan
/// 1. Add `egui`/`eframe` to Cargo.toml.
/// 2. Implement `MiasmaApp: eframe::App` with three panels:
///    - **Dissolve**: drag-and-drop file or paste text → shows QR code of MID.
///    - **Retrieve**: MID text input + QR scanner (rqrr crate) → save-as dialog.
///    - **Status**: node metrics, quota sliders, emergency wipe button.
/// 3. Run the Miasma node in a separate tokio thread; communicate via channels.
///
/// # Binary size target
/// With LTO + strip: ≤ 25 MB on Linux (well within the ≤ 60 MB PRD target).
mod app;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "miasma_desktop=info".into()),
        )
        .init();

    // Phase 3: launch eframe window.
    // eframe::run_native(
    //     "Miasma",
    //     eframe::NativeOptions::default(),
    //     Box::new(|cc| Box::new(app::MiasmaApp::new(cc))),
    // ).expect("GUI launch failed");

    println!("miasma-desktop: Phase 3 GUI stub. Build with egui feature enabled.");
    println!("Use `miasma-cli` for the full feature set in the meantime.");
}
