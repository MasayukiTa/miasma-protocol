#![allow(dead_code)]

/// MiasmaApp — egui application state (Phase 3, Task 22).
///
/// Phase 3: replace stubs with real egui widgets.
use std::sync::{Arc, Mutex};

// ─── Shared state ─────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct AppState {
    pub data_dir: String,
    pub storage_mb: u64,
    pub bandwidth_mb_day: u64,

    // Dissolve panel
    pub dissolve_text: String,
    pub last_mid: Option<String>,

    // Retrieve panel
    pub mid_input: String,
    pub retrieved_bytes: Option<Vec<u8>>,

    // Status
    pub share_count: u64,
    pub used_mb: f64,
    pub quota_mb: u64,

    pub error: Option<String>,
    pub is_loading: bool,
}

/// egui App struct.
///
/// Phase 3: derive `eframe::App` and implement `update()`.
pub struct MiasmaApp {
    state: Arc<Mutex<AppState>>,
    active_tab: Tab,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Dissolve,
    Retrieve,
    Status,
}

impl MiasmaApp {
    /// Called by eframe to create the app.
    pub fn new(data_dir: String, storage_mb: u64, bandwidth_mb_day: u64) -> Self {
        let state = Arc::new(Mutex::new(AppState {
            data_dir,
            storage_mb,
            bandwidth_mb_day,
            ..Default::default()
        }));

        Self {
            state,
            active_tab: Tab::Dissolve,
        }
    }

    // Phase 3: implement eframe::App::update() with egui widgets.
    // pub fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
    //     egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
    //         ui.horizontal(|ui| {
    //             ui.selectable_value(&mut self.active_tab, Tab::Dissolve, "Dissolve");
    //             ui.selectable_value(&mut self.active_tab, Tab::Retrieve, "Retrieve");
    //             ui.selectable_value(&mut self.active_tab, Tab::Status, "Status");
    //         });
    //     });
    //     egui::CentralPanel::default().show(ctx, |ui| {
    //         match self.active_tab {
    //             Tab::Dissolve => self.dissolve_panel(ui),
    //             Tab::Retrieve => self.retrieve_panel(ui),
    //             Tab::Status   => self.status_panel(ui),
    //         }
    //     });
    // }
}
