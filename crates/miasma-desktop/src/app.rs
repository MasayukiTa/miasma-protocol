/// MiasmaApp — egui application with daemon-centric IPC.
///
/// 4-tab layout: Dissolve | Retrieve | Status | Settings
///
/// All operations go through the local daemon's IPC control plane.
/// If the daemon is not running, the UI shows a clear actionable error.
use eframe::egui;

use crate::worker::{WorkerCmd, WorkerHandle, WorkerResult};

// ─── Tab enum ─────────────────────────────────────────────────────────────────

#[derive(PartialEq, Eq, Clone, Copy, Default)]
enum Tab {
    #[default]
    Dissolve,
    Retrieve,
    Status,
    Settings,
}

// ─── App struct ───────────────────────────────────────────────────────────────

pub struct MiasmaApp {
    worker: WorkerHandle,
    tab: Tab,

    // Dissolve panel
    dissolve_text: String,
    last_mid: Option<String>,

    // Retrieve panel
    mid_input: String,
    retrieved_summary: Option<String>,
    save_data: Option<Vec<u8>>,

    // Status (from daemon)
    peer_id: String,
    peer_count: usize,
    share_count: usize,
    used_mb: f64,
    pending_replication: usize,
    replicated_count: usize,
    listen_addrs: Vec<String>,

    // Settings
    data_dir_display: String,

    // General
    busy: bool,
    status_msg: Option<String>,
    show_wipe_confirm: bool,
}

impl MiasmaApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let data_dir = miasma_core::default_data_dir();
        let worker = WorkerHandle::spawn(data_dir.clone());

        // Seed initial status from daemon.
        let _ = worker.tx.try_send(WorkerCmd::GetStatus);

        Self {
            worker,
            tab: Tab::default(),
            dissolve_text: String::new(),
            last_mid: None,
            mid_input: String::new(),
            retrieved_summary: None,
            save_data: None,
            peer_id: String::new(),
            peer_count: 0,
            share_count: 0,
            used_mb: 0.0,
            pending_replication: 0,
            replicated_count: 0,
            listen_addrs: Vec::new(),
            data_dir_display: data_dir.to_string_lossy().into_owned(),
            busy: false,
            status_msg: None,
            show_wipe_confirm: false,
        }
    }

    // poll worker responses (called every frame)
    fn poll_worker(&mut self) {
        while let Ok(res) = self.worker.rx.try_recv() {
            self.busy = false;
            match res {
                WorkerResult::Dissolved { mid } => {
                    self.last_mid = Some(mid);
                    self.status_msg = Some("Dissolution complete — MID ready.".into());
                }
                WorkerResult::Retrieved { mid, data } => {
                    self.retrieved_summary = Some(format!(
                        "Retrieved {} bytes  ({})",
                        data.len(),
                        &mid[..mid.len().min(30)]
                    ));
                    self.save_data = Some(data);
                    self.status_msg = Some("Retrieved. Click 'Save to File…' to export.".into());
                }
                WorkerResult::Status {
                    peer_id,
                    peer_count,
                    share_count,
                    used_mb,
                    pending_replication,
                    replicated_count,
                    listen_addrs,
                } => {
                    self.peer_id = peer_id;
                    self.peer_count = peer_count;
                    self.share_count = share_count;
                    self.used_mb = used_mb;
                    self.pending_replication = pending_replication;
                    self.replicated_count = replicated_count;
                    self.listen_addrs = listen_addrs;
                }
                WorkerResult::Wiped => {
                    self.last_mid = None;
                    self.save_data = None;
                    self.show_wipe_confirm = false;
                    self.status_msg = Some("WIPED — all shares are now unreadable.".into());
                }
                WorkerResult::Err(e) => {
                    self.status_msg = Some(format!("Error: {e}"));
                }
            }
        }
    }

    // Dissolve panel
    fn dissolve_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Dissolve — Store content into Miasma");
        ui.separator();

        ui.label("Paste text or use the file picker:");
        ui.add(
            egui::TextEdit::multiline(&mut self.dissolve_text)
                .hint_text("Paste text here…")
                .desired_rows(6)
                .desired_width(f32::INFINITY),
        );

        ui.horizontal(|ui| {
            if ui.button("Load File…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    let _ = self.worker.tx.try_send(WorkerCmd::DissolveFile(path));
                    self.busy = true;
                    self.status_msg = Some("Dissolving file…".into());
                }
            }

            ui.add_enabled_ui(!self.dissolve_text.is_empty() && !self.busy, |ui| {
                if ui.button("Dissolve Text").clicked() {
                    let _ = self
                        .worker
                        .tx
                        .try_send(WorkerCmd::DissolveText(self.dissolve_text.clone()));
                    self.busy = true;
                    self.status_msg = Some("Dissolving…".into());
                }
            });

            if self.busy {
                ui.spinner();
            }
        });

        if let Some(mid) = self.last_mid.clone() {
            ui.separator();
            ui.label("Miasma Content Identifier (MID):");

            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut mid.clone())
                        .desired_width(ui.available_width() - 100.0),
                );
                if ui.button("Copy").clicked() {
                    ui.output_mut(|o| o.copied_text = mid.clone());
                }
            });
        }
    }

    // Retrieve panel
    fn retrieve_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Retrieve — Reconstruct content from Miasma");
        ui.separator();

        ui.label("Enter MID (miasma:…):");
        ui.add(
            egui::TextEdit::singleline(&mut self.mid_input)
                .hint_text("miasma:<base58>")
                .desired_width(f32::INFINITY),
        );

        ui.horizontal(|ui| {
            ui.add_enabled_ui(!self.mid_input.is_empty() && !self.busy, |ui| {
                if ui.button("Retrieve").clicked() {
                    let _ = self
                        .worker
                        .tx
                        .try_send(WorkerCmd::Retrieve(self.mid_input.clone()));
                    self.busy = true;
                    self.status_msg = Some("Retrieving…".into());
                }
            });

            if self.busy {
                ui.spinner();
            }
        });

        if let Some(summary) = &self.retrieved_summary {
            ui.separator();
            ui.label(summary);
        }

        if self.save_data.is_some() {
            if ui.button("Save to File…").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("retrieved.bin")
                    .save_file()
                {
                    if let Some(data) = &self.save_data {
                        match std::fs::write(&path, data) {
                            Ok(_) => {
                                self.status_msg =
                                    Some(format!("Saved -> {}", path.display()));
                            }
                            Err(e) => {
                                self.status_msg = Some(format!("Save failed: {e}"));
                            }
                        }
                    }
                }
            }
        }
    }

    // Status panel
    fn status_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Daemon Status");
        ui.separator();

        if ui.button("Refresh").clicked() {
            let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
        }

        egui::Grid::new("status_grid")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Peer ID:");
                if self.peer_id.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "(not connected)");
                } else {
                    ui.label(&self.peer_id);
                }
                ui.end_row();

                ui.label("Connected peers:");
                ui.label(self.peer_count.to_string());
                ui.end_row();

                ui.label("Shares stored:");
                ui.label(self.share_count.to_string());
                ui.end_row();

                ui.label("Storage used:");
                ui.label(format!("{:.1} MiB", self.used_mb));
                ui.end_row();

                ui.label("Pending replication:");
                ui.label(self.pending_replication.to_string());
                ui.end_row();

                ui.label("Replicated:");
                ui.label(self.replicated_count.to_string());
                ui.end_row();

                ui.label("Listen addresses:");
                if self.listen_addrs.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "(none)");
                } else {
                    ui.vertical(|ui| {
                        for addr in &self.listen_addrs {
                            ui.label(addr);
                        }
                    });
                }
                ui.end_row();

                ui.label("Data directory:");
                ui.label(&self.data_dir_display);
                ui.end_row();
            });

        ui.separator();
        ui.separator();

        ui.horizontal(|ui| {
            ui.colored_label(egui::Color32::RED, "Emergency Wipe");
        });
        ui.label("Deletes the master key. All stored shares become permanently unreadable.");

        if ui
            .button(egui::RichText::new("WIPE ALL SHARES").color(egui::Color32::RED))
            .clicked()
        {
            self.show_wipe_confirm = true;
        }
    }

    // Settings panel
    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();

        egui::Grid::new("settings_grid")
            .num_columns(2)
            .min_col_width(120.0)
            .show(ui, |ui| {
                ui.label("Data directory:");
                ui.label(&self.data_dir_display);
                ui.end_row();
            });

        ui.separator();
        ui.add_space(8.0);

        ui.label("The desktop GUI connects to the local miasma daemon.");
        ui.label("Start the daemon with:");
        ui.monospace("  miasma daemon");

        ui.separator();
        ui.add_space(8.0);
        ui.label("Version: miasma-desktop 0.2.0 (daemon IPC)");
    }
}

// ─── eframe::App impl ─────────────────────────────────────────────────────────

impl eframe::App for MiasmaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();

        // Top tab bar.
        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Dissolve, "Dissolve");
                ui.selectable_value(&mut self.tab, Tab::Retrieve, "Retrieve");
                ui.selectable_value(&mut self.tab, Tab::Status, "Status");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
            });
        });

        // Bottom status bar.
        if let Some(msg) = &self.status_msg.clone() {
            egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(msg);
                    if ui.small_button("x").clicked() {
                        self.status_msg = None;
                    }
                });
            });
        }

        // Central panel.
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.tab {
                    Tab::Dissolve => self.dissolve_panel(ui),
                    Tab::Retrieve => self.retrieve_panel(ui),
                    Tab::Status => self.status_panel(ui),
                    Tab::Settings => self.settings_panel(ui),
                }
            });
        });

        // Wipe confirmation modal.
        if self.show_wipe_confirm {
            egui::Window::new("Emergency Wipe Confirmation")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label("This will permanently destroy the master key.");
                    ui.label("ALL stored shares will become UNREADABLE immediately.");
                    ui.label("This action CANNOT be undone.");
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .button(
                                egui::RichText::new("WIPE NOW")
                                    .color(egui::Color32::WHITE)
                                    .background_color(egui::Color32::RED),
                            )
                            .clicked()
                        {
                            let _ = self.worker.tx.try_send(WorkerCmd::Wipe);
                            self.busy = true;
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_wipe_confirm = false;
                        }
                    });
                });
        }
    }
}
