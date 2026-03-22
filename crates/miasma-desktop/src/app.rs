/// MiasmaApp — egui desktop application.
///
/// Layout: top tab bar, central content, bottom status bar.
/// Connection state machine: NeedsInit → Stopped → Starting → Connected
///
/// Supports two product modes (Technical / Easy) and three locales (EN / JA / ZH-CN).
/// Both modes share all backend code; only UI presentation differs.
use eframe::egui;

use crate::locale::{self, Locale, Strings};
use crate::variant::ProductMode;
use crate::worker::{DaemonState, WorkerCmd, WorkerHandle, WorkerResult};
use crate::LaunchIntent;

// ─── Font system ────────────────────────────────────────────────────────────

/// Configure fonts: load system CJK fonts for Japanese and Chinese rendering.
///
/// Font priority (per family):
///   Proportional: Segoe UI → Yu Gothic UI → Microsoft YaHei UI → egui default
///   Monospace:    Consolas → egui default monospace
///
/// On non-Windows or if system fonts are missing, falls back to egui's built-in
/// fonts (which cover Latin but not CJK — CJK will show as tofu).
fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Try to load Windows system fonts for CJK coverage.
    let font_dir = std::path::PathBuf::from(r"C:\Windows\Fonts");

    // Helper: try to load a font file and register it.
    let mut load_font = |name: &str, file: &str| -> bool {
        let path = font_dir.join(file);
        match std::fs::read(&path) {
            Ok(data) => {
                fonts.font_data.insert(
                    name.to_owned(),
                    egui::FontData::from_owned(data),
                );
                true
            }
            Err(_) => {
                tracing::debug!("Font not found: {}", path.display());
                false
            }
        }
    };

    // Load system fonts (all ship with Windows 10+).
    let has_segoe = load_font("Segoe UI", "segoeui.ttf");
    let has_segoe_bold = load_font("Segoe UI Bold", "segoeuib.ttf");
    let has_yu_gothic = load_font("Yu Gothic", "YuGothR.ttc");
    let has_msyh = load_font("Microsoft YaHei", "msyh.ttc");
    let has_consolas = load_font("Consolas", "consola.ttf");

    // Build proportional fallback chain.
    {
        let proportional = fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default();

        // Insert system fonts at the front (before egui defaults).
        let mut insert_pos = 0;
        if has_segoe {
            proportional.insert(insert_pos, "Segoe UI".to_owned());
            insert_pos += 1;
        }
        if has_segoe_bold {
            // Bold variant registered but not in the chain — used explicitly where needed.
        }
        if has_yu_gothic {
            proportional.insert(insert_pos, "Yu Gothic".to_owned());
            insert_pos += 1;
        }
        if has_msyh {
            proportional.insert(insert_pos, "Microsoft YaHei".to_owned());
            // insert_pos += 1; // not needed, last insert
        }
        // egui defaults remain at the end as final fallback.
    }

    // Build monospace fallback chain.
    {
        let monospace = fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default();

        if has_consolas {
            monospace.insert(0, "Consolas".to_owned());
        }
        // Add CJK fallback to monospace too (for diagnostics with CJK paths).
        if has_yu_gothic {
            // Insert after Consolas / default mono but before other fallbacks.
            let pos = if has_consolas { 1 } else { 0 };
            monospace.insert(pos, "Yu Gothic".to_owned());
        }
        if has_msyh {
            let pos = monospace.len().saturating_sub(1).max(1);
            monospace.insert(pos, "Microsoft YaHei".to_owned());
        }
    }

    ctx.set_fonts(fonts);

    // Dark theme with product feel.
    ctx.set_visuals(egui::Visuals::dark());

    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::proportional(14.0),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::proportional(13.5),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::proportional(20.0),
    );
    style.text_styles.insert(
        egui::TextStyle::Small,
        egui::FontId::proportional(11.5),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::monospace(12.5),
    );
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 5.0);
    style.spacing.window_margin = egui::Margin::same(12.0);

    // Softer window/panel backgrounds.
    style.visuals.window_fill = PANEL_BG;
    style.visuals.panel_fill = egui::Color32::from_rgb(20, 22, 26);
    style.visuals.widgets.noninteractive.bg_fill = CARD_BG;
    style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(40, 44, 52);
    style.visuals.widgets.inactive.weak_bg_fill = egui::Color32::from_rgb(40, 44, 52);
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(50, 55, 65);
    style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(60, 65, 78);
    style.visuals.selection.bg_fill = ACCENT.linear_multiply(0.3);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);

    // Rounder buttons.
    style.visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.active.rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(4.0);
    style.visuals.window_rounding = egui::Rounding::same(8.0);

    ctx.set_style(style);
}

// ─── Color palette ──────────────────────────────────────────────────────────

const GREEN: egui::Color32 = egui::Color32::from_rgb(46, 184, 106);
const YELLOW: egui::Color32 = egui::Color32::from_rgb(240, 180, 50);
const RED: egui::Color32 = egui::Color32::from_rgb(220, 70, 70);
const BLUE: egui::Color32 = egui::Color32::from_rgb(80, 160, 240);
const DIM: egui::Color32 = egui::Color32::from_rgb(150, 150, 160);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(90, 140, 220);
const CARD_BG: egui::Color32 = egui::Color32::from_rgb(32, 34, 40);
const PANEL_BG: egui::Color32 = egui::Color32::from_rgb(24, 26, 30);

// ─── Tab enum ───────────────────────────────────────────────────────────────

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Store,
    Retrieve,
    Status,
    Settings,
    Import,
}

// ─── App struct ─────────────────────────────────────────────────────────────

pub struct MiasmaApp {
    worker: WorkerHandle,
    tab: Tab,

    // Product mode and locale (persisted to desktop-prefs.toml)
    mode: ProductMode,
    locale: Locale,
    data_dir: std::path::PathBuf,

    // Connection state
    daemon_state: DaemonState,
    last_error: Option<String>,

    // Store panel
    dissolve_text: String,
    last_mid: Option<String>,

    // Retrieve panel
    mid_input: String,
    retrieved_summary: Option<String>,
    save_data: Option<Vec<u8>>,

    // Import panel (magnet/torrent)
    import_intent: Option<LaunchIntent>,
    import_state: ImportState,
    import_mids: Vec<String>,

    // Status (from daemon)
    peer_id: String,
    peer_count: usize,
    share_count: usize,
    used_mb: f64,
    quota_mb: u64,
    pending_replication: usize,
    replicated_count: usize,
    listen_addrs: Vec<String>,
    wss_port: u16,
    wss_tls_enabled: bool,
    proxy_configured: bool,
    proxy_type: Option<String>,
    obfs_quic_port: u16,
    transport_statuses: Vec<crate::worker::TransportStatusInfo>,

    // Settings / general
    data_dir_display: String,
    busy: bool,
    status_msg: Option<(String, MsgKind)>,
    show_wipe_confirm: bool,
    startup_time: std::time::Instant,
    last_status_poll: std::time::Instant,
    launch_attempts: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportState {
    /// No import in progress.
    Idle,
    /// Showing confirmation dialog.
    Confirming,
    /// Bridge is running.
    InProgress,
    /// Import succeeded.
    Complete,
    /// Import failed.
    Failed,
}

#[derive(Clone, Copy, PartialEq)]
enum MsgKind {
    Info,
    Success,
    Error,
}

impl MiasmaApp {
    pub fn new(cc: &eframe::CreationContext<'_>, mode: ProductMode, locale: Locale, intent: LaunchIntent) -> Self {
        configure_fonts(&cc.egui_ctx);

        let data_dir = miasma_core::default_data_dir();
        let worker = WorkerHandle::spawn(data_dir.clone());

        // If launched with a magnet/torrent intent, go to Import tab.
        let (initial_tab, import_intent, import_state) = match &intent {
            LaunchIntent::Normal => (Tab::Store, None, ImportState::Idle),
            LaunchIntent::Magnet(_) | LaunchIntent::TorrentFile(_) => {
                (Tab::Import, Some(intent), ImportState::Confirming)
            }
        };

        let now = std::time::Instant::now();

        Self {
            worker,
            tab: initial_tab,
            mode,
            locale,
            data_dir: data_dir.clone(),
            daemon_state: DaemonState::Stopped,
            last_error: None,
            dissolve_text: String::new(),
            last_mid: None,
            mid_input: String::new(),
            retrieved_summary: None,
            save_data: None,
            import_intent,
            import_state,
            import_mids: Vec::new(),
            peer_id: String::new(),
            peer_count: 0,
            share_count: 0,
            used_mb: 0.0,
            quota_mb: 0,
            pending_replication: 0,
            replicated_count: 0,
            listen_addrs: Vec::new(),
            wss_port: 0,
            wss_tls_enabled: false,
            proxy_configured: false,
            proxy_type: None,
            obfs_quic_port: 0,
            transport_statuses: Vec::new(),
            data_dir_display: data_dir.to_string_lossy().into_owned(),
            busy: false,
            status_msg: None,
            show_wipe_confirm: false,
            startup_time: now,
            last_status_poll: now,
            launch_attempts: 0,
        }
    }

    /// Current locale string table.
    fn s(&self) -> &'static Strings {
        locale::strings(self.locale)
    }

    fn set_msg(&mut self, kind: MsgKind, msg: impl Into<String>) {
        self.status_msg = Some((msg.into(), kind));
    }

    /// Persist current mode and locale to desktop-prefs.toml.
    fn save_prefs(&self) {
        let prefs = crate::variant::DesktopPrefs {
            mode: self.mode,
            locale: self.locale,
        };
        prefs.save(&self.data_dir);
    }

    // ── Poll worker ──────────────────────────────────────────────────────

    fn poll_worker(&mut self) {
        while let Ok(res) = self.worker.rx.try_recv() {
            match res {
                WorkerResult::Dissolved { mid } => {
                    self.busy = false;
                    self.last_mid = Some(mid);
                    self.set_msg(MsgKind::Success, self.s().store_success);
                }
                WorkerResult::Retrieved { mid, data } => {
                    self.busy = false;
                    let size = format_size(data.len() as u64);
                    self.retrieved_summary = Some(format!(
                        "{size}  — {}",
                        truncate_mid(&mid),
                    ));
                    self.save_data = Some(data);
                    self.set_msg(MsgKind::Success, self.s().retrieve_success);
                }
                WorkerResult::Status {
                    peer_id,
                    peer_count,
                    share_count,
                    used_mb,
                    quota_mb,
                    pending_replication,
                    replicated_count,
                    listen_addrs,
                    wss_port,
                    wss_tls_enabled,
                    proxy_configured,
                    proxy_type,
                    obfs_quic_port,
                    transport_statuses,
                } => {
                    self.busy = false;
                    self.peer_id = peer_id;
                    self.peer_count = peer_count;
                    self.share_count = share_count;
                    self.used_mb = used_mb;
                    self.quota_mb = quota_mb;
                    self.pending_replication = pending_replication;
                    self.replicated_count = replicated_count;
                    self.listen_addrs = listen_addrs;
                    self.wss_port = wss_port;
                    self.wss_tls_enabled = wss_tls_enabled;
                    self.proxy_configured = proxy_configured;
                    self.proxy_type = proxy_type;
                    self.obfs_quic_port = obfs_quic_port;
                    self.transport_statuses = transport_statuses;
                }
                WorkerResult::Wiped => {
                    self.busy = false;
                    self.last_mid = None;
                    self.save_data = None;
                    self.show_wipe_confirm = false;
                    self.set_msg(MsgKind::Error, self.s().wipe_done);
                }
                WorkerResult::StateChanged(state) => {
                    self.last_error = None;
                    self.daemon_state = state;
                }
                WorkerResult::Initialized => {
                    self.busy = false;
                    self.set_msg(MsgKind::Success, self.s().node_init_msg);
                }
                WorkerResult::ImportStarted { name } => {
                    self.import_state = ImportState::InProgress;
                    self.set_msg(MsgKind::Info, format!("{}: {name}", self.s().import_progress));
                }
                WorkerResult::ImportComplete { mids } => {
                    self.busy = false;
                    self.import_state = ImportState::Complete;
                    self.import_mids = mids;
                    self.set_msg(MsgKind::Success, self.s().import_complete);
                }
                WorkerResult::Err(e) => {
                    self.busy = false;
                    if self.import_state == ImportState::InProgress {
                        self.import_state = ImportState::Failed;
                    }
                    self.last_error = Some(e.clone());
                    self.set_msg(MsgKind::Error, e);
                }
            }
        }
    }

    // ── Connection header ────────────────────────────────────────────────

    fn connection_header(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let frame = egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(16.0, 14.0))
            .rounding(8.0);

        match self.daemon_state {
            DaemonState::Connected => {
                return;
            }
            DaemonState::NeedsInit => {
                let frame = frame.fill(egui::Color32::from_rgb(45, 40, 30));
                frame.show(ui, |ui| {
                    ui.vertical(|ui| {
                        let title = if easy { s.welcome_title_easy } else { s.welcome_title };
                        ui.label(
                            egui::RichText::new(title)
                                .size(18.0)
                                .strong(),
                        );
                        ui.add_space(6.0);
                        let desc = if easy { s.welcome_desc_easy } else { s.welcome_desc };
                        ui.label(desc);
                        ui.add_space(4.0);
                        let detail = if easy { s.welcome_detail_easy } else { s.welcome_detail };
                        ui.label(
                            egui::RichText::new(detail).color(DIM)
                        );
                        ui.add_space(10.0);
                        ui.add_enabled_ui(!self.busy, |ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new(s.welcome_button).strong().size(14.0),
                            );
                            if ui.add_sized([180.0, 36.0], btn).clicked() {
                                let _ = self.worker.tx.try_send(WorkerCmd::Init);
                                self.busy = true;
                                self.set_msg(MsgKind::Info, if easy { s.welcome_progress_easy } else { s.welcome_progress });
                            }
                        });
                        if self.busy {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.spinner();
                                let progress = if easy { s.welcome_progress_easy } else { s.welcome_progress };
                                ui.label(egui::RichText::new(progress).color(DIM));
                            });
                        }
                    });
                });
                ui.add_space(4.0);
            }
            DaemonState::Stopped => {
                let frame = frame.fill(egui::Color32::from_rgb(50, 30, 30));
                frame.show(ui, |ui| {
                    ui.vertical(|ui| {
                        let title = if easy { s.stopped_title_easy } else { s.stopped_title };
                        ui.label(
                            egui::RichText::new(title)
                                .size(14.0)
                                .color(RED),
                        );
                        ui.add_space(2.0);
                        if let Some(ref err) = self.last_error {
                            ui.label(egui::RichText::new(err).color(DIM).small());
                            ui.add_space(4.0);
                        } else {
                            let desc = if easy { s.stopped_desc_easy } else { s.stopped_desc };
                            ui.label(
                                egui::RichText::new(desc).color(DIM).small()
                            );
                            ui.add_space(4.0);
                        }
                        ui.horizontal(|ui| {
                            ui.add_enabled_ui(!self.busy, |ui| {
                                let btn_text = if easy { s.stopped_button_easy } else { s.stopped_button };
                                if ui
                                    .add_sized(
                                        [140.0, 28.0],
                                        egui::Button::new(btn_text),
                                    )
                                    .clicked()
                                {
                                    let _ = self.worker.tx.try_send(WorkerCmd::StartDaemon);
                                    self.busy = true;
                                    self.last_error = None;
                                    let label = if easy { s.starting_label_easy } else { s.starting_label };
                                    self.set_msg(MsgKind::Info, label);
                                }
                            });
                        });
                    });
                });
                ui.add_space(4.0);
            }
            DaemonState::Starting => {
                let frame = frame.fill(egui::Color32::from_rgb(30, 38, 50));
                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        let label = if easy { s.starting_label_easy } else { s.starting_label };
                        ui.label(egui::RichText::new(label).color(BLUE));
                    });
                });
                ui.add_space(4.0);
            }
        }
    }

    // ── Store panel ──────────────────────────────────────────────────────

    fn store_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;

        let heading = if easy { s.store_heading_easy } else { s.store_heading };
        section_heading(ui, heading);
        ui.add_space(4.0);
        let desc = if easy { s.store_desc_easy } else { s.store_desc };
        ui.label(egui::RichText::new(desc).color(DIM));
        ui.add_space(10.0);

        // Not-connected hint for Easy mode.
        if easy && !connected {
            card_frame().show(ui, |ui| {
                ui.colored_label(YELLOW, s.store_not_connected_hint);
            });
            ui.add_space(8.0);
        }

        // Text input card.
        card_frame().show(ui, |ui| {
            ui.label(s.store_text_label);
            ui.add_space(2.0);
            ui.add_enabled(
                connected,
                egui::TextEdit::multiline(&mut self.dissolve_text)
                    .hint_text(s.store_text_hint)
                    .desired_rows(if easy { 6 } else { 5 })
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                // Primary action button — accent for Easy, normal for Technical.
                ui.add_enabled_ui(
                    connected && !self.dissolve_text.is_empty() && !self.busy,
                    |ui| {
                        let btn = if easy {
                            egui::Button::new(
                                egui::RichText::new(s.store_button).strong().size(14.0),
                            ).fill(ACCENT)
                        } else {
                            egui::Button::new(s.store_button)
                        };
                        let size = if easy { [140.0, 34.0] } else { [120.0, 28.0] };
                        if ui.add_sized(size, btn).clicked() {
                            let _ = self
                                .worker
                                .tx
                                .try_send(WorkerCmd::DissolveText(self.dissolve_text.clone()));
                            self.busy = true;
                            self.set_msg(MsgKind::Info, s.store_busy);
                        }
                    },
                );

                ui.add_enabled_ui(connected && !self.busy, |ui| {
                    if ui
                        .add_sized([130.0, if easy { 34.0 } else { 28.0 }], egui::Button::new(s.store_choose_file))
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            let _ = self.worker.tx.try_send(WorkerCmd::DissolveFile(path));
                            self.busy = true;
                            self.set_msg(MsgKind::Info, s.store_busy);
                        }
                    }
                });

                if self.busy {
                    ui.spinner();
                }
            });
        });

        // MID result card.
        if let Some(ref mid) = self.last_mid.clone() {
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                let mid_label = if easy { s.store_mid_label_easy } else { s.store_mid_label };
                ui.label(egui::RichText::new(mid_label).strong().color(GREEN));
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let mut display = mid.clone();
                    ui.add(
                        egui::TextEdit::singleline(&mut display)
                            .desired_width(ui.available_width() - 80.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.add_sized([70.0, 26.0], egui::Button::new(s.store_copy)).clicked() {
                        ui.output_mut(|o| o.copied_text = mid.clone());
                        self.set_msg(MsgKind::Info, s.store_copied);
                    }
                });

                ui.add_space(4.0);
                let hint = if easy { s.store_share_hint_easy } else { s.store_share_hint };
                ui.label(
                    egui::RichText::new(hint)
                        .color(DIM)
                        .small(),
                );
            });
        }
    }

    // ── Retrieve panel ───────────────────────────────────────────────────

    fn retrieve_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;

        let heading = if easy { s.retrieve_heading_easy } else { s.retrieve_heading };
        section_heading(ui, heading);
        ui.add_space(4.0);
        let desc = if easy { s.retrieve_desc_easy } else { s.retrieve_desc };
        ui.label(egui::RichText::new(desc).color(DIM));
        ui.add_space(10.0);

        // Not-connected hint for Easy mode.
        if easy && !connected {
            card_frame().show(ui, |ui| {
                ui.colored_label(YELLOW, s.retrieve_not_connected_hint);
            });
            ui.add_space(8.0);
        }

        // Input card.
        card_frame().show(ui, |ui| {
            let mid_label = if easy { s.retrieve_mid_label_easy } else { s.retrieve_mid_label };
            ui.label(mid_label);
            ui.add_space(2.0);
            ui.add_enabled(
                connected,
                egui::TextEdit::singleline(&mut self.mid_input)
                    .hint_text("miasma:...")
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add_enabled_ui(
                    connected && !self.mid_input.is_empty() && !self.busy,
                    |ui| {
                        let label = if easy { s.retrieve_button_easy } else { s.retrieve_button };
                        let btn = if easy {
                            egui::Button::new(
                                egui::RichText::new(label).strong().size(14.0),
                            ).fill(ACCENT)
                        } else {
                            egui::Button::new(label)
                        };
                        let size = if easy { [140.0, 34.0] } else { [120.0, 28.0] };
                        if ui.add_sized(size, btn).clicked() {
                            let _ = self
                                .worker
                                .tx
                                .try_send(WorkerCmd::Retrieve(self.mid_input.clone()));
                            self.busy = true;
                            self.set_msg(MsgKind::Info, s.retrieve_busy);
                        }
                    },
                );

                if self.busy {
                    ui.spinner();
                }
            });
        });

        // Result card.
        if let Some(summary) = self.retrieved_summary.clone() {
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                ui.label(egui::RichText::new(s.retrieve_result_label).strong().color(GREEN));
                ui.add_space(2.0);
                ui.label(&summary);
                ui.add_space(6.0);

                if self.save_data.is_some() {
                    let save_btn = if easy {
                        egui::Button::new(
                            egui::RichText::new(s.retrieve_save_button).strong().size(14.0),
                        ).fill(ACCENT)
                    } else {
                        egui::Button::new(s.retrieve_save_button)
                    };
                    let size = if easy { [160.0, 34.0] } else { [140.0, 28.0] };
                    if ui.add_sized(size, save_btn).clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_file_name("retrieved.bin")
                            .save_file()
                        {
                            if let Some(data) = &self.save_data {
                                match std::fs::write(&path, data) {
                                    Ok(_) => {
                                        self.set_msg(
                                            MsgKind::Success,
                                            format!("{} {}", s.retrieve_saved, path.display()),
                                        );
                                    }
                                    Err(e) => {
                                        self.set_msg(MsgKind::Error, format!("{} {e}", s.retrieve_save_failed));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    // ── Status panel ─────────────────────────────────────────────────────

    fn status_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();

        section_heading(ui, s.status_heading);
        ui.add_space(4.0);

        // Action buttons — smaller row for Easy, full row for Technical.
        ui.horizontal(|ui| {
            if ui.add_sized([90.0, 26.0], egui::Button::new(s.status_refresh)).clicked() {
                let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
            }
            if !easy {
                if ui
                    .add_sized([160.0, 26.0], egui::Button::new(s.status_copy_diag))
                    .clicked()
                {
                    let diag = self.build_diagnostics();
                    ui.output_mut(|o| o.copied_text = diag);
                    self.set_msg(MsgKind::Info, s.status_diag_copied);
                }
            }
            // "Save Report" — available in both modes for support.
            if ui
                .add_sized([130.0, 26.0], egui::Button::new(s.status_save_diag))
                .clicked()
            {
                let diag = self.build_diagnostics();
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("miasma-diagnostics.txt")
                    .add_filter("Text files", &["txt"])
                    .save_file()
                {
                    match std::fs::write(&path, &diag) {
                        Ok(()) => self.set_msg(MsgKind::Success, format!("{} {}", s.status_diag_saved, path.display())),
                        Err(e) => self.set_msg(MsgKind::Error, format!("{}{e}", s.status_diag_save_failed)),
                    }
                }
            }
        });

        ui.add_space(8.0);

        if easy {
            self.status_panel_easy(ui);
        } else {
            self.status_panel_technical(ui);
        }

        // ── Emergency wipe ──────────────────────────────────────────
        ui.add_space(12.0);

        card_frame().show(ui, |ui| {
            ui.add_enabled_ui(self.daemon_state == DaemonState::Connected, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(s.wipe_label).color(RED).strong());
                    ui.label(
                        egui::RichText::new(s.wipe_desc)
                            .color(DIM)
                            .small(),
                    );
                });
                ui.add_space(4.0);
                if ui
                    .add_sized(
                        [160.0, 28.0],
                        egui::Button::new(
                            egui::RichText::new(s.wipe_button).color(RED),
                        ),
                    )
                    .clicked()
                {
                    self.show_wipe_confirm = true;
                }
            });
        });
    }

    /// Easy-mode status: simplified view — big status indicator + key numbers + next step.
    fn status_panel_easy(&self, ui: &mut egui::Ui) {
        let s = self.s();

        // Big status card.
        let (status_color, status_text, hint) = if self.daemon_state == DaemonState::Connected {
            if self.peer_count > 0 {
                (GREEN, s.status_ready, s.status_hint_ready)
            } else {
                (YELLOW, s.status_state_connected, s.status_hint_no_peers)
            }
        } else {
            (RED, s.status_not_ready, s.status_hint_not_ready)
        };

        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                // Status dot.
                let dot_rect = ui.allocate_space(egui::vec2(14.0, 14.0));
                ui.painter().circle_filled(
                    dot_rect.1.center(),
                    6.0,
                    status_color,
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(status_text)
                        .size(18.0)
                        .strong()
                        .color(status_color),
                );
            });

            ui.add_space(4.0);
            ui.label(egui::RichText::new(hint).color(DIM));

            if self.daemon_state == DaemonState::Connected {
                ui.add_space(10.0);

                egui::Grid::new("easy_status_grid")
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(s.status_items_stored).color(DIM));
                        ui.label(
                            egui::RichText::new(self.share_count.to_string())
                                .size(15.0)
                                .strong(),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new(s.status_peers).color(DIM));
                        let peer_text = self.peer_count.to_string();
                        if self.peer_count > 0 {
                            ui.label(
                                egui::RichText::new(peer_text).size(15.0).color(GREEN),
                            );
                        } else {
                            ui.label(egui::RichText::new(peer_text).size(15.0));
                        }
                        ui.end_row();

                        if self.quota_mb > 0 {
                            ui.label(egui::RichText::new(s.status_used).color(DIM));
                            let pct = (self.used_mb / self.quota_mb as f64) * 100.0;
                            let used_text = format!(
                                "{:.1} / {} MiB  ({:.0}%)",
                                self.used_mb, self.quota_mb, pct
                            );
                            if pct > 90.0 {
                                ui.colored_label(YELLOW, used_text);
                            } else {
                                ui.label(used_text);
                            }
                            ui.end_row();
                        }
                    });
            }
        });
    }

    /// Technical-mode status: full diagnostics with card grouping.
    fn status_panel_technical(&self, ui: &mut egui::Ui) {
        let s = self.s();

        // ── Connection & identity ─────────────────────────────────────
        card_frame().show(ui, |ui| {
        ui.label(egui::RichText::new(s.status_connection).strong().color(ACCENT));
        ui.add_space(4.0);

        egui::Grid::new("conn_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new(s.status_state).color(DIM));
                match self.daemon_state {
                    DaemonState::Connected => {
                        ui.colored_label(GREEN, s.status_state_connected);
                    }
                    DaemonState::Starting => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.colored_label(BLUE, s.status_state_starting);
                        });
                    }
                    DaemonState::Stopped => {
                        ui.colored_label(RED, s.status_state_not_running);
                    }
                    DaemonState::NeedsInit => {
                        ui.colored_label(YELLOW, s.status_state_not_init);
                    }
                }
                ui.end_row();

                ui.label(egui::RichText::new(s.status_peer_id).color(DIM));
                if self.peer_id.is_empty() {
                    ui.colored_label(DIM, "—");
                } else {
                    ui.label(
                        egui::RichText::new(&self.peer_id)
                            .font(egui::FontId::monospace(11.0)),
                    );
                }
                ui.end_row();

                ui.label(egui::RichText::new(s.status_peers).color(DIM));
                let peer_text = self.peer_count.to_string();
                if self.peer_count > 0 {
                    ui.colored_label(GREEN, peer_text);
                } else {
                    ui.label(peer_text);
                }
                ui.end_row();

                if !self.listen_addrs.is_empty() {
                    ui.label(egui::RichText::new(s.status_listening).color(DIM));
                    ui.vertical(|ui| {
                        for addr in &self.listen_addrs {
                            ui.label(
                                egui::RichText::new(addr)
                                    .font(egui::FontId::monospace(11.0)),
                            );
                        }
                    });
                    ui.end_row();
                }
            });
        }); // end connection card

        ui.add_space(8.0);

        // ── Storage & replication ─────────────────────────────────────
        card_frame().show(ui, |ui| {
        ui.label(egui::RichText::new(s.status_storage).strong().color(ACCENT));
        ui.add_space(4.0);

        egui::Grid::new("storage_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new(s.status_shares).color(DIM));
                ui.label(self.share_count.to_string());
                ui.end_row();

                ui.label(egui::RichText::new(s.status_used).color(DIM));
                if self.quota_mb > 0 {
                    let pct = (self.used_mb / self.quota_mb as f64) * 100.0;
                    let used_text = format!(
                        "{:.1} / {} MiB  ({:.0}%)",
                        self.used_mb, self.quota_mb, pct
                    );
                    if pct > 90.0 {
                        ui.colored_label(YELLOW, used_text);
                    } else {
                        ui.label(used_text);
                    }
                } else {
                    ui.label(format!("{:.1} MiB", self.used_mb));
                }
                ui.end_row();

                ui.label(egui::RichText::new(s.status_replication).color(DIM));
                if self.pending_replication > 0 {
                    ui.colored_label(
                        YELLOW,
                        format!(
                            "{} replicated, {} pending",
                            self.replicated_count, self.pending_replication
                        ),
                    );
                } else if self.replicated_count > 0 {
                    ui.colored_label(
                        GREEN,
                        format!("{} replicated", self.replicated_count),
                    );
                } else {
                    ui.colored_label(DIM, "—");
                }
                ui.end_row();
            });
        }); // end storage card

        // ── Transport ─────────────────────────────────────────────────
        if !self.transport_statuses.is_empty()
            || self.wss_port > 0
            || self.obfs_quic_port > 0
            || self.proxy_configured
        {
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
            ui.label(egui::RichText::new(s.status_transport).strong().color(ACCENT));
            ui.add_space(4.0);

            // Summary line: active services.
            ui.horizontal_wrapped(|ui| {
                if self.wss_port > 0 {
                    let tls = if self.wss_tls_enabled { "TLS" } else { "plain" };
                    tag_label(ui, GREEN, &format!("WSS :{} ({tls})", self.wss_port));
                }
                if self.obfs_quic_port > 0 {
                    tag_label(ui, GREEN, &format!("ObfuscatedQuic :{}", self.obfs_quic_port));
                }
                if self.proxy_configured {
                    let pt = self.proxy_type.as_deref().unwrap_or("proxy");
                    tag_label(ui, BLUE, pt);
                }
            });

            if !self.transport_statuses.is_empty() {
                ui.add_space(6.0);

                egui::Grid::new("transport_grid")
                    .num_columns(4)
                    .spacing([12.0, 3.0])
                    .striped(true)
                    .show(ui, |ui| {
                        // Header.
                        ui.label(egui::RichText::new(s.status_transport_name).strong().small());
                        ui.label(egui::RichText::new(s.status_transport_status).strong().small());
                        ui.label(egui::RichText::new(s.status_transport_counts).strong().small());
                        ui.label(egui::RichText::new(s.status_transport_details).strong().small());
                        ui.end_row();

                        for t in &self.transport_statuses {
                            ui.label(&t.name);

                            // Status badge.
                            if t.selected {
                                ui.colored_label(GREEN, "Active");
                            } else if t.available && t.failure_count == 0 {
                                ui.colored_label(GREEN, "Ready");
                            } else if t.available && t.failure_count > 0 {
                                ui.colored_label(YELLOW, "Degraded");
                            } else if t.failure_count > 0 {
                                ui.colored_label(RED, "Failing");
                            } else {
                                ui.colored_label(DIM, "Idle");
                            }

                            // Counts.
                            ui.label(format!("{} / {}", t.success_count, t.failure_count));

                            // Last error or phase failures.
                            if let Some(ref err) = t.last_error {
                                let short = if err.len() > 50 {
                                    format!("{}...", &err[..50])
                                } else {
                                    err.clone()
                                };
                                ui.label(egui::RichText::new(short).color(DIM).small());
                            } else if t.session_failures > 0 || t.data_failures > 0 {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "session:{} data:{}",
                                        t.session_failures, t.data_failures
                                    ))
                                    .color(DIM)
                                    .small(),
                                );
                            } else {
                                ui.colored_label(DIM, "—");
                            }
                            ui.end_row();
                        }
                    });

                // Troubleshooting hint when all transports failing.
                let all_failing = self
                    .transport_statuses
                    .iter()
                    .all(|t| t.failure_count > 0 && t.success_count == 0);
                if all_failing && self.transport_statuses.iter().any(|t| t.failure_count > 0)
                {
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(YELLOW, s.status_all_failing);
                    });
                }
            }
            }); // end transport card
        }
    }

    // ── Settings panel ───────────────────────────────────────────────────

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();

        section_heading(ui, s.settings_heading);
        ui.add_space(8.0);

        // ── Preferences card (Language + Mode) ───────────────────────
        card_frame().show(ui, |ui| {
            ui.label(egui::RichText::new(s.settings_language).strong().color(ACCENT));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                for lang in Locale::ALL {
                    let selected = self.locale == lang;
                    if ui.selectable_label(selected, lang.display_name()).clicked() {
                        self.locale = lang;
                        self.save_prefs();
                    }
                }
            });

            ui.add_space(12.0);

            ui.label(egui::RichText::new(s.settings_mode).strong().color(ACCENT));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let is_easy = self.mode.is_easy();
                if ui.selectable_label(is_easy, s.settings_mode_easy).clicked() {
                    self.mode = ProductMode::Easy;
                    self.save_prefs();
                }
                if ui.selectable_label(!is_easy, s.settings_mode_technical).clicked() {
                    self.mode = ProductMode::Technical;
                    self.save_prefs();
                }
            });
            ui.add_space(2.0);
            let mode_desc = if easy { s.settings_mode_desc_easy } else { s.settings_mode_desc_technical };
            ui.label(egui::RichText::new(mode_desc).color(DIM).small());
        });

        ui.add_space(8.0);

        // ── Paths card ───────────────────────────────────────────────
        card_frame().show(ui, |ui| {
            ui.label(egui::RichText::new(s.settings_paths).strong().color(ACCENT));
            ui.add_space(4.0);

            egui::Grid::new("paths_grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(s.settings_data_dir).color(DIM));
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(&self.data_dir_display)
                                .font(egui::FontId::monospace(11.0)),
                        );
                        if ui.small_button(s.copy).clicked() {
                            ui.output_mut(|o| o.copied_text = self.data_dir_display.clone());
                            self.set_msg(MsgKind::Info, s.settings_path_copied);
                        }
                    });
                    ui.end_row();

                    ui.label(egui::RichText::new(s.settings_config_file).color(DIM));
                    ui.label(
                        egui::RichText::new(format!("{}{}config.toml", &self.data_dir_display, std::path::MAIN_SEPARATOR))
                            .font(egui::FontId::monospace(11.0)),
                    );
                    ui.end_row();

                    ui.label(egui::RichText::new(s.settings_log).color(DIM));
                    ui.label(
                        egui::RichText::new(format!("{}{}desktop.log.*", &self.data_dir_display, std::path::MAIN_SEPARATOR))
                            .font(egui::FontId::monospace(11.0)),
                    );
                    ui.end_row();

                    ui.label(egui::RichText::new(s.settings_install).color(DIM));
                    if let Ok(exe) = std::env::current_exe() {
                        if let Some(dir) = exe.parent() {
                            ui.label(
                                egui::RichText::new(dir.to_string_lossy())
                                    .font(egui::FontId::monospace(11.0)),
                            );
                        }
                    }
                    ui.end_row();
                });
        });

        ui.add_space(8.0);

        // ── About card (How it works) ────────────────────────────────
        card_frame().show(ui, |ui| {
            ui.label(egui::RichText::new(s.settings_how).strong().color(ACCENT));
            ui.add_space(4.0);
            let line1 = if easy { s.settings_how_line1_easy } else { s.settings_how_line1 };
            ui.label(line1);
            let line2 = if easy { s.settings_how_line2_easy } else { s.settings_how_line2 };
            ui.label(line2);
            ui.add_space(6.0);
            ui.label(egui::RichText::new(s.settings_stored_in).color(DIM));
            ui.label(
                egui::RichText::new(&self.data_dir_display)
                    .font(egui::FontId::monospace(11.0)),
            );
            ui.label(
                egui::RichText::new(s.settings_preserved)
                    .color(DIM).small(),
            );
        });

        ui.add_space(8.0);

        // ── Actions card ─────────────────────────────────────────────
        card_frame().show(ui, |ui| {
            ui.label(egui::RichText::new(s.settings_actions).strong().color(ACCENT));
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                if ui
                    .add_sized([160.0, 30.0], egui::Button::new(s.status_copy_diag))
                    .clicked()
                {
                    let diag = self.build_diagnostics();
                    ui.output_mut(|o| o.copied_text = diag);
                    self.set_msg(MsgKind::Info, s.status_diag_copied);
                }
                if ui
                    .add_sized([130.0, 30.0], egui::Button::new(s.status_save_diag))
                    .clicked()
                {
                    let diag = self.build_diagnostics();
                    if let Some(path) = rfd::FileDialog::new()
                        .set_file_name("miasma-diagnostics.txt")
                        .add_filter("Text files", &["txt"])
                        .save_file()
                    {
                        match std::fs::write(&path, &diag) {
                            Ok(()) => self.set_msg(MsgKind::Success, format!("{} {}", s.status_diag_saved, path.display())),
                            Err(e) => self.set_msg(MsgKind::Error, format!("{}{e}", s.status_diag_save_failed)),
                        }
                    }
                }

                #[cfg(windows)]
                if ui
                    .add_sized([160.0, 30.0], egui::Button::new(s.settings_open_folder))
                    .clicked()
                {
                    let _ = std::process::Command::new("explorer")
                        .arg(&self.data_dir_display)
                        .spawn();
                }

                #[cfg(not(windows))]
                if ui
                    .add_sized([160.0, 30.0], egui::Button::new(s.settings_open_folder))
                    .clicked()
                {
                    let _ = std::process::Command::new("xdg-open")
                        .arg(&self.data_dir_display)
                        .spawn();
                }
            });
        });

        ui.add_space(12.0);

        let variant_label = if easy { "" } else { " Technical Beta" };
        ui.label(
            egui::RichText::new(format!(
                "Miasma{variant_label} v{}",
                env!("CARGO_PKG_VERSION")
            ))
            .color(DIM)
            .small(),
        );
    }

    // ── Import panel (magnet / .torrent) ──────────────────────────────────

    fn import_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();

        section_heading(ui, s.import_heading);
        ui.add_space(8.0);

        match self.import_state {
            ImportState::Idle => {
                // No import — show hint to go to Save tab instead.
                card_frame().show(ui, |ui| {
                    ui.label(s.import_idle_hint);
                });
            }
            ImportState::Confirming => {
                // Show what was received and ask for confirmation.
                card_frame().show(ui, |ui| {
                    let description = match &self.import_intent {
                        Some(LaunchIntent::Magnet(uri)) => {
                            let display = if uri.len() > 80 {
                                format!("{}...", &uri[..80])
                            } else {
                                uri.clone()
                            };
                            format!("{}: {display}", s.import_magnet_label)
                        }
                        Some(LaunchIntent::TorrentFile(path)) => {
                            format!("{}: {}", s.import_torrent_label, path.display())
                        }
                        _ => String::new(),
                    };

                    ui.label(egui::RichText::new(&description).strong());
                    ui.add_space(8.0);

                    let explain = if easy { s.import_explain_easy } else { s.import_explain };
                    ui.label(explain);
                    ui.add_space(12.0);

                    let connected = self.daemon_state == DaemonState::Connected;
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(connected && !self.busy, |ui| {
                            let btn = if easy {
                                egui::Button::new(
                                    egui::RichText::new(s.import_button).strong().size(14.0),
                                ).fill(ACCENT)
                            } else {
                                egui::Button::new(s.import_button)
                            };
                            if ui.add_sized([140.0, 34.0], btn).clicked() {
                                if let Some(intent) = &self.import_intent {
                                    let cmd = match intent {
                                        LaunchIntent::Magnet(uri) => {
                                            WorkerCmd::ImportMagnet(uri.clone())
                                        }
                                        LaunchIntent::TorrentFile(path) => {
                                            WorkerCmd::ImportTorrentFile(path.clone())
                                        }
                                        LaunchIntent::Normal => unreachable!(),
                                    };
                                    let _ = self.worker.tx.try_send(cmd);
                                    self.busy = true;
                                    self.import_state = ImportState::InProgress;
                                }
                            }
                        });

                        if ui.add_sized([100.0, 34.0], egui::Button::new(s.import_cancel)).clicked() {
                            self.import_state = ImportState::Idle;
                            self.import_intent = None;
                            self.tab = Tab::Store;
                        }
                    });

                    if !connected {
                        ui.add_space(4.0);
                        ui.colored_label(YELLOW, s.import_not_connected);
                    }
                });
            }
            ImportState::InProgress => {
                card_frame().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(egui::RichText::new(s.import_progress).color(BLUE));
                    });
                });
            }
            ImportState::Complete => {
                card_frame().show(ui, |ui| {
                    ui.label(egui::RichText::new(s.import_complete).strong().color(GREEN));
                    ui.add_space(8.0);

                    for (i, mid) in self.import_mids.clone().iter().enumerate() {
                        ui.horizontal(|ui| {
                            let label = format!("#{}: {}", i + 1, truncate_mid(mid));
                            ui.label(egui::RichText::new(&label).font(egui::FontId::monospace(11.0)));
                            if ui.small_button(s.store_copy).clicked() {
                                ui.output_mut(|o| o.copied_text = mid.clone());
                                self.set_msg(MsgKind::Info, s.store_copied);
                            }
                        });
                    }

                    ui.add_space(8.0);
                    if ui.add_sized([120.0, 28.0], egui::Button::new(s.import_done)).clicked() {
                        self.import_state = ImportState::Idle;
                        self.tab = Tab::Store;
                    }
                });
            }
            ImportState::Failed => {
                card_frame().show(ui, |ui| {
                    ui.colored_label(RED, s.import_failed);
                    if let Some(ref err) = self.last_error {
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new(err).color(DIM).small());
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.add_sized([120.0, 28.0], egui::Button::new(s.import_retry)).clicked() {
                            self.import_state = ImportState::Confirming;
                        }
                        if ui.add_sized([120.0, 28.0], egui::Button::new(s.import_cancel)).clicked() {
                            self.import_state = ImportState::Idle;
                            self.import_intent = None;
                            self.tab = Tab::Store;
                        }
                    });
                });
            }
        }
    }

    // ── Diagnostics (always in English — support/debug artifact) ─────────

    fn build_diagnostics(&self) -> String {
        let mut d = String::with_capacity(2048);
        d.push_str("Miasma Diagnostics Report\n");
        d.push_str("========================\n\n");

        d.push_str(&format!("Desktop version: {} (beta)\n", env!("CARGO_PKG_VERSION")));
        d.push_str(&format!("OS:              {} {}\n", std::env::consts::OS, std::env::consts::ARCH));
        d.push_str(&format!("Timestamp:       {}\n", epoch_timestamp()));
        let uptime_secs = self.startup_time.elapsed().as_secs();
        d.push_str(&format!("Desktop uptime:  {}m {}s\n", uptime_secs / 60, uptime_secs % 60));

        // Detect installed vs portable.
        let exe_path = std::env::current_exe().unwrap_or_default();
        let install_type = if exe_path.to_string_lossy().contains("Program Files") {
            "Installed (MSI)"
        } else {
            "Portable"
        };
        d.push_str(&format!("Install type:    {}\n", install_type));

        d.push_str(&format!("Data directory:  {}\n", self.data_dir_display));
        d.push_str(&format!("Desktop log:     {}{}desktop.log.*\n", self.data_dir_display, std::path::MAIN_SEPARATOR));
        d.push_str(&format!("Daemon log:      {}{}daemon.log.*\n", self.data_dir_display, std::path::MAIN_SEPARATOR));
        d.push_str(&format!("Mode:            {:?}\n", self.mode));
        d.push_str(&format!("Locale:          {:?}\n", self.locale));
        d.push_str(&format!("Launch attempts: {}\n", self.launch_attempts));
        d.push_str(&format!(
            "Daemon state:    {}\n",
            match self.daemon_state {
                DaemonState::Connected => "Connected",
                DaemonState::Starting => "Starting",
                DaemonState::Stopped => "Stopped",
                DaemonState::NeedsInit => "Not initialized",
            }
        ));

        d.push_str("\n--- Connection ---\n");
        d.push_str(&format!(
            "Peer ID:    {}\n",
            if self.peer_id.is_empty() { "(none)" } else { &self.peer_id }
        ));
        d.push_str(&format!("Peers:      {}\n", self.peer_count));
        d.push_str(&format!(
            "Listening:  {}\n",
            if self.listen_addrs.is_empty() {
                "(none)".to_string()
            } else {
                self.listen_addrs.join(", ")
            }
        ));

        d.push_str("\n--- Storage ---\n");
        d.push_str(&format!("Shares:     {}\n", self.share_count));
        d.push_str(&format!(
            "Used:       {:.1} / {} MiB\n",
            self.used_mb, self.quota_mb
        ));
        d.push_str(&format!(
            "Replicated: {}, pending: {}\n",
            self.replicated_count, self.pending_replication
        ));

        d.push_str("\n--- Transport ---\n");
        d.push_str(&format!(
            "WSS:             port={} tls={}\n",
            self.wss_port, self.wss_tls_enabled
        ));
        d.push_str(&format!("ObfuscatedQuic:  port={}\n", self.obfs_quic_port));
        d.push_str(&format!(
            "Proxy:           configured={} type={}\n",
            self.proxy_configured,
            self.proxy_type.as_deref().unwrap_or("none")
        ));

        if !self.transport_statuses.is_empty() {
            d.push_str("\n--- Transport Readiness ---\n");
            for t in &self.transport_statuses {
                let status = if t.selected {
                    "ACTIVE"
                } else if t.available {
                    "ready"
                } else if t.failure_count > 0 {
                    "failing"
                } else {
                    "idle"
                };
                d.push_str(&format!(
                    "  {:<18} {:<8} ok={:<4} fail={:<4}",
                    t.name, status, t.success_count, t.failure_count,
                ));
                if let Some(ref err) = t.last_error {
                    d.push_str(&format!("  err={err}"));
                }
                d.push('\n');
            }
        }

        if let Some(ref err) = self.last_error {
            d.push_str(&format!("\n--- Last Error ---\n{err}\n"));
        }

        d.push_str("\n(end of report)\n");
        d
    }
}

// ─── UI helpers ─────────────────────────────────────────────────────────────

fn section_heading(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(18.0).strong().color(egui::Color32::from_rgb(220, 225, 235)));
}

/// Wrap content in a subtle card frame for visual grouping.
fn card_frame() -> egui::Frame {
    egui::Frame::none()
        .inner_margin(egui::Margin::same(14.0))
        .rounding(8.0)
        .fill(CARD_BG)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 48, 56)))
}

fn tag_label(ui: &mut egui::Ui, color: egui::Color32, text: &str) {
    let frame = egui::Frame::none()
        .inner_margin(egui::Margin::symmetric(8.0, 2.0))
        .rounding(4.0)
        .fill(color.linear_multiply(0.15));
    frame.show(ui, |ui| {
        ui.label(egui::RichText::new(text).color(color).small());
    });
}

fn truncate_mid(mid: &str) -> String {
    if mid.len() <= 40 {
        mid.to_string()
    } else {
        format!("{}...{}", &mid[..20], &mid[mid.len() - 12..])
    }
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

fn epoch_timestamp() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s since epoch", d.as_secs())
}

// ─── eframe::App impl ──────────────────────────────────────────────────────

impl eframe::App for MiasmaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(200));
        self.poll_worker();

        // Periodic status poll (~30 seconds).
        if self.daemon_state == DaemonState::Connected
            && self.last_status_poll.elapsed() > std::time::Duration::from_secs(30)
        {
            let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
            self.last_status_poll = std::time::Instant::now();
        }

        let s = self.s();
        let easy = self.mode.is_easy();

        // ── Top navigation bar ────────────────────────────────────────
        egui::TopBottomPanel::top("nav_bar")
            .frame(egui::Frame::none()
                .fill(egui::Color32::from_rgb(28, 30, 36))
                .inner_margin(egui::Margin::symmetric(12.0, 6.0)))
            .show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let store_label = if easy { s.tab_store_easy } else { s.tab_store };
                let retrieve_label = if easy { s.tab_retrieve_easy } else { s.tab_retrieve };
                ui.selectable_value(&mut self.tab, Tab::Store, store_label);
                ui.selectable_value(&mut self.tab, Tab::Retrieve, retrieve_label);
                ui.selectable_value(&mut self.tab, Tab::Status, s.tab_status);
                ui.selectable_value(&mut self.tab, Tab::Settings, s.tab_settings);
                // Show Import tab only when an import is active.
                if self.import_intent.is_some() || self.import_state != ImportState::Idle {
                    ui.selectable_value(&mut self.tab, Tab::Import, s.tab_import);
                }

                // Right-aligned connection indicator.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    match self.daemon_state {
                        DaemonState::Connected => {
                            ui.colored_label(GREEN, s.connected);
                        }
                        DaemonState::Starting => {
                            ui.colored_label(BLUE, s.starting);
                        }
                        DaemonState::Stopped => {
                            ui.colored_label(RED, s.offline);
                        }
                        DaemonState::NeedsInit => {
                            ui.colored_label(YELLOW, s.setup_needed);
                        }
                    }
                });
            });
            ui.add_space(2.0);
        });

        // ── Bottom status bar ─────────────────────────────────────────
        if let Some((ref msg, kind)) = self.status_msg.clone() {
            egui::TopBottomPanel::bottom("status_bar")
                .max_height(24.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        let color = match kind {
                            MsgKind::Info => DIM,
                            MsgKind::Success => GREEN,
                            MsgKind::Error => RED,
                        };
                        ui.colored_label(color, msg);
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.small_button(s.dismiss).clicked() {
                                    self.status_msg = None;
                                }
                            },
                        );
                    });
                });
        }

        // ── Central panel ─────────────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            // Show connection header when not connected.
            self.connection_header(ui);

            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    ui.add_space(4.0);
                    match self.tab {
                        Tab::Store => self.store_panel(ui),
                        Tab::Retrieve => self.retrieve_panel(ui),
                        Tab::Status => self.status_panel(ui),
                        Tab::Settings => self.settings_panel(ui),
                        Tab::Import => self.import_panel(ui),
                    }
                    ui.add_space(8.0);
                });
        });

        // ── Wipe confirmation dialog ──────────────────────────────────
        if self.show_wipe_confirm {
            egui::Window::new(s.wipe_confirm_title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.add_space(4.0);
                    ui.label(s.wipe_confirm_line1);
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(s.wipe_confirm_line2).strong(),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_sized(
                                [120.0, 30.0],
                                egui::Button::new(
                                    egui::RichText::new(s.wipe_confirm_button)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(RED),
                            )
                            .clicked()
                        {
                            let _ = self.worker.tx.try_send(WorkerCmd::Wipe);
                            self.busy = true;
                        }
                        ui.add_space(8.0);
                        if ui
                            .add_sized([120.0, 30.0], egui::Button::new(s.wipe_cancel))
                            .clicked()
                        {
                            self.show_wipe_confirm = false;
                        }
                    });
                    ui.add_space(4.0);
                });
        }
    }
}
