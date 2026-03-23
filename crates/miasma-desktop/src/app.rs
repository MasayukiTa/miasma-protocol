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

/// Font detection results for diagnostics.
struct FontDetectionResult {
    loaded: Vec<String>,
    missing: Vec<String>,
}

/// Global font detection result — written once during configure_fonts().
static FONT_DETECTION: std::sync::OnceLock<FontDetectionResult> = std::sync::OnceLock::new();

/// Configure fonts: load system CJK fonts for Japanese and Chinese rendering.
///
/// Font priority (per family):
///   Proportional: Segoe UI → Meiryo → Yu Gothic → Microsoft YaHei → MS Gothic → egui default
///   Monospace:    Consolas → MS Gothic → Yu Gothic → Microsoft YaHei → egui default
///
/// On non-Windows or if system fonts are missing, falls back to egui's built-in
/// fonts (which cover Latin but not CJK — CJK will show as tofu).
fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Try to load Windows system fonts for CJK coverage.
    let font_dir = std::path::PathBuf::from(r"C:\Windows\Fonts");

    let mut loaded_fonts: Vec<String> = Vec::new();
    let mut missing_fonts: Vec<String> = Vec::new();

    // Helper: try to load a font file and register it.
    let mut load_font = |name: &str, file: &str| -> bool {
        let path = font_dir.join(file);
        match std::fs::read(&path) {
            Ok(data) => {
                fonts
                    .font_data
                    .insert(name.to_owned(), egui::FontData::from_owned(data));
                loaded_fonts.push(format!("{name} ({file})"));
                tracing::info!("Font loaded: {name} from {}", path.display());
                true
            }
            Err(_) => {
                missing_fonts.push(format!("{name} ({file})"));
                tracing::debug!("Font not found: {}", path.display());
                false
            }
        }
    };

    // Load system fonts — expanded set for better CJK coverage.
    // Primary UI font.
    let has_segoe = load_font("Segoe UI", "segoeui.ttf");
    let _has_segoe_bold = load_font("Segoe UI Bold", "segoeuib.ttf");
    // CJK fonts — multiple fallbacks for maximum coverage.
    let has_meiryo = load_font("Meiryo", "meiryo.ttc"); // Ships with Windows; excellent CJK
    let has_yu_gothic = load_font("Yu Gothic", "YuGothR.ttc"); // Win 10+ default JA
    let has_msyh = load_font("Microsoft YaHei", "msyh.ttc"); // Win default zh-CN
    let has_msgothic = load_font("MS Gothic", "msgothic.ttc"); // Legacy JA fallback, monospace-friendly
                                                               // Monospace.
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
        // Meiryo has broad CJK coverage and good screen rendering.
        if has_meiryo {
            proportional.insert(insert_pos, "Meiryo".to_owned());
            insert_pos += 1;
        }
        if has_yu_gothic {
            proportional.insert(insert_pos, "Yu Gothic".to_owned());
            insert_pos += 1;
        }
        if has_msyh {
            proportional.insert(insert_pos, "Microsoft YaHei".to_owned());
            insert_pos += 1;
        }
        if has_msgothic {
            proportional.insert(insert_pos, "MS Gothic".to_owned());
        }
        // egui defaults remain at the end as final fallback.
    }

    // Build monospace fallback chain.
    {
        let monospace = fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default();

        let mut pos = 0;
        if has_consolas {
            monospace.insert(pos, "Consolas".to_owned());
            pos += 1;
        }
        // MS Gothic is a JIS X 0208 monospace font — ideal for CJK in monospace contexts.
        if has_msgothic {
            monospace.insert(pos, "MS Gothic".to_owned());
            pos += 1;
        }
        if has_yu_gothic {
            monospace.insert(pos, "Yu Gothic".to_owned());
            pos += 1;
        }
        if has_msyh {
            monospace.insert(pos, "Microsoft YaHei".to_owned());
        }
    }

    // Store detection results for diagnostics.
    let _ = FONT_DETECTION.set(FontDetectionResult {
        loaded: loaded_fonts,
        missing: missing_fonts,
    });

    ctx.set_fonts(fonts);

    // Dark theme with product feel.
    ctx.set_visuals(egui::Visuals::dark());

    let mut style = (*ctx.style()).clone();
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(13.5));
    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(20.0));
    style
        .text_styles
        .insert(egui::TextStyle::Small, egui::FontId::proportional(11.5));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.5));
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
const NAV_BG: egui::Color32 = egui::Color32::from_rgb(18, 20, 24);
const NAV_ACTIVE_BG: egui::Color32 = egui::Color32::from_rgb(40, 44, 56);
const BRAND_TEXT: egui::Color32 = egui::Color32::from_rgb(180, 190, 210);
const SEPARATOR: egui::Color32 = egui::Color32::from_rgb(40, 42, 50);
const PROGRESS_BG: egui::Color32 = egui::Color32::from_rgb(45, 48, 56);
const PROGRESS_FILL: egui::Color32 = egui::Color32::from_rgb(70, 130, 200);

// ─── Tab enum ───────────────────────────────────────────────────────────────

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Store,
    Retrieve,
    Send,
    Inbox,
    Outbox,
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

    // Send panel (directed sharing)
    send_contact: String,
    send_password: String,
    send_retention: String,
    send_file_path: Option<std::path::PathBuf>,
    last_envelope_id: Option<String>,
    sharing_contact: Option<String>,

    // Inbox panel
    inbox_items: Vec<InboxItem>,
    inbox_retrieve_password: String,

    // Outbox panel
    outbox_items: Vec<InboxItem>,
    outbox_confirm_code: String,

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

/// An entry in the directed sharing inbox/outbox.
#[derive(Clone)]
struct InboxItem {
    envelope_id: String,
    sender: String,
    recipient: String,
    state: String,
    challenge_code: Option<String>,
    created_at: String,
    expires_at: String,
    filename: Option<String>,
    file_size: u64,
}

#[derive(Clone, Copy, PartialEq)]
enum MsgKind {
    Info,
    Success,
    Error,
}

impl MiasmaApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        mode: ProductMode,
        locale: Locale,
        intent: LaunchIntent,
    ) -> Self {
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

            // Directed sharing
            send_contact: String::new(),
            send_password: String::new(),
            send_retention: "7d".to_owned(),
            send_file_path: None,
            last_envelope_id: None,
            sharing_contact: None,

            // Inbox
            inbox_items: Vec::new(),
            inbox_retrieve_password: String::new(),
            outbox_items: Vec::new(),
            outbox_confirm_code: String::new(),
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
                    self.retrieved_summary = Some(format!("{size}  — {}", truncate_mid(&mid),));
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
                    self.set_msg(
                        MsgKind::Info,
                        format!("{}: {name}", self.s().import_progress),
                    );
                }
                WorkerResult::ImportComplete { mids } => {
                    self.busy = false;
                    self.import_state = ImportState::Complete;
                    self.import_mids = mids;
                    self.set_msg(MsgKind::Success, self.s().import_complete);
                }
                WorkerResult::SharingKey { contact } => {
                    self.sharing_contact = Some(contact);
                }
                WorkerResult::DirectedSent { envelope_id } => {
                    self.busy = false;
                    self.last_envelope_id = Some(envelope_id);
                    self.set_msg(MsgKind::Success, self.s().send_success);
                    // Auto-refresh outbox to show new item.
                    let _ = self.worker.tx.try_send(WorkerCmd::DirectedOutbox);
                }
                WorkerResult::DirectedRetrieved { data, filename } => {
                    self.busy = false;
                    // Save the retrieved directed data.
                    let fname = filename.as_deref().unwrap_or("directed_content.bin");
                    if let Some(path) = rfd::FileDialog::new()
                        .set_file_name(fname)
                        .save_file()
                    {
                        match std::fs::write(&path, &data) {
                            Ok(()) => {
                                self.set_msg(
                                    MsgKind::Success,
                                    format!("Saved to {}", path.display()),
                                );
                            }
                            Err(e) => {
                                self.set_msg(MsgKind::Error, format!("Save failed: {e}"));
                            }
                        }
                    }
                }
                WorkerResult::DirectedRevoked => {
                    self.busy = false;
                    self.set_msg(MsgKind::Success, "Revoked.");
                    // Refresh inbox and outbox.
                    let _ = self.worker.tx.try_send(WorkerCmd::DirectedInbox);
                    let _ = self.worker.tx.try_send(WorkerCmd::DirectedOutbox);
                }
                WorkerResult::DirectedConfirmed => {
                    self.busy = false;
                    self.outbox_confirm_code.clear();
                    self.set_msg(MsgKind::Success, self.s().outbox_confirm_success);
                    let _ = self.worker.tx.try_send(WorkerCmd::DirectedOutbox);
                }
                WorkerResult::DirectedInboxList(items) => {
                    self.inbox_items = items
                        .into_iter()
                        .map(|item| InboxItem {
                            envelope_id: item.envelope_id,
                            sender: item.sender_pubkey,
                            recipient: item.recipient_pubkey,
                            state: item.state,
                            challenge_code: item.challenge_code,
                            created_at: format_epoch(item.created_at),
                            expires_at: format_epoch(item.expires_at),
                            filename: item.filename,
                            file_size: item.file_size,
                        })
                        .collect();
                }
                WorkerResult::DirectedOutboxList(items) => {
                    self.outbox_items = items
                        .into_iter()
                        .map(|item| InboxItem {
                            envelope_id: item.envelope_id,
                            sender: item.sender_pubkey,
                            recipient: item.recipient_pubkey,
                            state: item.state,
                            challenge_code: item.challenge_code,
                            created_at: format_epoch(item.created_at),
                            expires_at: format_epoch(item.expires_at),
                            filename: item.filename,
                            file_size: item.file_size,
                        })
                        .collect();
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
                        let title = if easy {
                            s.welcome_title_easy
                        } else {
                            s.welcome_title
                        };
                        ui.label(egui::RichText::new(title).size(18.0).strong());
                        ui.add_space(6.0);
                        let desc = if easy {
                            s.welcome_desc_easy
                        } else {
                            s.welcome_desc
                        };
                        ui.label(desc);
                        ui.add_space(4.0);
                        let detail = if easy {
                            s.welcome_detail_easy
                        } else {
                            s.welcome_detail
                        };
                        ui.label(egui::RichText::new(detail).color(DIM));
                        ui.add_space(10.0);
                        ui.add_enabled_ui(!self.busy, |ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new(s.welcome_button).strong().size(14.0),
                            );
                            if ui.add_sized([180.0, 36.0], btn).clicked() {
                                let _ = self.worker.tx.try_send(WorkerCmd::Init);
                                self.busy = true;
                                self.set_msg(
                                    MsgKind::Info,
                                    if easy {
                                        s.welcome_progress_easy
                                    } else {
                                        s.welcome_progress
                                    },
                                );
                            }
                        });
                        if self.busy {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.spinner();
                                let progress = if easy {
                                    s.welcome_progress_easy
                                } else {
                                    s.welcome_progress
                                };
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
                        let title = if easy {
                            s.stopped_title_easy
                        } else {
                            s.stopped_title
                        };
                        ui.label(egui::RichText::new(title).size(14.0).color(RED));
                        ui.add_space(2.0);
                        if let Some(ref err) = self.last_error {
                            ui.label(egui::RichText::new(err).color(DIM).small());
                            ui.add_space(4.0);
                        } else {
                            let desc = if easy {
                                s.stopped_desc_easy
                            } else {
                                s.stopped_desc
                            };
                            ui.label(egui::RichText::new(desc).color(DIM).small());
                            ui.add_space(4.0);
                        }
                        ui.horizontal(|ui| {
                            ui.add_enabled_ui(!self.busy, |ui| {
                                let btn_text = if easy {
                                    s.stopped_button_easy
                                } else {
                                    s.stopped_button
                                };
                                if ui
                                    .add_sized([140.0, 28.0], egui::Button::new(btn_text))
                                    .clicked()
                                {
                                    let _ = self.worker.tx.try_send(WorkerCmd::StartDaemon);
                                    self.busy = true;
                                    self.last_error = None;
                                    let label = if easy {
                                        s.starting_label_easy
                                    } else {
                                        s.starting_label
                                    };
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
                        let label = if easy {
                            s.starting_label_easy
                        } else {
                            s.starting_label
                        };
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

        let heading = if easy {
            s.store_heading_easy
        } else {
            s.store_heading
        };
        section_heading(ui, heading);
        ui.add_space(4.0);
        let desc = if easy {
            s.store_desc_easy
        } else {
            s.store_desc
        };
        ui.label(egui::RichText::new(desc).color(DIM));
        ui.add_space(10.0);

        // ── Easy mode: quick status dashboard ──
        if easy && connected {
            card_frame().show(ui, |ui| {
                ui.label(
                    egui::RichText::new(s.dashboard_quick_status)
                        .strong()
                        .color(ACCENT)
                        .size(13.0),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    // Storage mini indicator.
                    let storage_frame = egui::Frame::none()
                        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                        .rounding(6.0)
                        .fill(egui::Color32::from_rgb(28, 30, 38));
                    storage_frame.show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(s.dashboard_storage_label)
                                    .color(DIM)
                                    .small(),
                            );
                            if self.quota_mb > 0 {
                                let pct = (self.used_mb / self.quota_mb as f64) * 100.0;
                                ui.label(
                                    egui::RichText::new(format!("{:.0}%", pct))
                                        .size(18.0)
                                        .strong(),
                                );
                                // Mini progress bar.
                                let bar_width = 80.0;
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(bar_width, 4.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().rect_filled(rect, 2.0, PROGRESS_BG);
                                let fill_width = (pct as f32 / 100.0).min(1.0) * bar_width;
                                let fill_color = if pct > 90.0 { YELLOW } else { PROGRESS_FILL };
                                let fill_rect = egui::Rect::from_min_size(
                                    rect.min,
                                    egui::vec2(fill_width, 4.0),
                                );
                                ui.painter().rect_filled(fill_rect, 2.0, fill_color);
                            } else {
                                ui.label(
                                    egui::RichText::new(s.dashboard_no_data).color(DIM).small(),
                                );
                            }
                        });
                    });

                    // Peers mini indicator.
                    let peer_frame = egui::Frame::none()
                        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                        .rounding(6.0)
                        .fill(egui::Color32::from_rgb(28, 30, 38));
                    peer_frame.show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(s.dashboard_peers_label)
                                    .color(DIM)
                                    .small(),
                            );
                            let peer_color = if self.peer_count > 0 { GREEN } else { YELLOW };
                            ui.label(
                                egui::RichText::new(self.peer_count.to_string())
                                    .size(18.0)
                                    .strong()
                                    .color(peer_color),
                            );
                            let peer_hint = if self.peer_count > 0 {
                                format!(
                                    "{} {}",
                                    self.peer_count,
                                    s.status_peers.trim_end_matches('：').trim_end_matches(':')
                                )
                            } else {
                                s.health_no_peers.to_string()
                            };
                            ui.label(egui::RichText::new(peer_hint).color(DIM).small());
                        });
                    });

                    // Items mini indicator.
                    let items_frame = egui::Frame::none()
                        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                        .rounding(6.0)
                        .fill(egui::Color32::from_rgb(28, 30, 38));
                    items_frame.show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(s.status_items_stored)
                                    .color(DIM)
                                    .small(),
                            );
                            ui.label(
                                egui::RichText::new(self.share_count.to_string())
                                    .size(18.0)
                                    .strong(),
                            );
                        });
                    });
                });
            });
            ui.add_space(8.0);
        }

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
                            )
                            .fill(ACCENT)
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
                        .add_sized(
                            [130.0, if easy { 34.0 } else { 28.0 }],
                            egui::Button::new(s.store_choose_file),
                        )
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
                let mid_label = if easy {
                    s.store_mid_label_easy
                } else {
                    s.store_mid_label
                };
                ui.label(egui::RichText::new(mid_label).strong().color(GREEN));
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let mut display = mid.clone();
                    ui.add(
                        egui::TextEdit::singleline(&mut display)
                            .desired_width(ui.available_width() - 80.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui
                        .add_sized([70.0, 26.0], egui::Button::new(s.store_copy))
                        .clicked()
                    {
                        ui.output_mut(|o| o.copied_text = mid.clone());
                        self.set_msg(MsgKind::Info, s.store_copied);
                    }
                });

                ui.add_space(4.0);
                let hint = if easy {
                    s.store_share_hint_easy
                } else {
                    s.store_share_hint
                };
                ui.label(egui::RichText::new(hint).color(DIM).small());
            });
        }
    }

    // ── Retrieve panel ───────────────────────────────────────────────────

    fn retrieve_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;

        let heading = if easy {
            s.retrieve_heading_easy
        } else {
            s.retrieve_heading
        };
        section_heading(ui, heading);
        ui.add_space(4.0);
        let desc = if easy {
            s.retrieve_desc_easy
        } else {
            s.retrieve_desc
        };
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
            let mid_label = if easy {
                s.retrieve_mid_label_easy
            } else {
                s.retrieve_mid_label
            };
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
                        let label = if easy {
                            s.retrieve_button_easy
                        } else {
                            s.retrieve_button
                        };
                        let btn = if easy {
                            egui::Button::new(egui::RichText::new(label).strong().size(14.0))
                                .fill(ACCENT)
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
                ui.label(
                    egui::RichText::new(s.retrieve_result_label)
                        .strong()
                        .color(GREEN),
                );
                ui.add_space(2.0);
                ui.label(&summary);
                ui.add_space(6.0);

                if self.save_data.is_some() {
                    let save_btn = if easy {
                        egui::Button::new(
                            egui::RichText::new(s.retrieve_save_button)
                                .strong()
                                .size(14.0),
                        )
                        .fill(ACCENT)
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
                                        self.set_msg(
                                            MsgKind::Error,
                                            format!("{} {e}", s.retrieve_save_failed),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    // ── Send panel (directed sharing) ──────────────────────────────────

    fn send_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let heading = if easy { s.send_heading_easy } else { s.send_heading };
        let desc = if easy { s.send_desc_easy } else { s.send_desc };

        card_frame().show(ui, |ui| {
            ui.colored_label(ACCENT, egui::RichText::new(heading).size(15.0).strong());
            ui.add_space(4.0);
            ui.colored_label(DIM, desc);
            ui.add_space(10.0);

            // Show sharing contact (own).
            if let Some(contact) = self.sharing_contact.clone() {
                let key_desc = if easy {
                    s.sharing_key_desc_easy
                } else {
                    s.sharing_key_desc
                };
                ui.colored_label(DIM, key_desc);
                ui.horizontal(|ui| {
                    ui.monospace(contact.as_str());
                    if ui.small_button(s.sharing_key_copy).clicked() {
                        ui.output_mut(|o| o.copied_text = contact.clone());
                        self.set_msg(MsgKind::Success, s.sharing_key_copied);
                    }
                });
                ui.add_space(8.0);
            } else if self.daemon_state == DaemonState::Connected {
                // Request sharing key on first render.
                let _ = self.worker.tx.try_send(WorkerCmd::GetSharingKey);
            }

            // Recipient contact.
            ui.horizontal(|ui| {
                ui.label(s.send_contact_label);
                ui.add(
                    egui::TextEdit::singleline(&mut self.send_contact)
                        .hint_text(s.send_contact_hint)
                        .desired_width(350.0),
                );
            });

            // Password.
            ui.horizontal(|ui| {
                ui.label(s.send_password_label);
                ui.add(
                    egui::TextEdit::singleline(&mut self.send_password)
                        .password(true)
                        .desired_width(200.0),
                );
            });

            // Retention.
            ui.horizontal(|ui| {
                ui.label(s.send_retention_label);
                ui.add(
                    egui::TextEdit::singleline(&mut self.send_retention)
                        .desired_width(80.0),
                );
                ui.colored_label(DIM, "(e.g. 24h, 7d, 30d)");
            });

            // File chooser.
            ui.horizontal(|ui| {
                if ui.button(s.send_choose_file).clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.send_file_path = Some(path);
                    }
                }
                if let Some(ref path) = self.send_file_path {
                    ui.monospace(path.display().to_string());
                }
            });

            ui.add_space(8.0);

            // Send button.
            let can_send = self.daemon_state == DaemonState::Connected
                && !self.busy
                && !self.send_contact.is_empty()
                && !self.send_password.is_empty()
                && self.send_file_path.is_some();

            if self.daemon_state != DaemonState::Connected {
                ui.colored_label(DIM, s.send_not_connected);
            } else if self.busy {
                ui.colored_label(DIM, s.send_busy);
            } else {
                ui.horizontal(|ui| {
                    let btn = egui::Button::new(
                        egui::RichText::new(s.send_button).color(egui::Color32::WHITE),
                    )
                    .fill(if can_send { ACCENT } else { CARD_BG });
                    if ui.add_enabled(can_send, btn).clicked() {
                        if let Some(ref path) = self.send_file_path {
                            self.busy = true;
                            let _ = self.worker.tx.try_send(WorkerCmd::DirectedSend {
                                file_path: path.clone(),
                                recipient_contact: self.send_contact.clone(),
                                password: self.send_password.clone(),
                                retention: self.send_retention.clone(),
                            });
                        }
                    }
                });
            }

            // Show last envelope ID.
            if let Some(ref eid) = self.last_envelope_id {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.colored_label(GREEN, "Envelope ID:");
                    ui.monospace(eid.as_str());
                    if ui.small_button(s.copy).clicked() {
                        ui.output_mut(|o| o.copied_text = eid.clone());
                    }
                });
            }
        });
    }

    // ── Inbox panel ─────────────────────────────────────────────────────

    fn inbox_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let heading = if easy { s.inbox_heading_easy } else { s.inbox_heading };
        let desc = if easy { s.inbox_desc_easy } else { s.inbox_desc };

        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(ACCENT, egui::RichText::new(heading).size(15.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button(s.inbox_refresh).clicked()
                        && self.daemon_state == DaemonState::Connected
                    {
                        let _ = self.worker.tx.try_send(WorkerCmd::DirectedInbox);
                    }
                });
            });
            ui.add_space(4.0);
            ui.colored_label(DIM, desc);
            ui.add_space(10.0);

            if self.inbox_items.is_empty() {
                ui.colored_label(DIM, s.inbox_empty);
                // Auto-refresh on first render.
                if self.daemon_state == DaemonState::Connected {
                    let _ = self.worker.tx.try_send(WorkerCmd::DirectedInbox);
                }
            } else {
                for item in &self.inbox_items.clone() {
                    card_frame().show(ui, |ui| {
                        // Envelope ID and colored state badge.
                        ui.horizontal(|ui| {
                            ui.monospace(&item.envelope_id[..16.min(item.envelope_id.len())]);
                            let (state_color, state_label) =
                                inbox_state_display(s, &item.state);
                            ui.colored_label(state_color, format!("  {state_label}"));
                        });

                        // Sender.
                        ui.horizontal(|ui| {
                            ui.colored_label(DIM, s.inbox_from);
                            ui.monospace(&item.sender[..20.min(item.sender.len())]);
                        });

                        // Filename and size.
                        if let Some(ref fname) = item.filename {
                            ui.horizontal(|ui| {
                                ui.colored_label(DIM, s.inbox_filename);
                                ui.label(fname.as_str());
                                if item.file_size > 0 {
                                    ui.colored_label(
                                        DIM,
                                        format!("  ({} {})", s.inbox_file_size, format_size(item.file_size)),
                                    );
                                }
                            });
                        }

                        // Timestamps.
                        ui.horizontal(|ui| {
                            ui.colored_label(DIM, format!("Created: {}", item.created_at));
                            ui.colored_label(DIM, format!("  Expires: {}", item.expires_at));
                        });

                        // Challenge code display (recipient shows this to sender out-of-band).
                        if let Some(ref code) = item.challenge_code {
                            ui.horizontal(|ui| {
                                ui.colored_label(
                                    GREEN,
                                    format!("{} {}", s.inbox_challenge, code),
                                );
                                if ui.small_button(s.copy).clicked() {
                                    ui.output_mut(|o| o.copied_text = code.clone());
                                }
                            });
                        }

                        // Error / terminal state messages.
                        match item.state.as_str() {
                            "Expired" => {
                                ui.colored_label(RED, s.inbox_expired);
                            }
                            "SenderRevoked" => {
                                ui.colored_label(RED, s.inbox_revoked);
                            }
                            "PasswordFailed" => {
                                ui.colored_label(RED, s.inbox_attempts_exhausted);
                            }
                            "ChallengeFailed" => {
                                ui.colored_label(RED, s.outbox_challenge_failed);
                            }
                            _ => {}
                        }

                        // Retrieve button (only in Confirmed state).
                        if item.state == "Confirmed" {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(s.inbox_password_label);
                                ui.add(
                                    egui::TextEdit::singleline(
                                        &mut self.inbox_retrieve_password,
                                    )
                                    .password(true)
                                    .desired_width(150.0),
                                );
                                let can_retrieve = !self.inbox_retrieve_password.is_empty()
                                    && self.daemon_state == DaemonState::Connected
                                    && !self.busy;
                                let btn = egui::Button::new(
                                    egui::RichText::new(s.inbox_retrieve_button)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(if can_retrieve { ACCENT } else { CARD_BG });
                                if ui.add_enabled(can_retrieve, btn).clicked() {
                                    self.busy = true;
                                    let _ =
                                        self.worker.tx.try_send(WorkerCmd::DirectedRetrieve {
                                            envelope_id: item.envelope_id.clone(),
                                            password: self.inbox_retrieve_password.clone(),
                                        });
                                }
                            });
                        }

                        // Delete button (non-terminal states only).
                        let is_terminal = matches!(
                            item.state.as_str(),
                            "Retrieved"
                                | "SenderRevoked"
                                | "RecipientDeleted"
                                | "Expired"
                                | "ChallengeFailed"
                                | "PasswordFailed"
                        );
                        if !is_terminal {
                            if ui.small_button(s.inbox_revoke_button).clicked() {
                                let _ = self.worker.tx.try_send(WorkerCmd::DirectedRevoke {
                                    envelope_id: item.envelope_id.clone(),
                                });
                            }
                        }
                    });
                    ui.add_space(4.0);
                }
            }
        });
    }

    // ── Outbox panel (sender view) ──────────────────────────────────────

    fn outbox_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let heading = if easy { s.outbox_heading_easy } else { s.outbox_heading };
        let desc = if easy { s.outbox_desc_easy } else { s.outbox_desc };

        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(ACCENT, egui::RichText::new(heading).size(15.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button(s.outbox_refresh).clicked()
                        && self.daemon_state == DaemonState::Connected
                    {
                        let _ = self.worker.tx.try_send(WorkerCmd::DirectedOutbox);
                    }
                });
            });
            ui.add_space(4.0);
            ui.colored_label(DIM, desc);
            ui.add_space(10.0);

            if self.outbox_items.is_empty() {
                ui.colored_label(DIM, s.outbox_empty);
                // Auto-refresh on first render.
                if self.daemon_state == DaemonState::Connected {
                    let _ = self.worker.tx.try_send(WorkerCmd::DirectedOutbox);
                }
            } else {
                for item in &self.outbox_items.clone() {
                    card_frame().show(ui, |ui| {
                        // Envelope ID and state badge.
                        ui.horizontal(|ui| {
                            ui.monospace(&item.envelope_id[..16.min(item.envelope_id.len())]);
                            let (state_color, state_label) = outbox_state_display(s, &item.state);
                            ui.colored_label(state_color, format!("  {state_label}"));
                        });

                        // Recipient.
                        ui.horizontal(|ui| {
                            ui.colored_label(DIM, s.outbox_to);
                            ui.monospace(&item.recipient[..20.min(item.recipient.len())]);
                        });

                        // Filename.
                        if let Some(ref fname) = item.filename {
                            ui.horizontal(|ui| {
                                ui.colored_label(DIM, s.outbox_filename);
                                ui.label(fname.as_str());
                            });
                        }

                        // Timestamps.
                        ui.horizontal(|ui| {
                            ui.colored_label(DIM, format!("Created: {}", item.created_at));
                            ui.colored_label(DIM, format!("  Expires: {}", item.expires_at));
                        });

                        // Sender confirmation: if ChallengeIssued, show challenge code entry.
                        if item.state == "ChallengeIssued" {
                            ui.add_space(4.0);
                            ui.colored_label(YELLOW, s.outbox_confirm_heading);
                            ui.horizontal(|ui| {
                                ui.label(s.outbox_confirm_label);
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.outbox_confirm_code)
                                        .hint_text(s.outbox_confirm_hint)
                                        .desired_width(120.0)
                                        .font(egui::TextStyle::Monospace),
                                );
                                let can_confirm = !self.outbox_confirm_code.is_empty()
                                    && self.daemon_state == DaemonState::Connected
                                    && !self.busy;
                                let btn = egui::Button::new(
                                    egui::RichText::new(s.outbox_confirm_button)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(if can_confirm { ACCENT } else { CARD_BG });
                                if ui.add_enabled(can_confirm, btn).clicked() {
                                    self.busy = true;
                                    let _ =
                                        self.worker.tx.try_send(WorkerCmd::DirectedConfirm {
                                            envelope_id: item.envelope_id.clone(),
                                            challenge_code: self.outbox_confirm_code.clone(),
                                        });
                                }
                            });
                        }

                        // Waiting state hint.
                        if item.state == "Pending" {
                            ui.colored_label(YELLOW, s.outbox_waiting_challenge);
                        }

                        // Revoke button for non-terminal states.
                        let is_terminal = matches!(
                            item.state.as_str(),
                            "Retrieved"
                                | "SenderRevoked"
                                | "RecipientDeleted"
                                | "Expired"
                                | "ChallengeFailed"
                                | "PasswordFailed"
                        );
                        if !is_terminal {
                            if ui.small_button(s.outbox_revoke_button).clicked() {
                                let _ = self.worker.tx.try_send(WorkerCmd::DirectedRevoke {
                                    envelope_id: item.envelope_id.clone(),
                                });
                            }
                        }
                    });
                    ui.add_space(4.0);
                }
            }
        });
    }

    // ── Status panel ─────────────────────────────────────────────────────

    fn status_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();

        section_heading(ui, s.status_heading);
        ui.add_space(4.0);

        // Action buttons — smaller row for Easy, full row for Technical.
        ui.horizontal(|ui| {
            if ui
                .add_sized([90.0, 26.0], egui::Button::new(s.status_refresh))
                .clicked()
            {
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
                        Ok(()) => self.set_msg(
                            MsgKind::Success,
                            format!("{} {}", s.status_diag_saved, path.display()),
                        ),
                        Err(e) => self
                            .set_msg(MsgKind::Error, format!("{}{e}", s.status_diag_save_failed)),
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
                    ui.label(egui::RichText::new(s.wipe_desc).color(DIM).small());
                });
                ui.add_space(4.0);
                if ui
                    .add_sized(
                        [160.0, 28.0],
                        egui::Button::new(egui::RichText::new(s.wipe_button).color(RED)),
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
                ui.painter()
                    .circle_filled(dot_rect.1.center(), 6.0, status_color);
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

            // Health checklist — explicit indicators for app/backend/network.
            ui.add_space(10.0);
            egui::Grid::new("easy_health_grid")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    // App — always running if we're here.
                    let check = egui::RichText::new("\u{2713}").color(GREEN); // ✓
                    let cross = egui::RichText::new("\u{2717}").color(RED); // ✗
                    let dot = egui::RichText::new("\u{25CF}").color(YELLOW); // ●

                    ui.label(check.clone());
                    ui.label(
                        egui::RichText::new(format!("{}  {}", s.health_app, s.health_ok))
                            .color(DIM),
                    );
                    ui.end_row();

                    // Backend.
                    match self.daemon_state {
                        DaemonState::Connected => {
                            ui.label(check.clone());
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}  {}",
                                    s.health_backend, s.health_ok
                                ))
                                .color(DIM),
                            );
                        }
                        DaemonState::Starting => {
                            ui.label(dot.clone());
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}  {}",
                                    s.health_backend, s.health_starting
                                ))
                                .color(YELLOW),
                            );
                        }
                        _ => {
                            ui.label(cross.clone());
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}  {}",
                                    s.health_backend, s.health_offline
                                ))
                                .color(RED),
                            );
                        }
                    }
                    ui.end_row();

                    // Network.
                    if self.daemon_state == DaemonState::Connected {
                        if self.peer_count > 0 {
                            ui.label(check);
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}  {} {}",
                                    s.health_network,
                                    self.peer_count,
                                    s.status_peers.trim_end_matches('：').trim_end_matches(':')
                                ))
                                .color(DIM),
                            );
                        } else {
                            ui.label(dot);
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}  {}",
                                    s.health_network, s.health_no_peers
                                ))
                                .color(YELLOW),
                            );
                        }
                    } else {
                        ui.label(cross);
                        ui.label(
                            egui::RichText::new(format!(
                                "{}  {}",
                                s.health_network, s.health_offline
                            ))
                            .color(RED),
                        );
                    }
                    ui.end_row();
                });

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
                            ui.label(egui::RichText::new(peer_text).size(15.0).color(GREEN));
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
                            ui.vertical(|ui| {
                                if pct > 90.0 {
                                    ui.colored_label(YELLOW, &used_text);
                                } else {
                                    ui.label(&used_text);
                                }
                                // Progress bar for Easy mode too.
                                let bar_width = 120.0;
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(bar_width, 4.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().rect_filled(rect, 2.0, PROGRESS_BG);
                                let fill_width = (pct as f32 / 100.0).min(1.0) * bar_width;
                                let fill_color = if pct > 90.0 { YELLOW } else { PROGRESS_FILL };
                                let fill_rect = egui::Rect::from_min_size(
                                    rect.min,
                                    egui::vec2(fill_width, 4.0),
                                );
                                ui.painter().rect_filled(fill_rect, 2.0, fill_color);
                            });
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
            ui.label(
                egui::RichText::new(s.status_connection)
                    .strong()
                    .color(ACCENT),
            );
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
                            egui::RichText::new(&self.peer_id).font(egui::FontId::monospace(11.0)),
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
                                    egui::RichText::new(addr).font(egui::FontId::monospace(11.0)),
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
                        let used_text =
                            format!("{:.1} / {} MiB  ({:.0}%)", self.used_mb, self.quota_mb, pct);
                        ui.vertical(|ui| {
                            if pct > 90.0 {
                                ui.colored_label(YELLOW, &used_text);
                            } else {
                                ui.label(&used_text);
                            }
                            // Storage progress bar.
                            let bar_width = ui.available_width().min(200.0);
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(bar_width, 4.0),
                                egui::Sense::hover(),
                            );
                            ui.painter().rect_filled(rect, 2.0, PROGRESS_BG);
                            let fill_width = (pct as f32 / 100.0).min(1.0) * bar_width;
                            let fill_color = if pct > 90.0 {
                                YELLOW
                            } else if pct > 75.0 {
                                egui::Color32::from_rgb(200, 160, 60)
                            } else {
                                PROGRESS_FILL
                            };
                            let fill_rect =
                                egui::Rect::from_min_size(rect.min, egui::vec2(fill_width, 4.0));
                            ui.painter().rect_filled(fill_rect, 2.0, fill_color);
                        });
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
                        ui.colored_label(GREEN, format!("{} replicated", self.replicated_count));
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
                ui.label(
                    egui::RichText::new(s.status_transport)
                        .strong()
                        .color(ACCENT),
                );
                ui.add_space(4.0);

                // Summary line: active services.
                ui.horizontal_wrapped(|ui| {
                    if self.wss_port > 0 {
                        let tls = if self.wss_tls_enabled { "TLS" } else { "plain" };
                        tag_label(ui, GREEN, &format!("WSS :{} ({tls})", self.wss_port));
                    }
                    if self.obfs_quic_port > 0 {
                        tag_label(
                            ui,
                            GREEN,
                            &format!("ObfuscatedQuic :{}", self.obfs_quic_port),
                        );
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
                            ui.label(
                                egui::RichText::new(s.status_transport_name)
                                    .strong()
                                    .small(),
                            );
                            ui.label(
                                egui::RichText::new(s.status_transport_status)
                                    .strong()
                                    .small(),
                            );
                            ui.label(
                                egui::RichText::new(s.status_transport_counts)
                                    .strong()
                                    .small(),
                            );
                            ui.label(
                                egui::RichText::new(s.status_transport_details)
                                    .strong()
                                    .small(),
                            );
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
                    if all_failing && self.transport_statuses.iter().any(|t| t.failure_count > 0) {
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
            ui.label(
                egui::RichText::new(s.settings_language)
                    .strong()
                    .color(ACCENT),
            );
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
                if ui
                    .selectable_label(!is_easy, s.settings_mode_technical)
                    .clicked()
                {
                    self.mode = ProductMode::Technical;
                    self.save_prefs();
                }
            });
            ui.add_space(2.0);
            let mode_desc = if easy {
                s.settings_mode_desc_easy
            } else {
                s.settings_mode_desc_technical
            };
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
                        egui::RichText::new(format!(
                            "{}{}config.toml",
                            &self.data_dir_display,
                            std::path::MAIN_SEPARATOR
                        ))
                        .font(egui::FontId::monospace(11.0)),
                    );
                    ui.end_row();

                    ui.label(egui::RichText::new(s.settings_log).color(DIM));
                    ui.label(
                        egui::RichText::new(format!(
                            "{}{}desktop.log.*",
                            &self.data_dir_display,
                            std::path::MAIN_SEPARATOR
                        ))
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
            let line1 = if easy {
                s.settings_how_line1_easy
            } else {
                s.settings_how_line1
            };
            ui.label(line1);
            let line2 = if easy {
                s.settings_how_line2_easy
            } else {
                s.settings_how_line2
            };
            ui.label(line2);
            ui.add_space(6.0);
            ui.label(egui::RichText::new(s.settings_stored_in).color(DIM));
            ui.label(
                egui::RichText::new(&self.data_dir_display).font(egui::FontId::monospace(11.0)),
            );
            ui.label(egui::RichText::new(s.settings_preserved).color(DIM).small());
        });

        ui.add_space(8.0);

        // ── Actions card ─────────────────────────────────────────────
        card_frame().show(ui, |ui| {
            ui.label(
                egui::RichText::new(s.settings_actions)
                    .strong()
                    .color(ACCENT),
            );
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
                            Ok(()) => self.set_msg(
                                MsgKind::Success,
                                format!("{} {}", s.status_diag_saved, path.display()),
                            ),
                            Err(e) => self.set_msg(
                                MsgKind::Error,
                                format!("{}{e}", s.status_diag_save_failed),
                            ),
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

                    // Pre-validate: check for problems before showing the Import button.
                    let validation_error = match &self.import_intent {
                        Some(LaunchIntent::Magnet(uri)) => {
                            if !uri.contains("xt=") {
                                Some("This magnet link appears to be malformed (missing xt= parameter).")
                            } else {
                                None
                            }
                        }
                        Some(LaunchIntent::TorrentFile(path)) => {
                            if !path.exists() {
                                Some("The .torrent file no longer exists. It may have been moved or deleted.")
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    if let Some(err) = validation_error {
                        ui.colored_label(YELLOW, err);
                        ui.add_space(4.0);
                    }

                    ui.horizontal(|ui| {
                        let can_import = connected && !self.busy && validation_error.is_none();
                        ui.add_enabled_ui(can_import, |ui| {
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
                            ui.label(
                                egui::RichText::new(&label).font(egui::FontId::monospace(11.0)),
                            );
                            if ui.small_button(s.store_copy).clicked() {
                                ui.output_mut(|o| o.copied_text = mid.clone());
                                self.set_msg(MsgKind::Info, s.store_copied);
                            }
                        });
                    }

                    ui.add_space(8.0);
                    if ui
                        .add_sized([120.0, 28.0], egui::Button::new(s.import_done))
                        .clicked()
                    {
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
                        if ui
                            .add_sized([120.0, 28.0], egui::Button::new(s.import_retry))
                            .clicked()
                        {
                            self.import_state = ImportState::Confirming;
                        }
                        if ui
                            .add_sized([120.0, 28.0], egui::Button::new(s.import_cancel))
                            .clicked()
                        {
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

        d.push_str(&format!(
            "Desktop version: {} (beta)\n",
            env!("CARGO_PKG_VERSION")
        ));
        d.push_str(&format!(
            "OS:              {} {}\n",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
        d.push_str(&format!("OS version:      {}\n", os_version()));
        d.push_str(&format!("Timestamp:       {}\n", epoch_timestamp()));
        let uptime_secs = self.startup_time.elapsed().as_secs();
        d.push_str(&format!(
            "Desktop uptime:  {}m {}s\n",
            uptime_secs / 60,
            uptime_secs % 60
        ));

        // Detect installed vs portable.
        let exe_path = std::env::current_exe().unwrap_or_default();
        let install_type = if exe_path.to_string_lossy().contains("Program Files") {
            "Installed (MSI)"
        } else {
            "Portable"
        };
        d.push_str(&format!("Install type:    {}\n", install_type));

        d.push_str(&format!("Data directory:  {}\n", self.data_dir_display));
        d.push_str(&format!(
            "Desktop log:     {}{}desktop.log.*\n",
            self.data_dir_display,
            std::path::MAIN_SEPARATOR
        ));
        d.push_str(&format!(
            "Daemon log:      {}{}daemon.log.*\n",
            self.data_dir_display,
            std::path::MAIN_SEPARATOR
        ));
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
            if self.peer_id.is_empty() {
                "(none)"
            } else {
                &self.peer_id
            }
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

        // Font detection results — helpful for diagnosing CJK rendering.
        if let Some(detection) = FONT_DETECTION.get() {
            d.push_str("\n--- Font Detection ---\n");
            if detection.loaded.is_empty() {
                d.push_str("  (no system fonts loaded — using egui defaults)\n");
            } else {
                d.push_str("  Loaded:\n");
                for f in &detection.loaded {
                    d.push_str(&format!("    {f}\n"));
                }
            }
            if !detection.missing.is_empty() {
                d.push_str("  Not found:\n");
                for f in &detection.missing {
                    d.push_str(&format!("    {f}\n"));
                }
            }
        }

        d.push_str("\n(end of report)\n");
        d
    }
}

// ─── UI helpers ─────────────────────────────────────────────────────────────

fn section_heading(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .size(18.0)
            .strong()
            .color(egui::Color32::from_rgb(220, 225, 235)),
    );
    // Subtle separator line below heading.
    let rect = ui.allocate_space(egui::vec2(ui.available_width(), 1.0)).1;
    ui.painter().rect_filled(rect, 0.0, SEPARATOR);
}

/// Wrap content in a subtle card frame for visual grouping.
fn format_epoch(epoch_secs: u64) -> String {
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

/// Map envelope state string to a (color, label) for outbox display.
fn outbox_state_display<'a>(s: &'a crate::locale::Strings, state: &'a str) -> (egui::Color32, &'a str) {
    match state {
        "Pending" => (YELLOW, s.outbox_waiting_challenge),
        "ChallengeIssued" => (YELLOW, s.outbox_confirm_heading),
        "Confirmed" => (GREEN, s.outbox_confirmed),
        "Retrieved" => (GREEN, s.outbox_retrieved),
        "Expired" => (RED, s.outbox_expired),
        "SenderRevoked" => (RED, s.outbox_revoked),
        "RecipientDeleted" => (DIM, s.outbox_revoked),
        "ChallengeFailed" => (RED, s.outbox_challenge_failed),
        "PasswordFailed" => (RED, s.outbox_password_failed),
        _ => (DIM, state),
    }
}

/// Map envelope state string to a (color, label) for inbox display.
fn inbox_state_display<'a>(s: &'a crate::locale::Strings, state: &'a str) -> (egui::Color32, &'a str) {
    match state {
        "Pending" | "ChallengeIssued" => (YELLOW, s.inbox_state),
        "Confirmed" => (GREEN, s.outbox_confirmed),
        "Retrieved" => (GREEN, s.inbox_retrieved),
        "Expired" => (RED, s.inbox_expired),
        "SenderRevoked" => (RED, s.inbox_revoked),
        "RecipientDeleted" => (DIM, s.outbox_revoked),
        "ChallengeFailed" => (RED, s.outbox_challenge_failed),
        "PasswordFailed" => (RED, s.inbox_attempts_exhausted),
        _ => (DIM, state),
    }
}

fn card_frame() -> egui::Frame {
    egui::Frame::none()
        .inner_margin(egui::Margin::same(14.0))
        .rounding(8.0)
        .fill(CARD_BG)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 48, 56)))
}

/// Nav bar tab button with active styling.
fn nav_tab(ui: &mut egui::Ui, current: &mut Tab, tab: Tab, label: &str) {
    let is_active = *current == tab;
    let text = if is_active {
        egui::RichText::new(label)
            .size(13.0)
            .strong()
            .color(egui::Color32::WHITE)
    } else {
        egui::RichText::new(label).size(13.0).color(DIM)
    };
    let frame = egui::Frame::none()
        .inner_margin(egui::Margin::symmetric(10.0, 5.0))
        .rounding(4.0)
        .fill(if is_active {
            NAV_ACTIVE_BG
        } else {
            egui::Color32::TRANSPARENT
        });
    let resp = frame
        .show(ui, |ui| {
            ui.label(text);
        })
        .response
        .interact(egui::Sense::click());
    if resp.clicked() {
        *current = tab;
    }
    if resp.hovered() && !is_active {
        ui.painter().rect_filled(
            resp.rect,
            4.0,
            egui::Color32::from_rgba_premultiplied(255, 255, 255, 8),
        );
    }
}

/// Get OS version string for diagnostics.
fn os_version() -> String {
    #[cfg(windows)]
    {
        // Try reading Windows version from registry-like env or version API.
        if let Ok(ver) = std::process::Command::new("cmd")
            .args(["/c", "ver"])
            .output()
        {
            let out = String::from_utf8_lossy(&ver.stdout);
            let trimmed = out.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = std::fs::read_to_string("/etc/os-release") {
            for line in info.lines() {
                if let Some(name) = line.strip_prefix("PRETTY_NAME=") {
                    return name.trim_matches('"').to_string();
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(ver) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            let out = String::from_utf8_lossy(&ver.stdout);
            let trimmed = out.trim();
            if !trimmed.is_empty() {
                return format!("macOS {trimmed}");
            }
        }
    }
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
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
            .frame(
                egui::Frame::none()
                    .fill(NAV_BG)
                    .inner_margin(egui::Margin::symmetric(14.0, 0.0))
                    .stroke(egui::Stroke::new(1.0, SEPARATOR)),
            )
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    // ── Brand mark ──
                    let brand = if easy { s.nav_brand_easy } else { s.nav_brand };
                    ui.label(
                        egui::RichText::new(brand)
                            .size(14.0)
                            .strong()
                            .color(BRAND_TEXT),
                    );
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("|").size(14.0).color(SEPARATOR));
                    ui.add_space(6.0);

                    // ── Tab buttons with active indicator ──
                    let store_label = if easy { s.tab_store_easy } else { s.tab_store };
                    let retrieve_label = if easy {
                        s.tab_retrieve_easy
                    } else {
                        s.tab_retrieve
                    };
                    nav_tab(ui, &mut self.tab, Tab::Store, store_label);
                    nav_tab(ui, &mut self.tab, Tab::Retrieve, retrieve_label);
                    let send_label = if easy { s.tab_send_easy } else { s.tab_send };
                    let inbox_label = if easy { s.tab_inbox_easy } else { s.tab_inbox };
                    let outbox_label = if easy { s.tab_outbox_easy } else { s.tab_outbox };
                    nav_tab(ui, &mut self.tab, Tab::Send, send_label);
                    nav_tab(ui, &mut self.tab, Tab::Inbox, inbox_label);
                    nav_tab(ui, &mut self.tab, Tab::Outbox, outbox_label);
                    nav_tab(ui, &mut self.tab, Tab::Status, s.tab_status);
                    nav_tab(ui, &mut self.tab, Tab::Settings, s.tab_settings);
                    // Show Import tab only when an import is active.
                    if self.import_intent.is_some() || self.import_state != ImportState::Idle {
                        nav_tab(ui, &mut self.tab, Tab::Import, s.tab_import);
                    }

                    // Right-aligned connection indicator with dot.
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (color, label) = match self.daemon_state {
                            DaemonState::Connected => (GREEN, s.connected),
                            DaemonState::Starting => (BLUE, s.starting),
                            DaemonState::Stopped => (RED, s.offline),
                            DaemonState::NeedsInit => (YELLOW, s.setup_needed),
                        };
                        ui.colored_label(color, label);
                        // Status dot.
                        let dot = ui.allocate_space(egui::vec2(8.0, 8.0));
                        ui.painter().circle_filled(dot.1.center(), 4.0, color);
                    });
                });
                ui.add_space(6.0);
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
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button(s.dismiss).clicked() {
                                self.status_msg = None;
                            }
                        });
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
                        Tab::Send => self.send_panel(ui),
                        Tab::Inbox => self.inbox_panel(ui),
                        Tab::Outbox => self.outbox_panel(ui),
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
                    ui.label(egui::RichText::new(s.wipe_confirm_line2).strong());
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
