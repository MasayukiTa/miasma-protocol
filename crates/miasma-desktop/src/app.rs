/// MiasmaApp — egui desktop application.
///
/// Layout: top tab bar, central content, bottom status bar.
/// Connection state machine: NeedsInit → Stopped → Starting → Connected
///
/// Design goals (RC polish):
/// - Feel intentional, not developer-centric
/// - Clear visual hierarchy: state → actions → details
/// - Error states are understandable and recoverable
/// - Destructive actions feel deliberate and safe
/// - Technical beta users can self-diagnose without raw dumps
use eframe::egui;

use crate::worker::{DaemonState, WorkerCmd, WorkerHandle, WorkerResult};

// ─── Color palette ──────────────────────────────────────────────────────────

const GREEN: egui::Color32 = egui::Color32::from_rgb(46, 184, 106);
const YELLOW: egui::Color32 = egui::Color32::from_rgb(240, 180, 50);
const RED: egui::Color32 = egui::Color32::from_rgb(220, 70, 70);
const BLUE: egui::Color32 = egui::Color32::from_rgb(80, 160, 240);
const DIM: egui::Color32 = egui::Color32::from_rgb(140, 140, 140);

// ─── Tab enum ───────────────────────────────────────────────────────────────

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Store,
    Retrieve,
    Status,
    Settings,
}

// ─── App struct ─────────────────────────────────────────────────────────────

pub struct MiasmaApp {
    worker: WorkerHandle,
    tab: Tab,

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
}

#[derive(Clone, Copy, PartialEq)]
enum MsgKind {
    Info,
    Success,
    Error,
}

impl MiasmaApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let data_dir = miasma_core::default_data_dir();
        let worker = WorkerHandle::spawn(data_dir.clone());

        Self {
            worker,
            tab: Tab::Store,
            daemon_state: DaemonState::Stopped,
            last_error: None,
            dissolve_text: String::new(),
            last_mid: None,
            mid_input: String::new(),
            retrieved_summary: None,
            save_data: None,
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
        }
    }

    fn set_msg(&mut self, kind: MsgKind, msg: impl Into<String>) {
        self.status_msg = Some((msg.into(), kind));
    }

    // ── Poll worker ──────────────────────────────────────────────────────

    fn poll_worker(&mut self) {
        while let Ok(res) = self.worker.rx.try_recv() {
            match res {
                WorkerResult::Dissolved { mid } => {
                    self.busy = false;
                    self.last_mid = Some(mid);
                    self.set_msg(MsgKind::Success, "Content stored successfully.");
                }
                WorkerResult::Retrieved { mid, data } => {
                    self.busy = false;
                    let size = format_size(data.len() as u64);
                    self.retrieved_summary = Some(format!(
                        "{size}  — {}",
                        truncate_mid(&mid),
                    ));
                    self.save_data = Some(data);
                    self.set_msg(MsgKind::Success, "Content retrieved. Save to export.");
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
                    self.set_msg(MsgKind::Error, "Wiped. All shares are now permanently unreadable.");
                }
                WorkerResult::StateChanged(state) => {
                    self.last_error = None;
                    self.daemon_state = state;
                }
                WorkerResult::Initialized => {
                    self.busy = false;
                    self.set_msg(MsgKind::Success, "Node initialized.");
                }
                WorkerResult::Err(e) => {
                    self.busy = false;
                    self.last_error = Some(e.clone());
                    self.set_msg(MsgKind::Error, e);
                }
            }
        }
    }

    // ── Connection header ────────────────────────────────────────────────

    fn connection_header(&mut self, ui: &mut egui::Ui) {
        let frame = egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(12.0, 10.0))
            .rounding(6.0);

        match self.daemon_state {
            DaemonState::Connected => {
                // Compact connected indicator — just a colored dot + text in the tab bar area.
                return;
            }
            DaemonState::NeedsInit => {
                let frame = frame.fill(egui::Color32::from_rgb(45, 40, 30));
                frame.show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("Welcome to Miasma")
                                .size(18.0)
                                .strong(),
                        );
                        ui.add_space(6.0);
                        ui.label("Store, encrypt, and share content over a peer-to-peer network.");
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "Click below to create your node identity. \
                                 This generates an encryption key and starts the \
                                 background daemon automatically."
                            ).color(DIM)
                        );
                        ui.add_space(10.0);
                        ui.add_enabled_ui(!self.busy, |ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new("Set Up Node").strong().size(14.0),
                            );
                            if ui.add_sized([180.0, 36.0], btn).clicked() {
                                let _ = self.worker.tx.try_send(WorkerCmd::Init);
                                self.busy = true;
                                self.set_msg(MsgKind::Info, "Setting up node...");
                            }
                        });
                        if self.busy {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(egui::RichText::new("Creating identity and starting daemon...").color(DIM));
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
                        ui.label(
                            egui::RichText::new("Daemon not running")
                                .size(14.0)
                                .color(RED),
                        );
                        ui.add_space(2.0);
                        if let Some(ref err) = self.last_error {
                            ui.label(egui::RichText::new(err).color(DIM).small());
                            ui.add_space(4.0);
                        } else {
                            ui.label(
                                egui::RichText::new(
                                    "The background daemon has stopped. \
                                     Click below to restart it."
                                ).color(DIM).small()
                            );
                            ui.add_space(4.0);
                        }
                        ui.horizontal(|ui| {
                            ui.add_enabled_ui(!self.busy, |ui| {
                                if ui
                                    .add_sized(
                                        [140.0, 28.0],
                                        egui::Button::new("Start Daemon"),
                                    )
                                    .clicked()
                                {
                                    let _ = self.worker.tx.try_send(WorkerCmd::StartDaemon);
                                    self.busy = true;
                                    self.last_error = None;
                                    self.set_msg(MsgKind::Info, "Starting daemon...");
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
                        ui.label(egui::RichText::new("Starting daemon...").color(BLUE));
                    });
                });
                ui.add_space(4.0);
            }
        }
    }

    // ── Store panel ──────────────────────────────────────────────────────

    fn store_panel(&mut self, ui: &mut egui::Ui) {
        let connected = self.daemon_state == DaemonState::Connected;

        section_heading(ui, "Store Content");
        ui.add_space(2.0);
        ui.label(egui::RichText::new(
            "Encrypt, split, and store content into the Miasma network.",
        ).color(DIM));
        ui.add_space(8.0);

        // Text input.
        ui.label("Text input:");
        ui.add_enabled(
            connected,
            egui::TextEdit::multiline(&mut self.dissolve_text)
                .hint_text("Paste or type content here...")
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add_enabled_ui(connected && !self.busy, |ui| {
                if ui
                    .add_sized([120.0, 28.0], egui::Button::new("Choose File..."))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        let _ = self.worker.tx.try_send(WorkerCmd::DissolveFile(path));
                        self.busy = true;
                        self.set_msg(MsgKind::Info, "Storing file...");
                    }
                }
            });

            ui.add_enabled_ui(
                connected && !self.dissolve_text.is_empty() && !self.busy,
                |ui| {
                    if ui
                        .add_sized([120.0, 28.0], egui::Button::new("Store Text"))
                        .clicked()
                    {
                        let _ = self
                            .worker
                            .tx
                            .try_send(WorkerCmd::DissolveText(self.dissolve_text.clone()));
                        self.busy = true;
                        self.set_msg(MsgKind::Info, "Storing text...");
                    }
                },
            );

            if self.busy {
                ui.spinner();
            }
        });

        // MID result.
        if let Some(ref mid) = self.last_mid.clone() {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Content ID (MID):").strong());
            ui.add_space(2.0);

            ui.horizontal(|ui| {
                let mut display = mid.clone();
                ui.add(
                    egui::TextEdit::singleline(&mut display)
                        .desired_width(ui.available_width() - 80.0)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.add_sized([70.0, 24.0], egui::Button::new("Copy")).clicked() {
                    ui.output_mut(|o| o.copied_text = mid.clone());
                    self.set_msg(MsgKind::Info, "MID copied to clipboard.");
                }
            });

            ui.add_space(2.0);
            ui.label(
                egui::RichText::new("Share this ID to let others retrieve the content.")
                    .color(DIM)
                    .small(),
            );
        }
    }

    // ── Retrieve panel ───────────────────────────────────────────────────

    fn retrieve_panel(&mut self, ui: &mut egui::Ui) {
        let connected = self.daemon_state == DaemonState::Connected;

        section_heading(ui, "Retrieve Content");
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new("Reconstruct content from its Miasma Content ID.")
                .color(DIM),
        );
        ui.add_space(8.0);

        ui.label("Content ID (MID):");
        ui.add_enabled(
            connected,
            egui::TextEdit::singleline(&mut self.mid_input)
                .hint_text("miasma:...")
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add_enabled_ui(
                connected && !self.mid_input.is_empty() && !self.busy,
                |ui| {
                    if ui
                        .add_sized([120.0, 28.0], egui::Button::new("Retrieve"))
                        .clicked()
                    {
                        let _ = self
                            .worker
                            .tx
                            .try_send(WorkerCmd::Retrieve(self.mid_input.clone()));
                        self.busy = true;
                        self.set_msg(MsgKind::Info, "Retrieving...");
                    }
                },
            );

            if self.busy {
                ui.spinner();
            }
        });

        if let Some(ref summary) = self.retrieved_summary {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Retrieved:").strong());
            ui.label(summary);
            ui.add_space(4.0);

            if self.save_data.is_some() {
                if ui
                    .add_sized([140.0, 28.0], egui::Button::new("Save to File..."))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_file_name("retrieved.bin")
                        .save_file()
                    {
                        if let Some(data) = &self.save_data {
                            match std::fs::write(&path, data) {
                                Ok(_) => {
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
                }
            }
        }
    }

    // ── Status panel ─────────────────────────────────────────────────────

    fn status_panel(&mut self, ui: &mut egui::Ui) {
        section_heading(ui, "Node Status");
        ui.add_space(4.0);

        // Action buttons.
        ui.horizontal(|ui| {
            if ui.add_sized([90.0, 26.0], egui::Button::new("Refresh")).clicked() {
                let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
            }
            if ui
                .add_sized([140.0, 26.0], egui::Button::new("Copy Diagnostics"))
                .clicked()
            {
                let diag = self.build_diagnostics();
                ui.output_mut(|o| o.copied_text = diag);
                self.set_msg(MsgKind::Info, "Diagnostics copied to clipboard.");
            }
        });

        ui.add_space(8.0);

        // ── Connection & identity ─────────────────────────────────────
        ui.label(egui::RichText::new("Connection").strong());
        ui.add_space(2.0);

        egui::Grid::new("conn_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new("State:").color(DIM));
                match self.daemon_state {
                    DaemonState::Connected => {
                        ui.colored_label(GREEN, "Connected");
                    }
                    DaemonState::Starting => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.colored_label(BLUE, "Starting...");
                        });
                    }
                    DaemonState::Stopped => {
                        ui.colored_label(RED, "Not running");
                    }
                    DaemonState::NeedsInit => {
                        ui.colored_label(YELLOW, "Not initialized");
                    }
                }
                ui.end_row();

                ui.label(egui::RichText::new("Peer ID:").color(DIM));
                if self.peer_id.is_empty() {
                    ui.colored_label(DIM, "—");
                } else {
                    ui.label(
                        egui::RichText::new(&self.peer_id)
                            .font(egui::FontId::monospace(11.0)),
                    );
                }
                ui.end_row();

                ui.label(egui::RichText::new("Peers:").color(DIM));
                let peer_text = self.peer_count.to_string();
                if self.peer_count > 0 {
                    ui.colored_label(GREEN, peer_text);
                } else {
                    ui.label(peer_text);
                }
                ui.end_row();

                if !self.listen_addrs.is_empty() {
                    ui.label(egui::RichText::new("Listening:").color(DIM));
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

        ui.add_space(12.0);

        // ── Storage & replication ─────────────────────────────────────
        ui.label(egui::RichText::new("Storage").strong());
        ui.add_space(2.0);

        egui::Grid::new("storage_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Shares:").color(DIM));
                ui.label(self.share_count.to_string());
                ui.end_row();

                ui.label(egui::RichText::new("Used:").color(DIM));
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

                ui.label(egui::RichText::new("Replication:").color(DIM));
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

        // ── Transport ─────────────────────────────────────────────────
        if !self.transport_statuses.is_empty()
            || self.wss_port > 0
            || self.obfs_quic_port > 0
            || self.proxy_configured
        {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Transport").strong());
            ui.add_space(2.0);

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
                        ui.label(egui::RichText::new("Transport").strong().small());
                        ui.label(egui::RichText::new("Status").strong().small());
                        ui.label(egui::RichText::new("Success / Fail").strong().small());
                        ui.label(egui::RichText::new("Details").strong().small());
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
                        ui.colored_label(YELLOW, "All transports failing.");
                        ui.label("Check proxy settings, firewall rules, or try a different transport in config.toml.");
                    });
                }
            }
        }

        // ── Emergency wipe ────────────────────────────────────────────
        ui.add_space(20.0);
        ui.separator();
        ui.add_space(4.0);

        ui.add_enabled_ui(self.daemon_state == DaemonState::Connected, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Emergency Wipe").color(RED).strong());
                ui.label(
                    egui::RichText::new("— permanently destroys all stored content")
                        .color(DIM)
                        .small(),
                );
            });
            ui.add_space(4.0);
            if ui
                .add_sized(
                    [160.0, 28.0],
                    egui::Button::new(
                        egui::RichText::new("Wipe All Shares").color(RED),
                    ),
                )
                .clicked()
            {
                self.show_wipe_confirm = true;
            }
        });
    }

    // ── Settings panel ───────────────────────────────────────────────────

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        section_heading(ui, "Settings");
        ui.add_space(8.0);

        // ── Paths ─────────────────────────────────────────────────────
        ui.label(egui::RichText::new("Paths").strong());
        ui.add_space(2.0);

        egui::Grid::new("paths_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Data directory:").color(DIM));
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&self.data_dir_display)
                            .font(egui::FontId::monospace(11.0)),
                    );
                    if ui.small_button("Copy").clicked() {
                        ui.output_mut(|o| o.copied_text = self.data_dir_display.clone());
                        self.set_msg(MsgKind::Info, "Path copied.");
                    }
                });
                ui.end_row();

                ui.label(egui::RichText::new("Config file:").color(DIM));
                ui.label(
                    egui::RichText::new(format!("{}{}config.toml", &self.data_dir_display, std::path::MAIN_SEPARATOR))
                        .font(egui::FontId::monospace(11.0)),
                );
                ui.end_row();

                ui.label(egui::RichText::new("Desktop log:").color(DIM));
                ui.label(
                    egui::RichText::new(format!("{}{}desktop.log.*", &self.data_dir_display, std::path::MAIN_SEPARATOR))
                        .font(egui::FontId::monospace(11.0)),
                );
                ui.end_row();
            });

        // Install location (show where the binaries live).
        ui.add_space(2.0);
        egui::Grid::new("install_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Install location:").color(DIM));
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

        ui.add_space(16.0);

        // ── How it works ──────────────────────────────────────────────
        ui.label(egui::RichText::new("How it works").strong());
        ui.add_space(2.0);
        ui.label("The desktop app manages a background daemon that handles storage and networking.");
        ui.label("The daemon starts automatically when you launch the app, and stops when you close it.");
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Your data is stored in:").color(DIM));
        ui.label(
            egui::RichText::new(&self.data_dir_display)
                .font(egui::FontId::monospace(11.0)),
        );
        ui.label(
            egui::RichText::new("This directory is preserved if you uninstall the app.")
                .color(DIM).small(),
        );

        ui.add_space(16.0);

        // ── Actions ───────────────────────────────────────────────────
        ui.label(egui::RichText::new("Actions").strong());
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            if ui
                .add_sized([140.0, 26.0], egui::Button::new("Copy Diagnostics"))
                .clicked()
            {
                let diag = self.build_diagnostics();
                ui.output_mut(|o| o.copied_text = diag);
                self.set_msg(MsgKind::Info, "Diagnostics copied to clipboard.");
            }

            #[cfg(windows)]
            if ui
                .add_sized([140.0, 26.0], egui::Button::new("Open Data Folder"))
                .clicked()
            {
                let _ = std::process::Command::new("explorer")
                    .arg(&self.data_dir_display)
                    .spawn();
            }

            #[cfg(not(windows))]
            if ui
                .add_sized([140.0, 26.0], egui::Button::new("Open Data Folder"))
                .clicked()
            {
                let _ = std::process::Command::new("xdg-open")
                    .arg(&self.data_dir_display)
                    .spawn();
            }
        });

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(4.0);

        ui.label(
            egui::RichText::new(format!(
                "Miasma Desktop v{}  (beta)",
                env!("CARGO_PKG_VERSION")
            ))
            .color(DIM)
            .small(),
        );
    }

    // ── Diagnostics ──────────────────────────────────────────────────────

    fn build_diagnostics(&self) -> String {
        let mut d = String::with_capacity(1024);
        d.push_str("Miasma Diagnostics Report\n");
        d.push_str("========================\n\n");

        d.push_str(&format!("Desktop version: {} (beta)\n", env!("CARGO_PKG_VERSION")));
        d.push_str(&format!("Timestamp:       {}\n", epoch_timestamp()));
        d.push_str(&format!("Data directory:  {}\n", self.data_dir_display));
        d.push_str(&format!("Desktop log:     {}{}desktop.log.*\n", self.data_dir_display, std::path::MAIN_SEPARATOR));
        d.push_str(&format!("Daemon log:      {}{}daemon.log.*\n", self.data_dir_display, std::path::MAIN_SEPARATOR));
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
    ui.label(egui::RichText::new(text).size(18.0).strong());
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

        // ── Top navigation bar ────────────────────────────────────────
        egui::TopBottomPanel::top("nav_bar").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Store, "Store");
                ui.selectable_value(&mut self.tab, Tab::Retrieve, "Retrieve");
                ui.selectable_value(&mut self.tab, Tab::Status, "Status");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");

                // Right-aligned connection indicator.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    match self.daemon_state {
                        DaemonState::Connected => {
                            ui.colored_label(GREEN, "Connected");
                        }
                        DaemonState::Starting => {
                            ui.colored_label(BLUE, "Starting...");
                        }
                        DaemonState::Stopped => {
                            ui.colored_label(RED, "Offline");
                        }
                        DaemonState::NeedsInit => {
                            ui.colored_label(YELLOW, "Setup needed");
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
                                if ui.small_button("dismiss").clicked() {
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
                    }
                    ui.add_space(8.0);
                });
        });

        // ── Wipe confirmation dialog ──────────────────────────────────
        if self.show_wipe_confirm {
            egui::Window::new("Confirm Emergency Wipe")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.add_space(4.0);
                    ui.label("This will permanently destroy the master encryption key.");
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "All stored shares will become unreadable immediately.\n\
                             This action cannot be undone.",
                        )
                        .strong(),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_sized(
                                [120.0, 30.0],
                                egui::Button::new(
                                    egui::RichText::new("Wipe Now")
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
                            .add_sized([120.0, 30.0], egui::Button::new("Cancel"))
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
