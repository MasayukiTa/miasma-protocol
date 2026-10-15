/// MiasmaApp — egui desktop application.
///
/// Layout: top tab bar, central content, bottom status bar.
/// Connection state machine: NeedsInit → Stopped → Starting → Connected
///
/// Supports two product modes (Technical / Easy) and three locales (EN / JA / ZH-CN).
/// Both modes share all backend code; only UI presentation differs.
use eframe::egui::{self, RichText};
use zeroize::{Zeroize, Zeroizing};

use crate::contacts::ContactsUi;
use crate::locale::{self, Locale, LogStrings, Strings, TransferStrings};
use crate::theme::{self, Palette, ThemeMode};
use crate::transfers::TransfersUi;
use crate::ui_kit::{self as kit, Level};
use crate::ux::{self, Answer, RefreshGate};
use crate::variant::ProductMode;
use crate::worker::{DaemonState, WorkerCmd, WorkerHandle, WorkerResult};
use crate::LaunchIntent;

// Compatibility: `contacts.rs` still imports its drawing helpers from here. They are the kit's
// own (`ui_kit.rs`); remove this line when contacts.rs imports `ui_kit` directly.
pub(crate) use crate::ui_kit::{card_frame, danger_button, primary_button, section_heading};

#[cfg(feature = "ui-tour")]
mod tour;

// Style, type scale and spacing are set in one place: `ui_kit::apply_theme`. Fonts are discovered
// per OS in `fonts.rs` (Meiryo first, read from the system, never bundled). Colours come from the
// palette in `theme.rs`; use `pal()` at the call site, never a literal.

/// The palette currently in force (light or dark).
fn pal() -> Palette {
    theme::palette()
}

// ─── Tab enum ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Tab {
    Contacts,
    Transfers,
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
    /// User's appearance choice (System / Light / Dark), persisted.
    theme_mode: ThemeMode,
    /// Which palette is currently applied to egui (None until the first frame is styled).
    applied_dark: Option<bool>,
    #[cfg(feature = "ui-tour")]
    tour: Option<tour::Tour>,
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
    save_file_path: Option<std::path::PathBuf>,

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

    // Transfers screen (resumable large-file transfers)
    transfers: TransfersUi,
    /// Contacts screen (trusted-contact push).
    contacts: ContactsUi,
    /// `miasma-share:` links handed over by later launches (see `link.rs`), and the instance lock
    /// that makes this window the one they are handed to.
    link_rx: Option<std::sync::mpsc::Receiver<String>>,
    _instance: Option<crate::link::Instance>,

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

    /// When each list was last asked for (see `ux::RefreshGate`): a list that is empty is not
    /// asked for again on every frame.
    inbox_gate: RefreshGate,
    outbox_gate: RefreshGate,
    sharing_gate: RefreshGate,
    /// The tab drawn on the previous frame, to notice a tab being opened.
    prev_tab: Tab,

    // Settings / general
    data_dir_display: String,
    busy: bool,
    status_msg: Option<(String, MsgKind)>,
    /// When `status_msg` was set (for the messages that go away by themselves).
    status_msg_at: std::time::Instant,
    show_wipe_confirm: bool,
    /// The "a transfer is running, close anyway?" dialog is open.
    show_close_confirm: bool,
    /// The person confirmed: the next close request goes through.
    close_confirmed: bool,
    /// Delete / revoke waiting for a yes: which side and which envelope.
    revoke_confirm: Option<(RevokeSide, String)>,
    /// Which side asked for the revoke whose answer is still to come (for its message).
    revoke_in_flight: Option<RevokeSide>,
    startup_time: std::time::Instant,
    last_status_poll: std::time::Instant,
    launch_attempts: u32,

    // Logs (memory-only by default; opt-in diagnostic files)
    logs: LogsState,
}

/// Why the background service's log lines are not shown.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DaemonLogsNote {
    Unsupported,
    Unavailable,
}

/// State of the Logs section, the diagnostic-logging banner and the old-log-files notice.
struct LogsState {
    /// The "Show logs" area is open.
    open: bool,
    /// Lines of the background service's buffer, from the last fetch (at most 500).
    daemon_lines: Vec<String>,
    /// Set when the last fetch could not return lines.
    daemon_note: Option<DaemonLogsNote>,
    /// Lines of this program's own buffer (at most 500).
    local_lines: Vec<String>,
    /// Switch state: `privacy.diagnostic_logging`.
    diagnostic_on: bool,
    /// Log files are being written (diagnostic logging on, or stealth mode off): the banner.
    writes_files: bool,
    /// Old log files found at startup, until the person answers.
    legacy: Option<miasma_core::logging::legacy::LegacyLogs>,
    /// The notice has been shown (recorded once).
    legacy_noted: bool,
}

/// Most lines shown from each buffer.
const LOG_VIEW_LINES: usize = 500;
/// Most bytes read from this program's own buffer.
const LOG_VIEW_BYTES: usize = 256 * 1024;

impl LogsState {
    fn new(data_dir: &std::path::Path) -> Self {
        let privacy = miasma_core::logging::load_privacy(data_dir);
        Self {
            open: false,
            daemon_lines: Vec::new(),
            daemon_note: None,
            local_lines: Vec::new(),
            diagnostic_on: privacy.diagnostic_logging,
            writes_files: privacy.writes_log_files(),
            // One scan at startup; it is cheap.
            legacy: miasma_core::logging::legacy::pending(data_dir),
            legacy_noted: false,
        }
    }

    /// Re-read this program's own buffer.
    fn refresh_local(&mut self) {
        self.local_lines = miasma_core::logging::global()
            .map(|l| l.read(None, LOG_VIEW_LINES, LOG_VIEW_BYTES).lines)
            .unwrap_or_default();
    }

    /// The text shown in the log area, also what "Copy" puts on the clipboard.
    fn shown_text(&self, l: &locale::LogStrings) -> String {
        fn last(lines: &[String]) -> &[String] {
            &lines[lines.len().saturating_sub(LOG_VIEW_LINES)..]
        }
        let mut out = String::new();
        out.push_str(&format!("[{}]\n", l.daemon_title));
        match self.daemon_note {
            Some(DaemonLogsNote::Unsupported) => {
                out.push_str(l.unsupported);
                out.push('\n');
            }
            Some(DaemonLogsNote::Unavailable) => {
                out.push_str(l.unavailable);
                out.push('\n');
            }
            None => {
                if self.daemon_lines.is_empty() {
                    out.push_str(l.empty);
                    out.push('\n');
                }
                for line in last(&self.daemon_lines) {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        out.push_str(&format!("\n[{}]\n", l.desktop_title));
        if self.local_lines.is_empty() {
            out.push_str(l.empty);
            out.push('\n');
        }
        for line in last(&self.local_lines) {
            out.push_str(line);
            out.push('\n');
        }
        out
    }
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
    challenge_code: Option<std::sync::Arc<Zeroizing<String>>>,
    created_at: String,
    expires_at: String,
    filename: Option<String>,
    file_size: u64,
}

/// Which side of a directed share asks to end it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RevokeSide {
    /// The recipient declines a file sent to them.
    Recipient,
    /// The sender takes a file back.
    Sender,
}

use crate::ux::MsgLevel as MsgKind;

/// The tabs of the navigation bar, left to right. The Import tab is last and shows only while an
/// import is active.
const NAV_TABS: [Tab; 10] = [
    Tab::Contacts,
    Tab::Transfers,
    Tab::Store,
    Tab::Retrieve,
    Tab::Send,
    Tab::Inbox,
    Tab::Outbox,
    Tab::Status,
    Tab::Settings,
    Tab::Import,
];

/// The first tab of the navigation bar: where a normal launch starts.
const FIRST_TAB: Tab = NAV_TABS[0];

/// The tab shown when the window opens. A normal launch starts on the first tab in the
/// navigation; opening a magnet link or a torrent file goes straight to the Import tab.
fn initial_tab(intent: &LaunchIntent) -> Tab {
    match intent {
        LaunchIntent::Normal => FIRST_TAB,
        LaunchIntent::Magnet(_) | LaunchIntent::TorrentFile(_) => Tab::Import,
    }
}

impl MiasmaApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        mode: ProductMode,
        locale: Locale,
        theme_mode: ThemeMode,
        data_dir: std::path::PathBuf,
        intent: LaunchIntent,
    ) -> Self {
        crate::fonts::install(&cc.egui_ctx);
        let dark = theme::resolve_dark(theme_mode, cc.integration_info.system_theme);
        kit::apply_theme(&cc.egui_ctx, dark);
        let worker = WorkerHandle::spawn(data_dir.clone(), cc.egui_ctx.clone());

        // If launched with a magnet/torrent intent, go to Import tab.
        let first_tab = initial_tab(&intent);
        let (import_intent, import_state) = match &intent {
            LaunchIntent::Normal => (None, ImportState::Idle),
            LaunchIntent::Magnet(_) | LaunchIntent::TorrentFile(_) => {
                (Some(intent), ImportState::Confirming)
            }
        };

        let now = std::time::Instant::now();

        Self {
            worker,
            tab: first_tab,
            prev_tab: first_tab,
            mode,
            locale,
            theme_mode,
            applied_dark: Some(dark),
            #[cfg(feature = "ui-tour")]
            tour: tour::Tour::from_env(),
            data_dir: data_dir.clone(),
            daemon_state: DaemonState::Stopped,
            last_error: None,
            dissolve_text: String::new(),
            last_mid: None,
            mid_input: String::new(),
            retrieved_summary: None,
            save_data: None,
            save_file_path: None,
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
            status_msg_at: now,
            show_wipe_confirm: false,
            show_close_confirm: false,
            close_confirmed: false,
            revoke_confirm: None,
            revoke_in_flight: None,
            inbox_gate: RefreshGate::new(ux::LIST_REFRESH_EVERY),
            outbox_gate: RefreshGate::new(ux::LIST_REFRESH_EVERY),
            sharing_gate: RefreshGate::new(ux::LIST_REFRESH_EVERY),
            startup_time: now,
            last_status_poll: now,
            launch_attempts: 0,
            logs: LogsState::new(&data_dir),

            transfers: TransfersUi::default(),
            contacts: ContactsUi::default(),
            link_rx: None,
            _instance: None,

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

    /// Show New transfer > Receive with a share ID filled in (a `miasma-share:` link was opened).
    pub fn open_share_link(&mut self, share_id: String) {
        self.tab = Tab::Transfers;
        self.transfers.prefill_receive(share_id);
    }

    /// Start receiving links handed over by later launches. `instance` is kept alive for as long as
    /// this window is, so the lock stays held.
    pub fn set_link_listener(
        &mut self,
        rx: std::sync::mpsc::Receiver<String>,
        instance: crate::link::Instance,
    ) {
        self.link_rx = Some(rx);
        self._instance = Some(instance);
    }

    /// Current locale string table.
    fn s(&self) -> &'static Strings {
        locale::strings(self.locale)
    }

    /// Logs section string table.
    fn lg(&self) -> &'static LogStrings {
        locale::log_strings(self.locale)
    }

    /// Transfers screen string table.
    fn tr(&self) -> &'static TransferStrings {
        locale::transfer_strings(self.locale)
    }

    fn set_msg(&mut self, kind: MsgKind, msg: impl Into<String>) {
        self.status_msg = Some((msg.into(), kind));
        self.status_msg_at = std::time::Instant::now();
    }

    /// Ask the service for the inbox now, and hold off the timed refresh for a while.
    fn request_inbox(&mut self) {
        self.inbox_gate.mark(std::time::Instant::now());
        let _ = self.worker.tx.try_send(WorkerCmd::DirectedInbox);
    }

    /// Ask the service for the outbox now, and hold off the timed refresh for a while.
    fn request_outbox(&mut self) {
        self.outbox_gate.mark(std::time::Instant::now());
        let _ = self.worker.tx.try_send(WorkerCmd::DirectedOutbox);
    }

    /// True while something on screen is moving or waiting for an answer, so the window should
    /// keep redrawing quickly. Everything else wakes the window by itself (input, worker replies).
    fn is_moving(&self) -> bool {
        self.busy
            || self.daemon_state == DaemonState::Starting
            || self.import_state == ImportState::InProgress
            || self.transfers.running_count() > 0
            || self.contacts.active_count() > 0
    }

    /// Persist current mode, locale and theme to desktop-prefs.toml.
    fn save_prefs(&self) {
        let prefs = crate::variant::DesktopPrefs {
            mode: self.mode,
            locale: self.locale,
            theme: self.theme_mode,
        };
        prefs.save(&self.data_dir);
    }

    // ── Dialogs ──────────────────────────────────────────────────────────

    /// The "are you sure" dialogs. One is open at a time; each is answered with a button or Esc.
    fn dialogs(&mut self, ctx: &egui::Context) {
        let s = self.s();
        let connected = self.daemon_state == DaemonState::Connected;

        // Closing the window would stop a running transfer.
        if self.show_close_confirm {
            let answer = ux::confirm::show(
                ctx,
                "close_confirm",
                s.close_title,
                s.close_confirm,
                s.close_cancel,
                |ui| {
                    kit::paragraph(ui, s.close_body);
                },
            );
            match answer {
                Answer::Confirm => {
                    self.show_close_confirm = false;
                    self.close_confirmed = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Answer::Cancel => self.show_close_confirm = false,
                Answer::Pending => {}
            }
            return;
        }

        // Emergency wipe: what goes, what stays, that it cannot be undone.
        if self.show_wipe_confirm {
            let answer = ux::confirm::show(
                ctx,
                "wipe_confirm",
                s.wipe_confirm_title,
                s.wipe_confirm_button,
                s.wipe_cancel,
                |ui| {
                    kit::paragraph(ui, s.wipe_confirm_line1);
                    ui.add_space(kit::SP_1);
                    ui.label(
                        RichText::new(s.wipe_confirm_line2)
                            .strong()
                            .color(pal().danger),
                    );
                    ui.add_space(kit::SP_1);
                    kit::paragraph_muted(ui, s.wipe_confirm_kept);
                    if !connected {
                        ui.add_space(kit::SP_1);
                        kit::hint(ui, s.wipe_confirm_offline);
                    }
                },
            );
            match answer {
                Answer::Confirm => {
                    self.show_wipe_confirm = false;
                    self.busy = true;
                    let _ = self.worker.tx.try_send(WorkerCmd::Wipe);
                }
                Answer::Cancel => self.show_wipe_confirm = false,
                Answer::Pending => {}
            }
            return;
        }

        // Decline (recipient) or revoke (sender): one confirmation, one word per side.
        if let Some((side, id)) = self.revoke_confirm.clone() {
            let (title, body, confirm) = match side {
                RevokeSide::Recipient => (
                    s.inbox_revoke_title,
                    s.inbox_revoke_body,
                    s.inbox_revoke_confirm,
                ),
                RevokeSide::Sender => (
                    s.outbox_revoke_title,
                    s.outbox_revoke_body,
                    s.outbox_revoke_confirm,
                ),
            };
            let answer = ux::confirm::show(
                ctx,
                "revoke_confirm",
                title,
                confirm,
                s.dialog_cancel,
                |ui| {
                    kit::paragraph(ui, body);
                },
            );
            match answer {
                Answer::Confirm => {
                    self.revoke_confirm = None;
                    self.revoke_in_flight = Some(side);
                    let _ = self
                        .worker
                        .tx
                        .try_send(WorkerCmd::DirectedRevoke { envelope_id: id });
                }
                Answer::Cancel => self.revoke_confirm = None,
                Answer::Pending => {}
            }
        }
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
                    if let Some(old) = self.save_file_path.take() {
                        let _ = std::fs::remove_file(old);
                    }
                    let size = format_size(data.len() as u64);
                    self.retrieved_summary = Some(format!("{size}  — {}", truncate_mid(&mid),));
                    self.save_data = Some(data);
                    self.set_msg(MsgKind::Success, self.s().retrieve_success);
                }
                WorkerResult::RetrievedToFile {
                    mid,
                    temp_path,
                    bytes_written,
                } => {
                    self.busy = false;
                    if let Some(old) = self.save_file_path.replace(temp_path) {
                        let _ = std::fs::remove_file(old);
                    }
                    self.save_data = None;
                    let size = format_size(bytes_written);
                    self.retrieved_summary = Some(format!("{size}  — {}", truncate_mid(&mid),));
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
                    if let Some(path) = self.save_file_path.take() {
                        let _ = std::fs::remove_file(path);
                    }
                    self.show_wipe_confirm = false;
                    // What the window still remembers about the erased data goes too.
                    self.inbox_items.clear();
                    self.outbox_items.clear();
                    self.sharing_contact = None;
                    self.last_envelope_id = None;
                    self.peer_id.clear();
                    self.contacts = ContactsUi::default();
                    self.transfers = TransfersUi::default();
                    // Finished, not failed: the success colour.
                    self.set_msg(MsgKind::Success, self.s().wipe_done);
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
                    self.send_password.zeroize();
                    self.last_envelope_id = Some(envelope_id);
                    self.set_msg(MsgKind::Success, self.s().send_success);
                    // Auto-refresh outbox to show new item.
                    self.request_outbox();
                }
                WorkerResult::DirectedRetrieved {
                    temp_path,
                    filename,
                    bytes_written,
                } => {
                    self.busy = false;
                    self.inbox_retrieve_password.zeroize();
                    // Content is in temp_path — let user choose save location.
                    let fname = filename.as_deref().unwrap_or("directed_content.bin");
                    if let Some(path) = rfd::FileDialog::new().set_file_name(fname).save_file() {
                        let result = std::fs::rename(&temp_path, &path).or_else(|_| {
                            // rename can fail across filesystems; fall back to copy+delete.
                            std::fs::copy(&temp_path, &path).map(|_| ())?;
                            std::fs::remove_file(&temp_path).ok();
                            Ok::<(), std::io::Error>(())
                        });
                        match result {
                            Ok(()) => {
                                self.set_msg(
                                    MsgKind::Success,
                                    format!("Saved {} bytes to {}", bytes_written, path.display()),
                                );
                            }
                            Err(e) => {
                                self.set_msg(MsgKind::Error, format!("Save failed: {e}"));
                            }
                        }
                    } else {
                        // User cancelled — clean up temp file.
                        std::fs::remove_file(&temp_path).ok();
                    }
                }
                WorkerResult::DirectedRevoked => {
                    self.busy = false;
                    let s = self.s();
                    let done = match self.revoke_in_flight.take() {
                        Some(RevokeSide::Recipient) => s.inbox_revoke_done,
                        _ => s.outbox_revoke_done,
                    };
                    self.set_msg(MsgKind::Success, done);
                    // Refresh inbox and outbox.
                    self.request_inbox();
                    self.request_outbox();
                }
                WorkerResult::DirectedConfirmed => {
                    self.busy = false;
                    self.outbox_confirm_code.zeroize();
                    self.set_msg(MsgKind::Success, self.s().outbox_confirm_success);
                    self.request_outbox();
                }
                WorkerResult::DirectedInboxList(items) => {
                    self.inbox_items = items
                        .into_iter()
                        .map(|item| InboxItem {
                            envelope_id: item.envelope_id,
                            sender: item
                                .sender_peer_id
                                .unwrap_or_else(|| "<legacy/unbound>".to_string()),
                            recipient: item.recipient_pubkey,
                            state: item.state,
                            challenge_code: item
                                .challenge_code
                                .map(|code| std::sync::Arc::new(Zeroizing::new(code))),
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
                            challenge_code: item
                                .challenge_code
                                .map(|code| std::sync::Arc::new(Zeroizing::new(code))),
                            created_at: format_epoch(item.created_at),
                            expires_at: format_epoch(item.expires_at),
                            filename: item.filename,
                            file_size: item.file_size,
                        })
                        .collect();
                }
                WorkerResult::PushReply { req, reply } => {
                    let c = locale::contact_strings(self.locale);
                    self.contacts.on_reply(c, req, reply);
                    for n in self.contacts.take_notices() {
                        self.set_msg(MsgKind::Success, n);
                    }
                }
                WorkerResult::TransferList(list) => self.transfers.on_list(list),
                WorkerResult::TransferPollFailed {
                    message,
                    daemon_down,
                } => {
                    // The worker owns reconnecting; ask it to look (and relaunch) now instead
                    // of waiting for the 30 s status poll.
                    if self.transfers.on_poll_failed(message, daemon_down) {
                        let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
                    }
                }
                WorkerResult::TransferStarted { id } => {
                    self.transfers.on_started(id);
                    self.set_msg(MsgKind::Success, self.tr().started);
                }
                WorkerResult::TransferNamePeeked { mid, name } => {
                    self.transfers.on_name_peeked(&mid, name);
                }
                WorkerResult::TransferCancelRequested => {
                    self.transfers.poll_soon();
                    self.set_msg(MsgKind::Info, self.tr().stop_requested);
                }
                WorkerResult::TransferRemoved { .. } => {
                    self.transfers.poll_soon();
                    self.set_msg(MsgKind::Info, self.tr().removed_msg);
                }
                WorkerResult::TransferRemoveRefused(reason) => {
                    let t = self.tr();
                    self.transfers.on_remove_refused(reason, t);
                }
                WorkerResult::TransferError(e) => {
                    self.transfers.on_error(e);
                }
                WorkerResult::Logs { daemon_lines, .. } => {
                    self.logs.daemon_lines = daemon_lines;
                    self.logs.daemon_note = None;
                    self.logs.refresh_local();
                }
                WorkerResult::LogsUnsupported => {
                    self.logs.daemon_lines.clear();
                    self.logs.daemon_note = Some(DaemonLogsNote::Unsupported);
                    self.logs.refresh_local();
                }
                WorkerResult::LogsUnavailable => {
                    self.logs.daemon_lines.clear();
                    self.logs.daemon_note = Some(DaemonLogsNote::Unavailable);
                    self.logs.refresh_local();
                }
                WorkerResult::DiagnosticSet { enabled, ok } => {
                    // The configuration is the source of truth for both the switch and the banner.
                    let privacy = miasma_core::logging::load_privacy(&self.data_dir);
                    self.logs.diagnostic_on = privacy.diagnostic_logging;
                    self.logs.writes_files = privacy.writes_log_files();
                    if !ok || privacy.diagnostic_logging != enabled {
                        self.set_msg(MsgKind::Error, self.lg().diag_save_failed);
                    }
                }
                WorkerResult::LegacyLogsDone {
                    removed,
                    failed,
                    kept,
                } => {
                    self.logs.legacy = None;
                    if !kept {
                        let l = self.lg();
                        if failed > 0 {
                            let msg = l.legacy_failed.replace("{n}", &failed.to_string());
                            self.set_msg(MsgKind::Error, msg);
                        } else {
                            let msg = l.legacy_deleted.replace("{n}", &removed.to_string());
                            self.set_msg(MsgKind::Success, msg);
                        }
                    }
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

    /// What the page shows above its content while the daemon is not up: one surface, one
    /// primary action.
    fn connection_header(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();

        match self.daemon_state {
            DaemonState::Connected => {}
            DaemonState::NeedsInit => {
                kit::surface(ui, |ui| {
                    kit::status_dot(ui, Level::Warn, s.setup_needed);
                    let title = if easy {
                        s.welcome_title_easy
                    } else {
                        s.welcome_title
                    };
                    ui.label(kit::section_text(title));
                    kit::paragraph(
                        ui,
                        if easy {
                            s.welcome_desc_easy
                        } else {
                            s.welcome_desc
                        },
                    );
                    kit::paragraph_muted(
                        ui,
                        if easy {
                            s.welcome_detail_easy
                        } else {
                            s.welcome_detail
                        },
                    );
                    let progress = if easy {
                        s.welcome_progress_easy
                    } else {
                        s.welcome_progress
                    };
                    kit::button_row(ui, |ui| {
                        if kit::primary(ui, !self.busy, s.welcome_button).clicked() {
                            let _ = self.worker.tx.try_send(WorkerCmd::Init);
                            self.busy = true;
                            self.set_msg(MsgKind::Info, progress);
                        }
                        if self.busy {
                            ui.spinner();
                            ui.label(kit::muted_text(progress));
                        }
                    });
                });
            }
            DaemonState::Stopped => {
                kit::surface(ui, |ui| {
                    kit::status_dot(ui, Level::Error, s.offline);
                    let title = if easy {
                        s.stopped_title_easy
                    } else {
                        s.stopped_title
                    };
                    ui.label(kit::section_text(title));
                    if let Some(ref err) = self.last_error {
                        kit::hint(ui, err);
                    } else {
                        kit::hint(
                            ui,
                            if easy {
                                s.stopped_desc_easy
                            } else {
                                s.stopped_desc
                            },
                        );
                    }
                    let btn_text = if easy {
                        s.stopped_button_easy
                    } else {
                        s.stopped_button
                    };
                    if kit::primary(ui, !self.busy, btn_text).clicked() {
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
            }
            DaemonState::Starting => {
                kit::surface(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        let label = if easy {
                            s.starting_label_easy
                        } else {
                            s.starting_label
                        };
                        ui.label(RichText::new(label).color(kit::level_color(Level::Info)));
                    });
                });
            }
        }
    }

    // ── Store panel ──────────────────────────────────────────────────────

    fn store_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;

        let title = if easy {
            s.store_heading_easy
        } else {
            s.store_heading
        };
        let desc = if easy {
            s.store_desc_easy
        } else {
            s.store_desc
        };
        kit::page(ui, title, Some(desc), |ui| {
            // Easy mode: the three numbers that matter, as plain figures.
            if easy && connected {
                kit::section(ui, s.dashboard_quick_status, |ui| {
                    let pct = if self.quota_mb > 0 {
                        (self.used_mb / self.quota_mb as f64) * 100.0
                    } else {
                        0.0
                    };
                    let storage = if self.quota_mb > 0 {
                        format!("{pct:.0}%")
                    } else {
                        s.dashboard_no_data.to_owned()
                    };
                    kit::stats(
                        ui,
                        &[
                            (s.dashboard_storage_label, storage, Level::Muted),
                            (
                                s.dashboard_peers_label,
                                self.peer_count.to_string(),
                                if self.peer_count > 0 {
                                    Level::Ok
                                } else {
                                    Level::Warn
                                },
                            ),
                            (
                                s.status_items_stored,
                                self.share_count.to_string(),
                                Level::Muted,
                            ),
                        ],
                    );
                    if self.quota_mb > 0 {
                        ui.add_space(kit::SP_1);
                        kit::progress(ui, (pct / 100.0) as f32, pct > 90.0);
                    }
                    if self.peer_count == 0 {
                        kit::notice(ui, Level::Warn, s.health_no_peers);
                    }
                });
            }

            if easy && !connected {
                kit::notice(ui, Level::Warn, s.store_not_connected_hint);
            }

            // The primary task: put text or a file into the network.
            kit::surface(ui, |ui| {
                ui.label(s.store_text_label);
                ui.add_enabled(
                    connected,
                    kit::input_multiline(&mut self.dissolve_text)
                        .hint_text(s.store_text_hint)
                        .desired_rows(if easy { 6 } else { 5 }),
                );
                kit::button_row(ui, |ui| {
                    let can_store = connected && !self.dissolve_text.is_empty() && !self.busy;
                    if kit::primary(ui, can_store, s.store_button).clicked() {
                        let _ = self
                            .worker
                            .tx
                            .try_send(WorkerCmd::DissolveText(self.dissolve_text.clone()));
                        self.busy = true;
                        self.set_msg(MsgKind::Info, s.store_busy);
                    }
                    if ui
                        .add_enabled(
                            connected && !self.busy,
                            kit::secondary_button(s.store_choose_file),
                        )
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            let _ = self.worker.tx.try_send(WorkerCmd::DissolveFile(path));
                            self.busy = true;
                            self.set_msg(MsgKind::Info, s.store_busy);
                        }
                    }
                    if self.busy {
                        ui.spinner();
                    }
                });
            });

            // The result: the MID to hand to whoever should retrieve it.
            if let Some(mid) = self.last_mid.clone() {
                ui.add_space(kit::SP_4);
                let mid_label = if easy {
                    s.store_mid_label_easy
                } else {
                    s.store_mid_label
                };
                kit::section(ui, mid_label, |ui| {
                    ui.horizontal(|ui| {
                        let mut display = mid.clone();
                        let w = kit::input_width_beside_button(ui);
                        ui.add(kit::input_mono(&mut display).desired_width(w));
                        if ui.add(kit::secondary_button(s.store_copy)).clicked() {
                            ui.output_mut(|o| o.copied_text = mid.clone());
                            self.set_msg(MsgKind::Info, s.store_copied);
                        }
                    });
                    kit::hint(
                        ui,
                        if easy {
                            s.store_share_hint_easy
                        } else {
                            s.store_share_hint
                        },
                    );
                });
            }
        });
    }

    // ── Transfers / Retrieve panels ──────────────────────────────────────

    fn transfers_panel(&mut self, ui: &mut egui::Ui) {
        let t = self.tr();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;
        for cmd in self.transfers.show(ui, t, easy, connected) {
            let _ = self.worker.tx.try_send(cmd);
        }
    }

    fn retrieve_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;

        let title = if easy {
            s.retrieve_heading_easy
        } else {
            s.retrieve_heading
        };
        let desc = if easy {
            s.retrieve_desc_easy
        } else {
            s.retrieve_desc
        };
        kit::page(ui, title, Some(desc), |ui| {
            if easy && !connected {
                kit::notice(ui, Level::Warn, s.retrieve_not_connected_hint);
            }

            kit::surface(ui, |ui| {
                ui.label(if easy {
                    s.retrieve_mid_label_easy
                } else {
                    s.retrieve_mid_label
                });
                ui.add_enabled(
                    connected,
                    kit::input_mono(&mut self.mid_input).hint_text("miasma:..."),
                );
                kit::button_row(ui, |ui| {
                    let can_get = connected && !self.mid_input.is_empty() && !self.busy;
                    let label = if easy {
                        s.retrieve_button_easy
                    } else {
                        s.retrieve_button
                    };
                    if kit::primary(ui, can_get, label).clicked() {
                        let _ = self
                            .worker
                            .tx
                            .try_send(WorkerCmd::Retrieve(self.mid_input.clone()));
                        self.busy = true;
                        self.set_msg(MsgKind::Info, s.retrieve_busy);
                    }
                    if self.busy {
                        ui.spinner();
                    }
                });
            });

            if let Some(summary) = self.retrieved_summary.clone() {
                ui.add_space(kit::SP_4);
                kit::section(ui, s.retrieve_result_label, |ui| {
                    kit::paragraph(ui, &summary);
                    if (self.save_data.is_some() || self.save_file_path.is_some())
                        && kit::primary(ui, true, s.retrieve_save_button).clicked()
                    {
                        self.save_retrieved(s);
                    }
                });
            }
        });
    }

    /// Ask where to put the retrieved data and write it there.
    fn save_retrieved(&mut self, s: &'static Strings) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("retrieved.bin")
            .save_file()
        else {
            return;
        };
        if let Some(temp_path) = self.save_file_path.clone() {
            let result = std::fs::rename(&temp_path, &path).or_else(|_| {
                std::fs::copy(&temp_path, &path).map(|_| ())?;
                std::fs::remove_file(&temp_path).ok();
                Ok::<(), std::io::Error>(())
            });
            match result {
                Ok(()) => {
                    self.save_file_path = None;
                    self.set_msg(
                        MsgKind::Success,
                        format!("{} {}", s.retrieve_saved, path.display()),
                    );
                }
                Err(e) => {
                    self.set_msg(MsgKind::Error, format!("{} {e}", s.retrieve_save_failed));
                }
            }
        } else if let Some(data) = &self.save_data {
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

    // ── Send panel (directed sharing) ──────────────────────────────────

    fn send_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let title = if easy {
            s.send_heading_easy
        } else {
            s.send_heading
        };
        let desc = if easy { s.send_desc_easy } else { s.send_desc };
        let connected = self.daemon_state == DaemonState::Connected;

        kit::page(ui, title, Some(desc), |ui| {
            kit::surface(ui, |ui| {
                // Own contact string: what a sender needs to address this device.
                if let Some(contact) = self.sharing_contact.clone() {
                    kit::hint(
                        ui,
                        if easy {
                            s.sharing_key_desc_easy
                        } else {
                            s.sharing_key_desc
                        },
                    );
                    if kit::mono_copy(ui, &contact, s.sharing_key_copy) {
                        self.set_msg(MsgKind::Success, s.sharing_key_copied);
                    }
                    ui.add_space(kit::SP_1);
                    kit::divider(ui);
                    ui.add_space(kit::SP_1);
                } else if connected && self.sharing_gate.take(std::time::Instant::now()) {
                    // Ask once when the tab opens; again only after a while if no answer came.
                    let _ = self.worker.tx.try_send(WorkerCmd::GetSharingKey);
                }

                kit::form_row(ui, s.send_contact_label, None, |ui| {
                    ui.add(kit::input(&mut self.send_contact).hint_text(s.send_contact_hint));
                });
                kit::form_row(ui, s.send_password_label, None, |ui| {
                    ui.add(
                        kit::input(&mut self.send_password)
                            .password(true)
                            .desired_width(240.0),
                    );
                });
                kit::form_row(
                    ui,
                    s.send_retention_label,
                    Some("(e.g. 24h, 7d, 30d)"),
                    |ui| {
                        ui.add(kit::input(&mut self.send_retention).desired_width(120.0));
                    },
                );
                kit::form_row(ui, s.inbox_filename, None, |ui| {
                    ui.horizontal(|ui| {
                        if ui.add(kit::secondary_button(s.send_choose_file)).clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.send_file_path = Some(path);
                            }
                        }
                        if let Some(ref path) = self.send_file_path {
                            kit::mono_elided(ui, &path.display().to_string());
                        }
                    });
                });

                let can_send = connected
                    && !self.busy
                    && !self.send_contact.is_empty()
                    && !self.send_password.is_empty()
                    && self.send_file_path.is_some();
                kit::form_actions(ui, |ui| {
                    if kit::primary(ui, can_send, s.send_button).clicked() {
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
                    if !connected {
                        ui.label(kit::muted_text(s.send_not_connected));
                    } else if self.busy {
                        ui.label(kit::muted_text(s.send_busy));
                    }
                });

                if let Some(eid) = self.last_envelope_id.clone() {
                    ui.add_space(kit::SP_1);
                    kit::form_row(ui, "Envelope ID:", None, |ui| {
                        kit::mono_copy(ui, &eid, s.copy);
                    });
                }
            });
        });
    }

    // ── Inbox panel ─────────────────────────────────────────────────────

    fn inbox_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;
        let title = if easy {
            s.inbox_heading_easy
        } else {
            s.inbox_heading
        };
        let desc = if easy {
            s.inbox_desc_easy
        } else {
            s.inbox_desc
        };

        // Taken out for the frame instead of cloned: the rows need `&mut self` for the password
        // field and the worker.
        let items = std::mem::take(&mut self.inbox_items);
        let refresh_clicked = std::cell::Cell::new(false);
        kit::page_actions(
            ui,
            title,
            Some(desc),
            |ui| {
                if ui.add(kit::compact_button(s.inbox_refresh)).clicked() {
                    refresh_clicked.set(true);
                }
            },
            |ui| {
                // On opening the tab, then every few seconds while it stays open (and after
                // anything that changes the list). An empty list used to be asked for on every
                // frame, forever.
                if connected && self.inbox_gate.take(std::time::Instant::now()) {
                    let _ = self.worker.tx.try_send(WorkerCmd::DirectedInbox);
                }
                if items.is_empty() {
                    ui.label(kit::muted_text(s.inbox_empty));
                    return;
                }
                for item in &items {
                    kit::list_item(ui, |ui| {
                        let (level, state_label) = inbox_state_display(s, &item.state);
                        envelope_header(ui, &item.envelope_id, level, state_label);

                        kit::kv_grid(ui, |g| {
                            g.row(s.inbox_from, |ui| {
                                kit::mono_elided(ui, short(&item.sender, 20));
                            });
                            if let Some(ref fname) = item.filename {
                                g.row(s.inbox_filename, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(fname.as_str());
                                        if item.file_size > 0 {
                                            ui.label(kit::muted_text(format!(
                                                "({} {})",
                                                s.inbox_file_size,
                                                format_size(item.file_size)
                                            )));
                                        }
                                    });
                                });
                            }
                            g.text("Created:", &item.created_at);
                            g.text("Expires:", &item.expires_at);
                            // Challenge code: the recipient reads this out to the sender.
                            if let Some(ref code) = item.challenge_code {
                                g.row(s.inbox_challenge, |ui| {
                                    kit::mono_copy(ui, code.as_str(), s.copy);
                                });
                            }
                        });

                        match item.state.as_str() {
                            "Expired" => kit::notice(ui, Level::Error, s.inbox_expired),
                            "SenderRevoked" => kit::notice(ui, Level::Error, s.inbox_revoked),
                            "PasswordFailed" => {
                                kit::notice(ui, Level::Error, s.inbox_attempts_exhausted)
                            }
                            "ChallengeFailed" => {
                                kit::notice(ui, Level::Error, s.outbox_challenge_failed)
                            }
                            _ => {}
                        }

                        // Retrieve (only in Confirmed state).
                        if item.state == "Confirmed" {
                            kit::form_row(ui, s.inbox_password_label, None, |ui| {
                                ui.horizontal(|ui| {
                                    ui.add(
                                        kit::input(&mut self.inbox_retrieve_password)
                                            .password(true)
                                            .desired_width(200.0),
                                    );
                                    let can_retrieve = !self.inbox_retrieve_password.is_empty()
                                        && connected
                                        && !self.busy;
                                    if kit::primary(ui, can_retrieve, s.inbox_retrieve_button)
                                        .clicked()
                                    {
                                        self.busy = true;
                                        let _ =
                                            self.worker.tx.try_send(WorkerCmd::DirectedRetrieve {
                                                envelope_id: item.envelope_id.clone(),
                                                password: self.inbox_retrieve_password.clone(),
                                            });
                                    }
                                });
                            });
                        }

                        // Decline (non-terminal states only): asks first, it cannot be undone.
                        if !is_terminal_state(&item.state)
                            && ui.add(kit::danger_button(s.inbox_revoke_button)).clicked()
                        {
                            self.revoke_confirm =
                                Some((RevokeSide::Recipient, item.envelope_id.clone()));
                        }
                    });
                }
            },
        );
        self.inbox_items = items;
        if refresh_clicked.get() && connected {
            self.request_inbox();
        }
    }

    // ── Outbox panel (sender view) ──────────────────────────────────────

    fn outbox_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;
        let title = if easy {
            s.outbox_heading_easy
        } else {
            s.outbox_heading
        };
        let desc = if easy {
            s.outbox_desc_easy
        } else {
            s.outbox_desc
        };

        let items = std::mem::take(&mut self.outbox_items);
        let refresh_clicked = std::cell::Cell::new(false);
        kit::page_actions(
            ui,
            title,
            Some(desc),
            |ui| {
                if ui.add(kit::compact_button(s.outbox_refresh)).clicked() {
                    refresh_clicked.set(true);
                }
            },
            |ui| {
                if connected && self.outbox_gate.take(std::time::Instant::now()) {
                    let _ = self.worker.tx.try_send(WorkerCmd::DirectedOutbox);
                }
                if items.is_empty() {
                    ui.label(kit::muted_text(s.outbox_empty));
                    return;
                }
                for item in &items {
                    kit::list_item(ui, |ui| {
                        let (level, state_label) = outbox_state_display(s, &item.state);
                        envelope_header(ui, &item.envelope_id, level, state_label);

                        kit::kv_grid(ui, |g| {
                            g.row(s.outbox_to, |ui| {
                                kit::mono_elided(ui, short(&item.recipient, 20));
                            });
                            if let Some(ref fname) = item.filename {
                                g.text(s.outbox_filename, fname);
                            }
                            g.text("Created:", &item.created_at);
                            g.text("Expires:", &item.expires_at);
                        });

                        // Sender confirmation: ask for the challenge code.
                        if item.state == "ChallengeIssued" {
                            kit::notice(ui, Level::Warn, s.outbox_confirm_heading);
                            kit::form_row(ui, s.outbox_confirm_label, None, |ui| {
                                ui.horizontal(|ui| {
                                    ui.add(
                                        kit::input_mono(&mut self.outbox_confirm_code)
                                            .hint_text(s.outbox_confirm_hint)
                                            .desired_width(140.0),
                                    );
                                    let can_confirm = !self.outbox_confirm_code.is_empty()
                                        && connected
                                        && !self.busy;
                                    if kit::primary(ui, can_confirm, s.outbox_confirm_button)
                                        .clicked()
                                    {
                                        self.busy = true;
                                        let _ =
                                            self.worker.tx.try_send(WorkerCmd::DirectedConfirm {
                                                envelope_id: item.envelope_id.clone(),
                                                challenge_code: self.outbox_confirm_code.clone(),
                                            });
                                    }
                                });
                            });
                        }

                        if item.state == "Pending" {
                            kit::notice(ui, Level::Warn, s.outbox_waiting_challenge);
                        }

                        if !is_terminal_state(&item.state)
                            && ui.add(kit::danger_button(s.outbox_revoke_button)).clicked()
                        {
                            self.revoke_confirm =
                                Some((RevokeSide::Sender, item.envelope_id.clone()));
                        }
                    });
                }
            },
        );
        self.outbox_items = items;
        if refresh_clicked.get() && connected {
            self.request_outbox();
        }
    }

    // ── Status panel ─────────────────────────────────────────────────────

    fn status_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        let connected = self.daemon_state == DaemonState::Connected;

        kit::page(ui, s.status_heading, None, |ui| {
            kit::button_row(ui, |ui| {
                if ui.add(kit::secondary_button(s.status_refresh)).clicked() {
                    let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
                }
                if !easy {
                    self.copy_diagnostics_button(ui);
                }
                // "Save report" is in both modes: it is what support asks for.
                self.save_diagnostics_button(ui);
            });
            ui.add_space(kit::SP_2);

            if easy {
                self.status_panel_easy(ui);
            } else {
                self.status_panel_technical(ui);
            }

            // Emergency wipe: a section of its own at the bottom, never next to a primary.
            // The button works with the background service stopped too: the wipe then runs
            // without it, so it is never greyed out when it may be needed most.
            kit::section(ui, s.wipe_label, |ui| {
                kit::paragraph_muted(ui, s.wipe_desc);
                if ui.add(kit::danger_button(s.wipe_button)).clicked() {
                    self.show_wipe_confirm = true;
                }
                if !connected {
                    kit::hint(ui, s.wipe_offline_note);
                }
            });
        });
    }

    fn copy_diagnostics_button(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        if ui.add(kit::secondary_button(s.status_copy_diag)).clicked() {
            let diag = self.build_diagnostics();
            ui.output_mut(|o| o.copied_text = diag);
            self.set_msg(MsgKind::Info, s.status_diag_copied);
        }
    }

    fn save_diagnostics_button(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        if ui.add(kit::secondary_button(s.status_save_diag)).clicked() {
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
                    Err(e) => {
                        self.set_msg(MsgKind::Error, format!("{}{e}", s.status_diag_save_failed))
                    }
                }
            }
        }
    }

    /// Easy-mode status: one headline, three health lines, three numbers.
    fn status_panel_easy(&self, ui: &mut egui::Ui) {
        let s = self.s();

        let (level, status_text, hint) = if self.daemon_state == DaemonState::Connected {
            if self.peer_count > 0 {
                (Level::Ok, s.status_ready, s.status_hint_ready)
            } else {
                (
                    Level::Warn,
                    s.status_state_connected,
                    s.status_hint_no_peers,
                )
            }
        } else {
            (Level::Error, s.status_not_ready, s.status_hint_not_ready)
        };

        kit::status_headline(ui, level, status_text);
        kit::paragraph_muted(ui, hint);
        ui.add_space(kit::SP_2);

        // Health: app, backend, network.
        kit::divider(ui);
        ui.add_space(kit::SP_1);
        kit::status_dot(ui, Level::Ok, &format!("{}  {}", s.health_app, s.health_ok));
        match self.daemon_state {
            DaemonState::Connected => {
                kit::status_dot(
                    ui,
                    Level::Ok,
                    &format!("{}  {}", s.health_backend, s.health_ok),
                );
            }
            DaemonState::Starting => {
                kit::status_dot(
                    ui,
                    Level::Warn,
                    &format!("{}  {}", s.health_backend, s.health_starting),
                );
            }
            _ => {
                kit::status_dot(
                    ui,
                    Level::Error,
                    &format!("{}  {}", s.health_backend, s.health_offline),
                );
            }
        }
        if self.daemon_state == DaemonState::Connected {
            if self.peer_count > 0 {
                kit::status_dot(
                    ui,
                    Level::Ok,
                    &format!(
                        "{}  {} {}",
                        s.health_network,
                        self.peer_count,
                        s.status_peers.trim_end_matches('：').trim_end_matches(':')
                    ),
                );
            } else {
                kit::status_dot(
                    ui,
                    Level::Warn,
                    &format!("{}  {}", s.health_network, s.health_no_peers),
                );
            }
        } else {
            kit::status_dot(
                ui,
                Level::Error,
                &format!("{}  {}", s.health_network, s.health_offline),
            );
        }
        ui.add_space(kit::SP_2);

        if self.daemon_state == DaemonState::Connected {
            kit::divider(ui);
            ui.add_space(kit::SP_1);
            kit::kv_grid(ui, |g| {
                g.text(s.status_items_stored, &self.share_count.to_string());
                g.text(s.status_peers, &self.peer_count.to_string());
                if self.quota_mb > 0 {
                    g.row(s.status_used, |ui| self.storage_usage(ui));
                }
            });
            ui.add_space(kit::SP_4);
        }
    }

    /// "12.3 / 10240 MiB (11%)" with a bar under it.
    fn storage_usage(&self, ui: &mut egui::Ui) {
        let pct = (self.used_mb / self.quota_mb as f64) * 100.0;
        let used_text = format!("{:.1} / {} MiB  ({:.0}%)", self.used_mb, self.quota_mb, pct);
        if pct > 90.0 {
            ui.label(RichText::new(used_text).color(kit::level_color(Level::Warn)));
        } else {
            ui.label(used_text);
        }
        kit::progress(ui, (pct / 100.0) as f32, pct > 90.0);
    }

    /// Technical-mode status: full diagnostics, one section per topic.
    fn status_panel_technical(&self, ui: &mut egui::Ui) {
        let s = self.s();

        // ── Connection & identity ─────────────────────────────────────
        kit::section(ui, s.status_connection, |ui| {
            kit::kv_grid(ui, |g| {
                g.row(s.status_state, |ui| match self.daemon_state {
                    DaemonState::Connected => {
                        kit::status_dot(ui, Level::Ok, s.status_state_connected);
                    }
                    DaemonState::Starting => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(
                                RichText::new(s.status_state_starting)
                                    .color(kit::level_color(Level::Info)),
                            );
                        });
                    }
                    DaemonState::Stopped => {
                        kit::status_dot(ui, Level::Error, s.status_state_not_running);
                    }
                    DaemonState::NeedsInit => {
                        kit::status_dot(ui, Level::Warn, s.status_state_not_init);
                    }
                });
                g.row(s.status_peer_id, |ui| {
                    if self.peer_id.is_empty() {
                        ui.label(kit::muted_text("—"));
                    } else {
                        kit::mono(ui, &self.peer_id);
                    }
                });
                g.text(s.status_peers, &self.peer_count.to_string());
                if !self.listen_addrs.is_empty() {
                    g.row(s.status_listening, |ui| {
                        for addr in &self.listen_addrs {
                            kit::mono(ui, addr);
                        }
                    });
                }
            });
        });

        // ── Storage & replication ─────────────────────────────────────
        kit::section(ui, s.status_storage, |ui| {
            kit::kv_grid(ui, |g| {
                g.text(s.status_shares, &self.share_count.to_string());
                g.row(s.status_used, |ui| {
                    if self.quota_mb > 0 {
                        self.storage_usage(ui);
                    } else {
                        ui.label(format!("{:.1} MiB", self.used_mb));
                    }
                });
                g.row(s.status_replication, |ui| {
                    if self.pending_replication > 0 {
                        ui.label(
                            RichText::new(format!(
                                "{} replicated, {} pending",
                                self.replicated_count, self.pending_replication
                            ))
                            .color(kit::level_color(Level::Warn)),
                        );
                    } else if self.replicated_count > 0 {
                        ui.label(format!("{} replicated", self.replicated_count));
                    } else {
                        ui.label(kit::muted_text("—"));
                    }
                });
            });
        });

        // ── Transport ─────────────────────────────────────────────────
        if !self.transport_statuses.is_empty()
            || self.wss_port > 0
            || self.obfs_quic_port > 0
            || self.proxy_configured
        {
            kit::section(ui, s.status_transport, |ui| {
                // Services that are listening, as plain dotted lines.
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = kit::SP_4;
                    if self.wss_port > 0 {
                        let tls = if self.wss_tls_enabled { "TLS" } else { "plain" };
                        kit::status_dot(ui, Level::Ok, &format!("WSS :{} ({tls})", self.wss_port));
                    }
                    if self.obfs_quic_port > 0 {
                        kit::status_dot(
                            ui,
                            Level::Ok,
                            &format!("ObfuscatedQuic :{}", self.obfs_quic_port),
                        );
                    }
                    if self.proxy_configured {
                        kit::status_dot(
                            ui,
                            Level::Info,
                            self.proxy_type.as_deref().unwrap_or("proxy"),
                        );
                    }
                });

                if !self.transport_statuses.is_empty() {
                    ui.add_space(kit::SP_1);
                    let table = kit::table(ui, &[0.28, 0.18, 0.16, 0.38]);
                    table.header(
                        ui,
                        &[
                            s.status_transport_name,
                            s.status_transport_status,
                            s.status_transport_counts,
                            s.status_transport_details,
                        ],
                    );
                    for t in &self.transport_statuses {
                        table.row(ui, true, |row| {
                            row.text(&t.name);
                            let (level, label) = if t.selected {
                                (Level::Ok, "Active")
                            } else if t.available && t.failure_count == 0 {
                                (Level::Ok, "Ready")
                            } else if t.available && t.failure_count > 0 {
                                (Level::Warn, "Degraded")
                            } else if t.failure_count > 0 {
                                (Level::Error, "Failing")
                            } else {
                                (Level::Muted, "Idle")
                            };
                            row.status(level, label);
                            row.text(&format!("{} / {}", t.success_count, t.failure_count));
                            if let Some(ref err) = t.last_error {
                                row.muted(err);
                            } else if t.session_failures > 0 || t.data_failures > 0 {
                                row.muted(&format!(
                                    "session:{} data:{}",
                                    t.session_failures, t.data_failures
                                ));
                            } else {
                                row.muted("—");
                            }
                        });
                    }

                    // Troubleshooting hint when all transports are failing.
                    let all_failing = self
                        .transport_statuses
                        .iter()
                        .all(|t| t.failure_count > 0 && t.success_count == 0);
                    if all_failing && self.transport_statuses.iter().any(|t| t.failure_count > 0) {
                        ui.add_space(kit::SP_2);
                        kit::notice(ui, Level::Warn, s.status_all_failing);
                    }
                }
            });
        }
    }

    // ── Settings panel ───────────────────────────────────────────────────

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();

        kit::page(ui, s.settings_heading, None, |ui| {
            // Preferences: three aligned rows, no frame.
            kit::form_row(ui, s.settings_language, None, |ui| {
                let mut lang = self.locale;
                let options = Locale::ALL.map(|l| (l, l.display_name()));
                if kit::segmented(ui, &mut lang, &options) {
                    self.locale = lang;
                    self.save_prefs();
                }
            });
            kit::form_row(
                ui,
                s.settings_mode,
                Some(if easy {
                    s.settings_mode_desc_easy
                } else {
                    s.settings_mode_desc_technical
                }),
                |ui| {
                    let mut mode = self.mode;
                    let options = [
                        (ProductMode::Easy, s.settings_mode_easy),
                        (ProductMode::Technical, s.settings_mode_technical),
                    ];
                    if kit::segmented(ui, &mut mode, &options) {
                        self.mode = mode;
                        self.save_prefs();
                    }
                },
            );
            kit::form_row(ui, s.settings_theme, None, |ui| {
                let mut theme_mode = self.theme_mode;
                let options = [
                    (ThemeMode::System, s.settings_theme_system),
                    (ThemeMode::Light, s.settings_theme_light),
                    (ThemeMode::Dark, s.settings_theme_dark),
                ];
                if kit::segmented(ui, &mut theme_mode, &options) {
                    self.theme_mode = theme_mode;
                    self.save_prefs();
                }
            });
            ui.add_space(kit::SP_4);

            // ── Paths ────────────────────────────────────────────────
            kit::section(ui, s.settings_paths, |ui| {
                let sep = std::path::MAIN_SEPARATOR;
                kit::kv_grid(ui, |g| {
                    g.row(s.settings_data_dir, |ui| {
                        if kit::mono_copy(ui, &self.data_dir_display, s.copy) {
                            self.set_msg(MsgKind::Info, s.settings_path_copied);
                        }
                    });
                    g.mono(
                        s.settings_config_file,
                        &format!("{}{sep}config.toml", &self.data_dir_display),
                    );
                    let log_where = if self.logs.writes_files {
                        format!("{}{sep}lg", &self.data_dir_display)
                    } else {
                        self.lg().memory_only.to_owned()
                    };
                    g.mono(s.settings_log, &log_where);
                    if let Ok(exe) = std::env::current_exe() {
                        if let Some(dir) = exe.parent() {
                            g.mono(s.settings_install, &dir.to_string_lossy());
                        }
                    }
                });
            });

            // ── Logs ─────────────────────────────────────────────────
            self.logs_section(ui);

            // ── How it works ─────────────────────────────────────────
            kit::section(ui, s.settings_how, |ui| {
                kit::paragraph(
                    ui,
                    if easy {
                        s.settings_how_line1_easy
                    } else {
                        s.settings_how_line1
                    },
                );
                kit::paragraph(
                    ui,
                    if easy {
                        s.settings_how_line2_easy
                    } else {
                        s.settings_how_line2
                    },
                );
                ui.add_space(kit::SP_1);
                kit::paragraph_muted(ui, s.settings_stored_in);
                kit::mono(ui, &self.data_dir_display);
                kit::hint(ui, s.settings_preserved);
            });

            // ── Actions ──────────────────────────────────────────────
            kit::section(ui, s.settings_actions, |ui| {
                kit::button_row(ui, |ui| {
                    self.copy_diagnostics_button(ui);
                    self.save_diagnostics_button(ui);
                    if ui
                        .add(kit::secondary_button(s.settings_open_folder))
                        .clicked()
                    {
                        #[cfg(windows)]
                        let opener = "explorer";
                        #[cfg(not(windows))]
                        let opener = "xdg-open";
                        let _ = std::process::Command::new(opener)
                            .arg(&self.data_dir_display)
                            .spawn();
                    }
                });
            });

            let variant_label = if easy { "" } else { " Technical Beta" };
            kit::hint(
                ui,
                &format!("Miasma{variant_label} v{}", env!("CARGO_PKG_VERSION")),
            );
        });
    }

    // ── Logs section (Settings) ───────────────────────────────────────────

    fn logs_section(&mut self, ui: &mut egui::Ui) {
        let l = self.lg();
        kit::section(ui, l.heading, |ui| {
            // Opt-in diagnostic logging.
            let mut on = self.logs.diagnostic_on;
            if ui.checkbox(&mut on, l.diag_label).changed() {
                self.logs.diagnostic_on = on;
                let _ = self.worker.tx.try_send(WorkerCmd::SetDiagnostic(on));
            }
            kit::paragraph_muted(ui, l.diag_warning);
            ui.add_space(kit::SP_2);

            // The in-memory buffers.
            kit::button_row(ui, |ui| {
                let toggle = if self.logs.open {
                    l.hide_logs
                } else {
                    l.show_logs
                };
                if ui.add(kit::secondary_button(toggle)).clicked() {
                    self.logs.open = !self.logs.open;
                    if self.logs.open {
                        self.logs.refresh_local();
                        let _ = self.worker.tx.try_send(WorkerCmd::LogsFetch);
                    }
                }
            });
            if !self.logs.open {
                return;
            }
            kit::hint(ui, l.memory_note);
            let text = self.logs.shown_text(l);
            egui::ScrollArea::vertical()
                .id_source("settings_logs_view")
                .max_height(280.0)
                .auto_shrink([false, true])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(&text).monospace()));
                });
            kit::button_row(ui, |ui| {
                if ui.add(kit::secondary_button(l.refresh)).clicked() {
                    self.logs.refresh_local();
                    let _ = self.worker.tx.try_send(WorkerCmd::LogsFetch);
                }
                if ui.add(kit::secondary_button(l.copy)).clicked() {
                    // Clipboard only: logs are never exported to a file.
                    ui.output_mut(|o| o.copied_text = text.clone());
                    self.set_msg(MsgKind::Info, l.copied);
                }
                if ui.add(kit::secondary_button(l.clear)).clicked() {
                    self.logs.daemon_lines.clear();
                    self.logs.local_lines.clear();
                    let _ = self.worker.tx.try_send(WorkerCmd::LogsClear);
                }
            });
        });
    }

    /// The old-log-files notice: a window until the person chooses.
    fn legacy_logs_notice(&mut self, ctx: &egui::Context) {
        if self.logs.legacy.is_none() {
            return;
        }
        if !self.logs.legacy_noted {
            self.logs.legacy_noted = true;
            miasma_core::logging::legacy::record_notice_shown(&self.data_dir);
        }
        let l = self.lg();
        egui::Window::new(l.legacy_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                kit::paragraph(ui, l.legacy_body);
                ui.add_space(kit::SP_1);
                kit::button_row(ui, |ui| {
                    if ui.add(kit::primary_button(l.legacy_delete)).clicked() {
                        let _ = self
                            .worker
                            .tx
                            .try_send(WorkerCmd::LegacyLogs { delete: true });
                    }
                    if ui.add(kit::secondary_button(l.legacy_keep)).clicked() {
                        let _ = self
                            .worker
                            .tx
                            .try_send(WorkerCmd::LegacyLogs { delete: false });
                    }
                });
            });
    }

    // ── Import panel (magnet / .torrent) ──────────────────────────────────

    fn import_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();

        kit::page(ui, s.import_heading, None, |ui| match self.import_state {
            ImportState::Idle => {
                // No import: point at the Save tab instead.
                kit::paragraph(ui, s.import_idle_hint);
            }
            ImportState::Confirming => {
                kit::surface(ui, |ui| {
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
                    kit::mono(ui, &description);
                    kit::paragraph_muted(
                        ui,
                        if easy {
                            s.import_explain_easy
                        } else {
                            s.import_explain
                        },
                    );

                    let connected = self.daemon_state == DaemonState::Connected;

                    // Pre-validate: check for problems before offering the Import button.
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
                        kit::notice(ui, Level::Warn, err);
                    }

                    kit::button_row(ui, |ui| {
                        let can_import = connected && !self.busy && validation_error.is_none();
                        if kit::primary(ui, can_import, s.import_button).clicked() {
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
                        if ui.add(kit::secondary_button(s.import_cancel)).clicked() {
                            self.import_state = ImportState::Idle;
                            self.import_intent = None;
                            self.tab = Tab::Store;
                        }
                    });

                    if !connected {
                        kit::notice(ui, Level::Warn, s.import_not_connected);
                    }
                });
            }
            ImportState::InProgress => {
                kit::surface(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            RichText::new(s.import_progress).color(kit::level_color(Level::Info)),
                        );
                    });
                });
            }
            ImportState::Complete => {
                kit::surface(ui, |ui| {
                    kit::status_dot(ui, Level::Ok, s.import_complete);
                    for (i, mid) in self.import_mids.clone().iter().enumerate() {
                        let label = format!("#{}: {}", i + 1, truncate_mid(mid));
                        if kit::mono_copy_labelled(ui, &label, mid, s.store_copy) {
                            self.set_msg(MsgKind::Info, s.store_copied);
                        }
                    }
                    if kit::primary(ui, true, s.import_done).clicked() {
                        self.import_state = ImportState::Idle;
                        self.tab = Tab::Store;
                    }
                });
            }
            ImportState::Failed => {
                kit::surface(ui, |ui| {
                    kit::status_dot(ui, Level::Error, s.import_failed);
                    if let Some(ref err) = self.last_error {
                        kit::hint(ui, err);
                    }
                    kit::button_row(ui, |ui| {
                        if kit::primary(ui, true, s.import_retry).clicked() {
                            self.import_state = ImportState::Confirming;
                        }
                        if ui.add(kit::secondary_button(s.import_cancel)).clicked() {
                            self.import_state = ImportState::Idle;
                            self.import_intent = None;
                            self.tab = Tab::Store;
                        }
                    });
                });
            }
        });
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
        // Log lines are never part of the diagnostics.
        if self.logs.writes_files {
            d.push_str(&format!(
                "Logs:            diagnostic logging is ON; files in {}{}lg\n",
                self.data_dir_display,
                std::path::MAIN_SEPARATOR
            ));
        } else {
            d.push_str("Logs:            memory only (nothing is written to disk)\n");
        }
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
        if let Some(detection) = crate::fonts::detection() {
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

// ─── Small helpers ──────────────────────────────────────────────────────────

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

/// Map envelope state string to a (level, label) for outbox display.
fn outbox_state_display<'a>(s: &'a crate::locale::Strings, state: &'a str) -> (Level, &'a str) {
    match state {
        "Pending" => (Level::Warn, s.outbox_waiting_challenge),
        "ChallengeIssued" => (Level::Warn, s.outbox_confirm_heading),
        "Confirmed" => (Level::Ok, s.outbox_confirmed),
        "Retrieved" => (Level::Ok, s.outbox_retrieved),
        "Expired" => (Level::Error, s.outbox_expired),
        "SenderRevoked" => (Level::Error, s.outbox_revoked),
        "RecipientDeleted" => (Level::Muted, s.outbox_revoked),
        "ChallengeFailed" => (Level::Error, s.outbox_challenge_failed),
        "PasswordFailed" => (Level::Error, s.outbox_password_failed),
        _ => (Level::Muted, state),
    }
}

/// Map envelope state string to a (level, label) for inbox display.
fn inbox_state_display<'a>(s: &'a crate::locale::Strings, state: &'a str) -> (Level, &'a str) {
    match state {
        "Pending" | "ChallengeIssued" => (Level::Warn, s.inbox_state),
        "Confirmed" => (Level::Ok, s.outbox_confirmed),
        "Retrieved" => (Level::Ok, s.inbox_retrieved),
        "Expired" => (Level::Error, s.inbox_expired),
        "SenderRevoked" => (Level::Error, s.inbox_revoked),
        "RecipientDeleted" => (Level::Muted, s.outbox_revoked),
        "ChallengeFailed" => (Level::Error, s.outbox_challenge_failed),
        "PasswordFailed" => (Level::Error, s.inbox_attempts_exhausted),
        _ => (Level::Muted, state),
    }
}

/// An envelope in one of these states can no longer be acted on.
fn is_terminal_state(state: &str) -> bool {
    matches!(
        state,
        "Retrieved"
            | "SenderRevoked"
            | "RecipientDeleted"
            | "Expired"
            | "ChallengeFailed"
            | "PasswordFailed"
    )
}

/// The first `n` characters of `s` (never splits a character).
fn short(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// First line of an inbox/outbox item: the envelope id on the left, its state on the right.
fn envelope_header(ui: &mut egui::Ui, id: &str, level: Level, state_label: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(short(id, 16)).monospace().color(pal().text));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            kit::status_dot(ui, level, state_label);
        });
    });
}

/// Get OS version string for diagnostics.
fn os_version() -> String {
    #[cfg(windows)]
    {
        // Try reading Windows version from registry-like env or version API.
        use std::os::windows::process::CommandExt as _;
        // CREATE_NO_WINDOW: a GUI process spawning a console program would
        // otherwise flash a console window.
        if let Ok(ver) = std::process::Command::new("cmd")
            .args(["/c", "ver"])
            .creation_flags(0x0800_0000)
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

impl Drop for MiasmaApp {
    fn drop(&mut self) {
        self.send_password.zeroize();
        self.inbox_retrieve_password.zeroize();
        self.outbox_confirm_code.zeroize();
        if let Some(path) = self.save_file_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl eframe::App for MiasmaApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        #[cfg(feature = "ui-tour")]
        if let Some(mut t) = self.tour.take() {
            if !t.drive(self, ctx) {
                self.tour = Some(t);
            }
        }

        // Theme: resolve the choice against the OS theme every frame (cheap), and re-apply when
        // it changed. eframe itself resets the visuals when the OS theme flips, so also
        // re-apply if the panel colour is no longer ours.
        let dark = theme::resolve_dark(self.theme_mode, frame.info().system_theme);
        if self.applied_dark != Some(dark) || ctx.style().visuals.panel_fill != pal().bg {
            kit::apply_theme(ctx, dark);
            self.applied_dark = Some(dark);
        }

        // The window redraws quickly only while something moves; otherwise about once a second,
        // for the timers. Input and replies from the worker wake it sooner.
        let moving = self.is_moving();
        ctx.request_repaint_after(ux::repaint_delay(moving));

        // Closing the window stops the background service and every transfer with it: ask first
        // when one is running.
        if ctx.input(|i| i.viewport().close_requested()) && !self.close_confirmed {
            let running = self.transfers.running_count();
            let pushes = self.contacts.active_count();
            if ux::close_needs_confirmation(running, pushes) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.show_close_confirm = true;
            }
        }

        self.poll_worker();

        // Messages that go away by themselves: success and progress notes. Errors stay until
        // they are closed.
        if let Some((_, kind)) = &self.status_msg {
            if ux::message_expired(*kind, self.status_msg_at.elapsed(), moving) {
                self.status_msg = None;
            }
        }

        if let Some(id) = self.link_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.open_share_link(id);
        }

        // Periodic status poll (~30 seconds).
        if self.daemon_state == DaemonState::Connected
            && self.last_status_poll.elapsed() > std::time::Duration::from_secs(30)
        {
            let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
            self.last_status_poll = std::time::Instant::now();
        }

        // Transfers: about once a second while that tab is showing or a transfer is running.
        if self.daemon_state == DaemonState::Connected
            && self.transfers.poll_due(self.tab == Tab::Transfers)
            && self.worker.tx.try_send(WorkerCmd::TransferPoll).is_ok()
        {
            self.transfers.note_polled();
        }

        // Contacts: light polling in the background (arrivals), fast while the area is open.
        {
            let open = self.tab == Tab::Contacts;
            if open {
                self.contacts.mark_seen();
            }
            self.contacts
                .tick(open, self.daemon_state == DaemonState::Connected);
            let tx = self.worker.tx.clone();
            self.contacts
                .drain(|req| tx.try_send(WorkerCmd::Push(req)).is_ok());
        }

        let s = self.s();
        let easy = self.mode.is_easy();

        // ── Top navigation bar ────────────────────────────────────────
        // Two rows so nine tabs never overflow at the 700 px minimum width: brand and connection
        // on the first, the tab strip (which wraps if it must) on the second.
        // The bar's content sits on the same column as the pages below it.
        let edge = kit::column_edge(ctx.screen_rect().width());
        egui::TopBottomPanel::top("nav_bar")
            .frame(
                egui::Frame::none()
                    .fill(pal().surface)
                    .inner_margin(egui::Margin::symmetric(edge, 0.0)),
            )
            .show(ctx, |ui| {
                ui.add_space(kit::SP_2);
                ui.horizontal(|ui| {
                    let brand = if easy { s.nav_brand_easy } else { s.nav_brand };
                    ui.label(kit::section_text(brand));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (level, label) = match self.daemon_state {
                            DaemonState::Connected => (Level::Ok, s.connected),
                            DaemonState::Starting => (Level::Info, s.starting),
                            DaemonState::Stopped => (Level::Error, s.offline),
                            DaemonState::NeedsInit => (Level::Warn, s.setup_needed),
                        };
                        kit::status_dot(ui, level, label);
                    });
                });

                let store_label = if easy { s.tab_store_easy } else { s.tab_store };
                let retrieve_label = if easy {
                    s.tab_retrieve_easy
                } else {
                    s.tab_retrieve
                };
                let tr_label = if easy {
                    self.tr().tab_easy
                } else {
                    self.tr().tab
                };
                let ct = locale::contact_strings(self.locale);
                let contacts_label = match self.contacts.unseen() {
                    0 => ct.tab.to_owned(),
                    n => format!("{} ({n} {})", ct.tab, ct.nav_new),
                };
                let send_label = if easy { s.tab_send_easy } else { s.tab_send };
                let inbox_label = if easy { s.tab_inbox_easy } else { s.tab_inbox };
                let outbox_label = if easy {
                    s.tab_outbox_easy
                } else {
                    s.tab_outbox
                };
                let label_for = |tab: Tab| -> &str {
                    match tab {
                        Tab::Contacts => contacts_label.as_str(),
                        Tab::Transfers => tr_label,
                        Tab::Store => store_label,
                        Tab::Retrieve => retrieve_label,
                        Tab::Send => send_label,
                        Tab::Inbox => inbox_label,
                        Tab::Outbox => outbox_label,
                        Tab::Status => s.tab_status,
                        Tab::Settings => s.tab_settings,
                        Tab::Import => s.tab_import,
                    }
                };
                // The Import tab shows only while an import is active.
                let show_import =
                    self.import_intent.is_some() || self.import_state != ImportState::Idle;
                let count = if show_import {
                    NAV_TABS.len()
                } else {
                    NAV_TABS.len() - 1
                };
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                    for tab in &NAV_TABS[..count] {
                        if kit::nav_tab(ui, self.tab == *tab, label_for(*tab)).clicked() {
                            self.tab = *tab;
                        }
                    }
                });
                // Hairline under the whole bar, edge to edge.
                let y = ui.min_rect().bottom();
                ui.painter().hline(
                    ui.clip_rect().x_range(),
                    y,
                    egui::Stroke::new(1.0, pal().border),
                );
            });

        // A list tab was just opened: its list is due at once.
        if self.tab != self.prev_tab {
            match self.tab {
                Tab::Inbox => self.inbox_gate.reset(),
                Tab::Outbox => self.outbox_gate.reset(),
                Tab::Send => self.sharing_gate.reset(),
                _ => {}
            }
            self.prev_tab = self.tab;
        }

        // ── Bottom status bar ─────────────────────────────────────────
        if let Some((ref msg, kind)) = self.status_msg.clone() {
            egui::TopBottomPanel::bottom("status_bar")
                .frame(
                    egui::Frame::none()
                        .fill(pal().surface)
                        .stroke(egui::Stroke::new(1.0, pal().border))
                        .inner_margin(egui::Margin::symmetric(edge, kit::SP_1)),
                )
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        let level = match kind {
                            MsgKind::Info => Level::Muted,
                            MsgKind::Success => Level::Ok,
                            MsgKind::Error => Level::Error,
                        };
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(kit::compact_button(s.dismiss)).clicked() {
                                self.status_msg = None;
                            }
                            ui.with_layout(
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    kit::status_dot(ui, level, &msg);
                                },
                            );
                        });
                    });
                });
        }

        // ── Central panel: one scrolling column ───────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(pal().bg))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        kit::column(ui, |ui| {
                            // Diagnostic logging writes files: say so on every screen.
                            if self.logs.writes_files {
                                kit::notice(ui, Level::Warn, self.lg().diag_banner);
                            }
                            // Connection state first, when not connected.
                            self.connection_header(ui);
                            match self.tab {
                                Tab::Contacts => {
                                    let c = locale::contact_strings(self.locale);
                                    let connected = self.daemon_state == DaemonState::Connected;
                                    self.contacts.show(ui, c, connected, !easy);
                                }
                                Tab::Transfers => self.transfers_panel(ui),
                                Tab::Store => self.store_panel(ui),
                                Tab::Retrieve => self.retrieve_panel(ui),
                                Tab::Send => self.send_panel(ui),
                                Tab::Inbox => self.inbox_panel(ui),
                                Tab::Outbox => self.outbox_panel(ui),
                                Tab::Status => self.status_panel(ui),
                                Tab::Settings => self.settings_panel(ui),
                                Tab::Import => self.import_panel(ui),
                            }
                        });
                    });
            });

        self.legacy_logs_notice(ctx);

        self.dialogs(ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_launch_starts_on_the_first_tab_of_the_navigation() {
        assert_eq!(initial_tab(&LaunchIntent::Normal), NAV_TABS[0]);
        assert_eq!(initial_tab(&LaunchIntent::Normal), Tab::Contacts);
    }

    #[test]
    fn opening_a_magnet_or_torrent_still_goes_to_import() {
        assert_eq!(
            initial_tab(&LaunchIntent::Magnet("magnet:?xt=urn:btih:abc".into())),
            Tab::Import
        );
        assert_eq!(
            initial_tab(&LaunchIntent::TorrentFile("a.torrent".into())),
            Tab::Import
        );
    }

    #[test]
    fn every_tab_is_in_the_navigation_exactly_once() {
        for (i, a) in NAV_TABS.iter().enumerate() {
            for b in &NAV_TABS[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // Import is the one that is hidden unless an import is active, so it stays last.
        assert_eq!(NAV_TABS[NAV_TABS.len() - 1], Tab::Import);
    }
}
