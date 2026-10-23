/// MiasmaApp — egui desktop application.
///
/// Layout: top tab bar, central content, bottom status bar.
/// Connection state machine: NeedsInit → Stopped → Starting → Connected
///
/// Supports two product modes (Technical / Easy) and three locales (EN / JA / ZH-CN).
/// Both modes share all backend code; only UI presentation differs.
use eframe::egui::{self, RichText};
use zeroize::{Zeroize, Zeroizing};

use crate::a11y::CollapsingExt as _;
use crate::chat_ui::{ChatAction, ChatUi};
use crate::contacts::ContactsUi;
use crate::errors::{ErrorKind, UiError};
use crate::locale::{self, Locale, LogStrings, StorageStrings, Strings, TransferStrings};
use crate::theme::{self, Palette, ThemeMode};
use crate::transfers::TransfersUi;
use crate::ui_kit::{self as kit, Level};
use crate::ux::{self, Answer, RefreshGate};
use crate::variant::ProductMode;
use crate::worker::{DaemonState, WorkerCmd, WorkerHandle, WorkerResult};
use crate::LaunchIntent;
use miasma_core::push::speed_fmt::{SpeedShown, SpeedUnit};

// Compatibility: `contacts.rs` still imports its drawing helpers from here. They are the kit's
// own (`ui_kit.rs`); remove this line when contacts.rs imports `ui_kit` directly.
pub(crate) use crate::ui_kit::{card_frame, danger_button};

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
    Home,
    Contacts,
    Chat,
    Files,
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

/// The categories of the Settings page. Each one is a short page of its own; the Danger zone is
/// last and quiet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum SettingsCat {
    General,
    Privacy,
    Network,
    Updates,
    About,
    Danger,
}

impl SettingsCat {
    pub(crate) const ALL: [SettingsCat; 6] = [
        SettingsCat::General,
        SettingsCat::Privacy,
        SettingsCat::Network,
        SettingsCat::Updates,
        SettingsCat::About,
        SettingsCat::Danger,
    ];

    fn label(self, locale: Locale) -> &'static str {
        let t = locale::settings_strings(locale);
        match self {
            SettingsCat::General => t.cat_general,
            SettingsCat::Privacy => t.cat_privacy,
            SettingsCat::Network => t.cat_network,
            SettingsCat::Updates => t.cat_updates,
            SettingsCat::About => t.cat_about,
            SettingsCat::Danger => t.cat_danger,
        }
    }
}

// ─── App struct ─────────────────────────────────────────────────────────────

pub struct MiasmaApp {
    worker: WorkerHandle,
    tab: Tab,
    /// The category shown on the Settings page.
    settings_cat: SettingsCat,

    // Product mode and locale (persisted to desktop-prefs.toml)
    mode: ProductMode,
    locale: Locale,
    /// User's appearance choice (System / Light / Dark), persisted.
    theme_mode: ThemeMode,
    /// `ui.speed_unit` / `ui.speed_units_shown`.
    speed_prefs: crate::speed::SpeedPrefs,
    /// Which palette is currently applied to egui (None until the first frame is styled).
    applied_dark: Option<bool>,
    #[cfg(feature = "ui-tour")]
    tour: Option<tour::Tour>,
    data_dir: std::path::PathBuf,

    // Connection state
    daemon_state: DaemonState,
    last_error: Option<UiError>,

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
    /// A dialog was open at the end of the last frame: the page behind it is switched off.
    modal_open: bool,
    relay_down: Option<crate::worker::RelayDown>,
    share_count: usize,
    used_mb: f64,
    quota_mb: u64,
    pending_replication: usize,
    /// When the last status answer came (the Status screen says how long ago).
    status_updated_at: Option<std::time::Instant>,
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
    /// Chat screen (one-to-one messages between registered contacts).
    chat: ChatUi,
    /// The one send flow: Home, Contacts, Chat and dropped files all open it.
    send_flow: crate::send_flow::SendFlow,
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
    /// `chat.group_auto_join` as saved: join a group at once when a trusted contact adds me.
    group_auto_join: bool,
    /// Saving that setting failed (shown under it until the next change).
    group_join_save_failed: bool,

    // Settings / general
    data_dir_display: String,
    busy: bool,
    status_msg: Option<(String, MsgKind)>,
    /// When `status_msg` was set (for the messages that go away by themselves).
    status_msg_at: std::time::Instant,
    /// Failures of "open the data folder", reported by the launcher thread.
    open_tx: std::sync::mpsc::Sender<String>,
    open_rx: std::sync::mpsc::Receiver<String>,
    open_last: String,
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

    // Hybrid post-quantum protection of private conversations (`privacy.pqc_mode`)
    pqc_mode: miasma_core::config::PqcMode,

    // Storage (the shares this node keeps: listing and deletion)
    storage: StorageState,

    // Updates (check once after start, Settings section, banner)
    updates: crate::updates::UpdatesUi,
    network: crate::network_ui::NetworkUi,
    // Storage block of Settings: keep encrypted pieces for others (size chooser)
    hosting: crate::hosting_ui::HostingUi,
}

/// Why the stored-share list cannot be shown.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StorageNote {
    /// The background service is older and does not know the storage request.
    Unsupported,
    /// The background service is not reachable.
    Unavailable,
}

/// State of the Storage section in Settings.
struct StorageState {
    /// True once the person has opened the section; the list is asked for on first open.
    open: bool,
    /// Asking the service for the listing right now.
    loading: bool,
    /// The listing, oldest first.
    shares: Vec<miasma_core::store::StoredShare>,
    total_bytes: u64,
    /// Set when the listing cannot be shown at all.
    note: Option<StorageNote>,
    /// A delete waiting for the person to confirm.
    confirm: Option<miasma_core::store::ShareSelection>,
    /// The "delete older than" threshold, edited as text.
    days: String,
    /// Addresses ticked in the list for "Delete selected".
    selected: std::collections::HashSet<String>,
}

impl StorageState {
    fn new() -> Self {
        Self {
            open: false,
            loading: false,
            shares: Vec::new(),
            total_bytes: 0,
            note: None,
            confirm: None,
            days: "30".to_owned(),
            selected: std::collections::HashSet::new(),
        }
    }
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

/// The first place of the top row is Home in Easy mode and Status in Technical mode; Contacts,
/// Chat, Files and Settings follow in the same order in both, so switching mode moves nothing
/// the person already knows.
///
/// The top row of Technical mode: five groups instead of eleven tabs. "Files" opens the second
/// row ([`TECH_FILE_TABS`]); every screen of the old row is still one click or two away.
const TECH_NAV_TABS: [Tab; 5] = [
    Tab::Status,
    Tab::Contacts,
    Tab::Chat,
    Tab::Files,
    Tab::Settings,
];

/// The second row of Technical mode, shown while a file screen is open. Import stays last
/// because it is only shown while an import is active.
const TECH_FILE_TABS: [Tab; 7] = [
    Tab::Transfers,
    Tab::Store,
    Tab::Retrieve,
    Tab::Send,
    Tab::Inbox,
    Tab::Outbox,
    Tab::Import,
];

/// Store-facing navigation used by Easy mode. Internal file states stay separate but are
/// grouped under Files so a new user does not need to learn protocol structure first.
const EASY_NAV_TABS: [Tab; 5] = [
    Tab::Home,
    Tab::Contacts,
    Tab::Chat,
    Tab::Files,
    Tab::Settings,
];

fn is_file_tab(tab: Tab) -> bool {
    matches!(
        tab,
        Tab::Files
            | Tab::Transfers
            | Tab::Store
            | Tab::Retrieve
            | Tab::Send
            | Tab::Inbox
            | Tab::Outbox
            | Tab::Import
    )
}

fn easy_nav_selected(current: Tab, item: Tab) -> bool {
    match item {
        Tab::Files => is_file_tab(current),
        _ => current == item,
    }
}

/// Easy mode starts on a task-oriented Home screen; Technical mode keeps Contacts as the place
/// it opens on.
/// External magnet/torrent launches still open Import directly in either mode.
fn initial_tab(intent: &LaunchIntent, mode: ProductMode) -> Tab {
    match intent {
        LaunchIntent::Normal if mode.is_easy() => Tab::Home,
        LaunchIntent::Normal => Tab::Contacts,
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
        Self::new_with_ctx(
            &cc.egui_ctx,
            cc.integration_info.system_theme,
            mode,
            locale,
            theme_mode,
            data_dir,
            intent,
        )
    }

    /// Same as `new`, from a bare egui context (the window-less UI tour has no eframe frame).
    pub(crate) fn new_with_ctx(
        ctx: &egui::Context,
        system_theme: Option<eframe::Theme>,
        mode: ProductMode,
        locale: Locale,
        theme_mode: ThemeMode,
        data_dir: std::path::PathBuf,
        intent: LaunchIntent,
    ) -> Self {
        crate::fonts::install(ctx, locale);
        let dark = theme::resolve_dark(theme_mode, system_theme);
        kit::apply_theme(ctx, dark);
        let worker = WorkerHandle::spawn(data_dir.clone(), ctx.clone());

        // If launched with a magnet/torrent intent, go to Import tab.
        let first_tab = initial_tab(&intent, mode);
        let (import_intent, import_state) = match &intent {
            LaunchIntent::Normal => (None, ImportState::Idle),
            LaunchIntent::Magnet(_) | LaunchIntent::TorrentFile(_) => {
                (Some(intent), ImportState::Confirming)
            }
        };

        let now = std::time::Instant::now();
        let (open_tx, open_rx) = std::sync::mpsc::channel();

        Self {
            worker,
            tab: first_tab,
            settings_cat: SettingsCat::General,
            prev_tab: first_tab,
            mode,
            locale,
            theme_mode,
            speed_prefs: {
                let p = crate::variant::DesktopPrefs::load(&data_dir);
                crate::speed::SpeedPrefs {
                    unit: p.speed_unit,
                    shown: p.speed_units_shown,
                }
            },
            group_auto_join: crate::group::load_auto_join(&data_dir),
            group_join_save_failed: false,
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
            modal_open: false,
            relay_down: None,
            share_count: 0,
            used_mb: 0.0,
            quota_mb: 0,
            pending_replication: 0,
            status_updated_at: None,
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
            open_tx,
            open_rx,
            open_last: String::new(),
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
            pqc_mode: miasma_core::logging::load_privacy(&data_dir).pqc_mode,
            storage: StorageState::new(),
            updates: crate::updates::UpdatesUi::new(data_dir.clone()),
            network: crate::network_ui::NetworkUi::new(data_dir.clone()),
            hosting: crate::hosting_ui::HostingUi::new(data_dir.clone()),

            transfers: TransfersUi::default(),
            contacts: ContactsUi::default(),
            chat: ChatUi::default(),
            send_flow: crate::send_flow::SendFlow::default(),
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

    /// Advanced encryption block string table.
    fn pq(&self) -> &'static locale::PqcStrings {
        locale::pqc_strings(self.locale)
    }

    /// Transfers screen string table.
    fn tr(&self) -> &'static TransferStrings {
        locale::transfer_strings(self.locale)
    }

    /// Storage section string table.
    fn st(&self) -> &'static StorageStrings {
        locale::storage_strings(self.locale)
    }

    /// An error in the UI language; Technical mode adds the original wording.
    fn error_text(&self, e: &UiError) -> String {
        e.text(self.locale, !self.mode.is_easy())
    }

    /// The error as a hint line, with the original wording under it in Technical mode.
    fn error_hint(&self, ui: &mut egui::Ui, e: &UiError) {
        kit::hint(ui, e.plain(self.locale));
        if !self.mode.is_easy() && !e.detail.is_empty() {
            kit::mono(ui, &e.detail);
        }
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
            || self.send_flow.is_busy()
    }

    /// Persist current mode, locale and theme to desktop-prefs.toml.
    fn save_prefs(&self) {
        let prefs = crate::variant::DesktopPrefs {
            mode: self.mode,
            locale: self.locale,
            theme: self.theme_mode,
            speed_unit: self.speed_prefs.unit,
            speed_units_shown: self.speed_prefs.shown,
        };
        prefs.save(&self.data_dir);
    }

    // ── Dialogs ──────────────────────────────────────────────────────────

    /// Whether one of the dialogs drawn by [`Self::dialogs`] is open.
    /// Any dialog is open, including the ones the screens draw themselves. A dialog belongs to
    /// the screen that draws it, so it only counts while that screen is showing.
    fn any_modal_open(&self) -> bool {
        self.dialog_is_open()
            || self.send_flow.is_open()
            || (self.tab == Tab::Chat && self.chat.modal_open())
            || (self.tab == Tab::Contacts && self.contacts.modal_open())
    }

    fn dialog_is_open(&self) -> bool {
        self.show_close_confirm
            || self.show_wipe_confirm
            || self.revoke_confirm.is_some()
            || self.storage.confirm.is_some()
    }

    /// Files dragged over the window get a "Drop files to send" veil; files dropped on it open
    /// the send flow. On a conversation, or on a person's row in Contacts, that person is
    /// already chosen.
    fn handle_drops(&mut self, ctx: &egui::Context) {
        let d = crate::send_flow::read_drops(ctx);
        // With "Add a contact" open, a dropped picture is read as a QR code for that form (it is
        // not offered for sending).
        if self.tab == Tab::Contacts && self.contacts.add_dialog_open() && !self.dialog_is_open() {
            if d.hovering {
                crate::send_flow::paint_drop_overlay(
                    ctx,
                    locale::contact_strings(self.locale).qr_img_overlay,
                );
            }
            if let Some(path) = d.paths.into_iter().next() {
                self.contacts.load_qr_image(ctx, path);
            }
            return;
        }
        if d.hovering && !self.dialog_is_open() {
            crate::send_flow::paint_drop_overlay(
                ctx,
                locale::compose_strings(self.locale).drop_overlay,
            );
        }
        if d.paths.is_empty() || self.dialog_is_open() {
            return;
        }
        if self.daemon_state != DaemonState::Connected {
            let text = self.tr().forms_offline;
            self.set_msg(MsgKind::Error, text);
            return;
        }
        let contact = match self.tab {
            Tab::Chat => self.chat.open_contact_id().map(str::to_owned),
            Tab::Contacts => self.contacts.drop_contact(d.pos),
            _ => None,
        }
        .filter(|id| self.contacts.can_send_to(id));
        self.send_flow
            .open_with_files(d.paths, contact, self.contacts.contact_list());
    }

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

        // Deleting stored shares: what it frees, and who it affects.
        if let Some(selection) = self.storage.confirm.clone() {
            let st = self.st();
            let au = locale::audit_strings(self.locale);
            let scope = match &selection {
                miasma_core::store::ShareSelection::All => crate::transfers::fill(
                    au.storage_scope_all,
                    &[("n", &self.share_count.to_string())],
                ),
                miasma_core::store::ShareSelection::Ids(ids) => {
                    crate::transfers::fill(au.storage_scope_ids, &[("n", &ids.len().to_string())])
                }
                miasma_core::store::ShareSelection::OlderThanDays(d) => {
                    crate::transfers::fill(au.storage_scope_days, &[("n", &d.to_string())])
                }
            };
            let answer = ux::confirm::show(
                ctx,
                "storage_delete_confirm",
                st.confirm_title,
                st.confirm_button,
                st.cancel,
                |ui| {
                    kit::paragraph(ui, &scope);
                    kit::paragraph_muted(ui, st.confirm_body);
                },
            );
            match answer {
                Answer::Confirm => {
                    self.storage.confirm = None;
                    let _ = self
                        .worker
                        .tx
                        .try_send(WorkerCmd::StorageDelete { selection });
                }
                Answer::Cancel => self.storage.confirm = None,
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
                    relay_down,
                    keeping_awake,
                } => {
                    self.busy = false;
                    self.chat.relay_down = relay_down.is_some();
                    self.relay_down = relay_down;
                    self.transfers.keeping_awake = keeping_awake;
                    self.peer_id = peer_id;
                    self.peer_count = peer_count;
                    self.share_count = share_count;
                    self.used_mb = used_mb;
                    self.quota_mb = quota_mb;
                    self.pending_replication = pending_replication;
                    self.status_updated_at = Some(std::time::Instant::now());
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
                    self.chat = ChatUi::default();
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
                                let s = self.s();
                                let saved = format!(
                                    "{} {} ({})",
                                    s.retrieve_saved,
                                    path.display(),
                                    format_size(bytes_written)
                                );
                                self.set_msg(MsgKind::Success, saved);
                            }
                            Err(e) => {
                                let err = UiError::new(ErrorKind::DiskError, e.to_string());
                                let text = self.error_text(&err);
                                self.set_msg(MsgKind::Error, text);
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
                                .unwrap_or_else(|| LEGACY_SENDER.to_string()),
                            recipient: item.recipient_pubkey,
                            state: item.state,
                            challenge_code: item
                                .challenge_code
                                .map(|code| std::sync::Arc::new(Zeroizing::new(code))),
                            created_at: format_epoch_full(item.created_at, self.locale),
                            expires_at: format_expiry(item.expires_at, self.locale),
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
                            created_at: format_epoch_full(item.created_at, self.locale),
                            expires_at: format_expiry(item.expires_at, self.locale),
                            filename: item.filename,
                            file_size: item.file_size,
                        })
                        .collect();
                }
                WorkerResult::PushReply { req, reply } => {
                    let c = locale::contact_strings(self.locale);
                    self.contacts
                        .set_error_context(self.locale, !self.mode.is_easy());
                    self.contacts.on_reply(c, req, reply);
                    for n in self.contacts.take_notices() {
                        self.set_msg(MsgKind::Success, n);
                    }
                }
                WorkerResult::ChatReply { req, reply } => {
                    let c = locale::chat_strings(self.locale);
                    self.chat.on_reply(c, req, reply);
                    for n in self.chat.take_notices() {
                        self.set_msg(MsgKind::Success, n);
                    }
                }
                WorkerResult::TransferList(list) => self.transfers.on_list(list),
                WorkerResult::TransferPollFailed {
                    message,
                    daemon_down,
                } => {
                    let message = self.error_text(&message);
                    // The worker owns reconnecting; ask it to look (and relaunch) now instead
                    // of waiting for the 30 s status poll.
                    if self.transfers.on_poll_failed(message, daemon_down) {
                        let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
                    }
                }
                WorkerResult::TransferStarted { id } => {
                    self.send_flow.on_started(id.clone());
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
                    let text = self.error_text(&e);
                    if self.send_flow.on_failed(text.clone()) {
                        // The send flow's own file: its dialog shows the reason, not the form
                        // of the Transfers screen.
                        self.transfers.note_flow_send(false);
                    } else {
                        self.transfers.on_error(text);
                    }
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
                WorkerResult::StorageShares {
                    shares,
                    total_bytes,
                } => {
                    self.storage.loading = false;
                    self.storage.note = None;
                    // Keep only ticks that still name a stored, unused share.
                    self.storage
                        .selected
                        .retain(|a| shares.iter().any(|s| &s.address == a && !s.in_use));
                    self.storage.shares = shares;
                    self.storage.total_bytes = total_bytes;
                }
                WorkerResult::StorageDeleted {
                    deleted,
                    freed_bytes,
                    skipped,
                } => {
                    let st = self.st();
                    if deleted == 0 && skipped.is_empty() {
                        self.set_msg(MsgKind::Info, st.nothing);
                    } else {
                        let msg = st
                            .deleted
                            .replace("{n}", &deleted.to_string())
                            .replace("{size}", &format_size(freed_bytes));
                        self.set_msg(MsgKind::Success, msg);
                    }
                    if !skipped.is_empty() {
                        let msg = st.skipped.replace("{ids}", &skipped.join(", "));
                        self.set_msg(MsgKind::Info, msg);
                    }
                    // Show the effect at once.
                    self.storage.loading = true;
                    let _ = self.worker.tx.try_send(WorkerCmd::StorageList);
                }
                WorkerResult::StorageUnavailable => {
                    self.storage.loading = false;
                    self.storage.note = Some(StorageNote::Unavailable);
                }
                WorkerResult::StorageUnsupported => {
                    self.storage.loading = false;
                    self.storage.note = Some(StorageNote::Unsupported);
                }
                WorkerResult::StorageFailed(e) => {
                    self.storage.loading = false;
                    let text = self.error_text(&e);
                    self.set_msg(MsgKind::Error, text);
                }
                WorkerResult::Err(e) => {
                    self.busy = false;
                    if self.import_state == ImportState::InProgress {
                        self.import_state = ImportState::Failed;
                    }
                    let text = self.error_text(&e);
                    self.last_error = Some(e);
                    self.set_msg(MsgKind::Error, text);
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
                    if let Some(err) = self.last_error.clone() {
                        self.error_hint(ui, &err);
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

    // ── Easy-mode Home / Files ────────────────────────────────────────

    fn home_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        // Not connected (first run, stopped, starting): the card above this page is the page.
        // The actions would only be greyed out, so they are not drawn at all.
        if self.daemon_state != DaemonState::Connected {
            return;
        }
        let peers = self.peer_count;
        let shares = self.share_count;
        let storage = if self.quota_mb > 0 {
            format!("{:.0}%", (self.used_mb / self.quota_mb as f64) * 100.0)
        } else {
            s.dashboard_no_data.to_owned()
        };

        // The three actions first, big enough to be the point of the screen. Three equal
        // columns; the first (send) is the primary, the other two are outlined.
        // Three columns when there is room, one column below TASK_COLUMNS_MIN_W (at 320 px the
        // third column ran off the window).
        let gap = kit::SP_3;
        let narrow = ui.available_width() < TASK_COLUMNS_MIN_W;
        let w = if narrow {
            ui.available_width().floor()
        } else {
            ((ui.available_width() - 2.0 * gap) / 3.0)
                .floor()
                .max(120.0)
        };
        let actions = |ui: &mut egui::Ui| {
            ui.spacing_mut().item_spacing = egui::vec2(gap, gap);
            if kit::large_action(ui, true, true, s.home_send_action, w).clicked() {
                // The one send flow, over this screen.
                self.send_flow.open_empty(self.contacts.contact_list());
            }
            if kit::large_action(ui, false, true, s.home_receive_action, w).clicked() {
                self.tab = Tab::Inbox;
            }
            if kit::large_action(ui, false, true, s.home_save_action, w).clicked() {
                self.tab = Tab::Store;
            }
        };
        if narrow {
            ui.vertical(actions);
        } else {
            ui.horizontal(actions);
        }

        // Status is one muted line; the numbers are behind "Details".
        ui.add_space(kit::SP_3);
        let (_, state_text) = header_chip(
            &self.daemon_state,
            self.relay_down.is_some(),
            s,
            locale::audit_strings(self.locale),
        );
        ui.label(kit::muted_text(state_text));
        ui.add_space(kit::SP_2);
        egui::CollapsingHeader::new(kit::muted_text(s.details_easy))
            .id_source("home_details")
            .default_open(false)
            .show_a11y(ui, |ui| {
                kit::stats(
                    ui,
                    &[
                        (s.dashboard_storage_label, storage, Level::Muted),
                        (
                            s.dashboard_peers_label,
                            peers.to_string(),
                            if peers > 0 { Level::Ok } else { Level::Warn },
                        ),
                        (s.status_items_stored, shares.to_string(), Level::Muted),
                    ],
                );
            });
    }

    fn files_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let connected = self.daemon_state == DaemonState::Connected;
        let transfer_label = self.tr().tab_easy;

        // The six actions say what this screen is for: no explanation under the heading.
        kit::page(ui, s.files_heading_easy, None, |ui| {
            // Two main tasks side by side, big; storing and restoring under them, still large;
            // what happened (transfers, sent files) as small links at the bottom.
            let gap = kit::SP_3;
            // Two columns across the whole width; one column in a narrow window.
            let narrow = ui.available_width() < TASK_COLUMNS_MIN_W;
            let w = if narrow {
                ui.available_width().floor()
            } else {
                ((ui.available_width() - gap) / 2.0).floor().max(120.0)
            };
            let main_tasks = |ui: &mut egui::Ui| {
                ui.spacing_mut().item_spacing = egui::vec2(gap, gap);
                if kit::large_action(ui, true, connected, s.home_send_action, w).clicked() {
                    // The one send flow, over this screen.
                    self.send_flow.open_empty(self.contacts.contact_list());
                }
                if kit::large_action(ui, false, connected, s.home_receive_action, w).clicked() {
                    self.tab = Tab::Inbox;
                }
            };
            if narrow {
                ui.vertical(main_tasks);
            } else {
                ui.horizontal(main_tasks);
            }
            ui.add_space(kit::SP_3);
            let store_tasks = |ui: &mut egui::Ui| {
                ui.spacing_mut().item_spacing = egui::vec2(gap, gap);
                if kit::large_action(ui, false, connected, s.home_save_action, w).clicked() {
                    self.tab = Tab::Store;
                }
                if kit::large_action(ui, false, connected, s.tab_retrieve_easy, w).clicked() {
                    self.tab = Tab::Retrieve;
                }
            };
            if narrow {
                ui.vertical(store_tasks);
            } else {
                ui.horizontal(store_tasks);
            }
            ui.add_space(kit::SP_4);
            kit::divider(ui);
            ui.horizontal(|ui| {
                if crate::form_check::add_enabled(ui, connected, kit::quiet_button(transfer_label))
                    .clicked()
                {
                    self.tab = Tab::Transfers;
                }
                if crate::form_check::add_enabled(
                    ui,
                    connected,
                    kit::quiet_button(s.tab_outbox_easy),
                )
                .clicked()
                {
                    self.tab = Tab::Outbox;
                }
            });
        });
    }

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
            if easy && !connected {
                kit::notice(ui, Level::Warn, s.store_not_connected_hint);
            }

            // The primary task: put text or a file into the network.
            kit::surface(ui, |ui| {
                ui.label(s.store_text_label);
                let au = locale::audit_strings(self.locale);
                let text_edit = crate::form_check::add_enabled(
                    ui,
                    connected,
                    kit::input_multiline(&mut self.dissolve_text)
                        .hint_text(s.store_text_hint)
                        .desired_rows(if easy { 6 } else { 5 }),
                );
                crate::form_check::name(&text_edit, au.a11y_store_text);
                kit::button_row(ui, |ui| {
                    let needs = [
                        crate::form_check::Need::general(connected, au.need_connection),
                        crate::form_check::Need::new(
                            &text_edit,
                            !self.dissolve_text.is_empty(),
                            au.need_text,
                        ),
                    ];
                    if crate::form_check::primary_with_reason(
                        ui,
                        s.store_button,
                        &needs,
                        !self.busy,
                        false,
                    ) {
                        let _ = self
                            .worker
                            .tx
                            .try_send(WorkerCmd::DissolveText(self.dissolve_text.clone()));
                        self.busy = true;
                        self.set_msg(MsgKind::Info, s.store_busy);
                    }
                    if crate::form_check::add_enabled(
                        ui,
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
                        let shown = ui.add(kit::input_mono(&mut display).desired_width(w));
                        crate::form_check::name(
                            &shown,
                            locale::audit_strings(self.locale).a11y_store_id,
                        );
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
                let au = locale::audit_strings(self.locale);
                let mid_edit = crate::form_check::add_enabled(
                    ui,
                    connected,
                    kit::input_mono(&mut self.mid_input).hint_text("miasma:..."),
                );
                crate::form_check::name(&mid_edit, au.a11y_get_id);
                kit::button_row(ui, |ui| {
                    let label = if easy {
                        s.retrieve_button_easy
                    } else {
                        s.retrieve_button
                    };
                    let typed = !self.mid_input.trim().is_empty();
                    let needs = [
                        crate::form_check::Need::general(connected, au.need_connection),
                        crate::form_check::Need::new(
                            &mid_edit,
                            typed,
                            if easy { au.need_code } else { au.need_mid },
                        ),
                        // Read with the parser the daemon uses: a text that cannot be an ID keeps
                        // the button off, and the reason says what an ID looks like.
                        crate::form_check::Need::new(
                            &mid_edit,
                            miasma_core::crypto::hash::ContentId::from_str(self.mid_input.trim())
                                .is_ok(),
                            au.bad_mid,
                        ),
                    ];
                    let attempt = crate::form_check::submitted(&mid_edit);
                    if crate::form_check::primary_with_reason(
                        ui, label, &needs, !self.busy, attempt,
                    ) {
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

                let au = locale::audit_strings(self.locale);
                let mut contact_field: Option<egui::Response> = None;
                let mut password_field: Option<egui::Response> = None;
                let mut file_button: Option<egui::Id> = None;
                kit::form_row(ui, s.send_contact_label, None, |ui| {
                    let hint = if self.mode.is_easy() {
                        s.send_contact_hint_easy
                    } else {
                        s.send_contact_hint
                    };
                    let r = ui.add(kit::input(&mut self.send_contact).hint_text(hint));
                    crate::form_check::name(&r, au.a11y_send_contact);
                    contact_field = Some(r);
                });
                kit::form_row(ui, s.send_password_label, None, |ui| {
                    let r = ui.add(
                        kit::input(&mut self.send_password)
                            .password(true)
                            .desired_width(240.0),
                    );
                    crate::form_check::name(&r, au.a11y_password);
                    password_field = Some(r);
                });
                kit::form_row(
                    ui,
                    s.send_retention_label,
                    Some(s.send_retention_hint),
                    |ui| {
                        let r = ui.add(kit::input(&mut self.send_retention).desired_width(120.0));
                        crate::form_check::name(&r, au.a11y_retention);
                    },
                );
                kit::form_row(ui, s.inbox_filename, None, |ui| {
                    ui.horizontal(|ui| {
                        let choose = ui.add(kit::secondary_button(s.send_choose_file));
                        file_button = Some(choose.id);
                        if choose.clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.send_file_path = Some(path);
                            }
                        }
                        if let Some(ref path) = self.send_file_path {
                            kit::mono_elided(ui, &path.display().to_string());
                        }
                    });
                });

                let field_id = |r: &Option<egui::Response>| r.as_ref().map(|r| r.id);
                let needs = [
                    crate::form_check::Need::general(connected, au.need_connection),
                    crate::form_check::Need {
                        field: field_id(&contact_field),
                        ok: !self.send_contact.is_empty(),
                        reason: au.need_contact,
                    },
                    crate::form_check::Need {
                        field: field_id(&password_field),
                        // Same rule the daemon applies to a new private share.
                        ok: miasma_core::transfer::password_policy::check_directed(
                            &self.send_password,
                        )
                        .is_ok(),
                        reason: if self.send_password.is_empty() {
                            au.need_password
                        } else {
                            au.need_private_password
                        },
                    },
                    crate::form_check::Need {
                        field: file_button,
                        ok: self.send_file_path.is_some(),
                        reason: au.need_file,
                    },
                ];
                let attempt = [&contact_field, &password_field]
                    .iter()
                    .any(|r| r.as_ref().is_some_and(crate::form_check::submitted));
                kit::form_actions(ui, |ui| {
                    if crate::form_check::primary_with_reason(
                        ui,
                        s.send_button,
                        &needs,
                        !self.busy,
                        attempt,
                    ) {
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
                    if self.busy {
                        ui.label(kit::muted_text(s.send_busy));
                    }
                });

                if let Some(eid) = self.last_envelope_id.clone() {
                    ui.add_space(kit::SP_1);
                    kit::form_row(
                        ui,
                        crate::uitext::envelope_id_label(self.locale),
                        None,
                        |ui| {
                            kit::mono_copy(ui, &eid, s.copy);
                        },
                    );
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
                        let (level, state_label) = inbox_state_display(s, &item.state, easy);
                        envelope_header(
                            ui,
                            &envelope_title(item, easy, self.locale),
                            level,
                            state_label,
                        );

                        kit::kv_grid(ui, |g| {
                            if !easy {
                                g.row(s.inbox_from, |ui| {
                                    if item.sender == LEGACY_SENDER {
                                        ui.label(crate::uitext::unknown_sender(self.locale));
                                    } else {
                                        kit::mono_elided(ui, short(&item.sender, 20));
                                    }
                                });
                            }
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
                            time_row(
                                g,
                                crate::uitext::created_label(self.locale),
                                &item.created_at,
                                easy,
                            );
                            time_row(
                                g,
                                crate::uitext::expires_label(self.locale),
                                &item.expires_at,
                                easy,
                            );
                            // Challenge code: the recipient reads this out to the sender.
                            if let Some(ref code) = item.challenge_code {
                                let label = if easy {
                                    s.inbox_challenge_easy
                                } else {
                                    s.inbox_challenge
                                };
                                g.row(label, |ui| {
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
                            "ChallengeFailed" => kit::notice(
                                ui,
                                Level::Error,
                                if easy {
                                    s.outbox_challenge_failed_easy
                                } else {
                                    s.outbox_challenge_failed
                                },
                            ),
                            _ => {}
                        }

                        // Retrieve (only in Confirmed state).
                        if item.state == "Confirmed" {
                            kit::form_row(ui, s.inbox_password_label, None, |ui| {
                                ui.horizontal(|ui| {
                                    let au = locale::audit_strings(self.locale);
                                    let pw = ui.add(
                                        kit::input(&mut self.inbox_retrieve_password)
                                            .password(true)
                                            .desired_width(200.0),
                                    );
                                    crate::form_check::name(&pw, au.a11y_file_password);
                                    let needs = [
                                        crate::form_check::Need::general(
                                            connected,
                                            au.need_connection,
                                        ),
                                        crate::form_check::Need::new(
                                            &pw,
                                            !self.inbox_retrieve_password.is_empty(),
                                            au.need_password,
                                        ),
                                    ];
                                    if crate::form_check::primary_with_reason(
                                        ui,
                                        s.inbox_retrieve_button,
                                        &needs,
                                        !self.busy,
                                        crate::form_check::submitted(&pw),
                                    ) {
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
                        let (level, state_label) = outbox_state_display(s, &item.state, easy);
                        envelope_header(
                            ui,
                            &envelope_title(item, easy, self.locale),
                            level,
                            state_label,
                        );

                        kit::kv_grid(ui, |g| {
                            if !easy {
                                g.row(s.outbox_to, |ui| {
                                    kit::mono_elided(ui, short(&item.recipient, 20));
                                });
                            }
                            if let Some(ref fname) = item.filename {
                                g.text(s.outbox_filename, fname);
                            }
                            time_row(
                                g,
                                crate::uitext::created_label(self.locale),
                                &item.created_at,
                                easy,
                            );
                            time_row(
                                g,
                                crate::uitext::expires_label(self.locale),
                                &item.expires_at,
                                easy,
                            );
                        });

                        // Sender confirmation: ask for the challenge code.
                        if item.state == "ChallengeIssued" {
                            let heading = if easy {
                                s.outbox_confirm_heading_easy
                            } else {
                                s.outbox_confirm_heading
                            };
                            kit::notice(ui, Level::Warn, heading);
                            kit::form_row(ui, s.outbox_confirm_label, None, |ui| {
                                ui.horizontal(|ui| {
                                    let au = locale::audit_strings(self.locale);
                                    let code = ui.add(
                                        kit::input_mono(&mut self.outbox_confirm_code)
                                            .hint_text(s.outbox_confirm_hint)
                                            .desired_width(140.0),
                                    );
                                    crate::form_check::name(&code, au.a11y_check_code);
                                    let needs = [
                                        crate::form_check::Need::general(
                                            connected,
                                            au.need_connection,
                                        ),
                                        crate::form_check::Need::new(
                                            &code,
                                            !self.outbox_confirm_code.is_empty(),
                                            au.need_code,
                                        ),
                                    ];
                                    if crate::form_check::primary_with_reason(
                                        ui,
                                        s.outbox_confirm_button,
                                        &needs,
                                        !self.busy,
                                        crate::form_check::submitted(&code),
                                    ) {
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

        kit::page(ui, s.status_heading, None, |ui| {
            kit::button_row(ui, |ui| {
                if ui.add(kit::secondary_button(s.status_refresh)).clicked() {
                    let _ = self.worker.tx.try_send(WorkerCmd::GetStatus);
                }
                // Visible proof that the numbers are current, also when nothing changed.
                if let Some(at) = self.status_updated_at {
                    ui.label(kit::muted_text(crate::uitext::updated_ago(
                        self.locale,
                        at.elapsed().as_secs(),
                    )));
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
                .add_filter(crate::uitext::text_files_filter(self.locale), &["txt"])
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

        let relay_text = self.relay_down.as_ref().map(|r| relay_down_text(s, r));
        let (level, status_text, hint) = if self.daemon_state == DaemonState::Connected {
            match &relay_text {
                // The relay cannot be reached: say so, with the time and the cause.
                Some(text) => (
                    Level::Warn,
                    locale::audit_strings(self.locale).chip_relay,
                    text.as_str(),
                ),
                None => (Level::Ok, s.status_ready, s.status_hint_ready),
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
                // Nobody connected right now is the normal idle state: a muted detail.
                kit::status_dot(
                    ui,
                    Level::Muted,
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
                if let Some(r) = &self.relay_down {
                    g.text(s.status_relay, &relay_down_text(s, r));
                }
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
        kit::progress(
            ui,
            self.s().status_storage,
            (pct / 100.0) as f32,
            pct > 90.0,
        );
    }

    /// Technical-mode status: full diagnostics, one section per topic.
    fn status_panel_technical(&self, ui: &mut egui::Ui) {
        let s = self.s();

        // ── Connection & identity ─────────────────────────────────────
        kit::section(ui, s.status_connection, |ui| {
            kit::kv_grid(ui, |g| {
                g.row(s.status_state, |ui| match self.daemon_state {
                    DaemonState::Connected => {
                        // The same words as the chip in the header.
                        let (level, text) = header_chip(
                            &self.daemon_state,
                            self.relay_down.is_some(),
                            s,
                            locale::audit_strings(self.locale),
                        );
                        kit::status_dot(ui, level, text);
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
                if let Some(r) = &self.relay_down {
                    g.text(s.status_relay, &relay_down_text(s, r));
                }
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
                                "{} of your items spread to other peers, {} still waiting",
                                self.replicated_count, self.pending_replication
                            ))
                            .color(kit::level_color(Level::Warn)),
                        );
                    } else if self.replicated_count > 0 {
                        ui.label(crate::uitext::replicated(
                            self.locale,
                            self.replicated_count as u64,
                        ));
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
                        // "plain" read as unencrypted WSS; what differs is whether TLS wraps it.
                        let tls = if self.wss_tls_enabled {
                            "TLS on"
                        } else {
                            "TLS off"
                        };
                        kit::status_dot(ui, Level::Ok, &format!("WSS :{}, {tls}", self.wss_port));
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
                    let loc = self.locale;
                    use crate::uitext::{self, TransportState as TS};
                    for t in &self.transport_statuses {
                        table.row(ui, true, |row| {
                            row.text(&t.name);
                            let (level, label) = if t.selected {
                                (Level::Ok, uitext::transport_state(loc, TS::Active))
                            } else if t.available && t.failure_count == 0 {
                                (Level::Ok, uitext::transport_state(loc, TS::Ready))
                            } else if t.available && t.failure_count > 0 {
                                (Level::Warn, uitext::transport_state(loc, TS::Degraded))
                            } else if t.failure_count > 0 {
                                (Level::Error, uitext::transport_state(loc, TS::Failing))
                            } else {
                                (Level::Muted, uitext::transport_state(loc, TS::Idle))
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
        kit::page(ui, s.settings_heading, None, |ui| {
            self.settings_category_row(ui);
            match self.settings_cat {
                SettingsCat::General => self.settings_general(ui),
                SettingsCat::Privacy => self.settings_privacy(ui),
                SettingsCat::Network => self.settings_network(ui),
                SettingsCat::Updates => {
                    let technical = !self.mode.is_easy();
                    self.updates.section(ui, self.locale, technical);
                }
                SettingsCat::About => self.settings_about(ui),
                SettingsCat::Danger => self.settings_danger(ui),
            }
        });
    }

    /// The row of categories under the page title; it wraps on a narrow window.
    fn settings_category_row(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
            for cat in SettingsCat::ALL {
                if kit::nav_tab(ui, self.settings_cat == cat, cat.label(self.locale)).clicked() {
                    self.settings_cat = cat;
                }
            }
        });
        ui.add_space(kit::SP_3);
    }

    /// General: language, mode, appearance, group invitations and the speed display.
    fn settings_general(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        {
            kit::form_row(ui, s.settings_language, None, |ui| {
                let mut lang = self.locale;
                let options = Locale::ALL.map(|l| (l, l.display_name()));
                if kit::segmented(ui, &mut lang, &options) {
                    self.locale = lang;
                    // A banner already on screen is in the old language; drop it.
                    self.status_msg = None;
                    // Read the fonts the new language needs (the others stay lazy).
                    crate::fonts::set_locale(ui.ctx(), lang);
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Title(
                        crate::buildinfo::window_title(lang),
                    ));
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
            {
                let gs = locale::group_strings(self.locale);
                kit::form_row(
                    ui,
                    gs.settings_join_label,
                    Some(if self.group_auto_join {
                        gs.settings_join_auto_desc
                    } else {
                        gs.settings_join_ask_desc
                    }),
                    |ui| {
                        let mut on = self.group_auto_join;
                        let options =
                            [(true, gs.settings_join_auto), (false, gs.settings_join_ask)];
                        if kit::segmented(ui, &mut on, &options) {
                            self.group_auto_join = on;
                            self.group_join_save_failed =
                                crate::group::save_auto_join(&self.data_dir, on).is_err();
                            self.chat.set_group_auto_join(on);
                        }
                    },
                );
                if self.group_join_save_failed {
                    kit::notice(
                        ui,
                        Level::Error,
                        locale::update_strings(self.locale).config_save_failed,
                    );
                }
            }
            {
                let sp = crate::speed::speed_strings(self.locale);
                kit::form_row(ui, sp.settings_unit, None, |ui| {
                    let mut unit = self.speed_prefs.unit;
                    let options = [
                        (SpeedUnit::Bits, sp.unit_bits),
                        (SpeedUnit::Bytes, sp.unit_bytes),
                    ];
                    if kit::segmented(ui, &mut unit, &options) {
                        self.speed_prefs.unit = unit;
                        self.save_prefs();
                    }
                });
                kit::form_row(ui, sp.settings_shown, None, |ui| {
                    let mut shown = self.speed_prefs.shown;
                    let options = [
                        (SpeedShown::Both, sp.shown_both),
                        (SpeedShown::BitsOnly, sp.shown_bits),
                        (SpeedShown::BytesOnly, sp.shown_bytes),
                    ];
                    if kit::segmented(ui, &mut shown, &options) {
                        self.speed_prefs.shown = shown;
                        self.save_prefs();
                    }
                });
            }
        }
    }

    /// Privacy and storage: chat protection, logs and how much this computer keeps for others.
    fn settings_privacy(&mut self, ui: &mut egui::Ui) {
        self.pqc_section(ui);
        let used = (self.quota_mb > 0).then_some(self.used_mb);
        if self.mode.is_easy() {
            // Easy: what keeps this computer's files safe first; logging is under "Advanced".
            self.hosting.section(ui, self.locale, used);
            egui::CollapsingHeader::new(kit::section_text(crate::uitext::advanced(self.locale)))
                .id_source("settings_privacy_advanced")
                .default_open(false)
                .show_a11y(ui, |ui| self.logs_section(ui));
        } else {
            self.logs_section(ui);
            self.hosting.section(ui, self.locale, used);
        }
    }

    /// Network: the connection settings, then the reachability check.
    fn settings_network(&mut self, ui: &mut egui::Ui) {
        if self.mode.is_easy() {
            // Relay addresses, certificates, retry time and the check are for Technical use.
            let title = self.s().settings_network_details_easy;
            egui::CollapsingHeader::new(kit::section_text(title))
                .id_source("settings_network_advanced")
                .default_open(false)
                .show_a11y(ui, |ui| self.network.section(ui, self.locale));
        } else {
            self.network.section(ui, self.locale);
        }
    }

    /// About: where things are kept, how the app works and what to send to support.
    fn settings_about(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let easy = self.mode.is_easy();
        {
            // ── Version and build: what a person tells support ───────
            kit::paragraph(ui, &crate::buildinfo::window_title(self.locale));
            ui.add_space(kit::SP_2);

            // ── Actions ──────────────────────────────────────────────
            kit::section(ui, s.settings_actions, |ui| {
                kit::button_row(ui, |ui| {
                    self.copy_diagnostics_button(ui);
                    self.save_diagnostics_button(ui);
                    if ui
                        .add(kit::secondary_button(s.settings_open_folder))
                        .clicked()
                    {
                        self.open_last =
                            crate::transfers::plain_path(&self.data_dir_display).to_owned();
                        crate::open_path::launch(
                            crate::open_path::Action::Open,
                            std::path::PathBuf::from(&self.data_dir_display),
                            self.open_tx.clone(),
                        );
                    }
                });
            });

            // ── Paths and how it works: closed. The paths carry the user name of this
            // computer, so they are not in the page body either. ──
            let tech_title = kit::muted_text(crate::uitext::technical_details(self.locale));
            egui::CollapsingHeader::new(tech_title)
                .id_source("about_technical")
                .default_open(false)
                .show_a11y(ui, |ui| {
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
                            g.mono(
                                crate::buildinfo::build_row_label(self.locale),
                                &crate::buildinfo::build_row_value(),
                            );
                            if let Ok(exe) = std::env::current_exe() {
                                if let Some(dir) = exe.parent() {
                                    g.mono(s.settings_install, &dir.to_string_lossy());
                                }
                            }
                        });
                    });

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
                        kit::hint(ui, s.settings_preserved);
                    });
                });
        }
    }

    /// The Danger zone: every operation of the page that deletes data, in one place. Each one
    /// opens its own confirmation, which says what is deleted (see `confirm_dialogs`).
    fn settings_danger(&mut self, ui: &mut egui::Ui) {
        let s = self.s();
        let t = locale::settings_strings(self.locale);
        let connected = self.daemon_state == DaemonState::Connected;
        kit::paragraph_muted(ui, t.danger_intro);
        ui.add_space(kit::SP_2);

        // Emergency wipe. The button works with the background service stopped too: the wipe
        // then runs without it, so it is never greyed out when it may be needed most.
        kit::section(ui, s.wipe_label, |ui| {
            kit::paragraph_muted(ui, s.wipe_desc);
            if ui.add(kit::danger_button(s.wipe_button)).clicked() {
                self.show_wipe_confirm = true;
            }
            if !connected {
                kit::hint(ui, s.wipe_offline_note);
            }
        });

        // The shares this device keeps: delete some, old ones, or all.
        self.storage_section(ui);
    }

    // ── Advanced encryption (Settings) ───────────────────────────────────────────

    /// The three choices of `privacy.pqc_mode`, with what each one does. The
    /// choice is written to the configuration at once; the background service
    /// reads it when it starts.
    fn pqc_section(&mut self, ui: &mut egui::Ui) {
        use miasma_core::config::PqcMode;
        let p = self.pq();
        let available = PqcMode::available();
        let mut chosen = self.pqc_mode;
        let easy = self.mode.is_easy();
        let locale = self.locale;
        kit::section(ui, p.heading, |ui| {
            if !available && easy {
                // Nothing can be chosen in this build: one line, no switched-off controls.
                kit::paragraph_muted(ui, p.unavailable);
                return;
            }
            if !available {
                kit::notice(ui, Level::Warn, p.unavailable);
                ui.add_space(kit::SP_1);
            }
            // Without the protection in this build the choices are shown switched off: they
            // would be saved but change nothing.
            ui.add_enabled_ui(available, |ui| {
                for (mode, label) in [
                    (PqcMode::Off, p.off),
                    (PqcMode::Prefer, p.prefer),
                    (PqcMode::Require, p.require),
                ] {
                    let r = ui.radio_value(&mut chosen, mode, label);
                    // Each choice is named by its own label; the heading names the group.
                    r.widget_info(|| {
                        egui::WidgetInfo::selected(
                            egui::WidgetType::RadioButton,
                            chosen == mode,
                            label,
                        )
                    });
                    // egui draws a switched-off radio grey but does not publish it as disabled.
                    if !available {
                        crate::form_check::mark_disabled(&r);
                    }
                }
            });
            // What the protection is and what each choice does: opened on request.
            egui::CollapsingHeader::new(kit::muted_text(crate::uitext::details(locale)))
                .id_source("settings_pqc_details")
                .default_open(false)
                .show_a11y(ui, |ui| {
                    kit::paragraph_muted(ui, p.intro);
                    for (label, help) in [
                        (p.off, p.off_help),
                        (p.prefer, p.prefer_help),
                        (p.require, p.require_help),
                    ] {
                        ui.add_space(kit::SP_1);
                        ui.label(RichText::new(label).strong());
                        kit::hint(ui, help);
                    }
                });
            if available {
                ui.add_space(kit::SP_1);
                kit::hint(ui, p.restart_note);
                kit::hint(ui, p.review_note);
            }
        });
        if chosen != self.pqc_mode {
            let saved =
                miasma_core::config::set_pqc_mode_persistent(&self.data_dir, chosen).is_ok();
            // The configuration is the source of truth for the choice shown.
            self.pqc_mode = miasma_core::logging::load_privacy(&self.data_dir).pqc_mode;
            if !saved || self.pqc_mode != chosen {
                self.set_msg(MsgKind::Error, self.pq().save_failed);
            }
        }
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

    /// The shares this device keeps: the listing and the delete controls. The
    /// service answers with its current view of what is in use.
    fn storage_section(&mut self, ui: &mut egui::Ui) {
        let st = self.st();
        kit::section(ui, st.heading, |ui| {
            kit::paragraph_muted(ui, st.desc);
            kit::button_row(ui, |ui| {
                let toggle = if self.storage.open { st.hide } else { st.show };
                if ui.add(kit::secondary_button(toggle)).clicked() {
                    self.storage.open = !self.storage.open;
                    if self.storage.open {
                        self.storage.loading = true;
                        let _ = self.worker.tx.try_send(WorkerCmd::StorageList);
                    }
                }
                if self.storage.open && ui.add(kit::secondary_button(st.refresh)).clicked() {
                    self.storage.loading = true;
                    let _ = self.worker.tx.try_send(WorkerCmd::StorageList);
                }
            });
            if !self.storage.open {
                return;
            }
            if let Some(note) = self.storage.note {
                let text = match note {
                    StorageNote::Unsupported => st.note_unsupported,
                    StorageNote::Unavailable => st.note_unavailable,
                };
                kit::paragraph_muted(ui, text);
                return;
            }
            if self.storage.shares.is_empty() {
                kit::hint(
                    ui,
                    if self.storage.loading {
                        st.loading
                    } else {
                        st.empty
                    },
                );
                return;
            }
            let summary = st
                .total
                .replace("{count}", &self.storage.shares.len().to_string())
                .replace("{size}", &format_size(self.storage.total_bytes));
            kit::paragraph(ui, &summary);

            let locale = self.locale;
            egui::ScrollArea::vertical()
                .id_source("settings_storage_view")
                .max_height(220.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for s in &self.storage.shares {
                        let when = if s.modified_secs == 0 {
                            "-".to_owned()
                        } else {
                            format_epoch(s.modified_secs, locale)
                        };
                        let mark = if s.in_use {
                            format!("  ({})", st.in_use)
                        } else {
                            String::new()
                        };
                        let label = RichText::new(format!(
                            "{}  {}  {when}{mark}",
                            s.id,
                            format_size(s.size_bytes)
                        ))
                        .monospace();
                        let mut on = self.storage.selected.contains(&s.address);
                        let changed = crate::form_check::add_enabled(
                            ui,
                            !s.in_use,
                            egui::Checkbox::new(&mut on, label),
                        )
                        .changed();
                        if changed {
                            if on {
                                self.storage.selected.insert(s.address.clone());
                            } else {
                                self.storage.selected.remove(&s.address);
                            }
                        }
                    }
                });

            ui.add_space(kit::SP_2);
            let mut delete: Option<miasma_core::store::ShareSelection> = None;
            kit::button_row(ui, |ui| {
                let none = self.storage.selected.is_empty();
                let btn = crate::form_check::add_enabled(
                    ui,
                    !none,
                    kit::danger_button(st.delete_selected_button),
                );
                if btn.clicked() {
                    let mut ids: Vec<String> = self.storage.selected.iter().cloned().collect();
                    ids.sort();
                    delete = Some(miasma_core::store::ShareSelection::Ids(ids));
                }
                if ui.add(kit::danger_button(st.delete_all_button)).clicked() {
                    delete = Some(miasma_core::store::ShareSelection::All);
                }
            });
            kit::button_row(ui, |ui| {
                ui.label(st.delete_old);
                let days = ui.add(kit::input(&mut self.storage.days).desired_width(56.0));
                crate::form_check::name(&days, locale::audit_strings(self.locale).a11y_days);
                ui.label(st.days_label);
                if ui.add(kit::danger_button(st.delete_old_button)).clicked() {
                    match self.storage.days.trim().parse::<u64>() {
                        Ok(d) if d > 0 => {
                            delete = Some(miasma_core::store::ShareSelection::OlderThanDays(d))
                        }
                        _ => self.set_msg(MsgKind::Error, st.bad_days),
                    }
                }
            });
            if let Some(sel) = delete {
                self.storage.confirm = Some(sel);
            }
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
        crate::a11y::dialog_enter(ctx, "legacy_logs");
        // Esc keeps the files (the choice that cannot lose anything).
        let mut keep = crate::a11y::esc_pressed(ctx);
        crate::a11y::dialog_title(ctx, l.legacy_title);
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
                        crate::a11y::dialog_leave(ui.ctx(), "legacy_logs");
                    }
                    let keep_button = ui.add(kit::secondary_button(l.legacy_keep));
                    crate::a11y::dialog_focus_safe_button(ui.ctx(), "legacy_logs", &keep_button);
                    keep |= keep_button.clicked();
                });
            });
        if keep {
            let _ = self
                .worker
                .tx
                .try_send(WorkerCmd::LegacyLogs { delete: false });
            crate::a11y::dialog_leave(ctx, "legacy_logs");
        }
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
                    if let Some(err) = self.last_error.clone() {
                        self.error_hint(ui, &err);
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
            env!("MIASMA_VERSION")
        ));
        d.push_str(&format!(
            "Build:           {}\n",
            crate::buildinfo::BUILD_ID
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
            d.push_str(&format!("\n--- Last Error ---\n{}\n", err.report_line()));
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
            if !detection.deferred.is_empty() {
                d.push_str("  Available, read when a character needs them:\n");
                for f in &detection.deferred {
                    d.push_str(&format!("    {f}\n"));
                }
            }
        }

        d.push_str("\n(end of report)\n");
        d
    }
}

// ─── Small helpers ──────────────────────────────────────────────────────────

/// "Not connected for 3 h 12 min: <cause>" in the window's language.
pub(crate) fn relay_down_text(s: &Strings, r: &crate::worker::RelayDown) -> String {
    use miasma_core::transport::relay_watchdog::RelayCause as C;
    let span = match r.secs {
        0..=59 => s.relay_down_s.replace("{n}", &r.secs.to_string()),
        60..=3599 => s.relay_down_min.replace("{n}", &(r.secs / 60).to_string()),
        _ => s
            .relay_down_h
            .replace("{h}", &(r.secs / 3600).to_string())
            .replace("{m}", &(r.secs % 3600 / 60).to_string()),
    };
    let why = match r.cause {
        C::Dns => s.relay_cause_dns,
        C::Timeout => s.relay_cause_timeout,
        C::Tls => s.relay_cause_tls,
        C::Denied => s.relay_cause_denied,
        C::Other => s.relay_cause_other,
    };
    let mut out = format!("{span}: {why}");
    if let Some(i) = &r.inspected {
        let tpl = if i.trusted {
            s.relay_cert_trusted
        } else {
            s.relay_cert_untrusted
        };
        out.push_str("\n");
        out.push_str(&tpl.replace("{ca}", &i.issuer));
    }
    out
}

fn format_epoch(epoch_secs: u64, locale: Locale) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::uitext::relative_time(locale, epoch_secs, now)
}

/// Inbox and outbox times: "3d ago (Oct 17, 2026 14:05 UTC)". The relative part is for a quick
/// look, the date for someone who needs to say when.
fn format_epoch_full(epoch_secs: u64, locale: Locale) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::uitext::relative_and_absolute(locale, epoch_secs, now)
}

/// Stands in for the sender of an old-format envelope that carries none; shown as words.
const LEGACY_SENDER: &str = "<legacy/unbound>";

/// "Expires" value of an envelope: says whether the time has passed.
fn format_expiry(epoch_secs: u64, locale: Locale) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let text = crate::uitext::expiry_text(locale, epoch_secs, now);
    if epoch_secs == 0 {
        text
    } else {
        format!(
            "{text} ({})",
            crate::uitext::absolute_time(locale, epoch_secs)
        )
    }
}

/// Map envelope state string to a (level, label) for outbox display.
fn outbox_state_display<'a>(
    s: &'a crate::locale::Strings,
    state: &'a str,
    easy: bool,
) -> (Level, &'a str) {
    match state {
        // The sentence for these two is shown under the details; the header is one short word.
        "Pending" => (Level::Warn, s.envelope_waiting),
        "ChallengeIssued" => (Level::Warn, s.envelope_needs_action),
        "Confirmed" => (Level::Ok, s.outbox_confirmed),
        "Retrieved" => (Level::Ok, s.outbox_retrieved),
        "Expired" => (Level::Error, s.outbox_expired),
        "SenderRevoked" => (Level::Error, s.outbox_revoked),
        "RecipientDeleted" => (Level::Muted, s.outbox_revoked),
        "ChallengeFailed" => (
            Level::Error,
            if easy {
                s.outbox_challenge_failed_easy
            } else {
                s.outbox_challenge_failed
            },
        ),
        "PasswordFailed" => (Level::Error, s.outbox_password_failed),
        _ => (Level::Muted, state),
    }
}

/// Map envelope state string to a (level, label) for inbox display.
fn inbox_state_display<'a>(
    s: &'a crate::locale::Strings,
    state: &'a str,
    easy: bool,
) -> (Level, &'a str) {
    match state {
        // Short words only: the sentence that explains a problem is shown under the details,
        // so the header must not say the same thing twice.
        "Pending" | "ChallengeIssued" => (Level::Warn, s.envelope_waiting),
        "Confirmed" => (Level::Ok, s.outbox_confirmed),
        "Retrieved" => (Level::Ok, s.outbox_retrieved),
        "Expired" => (Level::Error, s.outbox_expired),
        "SenderRevoked" => (Level::Error, s.outbox_revoked),
        "RecipientDeleted" => (Level::Muted, s.outbox_revoked),
        "ChallengeFailed" => (
            Level::Error,
            if easy {
                s.outbox_challenge_failed_easy
            } else {
                s.outbox_challenge_failed
            },
        ),
        "PasswordFailed" => (Level::Error, s.outbox_password_failed),
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

/// The title of an inbox/outbox item: the file name in Easy mode, the envelope id otherwise.
fn envelope_title(item: &InboxItem, easy: bool, locale: Locale) -> String {
    match (easy, item.filename.as_deref()) {
        (true, Some(name)) if !name.is_empty() => name.to_owned(),
        // Easy never leads with an identifier nobody can read.
        (true, _) => crate::uitext::unnamed_file(locale).to_owned(),
        _ => short(&item.envelope_id, 16).to_owned(),
    }
}

/// A date row. Easy shows how long ago (or how long to go); the exact date is in the hover text.
fn time_row(g: &mut kit::Kv, label: &str, full: &str, easy: bool) {
    if easy {
        let short_text = full.split(" (").next().unwrap_or(full).to_owned();
        g.row(label, |ui| {
            ui.label(short_text).on_hover_text(full);
        });
    } else {
        g.text(label, full);
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
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        crate::a11y::trap_input(ctx, raw_input);
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.update_frame(ctx, frame.info().system_theme);
    }
}

impl MiasmaApp {
    /// One frame of the app. `system_theme` is the OS light/dark choice, when known.
    pub(crate) fn update_frame(
        &mut self,
        ctx: &egui::Context,
        system_theme: Option<eframe::Theme>,
    ) {
        #[cfg(feature = "ui-tour")]
        if let Some(mut t) = self.tour.take() {
            if !t.drive(self, ctx) {
                self.tour = Some(t);
            }
        }

        // A dialog that closed in the last frame hands focus back to the control that opened it.
        crate::a11y::restore_pending_focus(ctx);
        let modal = self.modal_open;

        // Theme: resolve the choice against the OS theme every frame (cheap), and re-apply when
        // it changed. eframe itself resets the visuals when the OS theme flips, so also
        // re-apply if the panel colour is no longer ours.
        let dark = theme::resolve_dark(self.theme_mode, system_theme);
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
        self.updates.tick(ctx);
        while let Ok(why) = self.open_rx.try_recv() {
            let c = locale::contact_strings(self.locale);
            let text =
                crate::transfers::fill(c.open_failed, &[("path", &self.open_last), ("why", &why)]);
            self.set_msg(MsgKind::Error, text);
        }

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
            {
                let sp = self.contacts.speed_mut();
                sp.prefs = self.speed_prefs;
                sp.locale = self.locale;
            }
            self.contacts
                .tick(open, self.daemon_state == DaemonState::Connected);
            let tx = self.worker.tx.clone();
            self.contacts
                .drain(|req| tx.try_send(WorkerCmd::Push(req)).is_ok());
        }

        // Chat: a light poll for arrivals in the background; quick only while the tab is open
        // (or a send is in flight, which the chat screen tracks itself).
        {
            let open = self.tab == Tab::Chat;
            if open {
                self.chat.mark_seen();
            }
            self.chat.set_locale(self.locale);
            self.chat
                .tick(open, self.daemon_state == DaemonState::Connected);
            let tx = self.worker.tx.clone();
            self.chat
                .drain(|req| tx.try_send(WorkerCmd::Chat(req)).is_ok());
        }

        // The send flow: files of an invitation-code send go to the worker one at a time, the
        // next after the daemon answered the one before.
        if self.daemon_state == DaemonState::Connected {
            if let Some(out) = self.send_flow.next_command() {
                self.transfers.note_flow_send(out.protected);
                if self.worker.tx.try_send(out.cmd).is_err() {
                    self.send_flow.put_back();
                }
            }
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
                if modal {
                    ui.set_enabled(false);
                }
                ui.add_space(kit::SP_2);
                ui.horizontal(|ui| {
                    // The product name does not change with the mode; Technical mode adds a small
                    // badge after it.
                    ui.label(kit::section_text(s.nav_brand_easy));
                    if !easy {
                        egui::Frame::none()
                            .stroke(egui::Stroke::new(1.0, pal().border_strong))
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(kit::SP_2, 1.0))
                            .show(ui, |ui| {
                                ui.label(kit::meta_text(s.settings_mode_technical, pal().muted));
                            });
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (level, label) = header_chip(
                            &self.daemon_state,
                            self.relay_down.is_some(),
                            s,
                            locale::audit_strings(self.locale),
                        );
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
                let chat_label =
                    crate::chat::nav_label(locale::chat_strings(self.locale), self.chat.unseen());
                let send_label = if easy { s.tab_send_easy } else { s.tab_send };
                let inbox_label = if easy { s.tab_inbox_easy } else { s.tab_inbox };
                let outbox_label = if easy {
                    s.tab_outbox_easy
                } else {
                    s.tab_outbox
                };
                let label_for = |tab: Tab| -> &str {
                    match tab {
                        Tab::Home => s.tab_home_easy,
                        Tab::Contacts => contacts_label.as_str(),
                        Tab::Files => s.tab_files_easy,
                        Tab::Chat => chat_label.as_str(),
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
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                    if easy {
                        for tab in EASY_NAV_TABS {
                            if kit::nav_tab(ui, easy_nav_selected(self.tab, tab), label_for(tab))
                                .clicked()
                            {
                                // The Chat tab shows the conversation list, also when pressed
                                // while a conversation is open.
                                if tab == Tab::Chat && self.tab == Tab::Chat {
                                    self.chat.show_list();
                                }
                                self.tab = tab;
                            }
                        }
                    } else {
                        for tab in TECH_NAV_TABS {
                            if kit::nav_tab(ui, easy_nav_selected(self.tab, tab), label_for(tab))
                                .clicked()
                            {
                                // The group opens on its first screen, unless one of its screens
                                // is already open.
                                if tab == Tab::Files && is_file_tab(self.tab) {
                                    continue;
                                }
                                if tab == Tab::Chat && self.tab == Tab::Chat {
                                    self.chat.show_list();
                                }
                                self.tab = if tab == Tab::Files {
                                    Tab::Transfers
                                } else {
                                    tab
                                };
                            }
                        }
                    }
                });
                // Technical mode: the screens of the Files group, one row below.
                if !easy && is_file_tab(self.tab) {
                    // Import is the only conditional tab.
                    let show_import = self.import_intent.is_some()
                        || self.import_state != ImportState::Idle
                        || self.tab == Tab::Import;
                    let count = if show_import {
                        TECH_FILE_TABS.len()
                    } else {
                        TECH_FILE_TABS.len() - 1
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                        for tab in &TECH_FILE_TABS[..count] {
                            if kit::nav_tab(ui, self.tab == *tab, label_for(*tab)).clicked() {
                                self.tab = *tab;
                            }
                        }
                    });
                }
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
                            // This bar is created before the page, so a focusable button here
                            // would be first in Tab order but is last on screen: it is reached
                            // with Esc (below) or by assistive technology instead.
                            let dismiss = kit::compact_button(s.dismiss).sense(egui::Sense {
                                click: true,
                                drag: false,
                                focusable: false,
                            });
                            if ui.add(dismiss).clicked() {
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
                // While a dialog is open nothing behind it reacts: the dialog is the only way on.
                if modal {
                    ui.set_enabled(false);
                }
                // Chat keeps its own scrolling (the message list scrolls, the composer stays in
                // view), so it is drawn outside the page's scroll area.
                if self.tab == Tab::Chat {
                    let mut action = None;
                    // Wider than the other pages: a wide window shows the conversation list
                    // beside the open conversation.
                    kit::column_max(ui, crate::chat_ui::TWO_PANE_MAX, |ui| {
                        if self.logs.writes_files {
                            kit::notice(ui, Level::Warn, self.lg().diag_banner);
                        }
                        self.updates.banner(ui, self.locale);
                        self.connection_header(ui);
                        let c = locale::chat_strings(self.locale);
                        let connected = self.daemon_state == DaemonState::Connected;
                        self.chat.refresh_file_states(
                            &self.contacts,
                            locale::contact_strings(self.locale),
                        );
                        action = self
                            .chat
                            .show(ui, c, connected, self.contacts.contact_list());
                    });
                    match action {
                        Some(ChatAction::OpenContacts) => self.tab = Tab::Contacts,
                        Some(ChatAction::SendFiles(id)) => {
                            // The paperclip opens the one send flow with this contact chosen.
                            self.send_flow.open_for_contact(&id);
                        }
                        Some(ChatAction::OpenSendFlow) => {
                            self.send_flow.open_empty(self.contacts.contact_list());
                        }
                        Some(ChatAction::RetryFile { contact_id, path }) => {
                            self.contacts.resend_file(&contact_id, &path);
                        }
                        Some(ChatAction::AddContact(code)) => {
                            self.contacts.prefill_add(&code);
                            self.tab = Tab::Contacts;
                        }
                        None => {}
                    }
                    return;
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        kit::column(ui, |ui| {
                            // Diagnostic logging writes files: say so on every screen.
                            if self.logs.writes_files {
                                kit::notice(ui, Level::Warn, self.lg().diag_banner);
                            }
                            self.updates.banner(ui, self.locale);
                            // Connection state first, when not connected.
                            self.connection_header(ui);
                            match self.tab {
                                Tab::Home => self.home_panel(ui),
                                Tab::Contacts => {
                                    let c = locale::contact_strings(self.locale);
                                    let connected = self.daemon_state == DaemonState::Connected;
                                    self.contacts.show(ui, c, connected, !easy);
                                    // "Send files" on a person's row: the one send flow, with
                                    // that person chosen.
                                    if let Some(id) = self.contacts.take_send_request() {
                                        self.send_flow.open_for_contact(&id);
                                    }
                                }
                                // Drawn above, outside the scroll area.
                                Tab::Chat => {}
                                Tab::Files => self.files_panel(ui),
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

        // Files dropped on the window, and the one send flow they (and every other "send") open.
        self.handle_drops(ctx);
        {
            let connected = self.daemon_state == DaemonState::Connected;
            let out = self.send_flow.show(
                ctx,
                locale::compose_strings(self.locale),
                self.tr(),
                locale::contact_strings(self.locale),
                &mut self.contacts,
                &self.transfers,
                connected,
            );
            if let Some((id, files)) = out.noted {
                self.chat.note_files_sent(&id, &files);
                for n in self.contacts.take_notices() {
                    self.set_msg(MsgKind::Success, n);
                }
            }
            match out.nav {
                Some(crate::send_flow::FlowNav::Files) => self.tab = Tab::Transfers,
                Some(crate::send_flow::FlowNav::Contacts) => self.tab = Tab::Contacts,
                None => {}
            }
        }

        // The page is drawn: a CJK character on it that no loaded font can draw reads the next
        // font (dialogs, drawn below, are looked at in the following frame).
        crate::fonts::ensure_glyphs(ctx);

        self.legacy_logs_notice(ctx);

        let dialog_open = self.dialog_is_open();
        self.dialogs(ctx);
        self.modal_open = self.any_modal_open();
        // Never leave the focus on a widget that is not on screen (see a11y::drop_orphan_focus).
        crate::a11y::trap_finish(ctx);
        crate::a11y::drop_orphan_focus(ctx);

        // Esc dismisses the message in the bottom bar when no dialog is open (a dialog takes
        // Esc for itself).
        if self.status_msg.is_some() && !dialog_open && crate::a11y::esc_pressed(ctx) {
            self.status_msg = None;
        }
    }
}

/// Width of the page column below which the task buttons stack in one column.
const TASK_COLUMNS_MIN_W: f32 = 560.0;

/// What the chip in the header says, from what is known: the service is up, and its relay is
/// reachable or not. Having no peer connected right now is the normal idle state (the direct
/// connection to a contact is made when something is sent), so it is not a problem state; the
/// peer count is a detail on the Status screen.
fn header_chip(
    state: &DaemonState,
    relay_down: bool,
    s: &'static Strings,
    au: &'static locale::AuditStrings,
) -> (Level, &'static str) {
    match state {
        DaemonState::Connected if !relay_down => (Level::Ok, au.chip_ready),
        DaemonState::Connected => (Level::Warn, au.chip_relay),
        DaemonState::Starting => (Level::Info, s.starting),
        DaemonState::Stopped => (Level::Error, s.offline),
        DaemonState::NeedsInit => (Level::Warn, s.setup_needed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_header_chip_follows_the_service_and_its_relay_not_the_peer_count() {
        for lang in Locale::ALL {
            let (s, au) = (locale::strings(lang), locale::audit_strings(lang));
            // Service up, relay reachable: Ready (whatever the number of connected peers).
            let (lvl, text) = header_chip(&DaemonState::Connected, false, s, au);
            assert_eq!((lvl, text), (Level::Ok, au.chip_ready), "{lang:?}");
            // Relay unreachable: a warning that names the cause.
            let (lvl, text) = header_chip(&DaemonState::Connected, true, s, au);
            assert_eq!((lvl, text), (Level::Warn, au.chip_relay), "{lang:?}");
            assert_eq!(
                header_chip(&DaemonState::Starting, false, s, au).1,
                s.starting
            );
            assert_eq!(
                header_chip(&DaemonState::Stopped, false, s, au).1,
                s.offline
            );
            assert_eq!(
                header_chip(&DaemonState::NeedsInit, false, s, au).1,
                s.setup_needed
            );
            let words = [
                header_chip(&DaemonState::Connected, false, s, au).1,
                header_chip(&DaemonState::Connected, true, s, au).1,
                header_chip(&DaemonState::Starting, false, s, au).1,
                header_chip(&DaemonState::NeedsInit, false, s, au).1,
            ];
            for (i, a) in words.iter().enumerate() {
                for b in &words[i + 1..] {
                    assert_ne!(a, b, "{lang:?}");
                }
            }
        }
    }

    /// Draw only the Easy Home page in a column of `width` px and return the rectangle it used.
    fn home_page_size(state: DaemonState, width: f32) -> egui::Rect {
        let ctx = egui::Context::default();
        let data = tempfile::tempdir().unwrap();
        let mut app = MiasmaApp::new_with_ctx(
            &ctx,
            None,
            ProductMode::Easy,
            Locale::En,
            ThemeMode::Light,
            data.path().to_path_buf(),
            LaunchIntent::Normal,
        );
        app.daemon_state = state;
        let mut used = egui::Rect::NOTHING;
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(width, 900.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    kit::column(ui, |ui| {
                        let top = ui.cursor().min;
                        app.home_panel(ui);
                        used = egui::Rect::from_min_max(top, ui.min_rect().max);
                    });
                });
            });
        }
        used
    }

    /// One frame of the whole window; returns the accessibility tree of that frame.
    fn window_frame(
        ctx: &egui::Context,
        app: &mut MiasmaApp,
        events: Vec<egui::Event>,
    ) -> Vec<(String, egui::Rect)> {
        app.daemon_state = DaemonState::Connected;
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1200.0, 900.0),
            )),
            events,
            ..Default::default()
        };
        let full = ctx.run(raw, |ctx| app.update_frame(ctx, None));
        let update = full
            .platform_output
            .accesskit_update
            .expect("accesskit tree");
        update
            .nodes
            .iter()
            .filter_map(|(_, n)| {
                let b = n.bounds()?;
                Some((
                    n.name()?.to_owned(),
                    egui::Rect::from_min_max(
                        egui::pos2(b.x0 as f32, b.y0 as f32),
                        egui::pos2(b.x1 as f32, b.y1 as f32),
                    ),
                ))
            })
            .collect()
    }

    /// A real mouse click on the button with this name: move, then press and release.
    fn click_button(ctx: &egui::Context, app: &mut MiasmaApp, name: &str) {
        for _ in 0..3 {
            window_frame(ctx, app, vec![]);
        }
        let nodes = window_frame(ctx, app, vec![]);
        let rect = nodes
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| {
                panic!(
                    "no button named {name:?} in {:?}",
                    nodes.iter().map(|(n, _)| n).collect::<Vec<_>>()
                )
            })
            .1;
        let pos = rect.center();
        window_frame(ctx, app, vec![egui::Event::PointerMoved(pos)]);
        let press = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        window_frame(ctx, app, vec![press(true)]);
        window_frame(ctx, app, vec![press(false)]);
        window_frame(ctx, app, vec![]);
        window_frame(ctx, app, vec![]);
    }

    #[test]
    fn every_button_of_the_easy_files_hub_goes_where_its_label_says() {
        // None: the send flow opens over the hub.
        let cases: [(
            fn(&'static Strings, &'static Strings) -> &'static str,
            Option<Tab>,
        ); 6] = [
            (|s, _| s.home_send_action, None),
            (|s, _| s.home_receive_action, Some(Tab::Inbox)),
            (|s, _| s.home_save_action, Some(Tab::Store)),
            (|s, _| s.tab_retrieve_easy, Some(Tab::Retrieve)),
            (|_, _| "", Some(Tab::Transfers)),
            (|s, _| s.tab_outbox_easy, Some(Tab::Outbox)),
        ];
        let mut failed: Vec<String> = Vec::new();
        for (i, (label_of, target)) in cases.into_iter().enumerate() {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            let data = tempfile::tempdir().unwrap();
            let mut app = MiasmaApp::new_with_ctx(
                &ctx,
                None,
                ProductMode::Easy,
                Locale::En,
                ThemeMode::Light,
                data.path().to_path_buf(),
                LaunchIntent::Normal,
            );
            app.tab = Tab::Files;
            app.logs.legacy = None;
            let s = app.s();
            let label = if i == 4 {
                app.tr().tab_easy
            } else {
                label_of(s, s)
            };
            // The real background worker may report "no service" in the middle of a frame and
            // switch the buttons off for that frame; a click is tried again then.
            let reached = |app: &MiasmaApp| match target {
                None => app.send_flow.is_open(),
                Some(tab) => app.tab == tab,
            };
            let mut ok = false;
            for _ in 0..4 {
                click_button(&ctx, &mut app, label);
                ok = reached(&app);
                if ok {
                    break;
                }
            }
            if !ok {
                failed.push(format!(
                    "{label}: now on {:?}, send flow open: {}",
                    app.tab,
                    app.send_flow.is_open()
                ));
            }
        }
        assert!(failed.is_empty(), "{failed:#?}");
    }

    /// Every text the first frames of the app draw, in drawing order.
    fn drawn_texts(mode: ProductMode, locale_: Locale) -> Vec<String> {
        fn collect(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
                egui::Shape::Vec(v) => v.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        let ctx = egui::Context::default();
        let data = tempfile::tempdir().unwrap();
        let mut app = MiasmaApp::new_with_ctx(
            &ctx,
            None,
            mode,
            locale_,
            ThemeMode::Light,
            data.path().to_path_buf(),
            LaunchIntent::Normal,
        );
        app.logs.legacy = None;
        let mut texts = Vec::new();
        for _ in 0..3 {
            texts.clear();
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(1100.0, 800.0),
                )),
                ..Default::default()
            };
            let full = ctx.run(raw, |ctx| app.update_frame(ctx, None));
            for c in &full.shapes {
                collect(&c.shape, &mut texts);
            }
        }
        texts
    }

    #[test]
    fn the_brand_is_miasma_in_both_modes_and_technical_adds_a_badge() {
        for l in Locale::ALL {
            let s = locale::strings(l);
            for mode in [ProductMode::Easy, ProductMode::Technical] {
                let texts = drawn_texts(mode, l);
                assert!(
                    texts.iter().any(|t| t == "Miasma"),
                    "{l:?} {mode:?}: no brand in {texts:?}"
                );
                assert!(
                    !texts.iter().any(|t| t.contains("Protocol")),
                    "{l:?} {mode:?}: {texts:?}"
                );
                let badge = texts.iter().any(|t| t == s.settings_mode_technical);
                assert_eq!(badge, !mode.is_easy(), "{l:?} {mode:?}: badge");
            }
        }
    }

    #[test]
    fn the_navigation_draws_the_common_destinations_in_the_same_order_in_both_modes() {
        let l = Locale::En;
        let s = locale::strings(l);
        let order_of = |mode| {
            let texts = drawn_texts(mode, l);
            let names = [
                s.tab_home_easy,
                s.tab_status,
                locale::contact_strings(l).tab,
                locale::chat_strings(l).tab,
                s.tab_files_easy,
                s.tab_settings,
            ];
            let mut found: Vec<(usize, &str)> = Vec::new();
            for n in names {
                if let Some(i) = texts.iter().position(|t| t.starts_with(n)) {
                    found.push((i, n));
                }
            }
            found.sort();
            found.into_iter().map(|(_, n)| n).collect::<Vec<_>>()
        };
        let easy = order_of(ProductMode::Easy);
        let tech = order_of(ProductMode::Technical);
        let common = |v: &[&str]| -> Vec<String> {
            v.iter()
                .filter(|n| **n != s.tab_home_easy && **n != s.tab_status)
                .map(|n| (*n).to_owned())
                .collect()
        };
        assert_eq!(common(&easy), common(&tech), "{easy:?} vs {tech:?}");
        assert_eq!(common(&easy).len(), 4, "{easy:?}");
    }

    #[test]
    fn the_chat_protection_radios_are_published_as_disabled_when_the_build_lacks_it() {
        if miasma_core::config::PqcMode::available() {
            return; // the radios are live in this build
        }
        let (radios, app) = privacy_radios();
        // The three choices, each under its own name, all switched off. (Other radios on the page,
        // such as the sizes of the hosting setting, are not part of this.)
        let p = app.pq();
        for label in [p.off, p.prefer, p.require] {
            assert!(
                radios.iter().any(|(n, d)| n == label && *d),
                "no disabled radio named {label:?}: {radios:?}"
            );
        }
    }

    #[test]
    fn the_chat_protection_radios_are_enabled_when_the_build_has_it() {
        if !miasma_core::config::PqcMode::available() {
            return; // the radios are switched off in this build
        }
        let (radios, app) = privacy_radios();
        let p = app.pq();
        assert_eq!(p.heading, "Advanced encryption");
        for label in [p.off, p.prefer, p.require] {
            assert!(
                radios.iter().any(|(n, d)| n == label && !*d),
                "no enabled radio named {label:?}: {radios:?}"
            );
        }
    }

    /// The radios of Settings > Privacy as published to assistive technology
    /// (name, switched off), and the app that drew them.
    fn privacy_radios() -> (Vec<(String, bool)>, MiasmaApp) {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let data = tempfile::tempdir().unwrap();
        // Technical mode: Easy mode shows one line instead of the switched-off choices.
        let mut app = MiasmaApp::new_with_ctx(
            &ctx,
            None,
            ProductMode::Technical,
            Locale::En,
            ThemeMode::Light,
            data.path().to_path_buf(),
            LaunchIntent::Normal,
        );
        app.tab = Tab::Settings;
        app.settings_cat = SettingsCat::Privacy;
        app.logs.legacy = None;
        let mut radios: Vec<(String, bool)> = Vec::new();
        for _ in 0..4 {
            app.daemon_state = DaemonState::Connected;
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(900.0, 1400.0),
                )),
                ..Default::default()
            };
            let full = ctx.run(raw, |ctx| app.update_frame(ctx, None));
            let update = full.platform_output.accesskit_update.unwrap();
            radios = update
                .nodes
                .iter()
                .filter(|(_, n)| n.role() == egui::accesskit::Role::RadioButton)
                .map(|(_, n)| (n.name().unwrap_or("").to_owned(), n.is_disabled()))
                .collect();
        }
        (radios, app)
    }

    #[test]
    fn home_puts_the_actions_first_and_draws_nothing_else_when_not_connected() {
        for width in [700.0_f32, 1200.0] {
            let connected = home_page_size(DaemonState::Connected, width);
            // Three 56 px actions, one status line, and a closed "Details" line: no card, no
            // heading, no numbers above the buttons.
            assert!(connected.height() >= kit::LARGE_ACTION_H, "{connected:?}");
            assert!(connected.height() < 140.0, "{connected:?}");
            assert!(connected.width() <= width, "{connected:?}");
            for state in [
                DaemonState::Stopped,
                DaemonState::Starting,
                DaemonState::NeedsInit,
            ] {
                let r = home_page_size(state.clone(), width);
                assert!(
                    r.height() < 1.0,
                    "{state:?} at {width}: the page below the card is empty, got {r:?}"
                );
            }
        }
    }

    #[test]
    fn easy_normal_launch_starts_on_home() {
        assert_eq!(
            initial_tab(&LaunchIntent::Normal, ProductMode::Easy),
            Tab::Home
        );
    }

    #[test]
    fn technical_normal_launch_keeps_contacts_first() {
        assert_eq!(
            initial_tab(&LaunchIntent::Normal, ProductMode::Technical),
            Tab::Contacts
        );
    }

    #[test]
    fn opening_a_magnet_or_torrent_still_goes_to_import() {
        assert_eq!(
            initial_tab(
                &LaunchIntent::Magnet("magnet:?xt=urn:btih:abc".into()),
                ProductMode::Easy
            ),
            Tab::Import
        );
        assert_eq!(
            initial_tab(
                &LaunchIntent::TorrentFile("a.torrent".into()),
                ProductMode::Technical
            ),
            Tab::Import
        );
    }

    #[test]
    fn the_relay_status_line_says_time_and_cause_in_every_locale() {
        use crate::worker::{Inspected, RelayDown};
        use miasma_core::transport::relay_watchdog::RelayCause;
        let down = RelayDown {
            secs: 11_520,
            cause: RelayCause::Tls,
            inspected: Some(Inspected {
                issuer: "Test Inspection CA".into(),
                trusted: false,
            }),
        };
        let en = relay_down_text(locale::strings(Locale::En), &down);
        assert!(en.contains("3 h 12 min"), "{en}");
        assert!(en.contains("certificate was not accepted"), "{en}");
        assert!(en.contains("Test Inspection CA"), "{en}");
        for lang in Locale::ALL {
            let text = relay_down_text(locale::strings(lang), &down);
            assert!(
                text.contains("3") && text.contains("12"),
                "{lang:?}: {text}"
            );
            assert!(text.contains("Test Inspection CA"), "{lang:?}: {text}");
        }
        let fresh = RelayDown {
            secs: 5,
            cause: RelayCause::Dns,
            inspected: None,
        };
        let en = relay_down_text(locale::strings(Locale::En), &fresh);
        assert!(en.contains("5 s") && en.contains("DNS"), "{en}");
    }

    #[test]
    fn technical_navigation_is_unique_and_keeps_import_last() {
        for (i, a) in TECH_NAV_TABS.iter().enumerate() {
            for b in &TECH_NAV_TABS[i + 1..] {
                assert_ne!(a, b);
            }
        }
        for (i, a) in TECH_FILE_TABS.iter().enumerate() {
            for b in &TECH_FILE_TABS[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(TECH_FILE_TABS[TECH_FILE_TABS.len() - 1], Tab::Import);
    }

    #[test]
    fn technical_navigation_groups_the_old_row_without_losing_a_screen() {
        // The old row of eleven tabs.
        let old = [
            Tab::Contacts,
            Tab::Chat,
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
        for tab in old {
            let on_top = TECH_NAV_TABS.contains(&tab);
            let in_group = TECH_FILE_TABS.contains(&tab);
            assert!(on_top || in_group, "{tab:?} is no longer reachable");
        }
        // The group is the same set the Files tab selects, so the second row is shown exactly
        // while one of its screens is open.
        for tab in TECH_FILE_TABS {
            assert!(easy_nav_selected(tab, Tab::Files));
        }
        assert!(TECH_NAV_TABS.len() < old.len());
    }

    #[test]
    fn the_common_destinations_keep_their_place_in_both_modes() {
        // Slot 0 is Home (Easy) or Status (Technical); the rest are the same, in the same order.
        assert_eq!(EASY_NAV_TABS[0], Tab::Home);
        assert_eq!(TECH_NAV_TABS[0], Tab::Status);
        assert_eq!(EASY_NAV_TABS[1..], TECH_NAV_TABS[1..]);
        assert_eq!(
            TECH_NAV_TABS[1..],
            [Tab::Contacts, Tab::Chat, Tab::Files, Tab::Settings]
        );
    }

    #[test]
    fn easy_navigation_has_five_task_oriented_items() {
        assert_eq!(
            EASY_NAV_TABS,
            [
                Tab::Home,
                Tab::Contacts,
                Tab::Chat,
                Tab::Files,
                Tab::Settings
            ]
        );
        for file_tab in [
            Tab::Files,
            Tab::Transfers,
            Tab::Store,
            Tab::Retrieve,
            Tab::Send,
            Tab::Inbox,
            Tab::Outbox,
            Tab::Import,
        ] {
            assert!(easy_nav_selected(file_tab, Tab::Files));
        }
    }

    // ── Every dialog, with an assistive-technology client attached ────────────────────────

    use crate::a11y::tests::{apply_in_every_order, assert_sound};
    use accesskit_consumer::Tree as PlatformTree;
    use egui::accesskit;

    /// The app running headless with AccessKit on, and a copy of the tree that the platform
    /// adapter keeps (every frame's update is applied to it, in several node orders).
    struct A11yRig {
        ctx: egui::Context,
        app: MiasmaApp,
        tree: Option<PlatformTree>,
        last: accesskit::TreeUpdate,
        clock: f64,
        _data: tempfile::TempDir,
        _worker: (
            std::sync::mpsc::Receiver<WorkerCmd>,
            std::sync::mpsc::SyncSender<WorkerResult>,
        ),
    }

    impl A11yRig {
        fn new(tab: Tab) -> Self {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            let data = tempfile::tempdir().unwrap();
            let mut app = MiasmaApp::new_with_ctx(
                &ctx,
                None,
                ProductMode::Easy,
                Locale::En,
                ThemeMode::Light,
                data.path().to_path_buf(),
                LaunchIntent::Normal,
            );
            app.tab = tab;
            app.daemon_state = DaemonState::Connected;
            app.logs.legacy = None;
            // No real worker: it answers on its own schedule (an empty data folder reports
            // "needs setup"), and `poll_worker` would apply that answer in the middle of a
            // frame, after the state was pinned. The app talks to channels nobody answers.
            let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel(32);
            let (res_tx, res_rx) = std::sync::mpsc::sync_channel(64);
            app.worker = crate::worker::WorkerHandle {
                tx: cmd_tx,
                rx: res_rx,
            };
            let mut rig = Self {
                ctx,
                app,
                tree: None,
                last: accesskit::TreeUpdate {
                    nodes: Vec::new(),
                    tree: None,
                    focus: accesskit::NodeId(0),
                },
                clock: 0.0,
                _data: data,
                _worker: (cmd_rx, res_tx),
            };
            rig.frames(2);
            rig
        }

        fn frame_with(&mut self, events: Vec<egui::Event>) {
            let mut raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 700.0),
                )),
                time: Some(self.clock),
                predicted_dt: 1.0 / 60.0,
                events,
                ..Default::default()
            };
            raw.viewports
                .entry(egui::ViewportId::ROOT)
                .or_default()
                .native_pixels_per_point = Some(1.0);
            self.clock += 1.0 / 60.0;
            // The real worker runs in the background and reports that no service is there;
            // the screens are looked at as with a service up.
            self.app.daemon_state = DaemonState::Connected;
            self.app.status_msg = None;
            self.app.last_error = None;
            let app = &mut self.app;
            let out = self.ctx.run(raw, |ctx| app.update_frame(ctx, None));
            let update = out
                .platform_output
                .accesskit_update
                .expect("an accessibility update");
            match &mut self.tree {
                None => {
                    let tree = PlatformTree::new(update.clone(), true);
                    assert_sound(&tree);
                    self.tree = Some(tree);
                }
                Some(tree) => apply_in_every_order(tree, &update),
            }
            self.last = update;
        }

        fn frames(&mut self, n: usize) {
            for _ in 0..n {
                self.frame_with(Vec::new());
            }
        }

        fn named(&self, name: &str, role: Option<accesskit::Role>) -> Vec<accesskit::NodeId> {
            self.last
                .nodes
                .iter()
                .filter(|(_, n)| n.name() == Some(name) && role.map_or(true, |r| n.role() == r))
                .map(|(id, _)| *id)
                .collect()
        }

        fn dialogs(&self) -> Vec<String> {
            self.last
                .nodes
                .iter()
                .filter(|(_, n)| n.role() == accesskit::Role::Dialog)
                .map(|(_, n)| n.name().unwrap_or_default().to_owned())
                .collect()
        }

        fn buttons(&self) -> Vec<String> {
            self.last
                .nodes
                .iter()
                .filter(|(_, n)| n.role() == accesskit::Role::Button)
                .filter_map(|(_, n)| n.name().map(str::to_owned))
                .collect()
        }

        /// What a UI Automation client does for Invoke: an action request at the button.
        fn request(&mut self, action: accesskit::Action, target: accesskit::NodeId) {
            self.frame_with(vec![egui::Event::AccessKitActionRequest(
                accesskit::ActionRequest {
                    action,
                    target,
                    data: None,
                },
            )]);
        }

        fn invoke(&mut self, name: &str) {
            let ids = self.named(name, Some(accesskit::Role::Button));
            assert!(
                !ids.is_empty(),
                "no button {name:?}; buttons: {:?}",
                self.buttons()
            );
            self.request(accesskit::Action::Default, ids[0]);
        }

        fn esc(&mut self) {
            self.frame_with(vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }]);
        }

        /// Ask for focus on every control inside every dialog, one after the other (what a
        /// screen reader's cursor does), then close the dialogs with Esc.
        fn walk_and_close(&mut self) {
            let inside: Vec<accesskit::NodeId> = self
                .last
                .nodes
                .iter()
                .filter(|(_, n)| n.role() == accesskit::Role::Dialog)
                .flat_map(|(_, n)| n.children().to_vec())
                .collect();
            for id in inside.into_iter().take(12) {
                if self.last.nodes.iter().any(|(i, _)| *i == id) {
                    self.request(accesskit::Action::Focus, id);
                }
            }
            for _ in 0..3 {
                self.esc();
                self.frames(2);
            }
        }
    }

    /// Open a dialog by pressing a button, as a UI Automation client does.
    fn invoke_opens_a_dialog(rig: &mut A11yRig, button: &str) {
        assert!(
            rig.dialogs().is_empty(),
            "a dialog is open before {button:?}"
        );
        rig.invoke(button);
        rig.frames(4);
        assert!(!rig.dialogs().is_empty(), "{button:?} opened no dialog");
        rig.walk_and_close();
        rig.frames(2);
        assert!(
            rig.dialogs().is_empty(),
            "{button:?}: the dialog is still open"
        );
    }

    #[test]
    fn dialogs_opened_through_assistive_technology_never_break_the_platform_tree() {
        let c = locale::contact_strings(Locale::En);
        // Chat: New conversation, Create a new group.
        let mut rig = A11yRig::new(Tab::Chat);
        rig.app.chat = ChatUi::fixture("list").unwrap();
        rig.app.contacts = ContactsUi::fixture("two", c).unwrap();
        rig.frames(3);
        invoke_opens_a_dialog(&mut rig, "New conversation");
        invoke_opens_a_dialog(&mut rig, "Create a new group");
        // Contacts: Add a contact, My invitation.
        let mut rig = A11yRig::new(Tab::Contacts);
        rig.app.contacts = ContactsUi::fixture("two", c).unwrap();
        rig.frames(3);
        invoke_opens_a_dialog(&mut rig, c.add_title);
        invoke_opens_a_dialog(&mut rig, c.invite_btn);
    }

    #[test]
    fn every_dialog_of_the_app_keeps_the_platform_tree_sound_while_it_opens_and_closes() {
        let c = locale::contact_strings(Locale::En);
        // Dialogs that the screens open from their own state.
        for (tab, chat, contacts) in [
            (Tab::Chat, Some("picker"), "two"),
            (Tab::Chat, Some("confirm"), "two"),
            (Tab::Chat, Some("verify"), "two"),
            (Tab::Contacts, None, "qr"),
            (Tab::Contacts, None, "verify"),
            (Tab::Contacts, None, "perm"),
            (Tab::Contacts, None, "added"),
            (Tab::Contacts, None, "adderror"),
        ] {
            let mut rig = A11yRig::new(tab);
            if let Some(fx) = chat {
                rig.app.chat = ChatUi::fixture(fx).unwrap();
            }
            rig.app.contacts = ContactsUi::fixture(contacts, c).unwrap();
            rig.frames(4);
            assert!(
                !rig.dialogs().is_empty(),
                "{tab:?}/{chat:?}/{contacts}: no dialog in the tree"
            );
            rig.walk_and_close();
            rig.frames(2);
        }
        // The send flow, in each of its states.
        for name in ["empty", "contact", "code", "sent", "codesent"] {
            let mut rig = A11yRig::new(Tab::Contacts);
            rig.app.contacts = ContactsUi::fixture("active", c).unwrap();
            rig.app.send_flow =
                crate::send_flow::SendFlow::fixture(name, rig.app.contacts.contact_list()).unwrap();
            rig.frames(4);
            assert!(!rig.dialogs().is_empty(), "send flow {name}: no dialog");
            rig.walk_and_close();
            rig.frames(2);
        }
        // The confirmations the app itself asks.
        for which in 0..2 {
            let mut rig = A11yRig::new(Tab::Home);
            match which {
                0 => rig.app.show_wipe_confirm = true,
                _ => rig.app.show_close_confirm = true,
            }
            rig.frames(4);
            assert!(!rig.dialogs().is_empty(), "confirmation {which}: no dialog");
            rig.walk_and_close();
            rig.frames(2);
        }
    }
}
