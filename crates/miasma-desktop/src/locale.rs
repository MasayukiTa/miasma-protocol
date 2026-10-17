/// Localization — translatable UI strings for the desktop app.
///
/// Three locales: English, Japanese, Simplified Chinese.
/// Each locale provides both Technical and Easy variants for key strings.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Locale {
    #[default]
    En,
    Ja,
    ZhCn,
}

impl Locale {
    /// Display name in the locale's own language (for the settings dropdown).
    pub fn display_name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ja => "日本語",
            Self::ZhCn => "简体中文",
        }
    }

    pub const ALL: [Locale; 3] = [Self::En, Self::Ja, Self::ZhCn];
}

/// All translatable strings for one locale.
///
/// Fields ending in `_easy` are the Easy-mode override.  When the field
/// is the same across modes, the `_easy` field repeats it.
pub struct Strings {
    // ── Tabs ──
    pub tab_store: &'static str,
    pub tab_store_easy: &'static str,
    pub tab_retrieve: &'static str,
    pub tab_retrieve_easy: &'static str,
    pub tab_status: &'static str,
    pub tab_settings: &'static str,

    // ── Connection indicator (top-right) ──
    pub connected: &'static str,
    pub starting: &'static str,
    pub offline: &'static str,
    pub setup_needed: &'static str,

    // ── Welcome / NeedsInit ──
    pub welcome_title: &'static str,
    pub welcome_title_easy: &'static str,
    pub welcome_desc: &'static str,
    pub welcome_desc_easy: &'static str,
    pub welcome_detail: &'static str,
    pub welcome_detail_easy: &'static str,
    pub welcome_button: &'static str,
    pub welcome_progress: &'static str,
    pub welcome_progress_easy: &'static str,

    // ── Stopped state ──
    pub stopped_title: &'static str,
    pub stopped_title_easy: &'static str,
    pub stopped_desc: &'static str,
    pub stopped_desc_easy: &'static str,
    pub stopped_button: &'static str,
    pub stopped_button_easy: &'static str,
    pub starting_label: &'static str,
    pub starting_label_easy: &'static str,

    // ── Store panel ──
    pub store_heading: &'static str,
    pub store_heading_easy: &'static str,
    pub store_desc: &'static str,
    pub store_desc_easy: &'static str,
    pub store_text_label: &'static str,
    pub store_text_hint: &'static str,
    pub store_choose_file: &'static str,
    pub store_button: &'static str,
    pub store_success: &'static str,
    pub store_mid_label: &'static str,
    pub store_mid_label_easy: &'static str,
    pub store_copy: &'static str,
    pub store_copied: &'static str,
    pub store_share_hint: &'static str,
    pub store_share_hint_easy: &'static str,
    pub store_busy: &'static str,
    pub store_not_connected_hint: &'static str,

    // ── Retrieve panel ──
    pub retrieve_heading: &'static str,
    pub retrieve_heading_easy: &'static str,
    pub retrieve_desc: &'static str,
    pub retrieve_desc_easy: &'static str,
    pub retrieve_mid_label: &'static str,
    pub retrieve_mid_label_easy: &'static str,
    pub retrieve_button: &'static str,
    pub retrieve_button_easy: &'static str,
    pub retrieve_busy: &'static str,
    pub retrieve_success: &'static str,
    pub retrieve_save_button: &'static str,
    pub retrieve_saved: &'static str,
    pub retrieve_save_failed: &'static str,
    pub retrieve_result_label: &'static str,
    pub retrieve_not_connected_hint: &'static str,

    // ── Status panel ──
    pub status_heading: &'static str,
    pub status_refresh: &'static str,
    pub status_copy_diag: &'static str,
    pub status_diag_copied: &'static str,
    pub status_connection: &'static str,
    pub status_state: &'static str,
    pub status_state_connected: &'static str,
    pub status_state_starting: &'static str,
    pub status_state_not_running: &'static str,
    pub status_state_not_init: &'static str,
    pub status_peer_id: &'static str,
    pub status_peers: &'static str,
    pub status_relay: &'static str,
    pub relay_down_s: &'static str,
    pub relay_down_min: &'static str,
    pub relay_down_h: &'static str,
    pub relay_cause_dns: &'static str,
    pub relay_cause_timeout: &'static str,
    pub relay_cause_tls: &'static str,
    pub relay_cause_denied: &'static str,
    pub relay_cause_other: &'static str,
    pub relay_cert_trusted: &'static str,
    pub relay_cert_untrusted: &'static str,
    pub status_listening: &'static str,
    pub status_storage: &'static str,
    pub status_shares: &'static str,
    pub status_used: &'static str,
    pub status_replication: &'static str,
    pub status_transport: &'static str,
    pub status_transport_name: &'static str,
    pub status_transport_status: &'static str,
    pub status_transport_counts: &'static str,
    pub status_transport_details: &'static str,
    pub status_all_failing: &'static str,

    // ── Easy status (simplified) ──
    pub status_ready: &'static str,
    pub status_not_ready: &'static str,
    pub status_items_stored: &'static str,
    pub status_hint_ready: &'static str,
    pub status_hint_not_ready: &'static str,
    pub status_hint_no_peers: &'static str,

    // ── Emergency wipe ──
    pub wipe_label: &'static str,
    pub wipe_desc: &'static str,
    pub wipe_button: &'static str,
    pub wipe_confirm_title: &'static str,
    pub wipe_confirm_line1: &'static str,
    pub wipe_confirm_line2: &'static str,
    pub wipe_confirm_button: &'static str,
    pub wipe_cancel: &'static str,
    pub wipe_done: &'static str,
    /// What is not erased (copies already sent, files saved elsewhere).
    pub wipe_confirm_kept: &'static str,
    /// Shown in the dialog when the background service is stopped: the wipe then runs without it.
    pub wipe_confirm_offline: &'static str,
    /// Shown under the wipe button when the background service is stopped.
    pub wipe_offline_note: &'static str,

    // ── Closing the window while a transfer runs ──
    pub close_title: &'static str,
    pub close_body: &'static str,
    pub close_confirm: &'static str,
    pub close_cancel: &'static str,

    // ── Confirmation before delete / revoke ──
    pub dialog_cancel: &'static str,
    pub inbox_revoke_title: &'static str,
    pub inbox_revoke_body: &'static str,
    pub inbox_revoke_confirm: &'static str,
    pub inbox_revoke_done: &'static str,
    pub outbox_revoke_title: &'static str,
    pub outbox_revoke_body: &'static str,
    pub outbox_revoke_confirm: &'static str,
    pub outbox_revoke_done: &'static str,

    // ── Settings ──
    pub settings_heading: &'static str,
    pub settings_paths: &'static str,
    pub settings_data_dir: &'static str,
    pub settings_config_file: &'static str,
    pub settings_log: &'static str,
    pub settings_install: &'static str,
    pub settings_path_copied: &'static str,
    pub settings_how: &'static str,
    pub settings_how_line1: &'static str,
    pub settings_how_line1_easy: &'static str,
    pub settings_how_line2: &'static str,
    pub settings_how_line2_easy: &'static str,
    pub settings_stored_in: &'static str,
    pub settings_preserved: &'static str,
    pub settings_actions: &'static str,
    pub settings_open_folder: &'static str,
    pub settings_language: &'static str,
    pub settings_mode: &'static str,
    pub settings_mode_technical: &'static str,
    pub settings_mode_easy: &'static str,
    pub settings_mode_desc_technical: &'static str,
    pub settings_mode_desc_easy: &'static str,
    pub settings_theme: &'static str,
    pub settings_theme_system: &'static str,
    pub settings_theme_light: &'static str,
    pub settings_theme_dark: &'static str,

    // ── Import (magnet / .torrent) ──
    pub tab_import: &'static str,
    pub import_heading: &'static str,
    pub import_idle_hint: &'static str,
    pub import_magnet_label: &'static str,
    pub import_torrent_label: &'static str,
    pub import_explain: &'static str,
    pub import_explain_easy: &'static str,
    pub import_button: &'static str,
    pub import_cancel: &'static str,
    pub import_not_connected: &'static str,
    pub import_progress: &'static str,
    pub import_complete: &'static str,
    pub import_failed: &'static str,
    pub import_retry: &'static str,
    pub import_done: &'static str,

    // ── Health checks (Easy mode) ──
    pub health_app: &'static str,
    pub health_backend: &'static str,
    pub health_network: &'static str,
    pub health_ok: &'static str,
    pub health_starting: &'static str,
    pub health_offline: &'static str,
    pub health_no_peers: &'static str,

    // ── Diagnostics export ──
    pub status_save_diag: &'static str,
    pub status_diag_saved: &'static str,
    pub status_diag_save_failed: &'static str,

    // ── Nav branding ──
    pub nav_brand: &'static str,
    pub nav_brand_easy: &'static str,

    // ── Easy dashboard (store tab quick stats) ──
    pub dashboard_quick_status: &'static str,
    pub dashboard_storage_label: &'static str,
    pub dashboard_peers_label: &'static str,
    pub dashboard_free: &'static str,
    pub dashboard_no_data: &'static str,

    // ── Storage progress bar ──
    pub storage_bar_label: &'static str,

    // ── Directed sharing ──
    pub tab_send: &'static str,
    pub tab_send_easy: &'static str,
    pub tab_inbox: &'static str,
    pub tab_inbox_easy: &'static str,
    pub send_heading: &'static str,
    pub send_heading_easy: &'static str,
    pub send_desc: &'static str,
    pub send_desc_easy: &'static str,
    pub send_contact_label: &'static str,
    pub send_contact_hint: &'static str,
    pub send_password_label: &'static str,
    pub send_retention_label: &'static str,
    pub send_choose_file: &'static str,
    pub send_button: &'static str,
    pub send_busy: &'static str,
    pub send_success: &'static str,
    pub send_not_connected: &'static str,
    pub inbox_heading: &'static str,
    pub inbox_heading_easy: &'static str,
    pub inbox_desc: &'static str,
    pub inbox_desc_easy: &'static str,
    pub inbox_empty: &'static str,
    pub inbox_from: &'static str,
    pub inbox_state: &'static str,
    pub inbox_challenge: &'static str,
    pub inbox_retrieve_button: &'static str,
    pub inbox_password_label: &'static str,
    pub inbox_revoke_button: &'static str,
    pub inbox_refresh: &'static str,
    pub sharing_key_label: &'static str,
    pub sharing_key_desc: &'static str,
    pub sharing_key_desc_easy: &'static str,
    pub sharing_key_copy: &'static str,
    pub sharing_key_copied: &'static str,

    // ── Outbox (sender view) ──
    pub tab_outbox: &'static str,
    pub tab_outbox_easy: &'static str,
    pub outbox_heading: &'static str,
    pub outbox_heading_easy: &'static str,
    pub outbox_desc: &'static str,
    pub outbox_desc_easy: &'static str,
    pub outbox_empty: &'static str,
    pub outbox_to: &'static str,
    pub outbox_state: &'static str,
    pub outbox_filename: &'static str,
    pub outbox_refresh: &'static str,
    pub outbox_revoke_button: &'static str,
    pub outbox_confirm_heading: &'static str,
    pub outbox_confirm_label: &'static str,
    pub outbox_confirm_hint: &'static str,
    pub outbox_confirm_button: &'static str,
    pub outbox_confirm_success: &'static str,
    pub outbox_waiting_challenge: &'static str,
    pub outbox_confirmed: &'static str,
    pub outbox_retrieved: &'static str,
    pub outbox_expired: &'static str,
    pub outbox_revoked: &'static str,
    pub outbox_challenge_failed: &'static str,
    pub outbox_password_failed: &'static str,
    pub inbox_filename: &'static str,
    pub inbox_file_size: &'static str,
    pub inbox_expired: &'static str,
    pub inbox_revoked: &'static str,
    pub inbox_retrieved: &'static str,
    pub inbox_wrong_password: &'static str,
    pub inbox_attempts_exhausted: &'static str,

    // ── General ──
    pub dismiss: &'static str,
    pub copy: &'static str,
    pub node_init_msg: &'static str,
}

pub fn strings(locale: Locale) -> &'static Strings {
    match locale {
        Locale::En => &EN,
        Locale::Ja => &JA,
        Locale::ZhCn => &ZH_CN,
    }
}

// ─── English ─────────────────────────────────────────────────────────────────

static EN: Strings = Strings {
    tab_store: "Store",
    tab_store_easy: "Save",
    tab_retrieve: "Retrieve",
    tab_retrieve_easy: "Get Back",
    tab_status: "Status",
    tab_settings: "Settings",

    connected: "Connected",
    starting: "Starting...",
    offline: "Offline",
    setup_needed: "Setup needed",

    welcome_title: "Welcome to Miasma",
    welcome_title_easy: "Welcome",
    welcome_desc: "Store, encrypt, and share content over a peer-to-peer network.",
    welcome_desc_easy: "Save your files securely and access them from anywhere.",
    welcome_detail: "Click below to create your node identity. This generates an encryption key and starts the background daemon automatically.",
    welcome_detail_easy: "Click below to get started. We'll set everything up for you.",
    welcome_button: "Set Up Node",
    welcome_progress: "Creating identity and starting daemon...",
    welcome_progress_easy: "Setting up...",

    stopped_title: "Daemon not running",
    stopped_title_easy: "Not running",
    stopped_desc: "The background daemon has stopped. Click below to restart it.",
    stopped_desc_easy: "The app needs to restart its background service. Click below.",
    stopped_button: "Start Daemon",
    stopped_button_easy: "Start",
    starting_label: "Starting daemon...",
    starting_label_easy: "Starting...",

    store_heading: "Store Content",
    store_heading_easy: "Save Content",
    store_desc: "Encrypt, split, and store content into the Miasma network.",
    store_desc_easy: "Save your content securely.",
    store_text_label: "Text input:",
    store_text_hint: "Paste or type content here...",
    store_choose_file: "Choose File...",
    store_button: "Store Text",
    store_success: "Content stored successfully.",
    store_mid_label: "Content ID (MID):",
    store_mid_label_easy: "Content ID:",
    store_copy: "Copy",
    store_copied: "MID copied to clipboard.",
    store_share_hint: "Share this ID to let others retrieve the content.",
    store_share_hint_easy: "Save this ID — you'll need it to get your content back.",
    store_busy: "Storing file...",
    store_not_connected_hint: "Start the app first to save content.",

    retrieve_heading: "Retrieve Content",
    retrieve_heading_easy: "Get Content Back",
    retrieve_desc: "Reconstruct content from its Miasma Content ID.",
    retrieve_desc_easy: "Enter your Content ID to get your content back.",
    retrieve_mid_label: "Content ID (MID):",
    retrieve_mid_label_easy: "Content ID:",
    retrieve_button: "Retrieve",
    retrieve_button_easy: "Get Back",
    retrieve_busy: "Retrieving...",
    retrieve_success: "Content retrieved. Save to export.",
    retrieve_save_button: "Save to File...",
    retrieve_saved: "Saved to",
    retrieve_save_failed: "Save failed:",
    retrieve_result_label: "Retrieved:",
    retrieve_not_connected_hint: "Start the app first to get content back.",

    status_heading: "Node Status",
    status_refresh: "Refresh",
    status_copy_diag: "Copy Diagnostics",
    status_diag_copied: "Diagnostics copied to clipboard.",
    status_connection: "Connection",
    status_state: "State:",
    status_state_connected: "Connected",
    status_state_starting: "Starting...",
    status_state_not_running: "Not running",
    status_state_not_init: "Not initialized",
    status_peer_id: "Peer ID:",
    status_peers: "Peers:",
    status_relay: "Relay:",
    relay_down_s: "Not connected for {n} s",
    relay_down_min: "Not connected for {n} min",
    relay_down_h: "Not connected for {h} h {m} min",
    relay_cause_dns: "this computer cannot look up the relay's address (DNS)",
    relay_cause_timeout: "the relay did not answer in time",
    relay_cause_tls: "the relay's certificate was not accepted (a network that inspects traffic?)",
    relay_cause_denied: "the relay refused this computer",
    relay_cause_other: "the connection to the relay failed",
    relay_cert_trusted: "This network re-signs secure connections (certificate from \"{ca}\", not a public CA). This computer trusts that CA.",
    relay_cert_untrusted: "This network re-signs secure connections (certificate from \"{ca}\", not a public CA) and this computer does not trust that CA. Install the CA in the system certificate store, or set transport.iroh_extra_ca_pem.",
    status_listening: "Listening:",
    status_storage: "Storage",
    status_shares: "Shares:",
    status_used: "Used:",
    status_replication: "Replication:",
    status_transport: "Transport",
    status_transport_name: "Transport",
    status_transport_status: "Status",
    status_transport_counts: "Success / Fail",
    status_transport_details: "Details",
    status_all_failing: "All transports failing. Check proxy settings, firewall rules, or try a different transport in config.toml.",

    status_ready: "Ready",
    status_not_ready: "Not ready",
    status_items_stored: "Items stored:",
    status_hint_ready: "You can save and retrieve content.",
    status_hint_not_ready: "The app is not running yet. Go to the Save tab to get started.",
    status_hint_no_peers: "Connected, but no peers found yet. Content may not replicate until peers appear.",

    wipe_label: "Emergency Wipe",
    wipe_desc: "Erases all data and keys that Miasma stores on this device. This cannot be undone.",
    wipe_button: "Erase All Data",
    wipe_confirm_title: "Erase all data?",
    wipe_confirm_line1: "This erases everything Miasma stores on this device, and the keys that open it: stored content, contacts and settings.",
    wipe_confirm_line2: "This cannot be undone.",
    wipe_confirm_button: "Erase everything",
    wipe_cancel: "Cancel",
    wipe_done: "Erased. Close Miasma and set it up again if you want to keep using it.",
    wipe_confirm_kept: "Not erased: copies you have already sent to others, and files you saved elsewhere, such as the receive folder.",
    wipe_confirm_offline: "The background service is stopped, so the data is erased directly, without it.",
    wipe_offline_note: "This also works while the background service is stopped.",
    close_title: "Close Miasma?",
    close_body: "A transfer is in progress. If you close now, it stops.\nThe part already transferred is kept, and you can resume it from where it stopped.",
    close_confirm: "Close",
    close_cancel: "Cancel",
    dialog_cancel: "Cancel",
    inbox_revoke_title: "Decline this file?",
    inbox_revoke_body: "You will not receive this file. This cannot be undone. The sender can send it again if needed.",
    inbox_revoke_confirm: "Decline",
    inbox_revoke_done: "Declined.",
    outbox_revoke_title: "Revoke this share?",
    outbox_revoke_body: "The recipient will no longer be able to get this file. This cannot be undone. You can send it again later.",
    outbox_revoke_confirm: "Revoke",
    outbox_revoke_done: "Revoked.",

    settings_heading: "Settings",
    settings_paths: "Paths",
    settings_data_dir: "Data directory:",
    settings_config_file: "Config file:",
    settings_log: "Desktop log:",
    settings_install: "Install location:",
    settings_path_copied: "Path copied.",
    settings_how: "How it works",
    settings_how_line1: "The desktop app manages a background daemon that handles storage and networking.",
    settings_how_line1_easy: "This app runs a background service to handle your saved content.",
    settings_how_line2: "The daemon starts automatically when you launch the app, and stops when you close it.",
    settings_how_line2_easy: "It starts automatically and stops when you close the app.",
    settings_stored_in: "Your data is stored in:",
    settings_preserved: "This directory is preserved if you uninstall the app.",
    settings_actions: "Actions",
    settings_open_folder: "Open Data Folder",
    settings_language: "Language",
    settings_mode: "Interface mode",
    settings_mode_technical: "Technical",
    settings_mode_easy: "Easy",
    settings_mode_desc_technical: "Full diagnostics, transport details, protocol visibility",
    settings_mode_desc_easy: "Simplified interface, less technical detail",
    settings_theme: "Appearance",
    settings_theme_system: "System",
    settings_theme_light: "Light",
    settings_theme_dark: "Dark",

    tab_import: "Import",
    import_heading: "Import Content",
    import_idle_hint: "No content to import. Use the Save tab to store new content.",
    import_magnet_label: "Magnet link",
    import_torrent_label: "Torrent file",
    import_explain: "This will download content via BitTorrent and store it in Miasma. The bridge process handles the transfer.",
    import_explain_easy: "This will download the content and save it securely in Miasma.",
    import_button: "Import",
    import_cancel: "Cancel",
    import_not_connected: "Start the app first before importing.",
    import_progress: "Importing",
    import_complete: "Import complete.",
    import_failed: "Import failed.",
    import_retry: "Retry",
    import_done: "Done",

    health_app: "App",
    health_backend: "Backend",
    health_network: "Network",
    health_ok: "OK",
    health_starting: "Starting",
    health_offline: "Offline",
    health_no_peers: "No peers yet",

    status_save_diag: "Save Report",
    status_diag_saved: "Diagnostics saved.",
    status_diag_save_failed: "Could not save diagnostics: ",

    nav_brand: "Miasma Protocol",
    nav_brand_easy: "Miasma",

    dashboard_quick_status: "Quick Status",
    dashboard_storage_label: "Storage",
    dashboard_peers_label: "Network",
    dashboard_free: "free",
    dashboard_no_data: "No data yet",

    storage_bar_label: "Storage used",

    // ── Directed sharing ──
    tab_send: "Send",
    tab_send_easy: "Send",
    tab_inbox: "Inbox",
    tab_inbox_easy: "Inbox",
    send_heading: "Directed Private Share",
    send_heading_easy: "Send to Someone",
    send_desc: "Encrypt and send a file to a specific recipient using their sharing contact.",
    send_desc_easy: "Send a file privately to someone you know.",
    send_contact_label: "Recipient contact:",
    send_contact_hint: "msk:...@PeerId",
    send_password_label: "Password:",
    send_retention_label: "Keep for:",
    send_choose_file: "Choose file...",
    send_button: "Send",
    send_busy: "Sending...",
    send_success: "Sent! Share the challenge code with recipient.",
    send_not_connected: "Connect to send files.",
    inbox_heading: "Directed Inbox",
    inbox_heading_easy: "Received Files",
    inbox_desc: "Incoming directed shares from other users.",
    inbox_desc_easy: "Files people have sent to you.",
    inbox_empty: "Inbox is empty.",
    inbox_from: "From:",
    inbox_state: "State:",
    inbox_challenge: "Challenge:",
    inbox_retrieve_button: "Retrieve",
    inbox_password_label: "Password:",
    inbox_revoke_button: "Decline",
    inbox_refresh: "Refresh",
    sharing_key_label: "Your sharing contact:",
    sharing_key_desc: "Share this contact string so others can send you directed files.",
    sharing_key_desc_easy: "Give this to people who want to send you files.",
    sharing_key_copy: "Copy Contact",
    sharing_key_copied: "Copied!",

    tab_outbox: "Outbox",
    tab_outbox_easy: "Sent",
    outbox_heading: "Directed Outbox",
    outbox_heading_easy: "Files You Sent",
    outbox_desc: "Outgoing directed shares you have sent to others.",
    outbox_desc_easy: "Files you sent to specific people.",
    outbox_empty: "Outbox is empty.",
    outbox_to: "To:",
    outbox_state: "State:",
    outbox_filename: "File:",
    outbox_refresh: "Refresh",
    outbox_revoke_button: "Revoke",
    outbox_confirm_heading: "Enter Challenge Code",
    outbox_confirm_label: "Code:",
    outbox_confirm_hint: "XXXX-XXXX",
    outbox_confirm_button: "Confirm",
    outbox_confirm_success: "Confirmed! Recipient can now retrieve the file.",
    outbox_waiting_challenge: "Waiting for recipient challenge...",
    outbox_confirmed: "Confirmed",
    outbox_retrieved: "Retrieved",
    outbox_expired: "Expired",
    outbox_revoked: "Revoked",
    outbox_challenge_failed: "Challenge Failed",
    outbox_password_failed: "Password Failed",
    inbox_filename: "File:",
    inbox_file_size: "Size:",
    inbox_expired: "This share has expired.",
    inbox_revoked: "This share was revoked by the sender.",
    inbox_retrieved: "Already retrieved.",
    inbox_wrong_password: "Wrong password.",
    inbox_attempts_exhausted: "Too many failed attempts.",

    dismiss: "Dismiss",
    copy: "Copy",
    node_init_msg: "Node initialized.",
};

// ─── Japanese ────────────────────────────────────────────────────────────────

static JA: Strings = Strings {
    tab_store: "保存",
    tab_store_easy: "保存",
    tab_retrieve: "取得",
    tab_retrieve_easy: "取り出す",
    tab_status: "ステータス",
    tab_settings: "設定",

    connected: "接続中",
    starting: "起動中...",
    offline: "オフライン",
    setup_needed: "セットアップが必要",

    welcome_title: "Miasmaへようこそ",
    welcome_title_easy: "ようこそ",
    welcome_desc: "ピアツーピアネットワークでコンテンツを暗号化して保存・共有できます。",
    welcome_desc_easy: "ファイルを安全に保存して、いつでもアクセスできます。",
    welcome_detail: "下のボタンをクリックしてノードIDを作成します。暗号鍵を生成し、バックグラウンドデーモンを自動起動します。",
    welcome_detail_easy: "下のボタンをクリックして始めましょう。すべて自動で設定されます。",
    welcome_button: "セットアップ",
    welcome_progress: "IDを作成してデーモンを起動中...",
    welcome_progress_easy: "セットアップ中...",

    stopped_title: "デーモン停止中",
    stopped_title_easy: "停止中",
    stopped_desc: "バックグラウンドデーモンが停止しました。下のボタンで再起動してください。",
    stopped_desc_easy: "バックグラウンドサービスを再起動してください。",
    stopped_button: "デーモン起動",
    stopped_button_easy: "起動",
    starting_label: "デーモン起動中...",
    starting_label_easy: "起動中...",

    store_heading: "コンテンツ保存",
    store_heading_easy: "保存",
    store_desc: "コンテンツを暗号化・分割してMiasmaネットワークに保存します。",
    store_desc_easy: "コンテンツを安全に保存します。",
    store_text_label: "テキスト入力:",
    store_text_hint: "テキストを入力またはペースト...",
    store_choose_file: "ファイルを選択...",
    store_button: "テキストを保存",
    store_success: "保存しました。",
    store_mid_label: "コンテンツID (MID):",
    store_mid_label_easy: "コンテンツID:",
    store_copy: "コピー",
    store_copied: "IDをコピーしました。",
    store_share_hint: "このIDを共有すると、他の人がコンテンツを取得できます。",
    store_share_hint_easy: "このIDを保存してください。取り出すときに必要です。",
    store_busy: "保存中...",
    store_not_connected_hint: "保存するにはアプリを起動してください。",

    retrieve_heading: "コンテンツ取得",
    retrieve_heading_easy: "取り出す",
    retrieve_desc: "MiasmaコンテンツIDからコンテンツを復元します。",
    retrieve_desc_easy: "コンテンツIDを入力して取り出します。",
    retrieve_mid_label: "コンテンツID (MID):",
    retrieve_mid_label_easy: "コンテンツID:",
    retrieve_button: "取得",
    retrieve_button_easy: "取り出す",
    retrieve_busy: "取得中...",
    retrieve_success: "取得しました。ファイルに保存できます。",
    retrieve_save_button: "ファイルに保存...",
    retrieve_saved: "保存しました:",
    retrieve_save_failed: "保存に失敗:",
    retrieve_result_label: "取得結果:",
    retrieve_not_connected_hint: "取り出すにはアプリを起動してください。",

    status_heading: "ノードステータス",
    status_refresh: "更新",
    status_copy_diag: "診断情報をコピー",
    status_diag_copied: "診断情報をコピーしました。",
    status_connection: "接続",
    status_state: "状態:",
    status_state_connected: "接続中",
    status_state_starting: "起動中...",
    status_state_not_running: "停止中",
    status_state_not_init: "未初期化",
    status_peer_id: "ピアID:",
    status_peers: "ピア数:",
    status_relay: "リレー:",
    relay_down_s: "{n} 秒間つながっていません",
    relay_down_min: "{n} 分間つながっていません",
    relay_down_h: "{h} 時間 {m} 分間つながっていません",
    relay_cause_dns: "このコンピューターがリレーのアドレスを引けません (DNS)",
    relay_cause_timeout: "リレーが時間内に応答しません",
    relay_cause_tls: "リレーの証明書が受け入れられませんでした (通信を検査するネットワークでは?)",
    relay_cause_denied: "リレーがこのコンピューターを拒否しました",
    relay_cause_other: "リレーへの接続に失敗しました",
    relay_cert_trusted: "このネットワークは安全な通信を再署名しています(証明書の発行元「{ca}」は公開 CA ではありません)。このコンピューターはその CA を信頼しています。",
    relay_cert_untrusted: "このネットワークは安全な通信を再署名しています(証明書の発行元「{ca}」は公開 CA ではありません)。このコンピューターはその CA を信頼していません。CA をシステムの証明書ストアに入れるか、transport.iroh_extra_ca_pem を設定してください。",
    status_listening: "リッスン:",
    status_storage: "ストレージ",
    status_shares: "シェア数:",
    status_used: "使用量:",
    status_replication: "レプリケーション:",
    status_transport: "トランスポート",
    status_transport_name: "トランスポート",
    status_transport_status: "状態",
    status_transport_counts: "成功 / 失敗",
    status_transport_details: "詳細",
    status_all_failing: "全トランスポートが失敗中です。プロキシ設定やファイアウォールを確認してください。",

    status_ready: "準備完了",
    status_not_ready: "準備中",
    status_items_stored: "保存済み:",
    status_hint_ready: "コンテンツの保存と取り出しができます。",
    status_hint_not_ready: "アプリがまだ起動していません。「保存」タブから始めましょう。",
    status_hint_no_peers: "接続済みですが、ピアが見つかりません。ピアが見つかるまでレプリケーションは保留されます。",

    wipe_label: "緊急消去",
    wipe_desc: "このパソコンにあるMiasmaのデータと、それを開くためのカギをすべて消します。元に戻せません。",
    wipe_button: "すべてのデータを消去",
    wipe_confirm_title: "すべてのデータを消去しますか？",
    wipe_confirm_line1: "このパソコンにあるMiasmaのデータと、それを開くためのカギをすべて消します。保存した内容、連絡先、設定などが対象です。",
    wipe_confirm_line2: "消したものは、二度と元に戻せません。",
    wipe_confirm_button: "すべて消去する",
    wipe_cancel: "やめる",
    wipe_done: "消去しました。Miasmaを閉じて、続けて使う場合は最初から設定し直してください。",
    wipe_confirm_kept: "消えないもの: すでに相手に送ったコピーと、受信フォルダなど別の場所に保存したファイル。",
    wipe_confirm_offline: "バックグラウンドのサービスが止まっているため、サービスを使わずに直接消去します。",
    wipe_offline_note: "バックグラウンドのサービスが止まっていても消去できます。",
    close_title: "閉じますか？",
    close_body: "転送中です。閉じると転送が止まります。\n途中までのファイルは残り、あとで続きから再開できます。",
    close_confirm: "閉じる",
    close_cancel: "キャンセル",
    dialog_cancel: "やめる",
    inbox_revoke_title: "このファイルを受け取りませんか？",
    inbox_revoke_body: "このファイルは受け取らないことにします。元に戻せません。必要なら、相手にもう一度送ってもらってください。",
    inbox_revoke_confirm: "受け取らない",
    inbox_revoke_done: "受け取らないことにしました。",
    outbox_revoke_title: "この送信を取り消しますか？",
    outbox_revoke_body: "取り消すと、相手はこのファイルを受け取れなくなります。元に戻せません。必要なら、あとで送り直してください。",
    outbox_revoke_confirm: "取り消す",
    outbox_revoke_done: "取り消しました。",

    settings_heading: "設定",
    settings_paths: "パス",
    settings_data_dir: "データディレクトリ:",
    settings_config_file: "設定ファイル:",
    settings_log: "デスクトップログ:",
    settings_install: "インストール場所:",
    settings_path_copied: "パスをコピーしました。",
    settings_how: "仕組み",
    settings_how_line1: "デスクトップアプリはバックグラウンドデーモンを管理し、ストレージとネットワークを処理します。",
    settings_how_line1_easy: "このアプリはバックグラウンドサービスでコンテンツを管理します。",
    settings_how_line2: "デーモンはアプリ起動時に自動起動し、閉じると停止します。",
    settings_how_line2_easy: "アプリを開くと自動的に起動し、閉じると停止します。",
    settings_stored_in: "データの保存先:",
    settings_preserved: "アンインストールしてもこのディレクトリは保持されます。",
    settings_actions: "操作",
    settings_open_folder: "データフォルダを開く",
    settings_language: "言語",
    settings_mode: "表示モード",
    settings_mode_technical: "テクニカル",
    settings_mode_easy: "かんたん",
    settings_mode_desc_technical: "診断情報、トランスポート詳細、プロトコル表示",
    settings_mode_desc_easy: "シンプルな表示、技術的詳細を非表示",
    settings_theme: "外観",
    settings_theme_system: "システム設定に合わせる",
    settings_theme_light: "ライト",
    settings_theme_dark: "ダーク",

    tab_import: "インポート",
    import_heading: "コンテンツのインポート",
    import_idle_hint: "インポートするコンテンツがありません。「保存」タブで新しいコンテンツを保存してください。",
    import_magnet_label: "マグネットリンク",
    import_torrent_label: "トレントファイル",
    import_explain: "BitTorrentでコンテンツをダウンロードし、Miasmaに保存します。ブリッジプロセスが転送を処理します。",
    import_explain_easy: "コンテンツをダウンロードして、Miasmaに安全に保存します。",
    import_button: "インポート",
    import_cancel: "キャンセル",
    import_not_connected: "インポートする前にアプリを起動してください。",
    import_progress: "インポート中",
    import_complete: "インポート完了。",
    import_failed: "インポートに失敗しました。",
    import_retry: "再試行",
    import_done: "完了",

    health_app: "アプリ",
    health_backend: "バックエンド",
    health_network: "ネットワーク",
    health_ok: "OK",
    health_starting: "起動中",
    health_offline: "オフライン",
    health_no_peers: "ノード未接続",

    status_save_diag: "レポートを保存",
    status_diag_saved: "診断情報を保存しました。",
    status_diag_save_failed: "診断情報の保存に失敗しました：",

    nav_brand: "Miasma Protocol",
    nav_brand_easy: "Miasma",

    dashboard_quick_status: "クイックステータス",
    dashboard_storage_label: "ストレージ",
    dashboard_peers_label: "ネットワーク",
    dashboard_free: "空き",
    dashboard_no_data: "データなし",

    storage_bar_label: "ストレージ使用量",

    // ── Directed sharing ──
    tab_send: "送信",
    tab_send_easy: "送る",
    tab_inbox: "受信箱",
    tab_inbox_easy: "届いたファイル",
    send_heading: "ダイレクト共有",
    send_heading_easy: "ファイルを送る",
    send_desc: "受信者の共有コンタクトを使って暗号化し送信します。",
    send_desc_easy: "知り合いにファイルを安全に送ります。",
    send_contact_label: "送信先コンタクト:",
    send_contact_hint: "msk:...@PeerId",
    send_password_label: "パスワード:",
    send_retention_label: "保持期間:",
    send_choose_file: "ファイル選択...",
    send_button: "送信",
    send_busy: "送信中...",
    send_success: "送信完了！チャレンジコードを受信者に共有してください。",
    send_not_connected: "接続してから送信してください。",
    inbox_heading: "ダイレクト受信箱",
    inbox_heading_easy: "届いたファイル",
    inbox_desc: "他のユーザーからのダイレクト共有。",
    inbox_desc_easy: "あなた宛に送られたファイル。",
    inbox_empty: "受信箱は空です。",
    inbox_from: "送信者:",
    inbox_state: "状態:",
    inbox_challenge: "チャレンジ:",
    inbox_retrieve_button: "取得",
    inbox_password_label: "パスワード:",
    inbox_revoke_button: "受け取らない",
    inbox_refresh: "更新",
    sharing_key_label: "あなたの共有コンタクト:",
    sharing_key_desc: "このコンタクト文字列を共有すると相手がダイレクト送信できます。",
    sharing_key_desc_easy: "ファイルを受け取るにはこれを相手に教えてください。",
    sharing_key_copy: "コピー",
    sharing_key_copied: "コピーしました！",

    tab_outbox: "送信済み",
    tab_outbox_easy: "送ったファイル",
    outbox_heading: "送信済みダイレクト共有",
    outbox_heading_easy: "送ったファイル",
    outbox_desc: "他のユーザーに送ったダイレクト共有。",
    outbox_desc_easy: "あなたが送ったファイルの一覧。",
    outbox_empty: "送信済みはありません。",
    outbox_to: "宛先:",
    outbox_state: "状態:",
    outbox_filename: "ファイル:",
    outbox_refresh: "更新",
    outbox_revoke_button: "取り消す",
    outbox_confirm_heading: "チャレンジコード入力",
    outbox_confirm_label: "コード:",
    outbox_confirm_hint: "XXXX-XXXX",
    outbox_confirm_button: "確認",
    outbox_confirm_success: "確認完了！受信者がファイルを取得できます。",
    outbox_waiting_challenge: "受信者のチャレンジ待ち...",
    outbox_confirmed: "確認済み",
    outbox_retrieved: "取得済み",
    outbox_expired: "期限切れ",
    outbox_revoked: "取り消し済み",
    outbox_challenge_failed: "チャレンジ失敗",
    outbox_password_failed: "パスワード失敗",
    inbox_filename: "ファイル:",
    inbox_file_size: "サイズ:",
    inbox_expired: "この共有は期限切れです。",
    inbox_revoked: "送信者がこの共有を取り消しました。",
    inbox_retrieved: "取得済みです。",
    inbox_wrong_password: "パスワードが違います。",
    inbox_attempts_exhausted: "試行回数を超過しました。",

    dismiss: "閉じる",
    copy: "コピー",
    node_init_msg: "初期化しました。",
};

// ─── Simplified Chinese ──────────────────────────────────────────────────────

static ZH_CN: Strings = Strings {
    tab_store: "存储",
    tab_store_easy: "保存",
    tab_retrieve: "检索",
    tab_retrieve_easy: "取回",
    tab_status: "状态",
    tab_settings: "设置",

    connected: "已连接",
    starting: "启动中...",
    offline: "离线",
    setup_needed: "需要设置",

    welcome_title: "欢迎使用 Miasma",
    welcome_title_easy: "欢迎",
    welcome_desc: "通过点对点网络加密存储和共享内容。",
    welcome_desc_easy: "安全保存您的文件，随时随地访问。",
    welcome_detail: "点击下方按钮创建节点身份。将自动生成加密密钥并启动后台守护进程。",
    welcome_detail_easy: "点击下方按钮开始使用，我们会自动完成所有设置。",
    welcome_button: "开始设置",
    welcome_progress: "正在创建身份并启动守护进程...",
    welcome_progress_easy: "正在设置...",

    stopped_title: "守护进程已停止",
    stopped_title_easy: "已停止",
    stopped_desc: "后台守护进程已停止。点击下方按钮重新启动。",
    stopped_desc_easy: "后台服务需要重新启动。请点击下方按钮。",
    stopped_button: "启动守护进程",
    stopped_button_easy: "启动",
    starting_label: "正在启动守护进程...",
    starting_label_easy: "正在启动...",

    store_heading: "存储内容",
    store_heading_easy: "保存内容",
    store_desc: "将内容加密、分片并存储到 Miasma 网络。",
    store_desc_easy: "安全保存您的内容。",
    store_text_label: "文本输入：",
    store_text_hint: "在此输入或粘贴文本...",
    store_choose_file: "选择文件...",
    store_button: "保存文本",
    store_success: "保存成功。",
    store_mid_label: "内容ID (MID)：",
    store_mid_label_easy: "内容ID：",
    store_copy: "复制",
    store_copied: "已复制ID。",
    store_share_hint: "分享此ID，其他人就能检索该内容。",
    store_share_hint_easy: "请保存此ID，取回内容时需要使用。",
    store_busy: "正在保存...",
    store_not_connected_hint: "请先启动应用再保存内容。",

    retrieve_heading: "检索内容",
    retrieve_heading_easy: "取回内容",
    retrieve_desc: "通过 Miasma 内容ID恢复内容。",
    retrieve_desc_easy: "输入内容ID取回您的内容。",
    retrieve_mid_label: "内容ID (MID)：",
    retrieve_mid_label_easy: "内容ID：",
    retrieve_button: "检索",
    retrieve_button_easy: "取回",
    retrieve_busy: "正在检索...",
    retrieve_success: "检索成功，可以保存到文件。",
    retrieve_save_button: "保存到文件...",
    retrieve_saved: "已保存到",
    retrieve_save_failed: "保存失败：",
    retrieve_result_label: "检索结果：",
    retrieve_not_connected_hint: "请先启动应用再取回内容。",

    status_heading: "节点状态",
    status_refresh: "刷新",
    status_copy_diag: "复制诊断信息",
    status_diag_copied: "已复制诊断信息。",
    status_connection: "连接",
    status_state: "状态：",
    status_state_connected: "已连接",
    status_state_starting: "启动中...",
    status_state_not_running: "未运行",
    status_state_not_init: "未初始化",
    status_peer_id: "节点ID：",
    status_peers: "节点数：",
    status_relay: "中继：",
    relay_down_s: "已断开 {n} 秒",
    relay_down_min: "已断开 {n} 分钟",
    relay_down_h: "已断开 {h} 小时 {m} 分钟",
    relay_cause_dns: "本机无法解析中继服务器的地址 (DNS)",
    relay_cause_timeout: "中继服务器未在时限内响应",
    relay_cause_tls: "中继服务器的证书未被接受（网络是否在检查流量？）",
    relay_cause_denied: "中继服务器拒绝了本机",
    relay_cause_other: "无法连接到中继服务器",
    relay_cert_trusted: "此网络会重新签署加密连接（证书由“{ca}”签发，并非公共 CA）。本机信任该 CA。",
    relay_cert_untrusted: "此网络会重新签署加密连接（证书由“{ca}”签发，并非公共 CA），本机不信任该 CA。请将该 CA 安装到系统证书存储，或设置 transport.iroh_extra_ca_pem。",
    status_listening: "监听：",
    status_storage: "存储",
    status_shares: "分片数：",
    status_used: "已使用：",
    status_replication: "副本：",
    status_transport: "传输",
    status_transport_name: "传输方式",
    status_transport_status: "状态",
    status_transport_counts: "成功 / 失败",
    status_transport_details: "详情",
    status_all_failing: "所有传输均失败。请检查代理设置和防火墙规则。",

    status_ready: "就绪",
    status_not_ready: "未就绪",
    status_items_stored: "已保存：",
    status_hint_ready: "您可以保存和取回内容。",
    status_hint_not_ready: "应用尚未启动。请前往「保存」标签页开始使用。",
    status_hint_no_peers: "已连接，但尚未找到节点。在找到节点之前内容可能不会复制。",

    wipe_label: "紧急擦除",
    wipe_desc: "擦除 Miasma 在此设备上保存的所有数据和用于打开它们的密钥。此操作无法恢复。",
    wipe_button: "擦除所有数据",
    wipe_confirm_title: "要擦除所有数据吗？",
    wipe_confirm_line1: "这会擦除 Miasma 保存在此设备上的所有内容，以及用于打开它们的密钥，包括已保存的内容、联系人和设置。",
    wipe_confirm_line2: "擦除后无法恢复。",
    wipe_confirm_button: "全部擦除",
    wipe_cancel: "取消",
    wipe_done: "已擦除。如需继续使用，请关闭 Miasma 并重新设置。",
    wipe_confirm_kept: "不会擦除：已经发送给他人的副本，以及您保存在其他位置的文件（例如接收文件夹）。",
    wipe_confirm_offline: "后台服务已停止，将不经过该服务直接擦除。",
    wipe_offline_note: "即使后台服务已停止，也可以擦除。",
    close_title: "要关闭吗？",
    close_body: "正在传输。关闭后传输会停止。\n已传输的部分会保留，之后可以从中断处继续。",
    close_confirm: "关闭",
    close_cancel: "取消",
    dialog_cancel: "取消",
    inbox_revoke_title: "不接收此文件吗？",
    inbox_revoke_body: "将不再接收此文件，且无法恢复。如有需要，请让对方重新发送。",
    inbox_revoke_confirm: "不接收",
    inbox_revoke_done: "已设为不接收。",
    outbox_revoke_title: "要撤销这次发送吗？",
    outbox_revoke_body: "撤销后，对方将无法再获取此文件，且无法恢复。如有需要，可以稍后重新发送。",
    outbox_revoke_confirm: "撤销",
    outbox_revoke_done: "已撤销。",

    settings_heading: "设置",
    settings_paths: "路径",
    settings_data_dir: "数据目录：",
    settings_config_file: "配置文件：",
    settings_log: "桌面日志：",
    settings_install: "安装位置：",
    settings_path_copied: "已复制路径。",
    settings_how: "工作原理",
    settings_how_line1: "桌面应用管理一个后台守护进程来处理存储和网络。",
    settings_how_line1_easy: "此应用通过后台服务管理您的内容。",
    settings_how_line2: "守护进程在应用启动时自动运行，关闭应用时停止。",
    settings_how_line2_easy: "打开应用自动启动，关闭应用自动停止。",
    settings_stored_in: "数据保存在：",
    settings_preserved: "卸载应用时此目录将被保留。",
    settings_actions: "操作",
    settings_open_folder: "打开数据文件夹",
    settings_language: "语言",
    settings_mode: "界面模式",
    settings_mode_technical: "专业版",
    settings_mode_easy: "简易版",
    settings_mode_desc_technical: "完整诊断信息、传输详情、协议可见",
    settings_mode_desc_easy: "简化界面，隐藏技术细节",
    settings_theme: "外观",
    settings_theme_system: "跟随系统",
    settings_theme_light: "浅色",
    settings_theme_dark: "深色",

    tab_import: "导入",
    import_heading: "导入内容",
    import_idle_hint: "没有需要导入的内容。请在「保存」标签页保存新内容。",
    import_magnet_label: "磁力链接",
    import_torrent_label: "种子文件",
    import_explain: "通过 BitTorrent 下载内容并保存至 Miasma。桥接进程将处理传输。",
    import_explain_easy: "下载内容并安全保存到 Miasma。",
    import_button: "开始导入",
    import_cancel: "取消",
    import_not_connected: "导入前请先启动应用。",
    import_progress: "正在导入",
    import_complete: "导入完成。",
    import_failed: "导入失败。",
    import_retry: "重试",
    import_done: "完成",

    health_app: "应用",
    health_backend: "后台服务",
    health_network: "网络",
    health_ok: "正常",
    health_starting: "启动中",
    health_offline: "离线",
    health_no_peers: "尚未连接节点",

    status_save_diag: "保存报告",
    status_diag_saved: "诊断信息已保存。",
    status_diag_save_failed: "无法保存诊断信息：",

    nav_brand: "Miasma Protocol",
    nav_brand_easy: "Miasma",

    dashboard_quick_status: "快速状态",
    dashboard_storage_label: "存储",
    dashboard_peers_label: "网络",
    dashboard_free: "可用",
    dashboard_no_data: "暂无数据",

    storage_bar_label: "存储使用量",

    // ── Directed sharing ──
    tab_send: "发送",
    tab_send_easy: "发送",
    tab_inbox: "收件箱",
    tab_inbox_easy: "收到的文件",
    send_heading: "定向私密共享",
    send_heading_easy: "发送文件",
    send_desc: "使用接收者的共享联系方式加密并发送文件。",
    send_desc_easy: "安全地发送文件给你认识的人。",
    send_contact_label: "接收者联系方式:",
    send_contact_hint: "msk:...@PeerId",
    send_password_label: "密码:",
    send_retention_label: "保留期:",
    send_choose_file: "选择文件...",
    send_button: "发送",
    send_busy: "发送中...",
    send_success: "发送成功！请将验证码分享给接收者。",
    send_not_connected: "请先连接再发送。",
    inbox_heading: "定向收件箱",
    inbox_heading_easy: "收到的文件",
    inbox_desc: "来自其他用户的定向共享。",
    inbox_desc_easy: "别人发给你的文件。",
    inbox_empty: "收件箱为空。",
    inbox_from: "发送者:",
    inbox_state: "状态:",
    inbox_challenge: "验证码:",
    inbox_retrieve_button: "取回",
    inbox_password_label: "密码:",
    inbox_revoke_button: "不接收",
    inbox_refresh: "刷新",
    sharing_key_label: "你的共享联系方式:",
    sharing_key_desc: "分享此联系方式，其他人即可向你发送定向文件。",
    sharing_key_desc_easy: "把这个给想发文件给你的人。",
    sharing_key_copy: "复制",
    sharing_key_copied: "已复制！",

    tab_outbox: "发件箱",
    tab_outbox_easy: "已发送",
    outbox_heading: "定向发件箱",
    outbox_heading_easy: "你发送的文件",
    outbox_desc: "你发送给其他用户的定向共享。",
    outbox_desc_easy: "你发送给特定人的文件。",
    outbox_empty: "发件箱为空。",
    outbox_to: "收件人:",
    outbox_state: "状态:",
    outbox_filename: "文件:",
    outbox_refresh: "刷新",
    outbox_revoke_button: "撤销",
    outbox_confirm_heading: "输入验证码",
    outbox_confirm_label: "验证码:",
    outbox_confirm_hint: "XXXX-XXXX",
    outbox_confirm_button: "确认",
    outbox_confirm_success: "确认成功！接收者现在可以取回文件。",
    outbox_waiting_challenge: "等待接收者验证码...",
    outbox_confirmed: "已确认",
    outbox_retrieved: "已取回",
    outbox_expired: "已过期",
    outbox_revoked: "已撤销",
    outbox_challenge_failed: "验证失败",
    outbox_password_failed: "密码失败",
    inbox_filename: "文件:",
    inbox_file_size: "大小:",
    inbox_expired: "此共享已过期。",
    inbox_revoked: "发送者已撤销此共享。",
    inbox_retrieved: "已取回。",
    inbox_wrong_password: "密码错误。",
    inbox_attempts_exhausted: "尝试次数已用尽。",

    dismiss: "关闭",
    copy: "复制",
    node_init_msg: "初始化完成。",
};

// ─── Transfers screen ───────────────────────────────────────────────────────
//
// Kept apart from `Strings` so the tests can list every field of this screen and check each
// one, in every locale, for emptiness. `{name}` placeholders are filled by `transfers::fill`.

/// Strings of the Transfers screen (`transfers.rs`).
pub struct TransferStrings {
    pub tab: &'static str,
    pub tab_easy: &'static str,
    pub heading: &'static str,
    pub heading_easy: &'static str,
    pub desc: &'static str,
    pub desc_easy: &'static str,

    // Direction and state.
    pub send: &'static str,
    pub receive: &'static str,
    pub st_running: &'static str,
    pub st_paused: &'static str,
    pub st_complete: &'static str,
    pub st_failed: &'static str,
    pub st_cancelled: &'static str,

    // List.
    pub empty: &'static str,
    pub empty_easy: &'static str,
    pub offline_note: &'static str,
    pub stale_note: &'static str,
    pub select_hint: &'static str,
    pub eta: &'static str,
    /// Suffix after a number of days in an ETA ("2d 03:20:11").
    pub day: &'static str,

    // Detail.
    pub mid_label: &'static str,
    pub mid_label_easy: &'static str,
    /// Small note beside the MID when a Share ID is shown too (Technical view).
    pub mid_internal_note: &'static str,
    pub copy: &'static str,
    pub copied: &'static str,
    pub phase_label: &'static str,
    pub ph_preparing: &'static str,
    pub ph_hashing: &'static str,
    pub ph_verifying: &'static str,
    pub ph_transferring: &'static str,
    pub ph_finalizing: &'static str,
    pub ph_done: &'static str,
    pub elapsed_label: &'static str,
    pub segments_label: &'static str,
    pub segment_word: &'static str,
    pub strip_unknown: &'static str,
    pub strip_done: &'static str,
    pub strip_inflight: &'static str,
    pub strip_pending: &'static str,
    /// `{n}`: the segment this session resumed from.
    pub strip_resumed: &'static str,
    /// `{n}`: segments drawn as one cell.
    pub strip_per_cell: &'static str,
    pub resumed_label: &'static str,
    pub resumed_fresh: &'static str,
    pub split_label: &'static str,
    /// `{a}` `{b}` `{c}`: percent of time fetching / decoding / writing.
    pub split_recv: &'static str,
    /// `{a}` `{b}` `{c}`: percent of time pushing / encoding / storing.
    pub split_send: &'static str,
    pub pieces_label: &'static str,
    /// `{ok}` `{bad}`
    pub pieces_fmt: &'static str,
    pub retries_label: &'static str,
    pub error_label: &'static str,

    // Easy-mode sentences. `{pct}` `{eta}`
    pub easy_running: &'static str,
    pub easy_running_eta: &'static str,
    pub easy_paused: &'static str,
    pub easy_complete: &'static str,
    pub easy_failed: &'static str,

    // Buttons and prompts.
    pub btn_stop: &'static str,
    pub btn_resume: &'static str,
    pub btn_try_again: &'static str,
    pub btn_restart: &'static str,
    pub btn_keep: &'static str,
    pub restart_confirm: &'static str,
    pub restart_yes: &'static str,
    pub resume_go: &'static str,
    pub resume_pw_optional: &'static str,
    pub resume_pw_required: &'static str,
    pub no_path_hint: &'static str,

    // New transfer.
    pub new_heading: &'static str,
    pub forms_offline: &'static str,
    pub recv_path_label: &'static str,
    pub recv_path_hint: &'static str,
    /// Shown while the sender's file name is looked up, before the Save-As dialog opens.
    pub recv_name_lookup: &'static str,
    pub send_path_label: &'static str,
    pub send_path_hint: &'static str,
    pub browse: &'static str,
    pub password_label: &'static str,
    /// The same field when it is required, not optional.
    pub password_short: &'static str,
    pub password_note: &'static str,
    /// Technical mode only: fetch directly from the sender's WebSocket tunnel URL.
    pub via_label: &'static str,
    pub via_hint: &'static str,
    pub via_note: &'static str,
    pub confirm_label: &'static str,
    pub mismatch: &'static str,
    pub recv_button: &'static str,
    pub send_button: &'static str,
    pub err_mid: &'static str,
    pub started: &'static str,
    pub stop_requested: &'static str,
    pub send_hint: &'static str,

    // Redundancy.
    pub red_label: &'static str,
    pub red_label_easy: &'static str,
    /// `{kn}` `{x}` `{loss}`
    pub red_row: &'static str,
    pub red_default: &'static str,
    pub easy_fast: &'static str,
    pub easy_fast_desc: &'static str,
    pub easy_bal: &'static str,
    pub easy_bal_desc: &'static str,
    pub easy_safe: &'static str,
    pub easy_safe_desc: &'static str,

    // Removing finished transfers.
    pub btn_remove: &'static str,
    pub btn_clear_finished: &'static str,
    pub clear_finished_hint: &'static str,
    pub remove_note_send: &'static str,
    pub remove_note_recv: &'static str,
    pub remove_note_plain: &'static str,
    pub remove_note_partial: &'static str,
    pub discard_confirm: &'static str,
    pub discard_yes: &'static str,
    pub removed_msg: &'static str,
    pub err_remove_running: &'static str,
    pub err_remove_paused: &'static str,
    pub recv_folder_note: &'static str,

    // Share ID: the ID a sender gives a receiver.
    /// Label of the receive form's ID field (accepts a share ID or a MID).
    pub recv_id_label: &'static str,
    /// Label of the share ID row in a transfer's details.
    pub share_id_label: &'static str,
    /// Under the share ID on a finished send: what to do with it.
    pub share_id_send_note: &'static str,
    /// Button next to the share ID: copies a ready-to-paste invitation message.
    pub copy_invitation: &'static str,
    /// Language of the copied invitation message (there is no Chinese text yet: English).
    pub invite_lang: miasma_core::transfer::InviteLang,
    /// Under the share ID: what the invitation contains and what it does not.
    pub invitation_note: &'static str,
    /// Toggle that shows the share ID as a QR code, and hides it again.
    pub show_qr: &'static str,
    pub hide_qr: &'static str,
    /// Under the QR code: it carries the share ID only.
    pub qr_note: &'static str,
    /// The share ID is too large to draw as a QR code (should not happen).
    pub qr_failed: &'static str,
    /// Shown when what was typed is a share ID that does not parse.
    pub err_share_id: &'static str,
    pub publisher_label: &'static str,
    pub publisher_verified: &'static str,
    /// A receive started from a bare MID.
    pub publisher_unverified: &'static str,
    /// A receive over iroh: how the data travels.
    pub path_label: &'static str,
    pub path_direct: &'static str,
    pub path_relay: &'static str,

    // Send password policy and the generator.
    /// Under the send password field: the rule, and the honest caveat.
    pub pw_policy_note: &'static str,
    /// Prefix of the refusal; the reasons follow, separated by `pw_err_sep`.
    pub pw_weak_prefix: &'static str,
    pub pw_err_sep: &'static str,
    pub pw_err_too_short: &'static str,
    pub pw_err_too_long: &'static str,
    pub pw_err_no_digit: &'static str,
    pub pw_err_no_letter: &'static str,
    pub pw_err_no_symbol: &'static str,
    /// Soft warning (compliant but under 12 characters).
    pub pw_short_warning: &'static str,
    pub pw_generate: &'static str,
    pub pw_generated_note: &'static str,
}

impl TransferStrings {
    /// Every field with its name, for the completeness test.
    #[cfg(test)]
    fn all(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("tab", self.tab),
            ("tab_easy", self.tab_easy),
            ("heading", self.heading),
            ("heading_easy", self.heading_easy),
            ("desc", self.desc),
            ("desc_easy", self.desc_easy),
            ("send", self.send),
            ("receive", self.receive),
            ("st_running", self.st_running),
            ("st_paused", self.st_paused),
            ("st_complete", self.st_complete),
            ("st_failed", self.st_failed),
            ("st_cancelled", self.st_cancelled),
            ("empty", self.empty),
            ("empty_easy", self.empty_easy),
            ("offline_note", self.offline_note),
            ("stale_note", self.stale_note),
            ("select_hint", self.select_hint),
            ("eta", self.eta),
            ("day", self.day),
            ("mid_label", self.mid_label),
            ("mid_label_easy", self.mid_label_easy),
            ("mid_internal_note", self.mid_internal_note),
            ("copy", self.copy),
            ("copied", self.copied),
            ("phase_label", self.phase_label),
            ("ph_preparing", self.ph_preparing),
            ("ph_hashing", self.ph_hashing),
            ("ph_verifying", self.ph_verifying),
            ("ph_transferring", self.ph_transferring),
            ("ph_finalizing", self.ph_finalizing),
            ("ph_done", self.ph_done),
            ("elapsed_label", self.elapsed_label),
            ("segments_label", self.segments_label),
            ("segment_word", self.segment_word),
            ("strip_unknown", self.strip_unknown),
            ("strip_done", self.strip_done),
            ("strip_inflight", self.strip_inflight),
            ("strip_pending", self.strip_pending),
            ("strip_resumed", self.strip_resumed),
            ("strip_per_cell", self.strip_per_cell),
            ("resumed_label", self.resumed_label),
            ("resumed_fresh", self.resumed_fresh),
            ("split_label", self.split_label),
            ("split_recv", self.split_recv),
            ("split_send", self.split_send),
            ("pieces_label", self.pieces_label),
            ("pieces_fmt", self.pieces_fmt),
            ("retries_label", self.retries_label),
            ("error_label", self.error_label),
            ("easy_running", self.easy_running),
            ("easy_running_eta", self.easy_running_eta),
            ("easy_paused", self.easy_paused),
            ("easy_complete", self.easy_complete),
            ("easy_failed", self.easy_failed),
            ("btn_stop", self.btn_stop),
            ("btn_resume", self.btn_resume),
            ("btn_try_again", self.btn_try_again),
            ("btn_restart", self.btn_restart),
            ("btn_keep", self.btn_keep),
            ("restart_confirm", self.restart_confirm),
            ("restart_yes", self.restart_yes),
            ("resume_go", self.resume_go),
            ("resume_pw_optional", self.resume_pw_optional),
            ("resume_pw_required", self.resume_pw_required),
            ("no_path_hint", self.no_path_hint),
            ("new_heading", self.new_heading),
            ("forms_offline", self.forms_offline),
            ("recv_path_label", self.recv_path_label),
            ("recv_path_hint", self.recv_path_hint),
            ("recv_name_lookup", self.recv_name_lookup),
            ("send_path_label", self.send_path_label),
            ("send_path_hint", self.send_path_hint),
            ("browse", self.browse),
            ("password_label", self.password_label),
            ("password_short", self.password_short),
            ("password_note", self.password_note),
            ("via_label", self.via_label),
            ("via_hint", self.via_hint),
            ("via_note", self.via_note),
            ("confirm_label", self.confirm_label),
            ("mismatch", self.mismatch),
            ("recv_button", self.recv_button),
            ("send_button", self.send_button),
            ("err_mid", self.err_mid),
            ("started", self.started),
            ("stop_requested", self.stop_requested),
            ("send_hint", self.send_hint),
            ("red_label", self.red_label),
            ("red_label_easy", self.red_label_easy),
            ("red_row", self.red_row),
            ("red_default", self.red_default),
            ("easy_fast", self.easy_fast),
            ("easy_fast_desc", self.easy_fast_desc),
            ("easy_bal", self.easy_bal),
            ("easy_bal_desc", self.easy_bal_desc),
            ("easy_safe", self.easy_safe),
            ("easy_safe_desc", self.easy_safe_desc),
            ("btn_remove", self.btn_remove),
            ("btn_clear_finished", self.btn_clear_finished),
            ("clear_finished_hint", self.clear_finished_hint),
            ("remove_note_send", self.remove_note_send),
            ("remove_note_recv", self.remove_note_recv),
            ("remove_note_plain", self.remove_note_plain),
            ("remove_note_partial", self.remove_note_partial),
            ("discard_confirm", self.discard_confirm),
            ("discard_yes", self.discard_yes),
            ("removed_msg", self.removed_msg),
            ("err_remove_running", self.err_remove_running),
            ("err_remove_paused", self.err_remove_paused),
            ("recv_folder_note", self.recv_folder_note),
            ("recv_id_label", self.recv_id_label),
            ("share_id_label", self.share_id_label),
            ("share_id_send_note", self.share_id_send_note),
            ("copy_invitation", self.copy_invitation),
            ("invitation_note", self.invitation_note),
            ("show_qr", self.show_qr),
            ("hide_qr", self.hide_qr),
            ("qr_note", self.qr_note),
            ("qr_failed", self.qr_failed),
            ("err_share_id", self.err_share_id),
            ("publisher_label", self.publisher_label),
            ("publisher_verified", self.publisher_verified),
            ("publisher_unverified", self.publisher_unverified),
            ("path_label", self.path_label),
            ("path_direct", self.path_direct),
            ("path_relay", self.path_relay),
            ("pw_policy_note", self.pw_policy_note),
            ("pw_weak_prefix", self.pw_weak_prefix),
            ("pw_err_sep", self.pw_err_sep),
            ("pw_err_too_short", self.pw_err_too_short),
            ("pw_err_too_long", self.pw_err_too_long),
            ("pw_err_no_digit", self.pw_err_no_digit),
            ("pw_err_no_letter", self.pw_err_no_letter),
            ("pw_err_no_symbol", self.pw_err_no_symbol),
            ("pw_short_warning", self.pw_short_warning),
            ("pw_generate", self.pw_generate),
            ("pw_generated_note", self.pw_generated_note),
        ]
    }
}

pub fn transfer_strings(locale: Locale) -> &'static TransferStrings {
    match locale {
        Locale::En => &TR_EN,
        Locale::Ja => &TR_JA,
        Locale::ZhCn => &TR_ZH_CN,
    }
}

static TR_EN: TransferStrings = TransferStrings {
    tab: "Transfers",
    tab_easy: "Transfers",
    heading: "Transfers",
    heading_easy: "Transfers",
    desc: "Large files are sent and received by the background service. They can be stopped and resumed, and this list shows exactly how far each one has got.",
    desc_easy: "Send or receive large files here. You can stop a transfer and continue it later from where it stopped.",

    send: "Send",
    receive: "Receive",
    st_running: "Running",
    st_paused: "Paused",
    st_complete: "Complete",
    st_failed: "Failed",
    st_cancelled: "Stopped",

    empty: "No transfers yet. Start one below.",
    empty_easy: "Nothing is being sent or received. Start a transfer below.",
    offline_note: "The background service is not running, so the list cannot be updated.",
    stale_note: "Showing the last known state.",
    select_hint: "Select a transfer to see its details.",
    eta: "ETA",
    day: "d",

    mid_label: "MID",
    mid_label_easy: "Content ID",
    mid_internal_note: "仅供内部使用，不能用于接收（请改为提供共享 ID）。",
    copy: "Copy",
    copied: "Copied",
    phase_label: "Phase",
    ph_preparing: "Getting ready",
    ph_hashing: "Reading the file",
    ph_verifying: "Checking what is already saved",
    ph_transferring: "Transferring",
    ph_finalizing: "Finishing up",
    ph_done: "Done",
    elapsed_label: "Elapsed",
    segments_label: "Segments",
    segment_word: "Segment",
    strip_unknown: "The number of segments is not known yet.",
    strip_done: "done",
    strip_inflight: "in progress",
    strip_pending: "waiting",
    strip_resumed: "resumed from segment {n}",
    strip_per_cell: "{n} segments per cell",
    resumed_label: "Resumed from segment",
    resumed_fresh: "started from the beginning",
    split_label: "Time split",
    split_recv: "fetch {a}%   decode {b}%   write {c}%",
    split_send: "push to peers {a}%   encode {b}%   store locally {c}%",
    pieces_label: "Pieces",
    pieces_fmt: "{ok} received, {bad} rejected",
    retries_label: "Segment retries",
    error_label: "Last error",

    easy_running: "{pct} done.",
    easy_running_eta: "{pct} done, about {eta} left.",
    easy_paused: "Stopped at {pct}. Your progress is saved; you can continue where it left off.",
    easy_complete: "Finished.",
    easy_failed: "This did not finish. See the message below, then try again.",

    btn_stop: "Stop (keep progress)",
    btn_resume: "Resume",
    btn_try_again: "Try again",
    btn_restart: "Start over",
    btn_keep: "Cancel",
    restart_confirm: "Discard the saved progress and start from the beginning?",
    restart_yes: "Discard and start over",
    resume_go: "Resume",
    resume_pw_optional: "The password is never saved, so it is asked for again. Leave it empty if the transfer has no password.",
    resume_pw_required: "This transfer was started with a password. Enter the same password to continue.",
    no_path_hint: "The save location is not known any more. Start the transfer again from the form below.",

    new_heading: "New transfer",
    forms_offline: "Start the background service first (see the top of the window).",
    recv_path_label: "Save to",
    recv_path_hint: "Where to write the finished file",
    recv_name_lookup: "正在查找文件名...",
    send_path_label: "File",
    send_path_hint: "The file to send",
    browse: "Browse...",
    password_label: "Password (optional)",
    password_short: "Password",
    password_note: "Used as part of the encryption key. It is not stored: keep it, you will need it to resume.",
    via_label: "Via URL (optional)",
    via_hint: "wss://... from the sender",
    via_note: "Fetch straight from the sender's tunnel URL instead of the network, so no peer or DHT is needed. Leave empty normally.",
    confirm_label: "Confirm password",
    mismatch: "The two passwords do not match.",
    recv_button: "Start receiving",
    send_button: "Start sending",
    err_mid: "Paste a Share ID (starts with \"miasma-share:\") or a MID (starts with \"miasma:\").",
    started: "Transfer started.",
    stop_requested: "Stopping at the next safe point. Progress is kept.",
    send_hint: "The receiver must be able to reach this computer, and this computer must stay on and online until the receiver has finished: other computers do not keep a copy by default.",

    red_label: "Redundancy",
    red_label_easy: "Protection",
    red_row: "{kn}   {x} storage   tolerates {loss} lost pieces",
    red_default: "(default)",
    easy_fast: "Fastest",
    easy_fast_desc: "Least disk space and time. There are no spare pieces, so damage cannot be repaired.",
    easy_bal: "Balanced",
    easy_bal_desc: "A little spare: up to 2 damaged pieces per part can be repaired.",
    easy_safe: "Safest",
    easy_safe_desc: "Uses twice the disk space. Up to 10 damaged pieces per part can be repaired.",

    btn_remove: "Remove from list",
    btn_clear_finished: "Clear finished",
    clear_finished_hint: "Removes finished transfers from this list. Files you received or sent are not touched. Stopped transfers that still hold partial data are kept.",
    remove_note_send: "Only removes this row. The file stays available to peers.",
    remove_note_recv: "Only removes this row. The received file is not deleted.",
    remove_note_plain: "Only removes this row. Nothing on disk is deleted.",
    remove_note_partial: "This transfer stopped with partial data. Removing it discards that data.",
    discard_confirm: "Discard the partial data and remove this transfer? This cannot be undone.",
    discard_yes: "Discard and remove",
    removed_msg: "Removed from the list.",
    err_remove_running: "This transfer is still running. Stop it first.",
    err_remove_paused: "This transfer is paused and can be resumed, so it was not removed.",
    recv_folder_note: "That is a folder. The file will be saved inside it, under the name it had when it was sent: {path}",
    recv_id_label: "Share ID (or MID)",
    share_id_label: "Share ID",
    share_id_send_note: "Give this Share ID (and the password) to the receiver. It also lets them check who published the file.",
    copy_invitation: "Copy invitation",
    invite_lang: miasma_core::transfer::InviteLang::En,
    invitation_note: "The invitation holds the Share ID only, never the password. Send the password by a different channel.",
    show_qr: "Show QR",
    hide_qr: "Hide QR",
    qr_note: "This QR code holds the Share ID only, not the password.",
    qr_failed: "The QR code could not be drawn.",
    err_share_id: "That Share ID is not valid: a character was probably mistyped. Check it against the original.",
    publisher_label: "Publisher",
    publisher_verified: "Verified by the Share ID",
    publisher_unverified: "Not authenticated: use the Share ID",
    path_label: "Connection",
    path_direct: "Direct (peer to peer)",
    path_relay: "Through a relay server (slower)",

    pw_policy_note: "Optional. If you set one: at least 6 characters with a digit, a letter (a-z, A-Z) and a symbol; a space does not count. Even so, a short password is weak: anyone who holds the transfer's manifest can try guesses offline. Press Generate for a strong one.",
    pw_weak_prefix: "Password not accepted:",
    pw_err_sep: "; ",
    pw_err_too_short: "it is shorter than 6 characters",
    pw_err_too_long: "it is longer than 1024 characters",
    pw_err_no_digit: "it has no digit (0-9)",
    pw_err_no_letter: "it has no letter (a-z, A-Z)",
    pw_err_no_symbol: "it has no symbol such as ! # $ %",
    pw_short_warning: "short: use 12+ characters or press Generate",
    pw_generate: "Generate",
    pw_generated_note: "Generated password, shown once. Store it now: it is not saved anywhere and cannot be recovered. The receiver needs it in addition to the MID.",
};

static TR_JA: TransferStrings = TransferStrings {
    tab: "転送",
    tab_easy: "ファイル転送",
    heading: "転送",
    heading_easy: "ファイル転送",
    desc: "大きなファイルの送受信はバックグラウンドで行われます。途中で止めても続きから再開でき、この一覧でそれぞれの進み具合を正確に確認できます。",
    desc_easy: "大きなファイルをここで送ったり受け取ったりできます。途中で止めても、あとで続きから再開できます。",

    send: "送信",
    receive: "受信",
    st_running: "転送中",
    st_paused: "一時停止",
    st_complete: "完了",
    st_failed: "失敗",
    st_cancelled: "停止",

    empty: "転送はまだありません。下から開始できます。",
    empty_easy: "送信も受信もしていません。下から転送を始めてください。",
    offline_note: "バックグラウンドのサービスが動いていないため、一覧を更新できません。",
    stale_note: "最後に確認できた状態を表示しています。",
    select_hint: "詳細を見たい転送を選んでください。",
    eta: "残り",
    day: "日",

    mid_label: "MID",
    mid_label_easy: "コンテンツID",
    mid_internal_note: "内部用。受信には使えません（共有IDを渡してください）。",
    copy: "コピー",
    copied: "コピーしました",
    phase_label: "段階",
    ph_preparing: "準備中",
    ph_hashing: "ファイルを読み込み中",
    ph_verifying: "保存済みの部分を確認中",
    ph_transferring: "転送中",
    ph_finalizing: "仕上げ中",
    ph_done: "完了",
    elapsed_label: "経過時間",
    segments_label: "セグメント",
    segment_word: "セグメント",
    strip_unknown: "セグメント数はまだ分かっていません。",
    strip_done: "完了",
    strip_inflight: "処理中",
    strip_pending: "待機中",
    strip_resumed: "セグメント{n}から再開",
    strip_per_cell: "1マス = {n}セグメント",
    resumed_label: "再開位置",
    resumed_fresh: "最初から開始",
    split_label: "時間の内訳",
    split_recv: "取得 {a}%   復号 {b}%   書き込み {c}%",
    split_send: "相手へ送信 {a}%   暗号化・分割 {b}%   ローカル保存 {c}%",
    pieces_label: "ピース",
    pieces_fmt: "受信 {ok}個 / 不一致で破棄 {bad}個",
    retries_label: "セグメントの再試行",
    error_label: "最後のエラー",

    easy_running: "{pct} 完了しました。",
    easy_running_eta: "{pct} 完了、残り約 {eta} です。",
    easy_paused: "{pct} で止まっています。進み具合は保存されているので、続きから再開できます。",
    easy_complete: "完了しました。",
    easy_failed: "最後まで終わりませんでした。下のメッセージを確認して、もう一度お試しください。",

    btn_stop: "進捗を保ったまま停止",
    btn_resume: "続きから再開",
    btn_try_again: "もう一度試す",
    btn_restart: "最初からやり直す",
    btn_keep: "キャンセル",
    restart_confirm: "保存済みの進捗を捨てて、最初からやり直しますか？",
    restart_yes: "捨てて最初からやり直す",
    resume_go: "再開する",
    resume_pw_optional: "パスワードは保存されないため、もう一度入力が必要です。パスワードを付けていない転送は空のままにしてください。",
    resume_pw_required: "この転送はパスワード付きで開始されました。続けるには同じパスワードを入力してください。",
    no_path_hint: "保存先が分からなくなりました。下のフォームからもう一度転送を開始してください。",

    new_heading: "新しい転送",
    forms_offline: "先にバックグラウンドのサービスを起動してください（画面の上部を参照）。",
    recv_path_label: "保存先",
    recv_path_hint: "完成したファイルの保存先",
    recv_name_lookup: "ファイル名を確認しています...",
    send_path_label: "ファイル",
    send_path_hint: "送信するファイル",
    browse: "参照...",
    password_label: "パスワード（任意）",
    password_short: "パスワード",
    password_note: "暗号化の鍵の一部として使われます。保存されないので、再開に必要です。控えておいてください。",
    via_label: "経由 URL（任意）",
    via_hint: "送信側の wss://...",
    via_note: "ネットワークではなく、送信側のトンネル URL から直接取得します。ピアも DHT も不要です。通常は空のままにします。",
    confirm_label: "パスワード（確認）",
    mismatch: "2つのパスワードが一致しません。",
    recv_button: "受信を開始",
    send_button: "送信を開始",
    err_mid: "共有ID(「miasma-share:」で始まる)またはMID(「miasma:」で始まる)を貼り付けてください。",
    started: "転送を開始しました。",
    stop_requested: "次の区切りで停止します。進捗は保たれます。",
    send_hint: "受信側からこのコンピュータへ接続できる必要があります。受信が終わるまで、このコンピュータの電源とネットワークを維持してください。既定では他のコンピュータに複製は残りません。",

    red_label: "冗長度",
    red_label_easy: "保護レベル",
    red_row: "{kn}   保存容量 {x}   欠けても復元できるピース数 {loss}",
    red_default: "（既定）",
    easy_fast: "最速",
    easy_fast_desc: "ディスク容量と時間が最小です。予備がないため、破損は修復できません。",
    easy_bal: "標準",
    easy_bal_desc: "少し予備があり、各部分で最大2ピースの破損まで修復できます。",
    easy_safe: "最も安全",
    easy_safe_desc: "ディスク容量が2倍になります。各部分で最大10ピースの破損まで修復できます。",

    btn_remove: "リストから外す",
    btn_clear_finished: "完了分を消去",
    clear_finished_hint: "完了・失敗・中止した転送をこの一覧から外します。受信したファイルや送信元ファイルには触れません。途中までのデータが残っている転送は残します。",
    remove_note_send: "この行を外すだけです。送信したファイルは引き続き相手が受け取れます。",
    remove_note_recv: "この行を外すだけです。受信したファイルは削除されません。",
    remove_note_plain: "この行を外すだけです。ディスク上のものは削除されません。",
    remove_note_partial: "この転送は途中までのデータを残して止まっています。外すとそのデータも破棄されます。",
    discard_confirm: "途中までのデータを破棄して、この転送を外しますか。元に戻せません。",
    discard_yes: "破棄して外す",
    removed_msg: "リストから外しました。",
    err_remove_running: "この転送はまだ実行中です。先に停止してください。",
    err_remove_paused: "この転送は一時停止中で再開できるため、外していません。",
    recv_folder_note: "指定先はフォルダです。送信時のファイル名でこのフォルダの中に保存します: {path}",
    recv_id_label: "共有ID (またはMID)",
    share_id_label: "共有ID",
    share_id_send_note: "この共有ID(とパスワード)を受信する人に渡してください。誰が公開したファイルかも確認できます。",
    copy_invitation: "招待文をコピー",
    invite_lang: miasma_core::transfer::InviteLang::Ja,
    invitation_note: "招待文には共有IDだけが入り、パスワードは入りません。パスワードは別の方法で渡してください。",
    show_qr: "QRコードを表示",
    hide_qr: "QRコードを隠す",
    qr_note: "このQRコードには共有IDだけが入っています。パスワードは含まれません。",
    qr_failed: "QRコードを描画できませんでした。",
    err_share_id: "共有IDが正しくありません。文字の打ち間違いの可能性があります。元のIDと見比べてください。",
    publisher_label: "発行元",
    publisher_verified: "共有IDで確認済み",
    publisher_unverified: "未確認: 共有IDを使ってください",
    path_label: "接続",
    path_direct: "直接接続（ピアツーピア）",
    path_relay: "リレーサーバ経由（低速）",

    pw_policy_note: "任意です。設定する場合は 6 文字以上で、数字・英字 (a-z, A-Z)・記号をそれぞれ含めてください（空白は記号に数えません）。ただし短いパスワードは弱く、転送のマニフェストを持つ人はオフラインで何度でも推測できます。「生成」で強いパスワードを作れます。",
    pw_weak_prefix: "このパスワードは使えません:",
    pw_err_sep: "、",
    pw_err_too_short: "6 文字未満です",
    pw_err_too_long: "1024 文字を超えています",
    pw_err_no_digit: "数字 (0-9) がありません",
    pw_err_no_letter: "英字 (a-z, A-Z) がありません",
    pw_err_no_symbol: "記号 (! # $ % など) がありません",
    pw_short_warning: "短めです: 12 文字以上にするか「生成」を押してください",
    pw_generate: "生成",
    pw_generated_note: "生成したパスワードです（この1回だけ表示）。今すぐ保管してください。どこにも保存されず、失くすと復元できません。受信する人には MID に加えてこのパスワードが必要です。",
};

static TR_ZH_CN: TransferStrings = TransferStrings {
    tab: "传输",
    tab_easy: "文件传输",
    heading: "传输",
    heading_easy: "文件传输",
    desc: "大文件由后台服务收发。传输可以中途停止并继续，此列表会准确显示每个传输的进度。",
    desc_easy: "在这里发送或接收大文件。可以随时停止，之后从中断处继续。",

    send: "发送",
    receive: "接收",
    st_running: "传输中",
    st_paused: "已暂停",
    st_complete: "已完成",
    st_failed: "失败",
    st_cancelled: "已停止",

    empty: "还没有传输。可以在下方开始。",
    empty_easy: "当前没有发送或接收。请在下方开始传输。",
    offline_note: "后台服务未运行，无法更新列表。",
    stale_note: "显示的是最近一次获取的状态。",
    select_hint: "选择一个传输以查看详情。",
    eta: "剩余",
    day: "天",

    mid_label: "MID",
    mid_label_easy: "内容ID",
    mid_internal_note: "Internal use only; it cannot be used to receive (give the Share ID instead).",
    copy: "复制",
    copied: "已复制",
    phase_label: "阶段",
    ph_preparing: "准备中",
    ph_hashing: "正在读取文件",
    ph_verifying: "正在检查已保存的部分",
    ph_transferring: "传输中",
    ph_finalizing: "正在收尾",
    ph_done: "完成",
    elapsed_label: "已用时间",
    segments_label: "分段",
    segment_word: "分段",
    strip_unknown: "分段数量暂未确定。",
    strip_done: "已完成",
    strip_inflight: "处理中",
    strip_pending: "等待中",
    strip_resumed: "从第{n}段继续",
    strip_per_cell: "每格 {n} 段",
    resumed_label: "继续位置",
    resumed_fresh: "从头开始",
    split_label: "耗时分布",
    split_recv: "获取 {a}%   解码 {b}%   写入 {c}%",
    split_send: "发送给对端 {a}%   编码 {b}%   本地存储 {c}%",
    pieces_label: "分片",
    pieces_fmt: "已接收 {ok} 个，校验不符丢弃 {bad} 个",
    retries_label: "分段重试次数",
    error_label: "最近的错误",

    easy_running: "已完成 {pct}。",
    easy_running_eta: "已完成 {pct}，大约还需 {eta}。",
    easy_paused: "已在 {pct} 处停止。进度已保存，可以从中断处继续。",
    easy_complete: "已完成。",
    easy_failed: "未能完成。请查看下方的信息，然后重试。",

    btn_stop: "停止（保留进度）",
    btn_resume: "继续",
    btn_try_again: "重试",
    btn_restart: "重新开始",
    btn_keep: "取消",
    restart_confirm: "放弃已保存的进度并从头开始吗？",
    restart_yes: "放弃并重新开始",
    resume_go: "继续",
    resume_pw_optional: "密码不会被保存，因此需要再次输入。如果此传输没有设置密码，请留空。",
    resume_pw_required: "此传输是带密码开始的。请输入相同的密码以继续。",
    no_path_hint: "已不知道保存位置。请从下方表单重新开始传输。",

    new_heading: "新建传输",
    forms_offline: "请先启动后台服务（见窗口顶部）。",
    recv_path_label: "保存到",
    recv_path_hint: "完成后文件的保存位置",
    recv_name_lookup: "Looking up the file name...",
    send_path_label: "文件",
    send_path_hint: "要发送的文件",
    browse: "浏览...",
    password_label: "密码（可选）",
    password_short: "密码",
    password_note: "会作为加密密钥的一部分使用。密码不会被保存，继续传输时需要，请妥善记下。",
    via_label: "经由 URL（可选）",
    via_hint: "发送方提供的 wss://...",
    via_note: "不通过网络，而是直接从发送方的隧道 URL 获取，无需对等节点或 DHT。通常留空。",
    confirm_label: "确认密码",
    mismatch: "两次输入的密码不一致。",
    recv_button: "开始接收",
    send_button: "开始发送",
    err_mid: "请粘贴共享 ID（以“miasma-share:”开头）或 MID（以“miasma:”开头）。",
    started: "传输已开始。",
    stop_requested: "将在下一个安全点停止，进度会保留。",
    send_hint: "接收方必须能够连接到这台电脑，并且在接收完成之前，这台电脑要保持开机和联网：默认情况下其他电脑不会保存副本。",

    red_label: "冗余度",
    red_label_easy: "保护级别",
    red_row: "{kn}   占用空间 {x}   可容忍丢失 {loss} 个分片",
    red_default: "（默认）",
    easy_fast: "最快",
    easy_fast_desc: "占用磁盘空间和时间最少。没有备用分片，损坏后无法修复。",
    easy_bal: "均衡",
    easy_bal_desc: "有少量备用：每部分最多可修复 2 个损坏的分片。",
    easy_safe: "最安全",
    easy_safe_desc: "占用两倍磁盘空间。每部分最多可修复 10 个损坏的分片。",

    btn_remove: "从列表中移除",
    btn_clear_finished: "清除已结束项",
    clear_finished_hint: "从此列表中移除已完成、失败或已取消的传输。不会改动您接收或发送的文件。仍保留部分数据的已停止传输会被保留。",
    remove_note_send: "仅移除此行。该文件仍可供对方接收。",
    remove_note_recv: "仅移除此行。已接收的文件不会被删除。",
    remove_note_plain: "仅移除此行。不会删除磁盘上的任何内容。",
    remove_note_partial: "此传输已停止并保留了部分数据。移除它会丢弃这些数据。",
    discard_confirm: "丢弃部分数据并移除此传输吗？此操作无法撤销。",
    discard_yes: "丢弃并移除",
    removed_msg: "已从列表中移除。",
    err_remove_running: "此传输仍在运行。请先停止它。",
    err_remove_paused: "此传输已暂停且可以继续，因此未被移除。",
    recv_folder_note: "该路径是文件夹。文件将以发送时的文件名保存在其中：{path}",
    recv_id_label: "共享 ID（或 MID）",
    share_id_label: "共享 ID",
    share_id_send_note: "请把此共享 ID（和密码）交给接收方。接收方还能借此核实发布者。",
    copy_invitation: "复制邀请",
    invite_lang: miasma_core::transfer::InviteLang::En,
    invitation_note: "邀请内容只包含共享 ID，不含密码。请通过其他渠道发送密码。",
    show_qr: "显示二维码",
    hide_qr: "隐藏二维码",
    qr_note: "此二维码只包含共享 ID，不含密码。",
    qr_failed: "无法绘制二维码。",
    err_share_id: "共享 ID 无效：可能输错了字符。请与原始 ID 核对。",
    publisher_label: "发布者",
    publisher_verified: "已通过共享 ID 核实",
    publisher_unverified: "未验证：请使用共享 ID",
    path_label: "连接",
    path_direct: "直连（点对点）",
    path_relay: "经中继服务器（较慢）",

    pw_policy_note: "可选。若设置，须至少 6 个字符，并包含数字、字母 (a-z, A-Z) 和符号；空格不算符号。即便如此，短密码仍然很弱：持有该传输清单的人可以离线反复猜测。点击“生成”可得到高强度密码。",
    pw_weak_prefix: "密码不符合要求：",
    pw_err_sep: "；",
    pw_err_too_short: "少于 6 个字符",
    pw_err_too_long: "超过 1024 个字符",
    pw_err_no_digit: "没有数字 (0-9)",
    pw_err_no_letter: "没有字母 (a-z, A-Z)",
    pw_err_no_symbol: "没有符号（如 ! # $ %）",
    pw_short_warning: "偏短：请使用 12 个以上字符，或点击“生成”",
    pw_generate: "生成",
    pw_generated_note: "已生成的密码（仅显示这一次）。请立即保存：它不会保存在任何地方，丢失后无法找回。接收方除 MID 外还需要此密码。",
};

// ─── Contacts (trusted-contact push) ────────────────────────────────────────

/// Declares `ContactStrings` and a field listing for the completeness test from one field list.
macro_rules! contact_strings {
    ($($f:ident),* $(,)?) => {
        /// Strings of the Contacts area (`contacts.rs`). `{name}`-style holes are filled with
        /// `transfers::fill`.
        pub struct ContactStrings { $(pub $f: &'static str),* }
        impl ContactStrings {
            /// Every field with its name, for the completeness test.
            #[cfg(test)]
            fn all(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}

contact_strings! {
    tab, heading, desc,
    help_title, help_1, help_2, help_3,
    loading, daemon_down, push_unavailable, old_daemon, retry_now,
    my_card, my_code, my_code_hint, my_fp, my_fp_hint, copy_code, copy_invite, copied, show_qr, hide_qr, qr_note,
    add_title, add_hint, add_paste, add_label, add_label_hint, add_button, add_busy,
    added_title, added_compare, label_required,
    err_bad_code, err_this_is_me, err_already_exists, err_label_taken, err_bad_label,
    err_unavailable, err_too_many, err_unknown_contact, err_send_disabled, err_bad_file,
    err_queue_full, err_not_found, err_internal, err_other,
    list_title, list_empty, chip_registered, chip_not_registered, hint_not_registered,
    allow_receive, allow_send, max_size, max_size_hint, max_size_invalid, rename, save, cancel,
    remove, remove_title, remove_body, remove_confirm, send_files, pick_title, drop_hint,
    drop_folder, drop_pick_contact, fingerprint, send_disabled_note,
    tr_title, tr_empty, dir_out, dir_in,
    st_queued, st_preparing, st_connecting, st_sending, st_verifying, st_done, st_failed,
    st_rejected, st_cancelled, st_waiting,
    btn_cancel, btn_try_now, btn_retry, btn_open_file, btn_show_folder, btn_clear_finished, eta,
    rej_too_large, rej_no_space, rej_not_allowed, rej_busy, rej_bad_name, rej_bad_request,
    fail_unreachable, fail_relay_down, fail_other, fail_lost_in, fail_peer_cancelled,
    fail_source_changed, wait_retry, wait_offline, wait_in_sec, wait_in_min, wait_in_hour,
    max_size_default_hint, eta_sec, eta_min, eta_min_even, eta_hour, eta_hour_even, eta_day,
    inbox_title, inbox_dir, open_folder, inbox_note, arrival_toast, queued_toast, nav_new, dismiss,
    qr_too_long,
    sugg_title, sugg_body, sugg_item, sugg_attempts, sugg_add, sugg_ignore, sugg_prefill_note,
    sugg_now, sugg_min, sugg_hour,
    open_missing, open_failed, saved_to, earlier_failed, earlier_show, earlier_hide,
}

pub fn contact_strings(locale: Locale) -> &'static ContactStrings {
    match locale {
        Locale::En => &CT_EN,
        Locale::Ja => &CT_JA,
        Locale::ZhCn => &CT_ZH_CN,
    }
}

static CT_EN: ContactStrings = ContactStrings {
    tab: "Contacts",
    heading: "Contacts",
    desc: "Add each other once, then send files to that person with one click. No Share ID and no password.",
    help_title: "How to start",
    help_1: "1. Press \"Copy invitation message\" below and send it to the other person by chat or e-mail.",
    help_2: "2. Paste the message you got from them into \"Add a contact\" and press Add. Ask them to do the same.",
    help_3: "3. Once you have both added each other, press \"Send files\" on their row and pick the files.",
    loading: "Loading...",
    daemon_down: "Miasma's background service is not running, so contacts are unavailable. Start it with the button at the top of the window.",
    push_unavailable: "Contacts are not available right now. Close Miasma and open it again. If that does not help, save the report in Settings and contact support.",
    old_daemon: "The background service does not answer contact requests. It is probably an older version. Close Miasma completely and start it again. If that does not help, update both the app and the background service.",
    retry_now: "Try again",
    my_card: "Send your contact to someone",
    my_code: "Your contact code",
    my_code_hint: "It is safe to show to others. It is not a password.",
    my_fp: "Your verification code",
    my_fp_hint: "Read this out to the other person, for example by phone, and ask them to compare it with the \"Verification code\" on their screen. If it differs, ask them to remove this contact.",
    copy_code: "Copy contact code",
    copy_invite: "Copy invitation message",
    copied: "Copied",
    show_qr: "Show QR code",
    hide_qr: "Hide QR code",
    qr_note: "Scan it with a phone camera to see the contact code as text, then send that text to your computer.",
    add_title: "Add a contact",
    add_hint: "Paste the message you got from the other person as it is. The contact code is found automatically.",
    add_paste: "Pasted message or contact code",
    add_label: "Name",
    add_label_hint: "A name you will recognise, e.g. Taro",
    add_button: "Add",
    add_busy: "Adding...",
    added_title: "Added {label}",
    added_compare: "Ask them to read out \"Your verification code\" and compare it with the code above. If it differs, remove this contact.",
    label_required: "Please type a name.",
    err_bad_code: "No Miasma contact code was found. Paste the whole message, or the line that starts with miasma-contact:.",
    err_this_is_me: "That is your own contact code. Paste the one you got from the other person.",
    err_already_exists: "This person is already in your contacts.",
    err_label_taken: "Another contact already has that name. Choose a different name.",
    err_bad_label: "The name is empty or too long. Use up to 64 characters.",
    err_unavailable: "Contacts are not available right now. Close Miasma and open it again.",
    err_too_many: "There are too many contacts. Remove one you no longer use first.",
    err_unknown_contact: "That contact no longer exists.",
    err_send_disabled: "Sending to this contact is turned off. Turn on \"Send files to this person\" first.",
    err_bad_file: "That file cannot be sent. Folders cannot be sent; choose a file.",
    err_queue_full: "Too many files are waiting. Wait for some to finish.",
    err_not_found: "That transfer is no longer running.",
    err_internal: "Something went wrong inside Miasma. Try again. If it keeps happening, check the log.",
    err_other: "Could not complete the request",
    list_title: "Your contacts",
    list_empty: "No contacts yet. Add one with \"Add a contact\" above.",
    chip_registered: "Registered",
    chip_not_registered: "They have not added you yet",
    hint_not_registered: "Your last file was refused. Ask them to add you in their Miasma > Contacts. Sending them your invitation message again helps.",
    allow_receive: "Receive files from this person",
    allow_send: "Send files to this person",
    max_size: "Max file size (GiB)",
    max_size_hint: "empty = no limit",
    max_size_invalid: "Type a number such as 2 or 0.5 (GiB), or leave it empty.",
    rename: "Rename",
    save: "Save",
    cancel: "Cancel",
    remove: "Remove",
    remove_title: "Remove this contact?",
    remove_body: "Transfers with \"{label}\" that are still running will be cancelled, and their partial files will be deleted. Files you already received stay in your inbox.",
    remove_confirm: "Remove",
    send_files: "Send files",
    pick_title: "Choose files to send",
    drop_hint: "Drop files here to send them",
    drop_folder: "Folders cannot be sent. Drop files, or zip the folder first.",
    drop_pick_contact: "Drop the files onto a contact's row so Miasma knows who should get them.",
    fingerprint: "Verification code",
    send_disabled_note: "Sending to this person is turned off.",
    tr_title: "File transfers",
    tr_empty: "No transfers yet.",
    dir_out: "Sending to",
    dir_in: "Receiving from",
    st_queued: "Waiting",
    st_preparing: "Preparing",
    st_connecting: "Connecting",
    st_sending: "Transferring",
    st_verifying: "Checking",
    st_done: "Done",
    st_failed: "Failed",
    st_rejected: "Refused",
    st_cancelled: "Cancelled",
    st_waiting: "Waiting to retry",
    btn_cancel: "Cancel",
    btn_try_now: "Try now",
    btn_retry: "Send again",
    btn_open_file: "Open file",
    btn_show_folder: "Show in folder",
    btn_clear_finished: "Clear finished",
    eta: "{t} left",
    rej_too_large: "They refused it: the file is larger than they accept.",
    rej_no_space: "They refused it: their computer does not have enough free disk space.",
    rej_not_allowed: "They have not added you yet. Ask them to add your contact code in Miasma > Contacts.",
    rej_busy: "They are busy with other transfers. Try again in a moment.",
    rej_bad_name: "They did not accept the file name. Rename the file and try again.",
    rej_bad_request: "They could not understand the request. The two Miasma versions may differ.",
    fail_unreachable: "Could not reach the other person. Check that their Miasma is running. If they are online, their network may be blocking direct connections.",
    fail_relay_down: "This computer is not connected to the relay, so the file cannot be sent yet. See Node Status.",
    fail_other: "The transfer failed",
    fail_lost_in: "The connection was interrupted. If the other person sends it again, it continues where it stopped.",
    fail_peer_cancelled: "The sender cancelled this transfer.",
    fail_source_changed: "The file was changed or replaced after it was queued, so it was not sent. Send it again.",
    wait_retry: "Waiting to retry (next attempt in {t}, attempt {n})",
    wait_offline: "Paused: the other side is offline.",
    wait_in_sec: "{n} s",
    wait_in_min: "{n} min",
    wait_in_hour: "{n} h",
    max_size_default_hint: "empty = default limit ({limit})",
    eta_sec: "00:00:{s2}",
    eta_min: "00:{m2}:{s2}",
    eta_min_even: "00:{m2}:{s2}",
    eta_hour: "{h2}:{m2}:{s2}",
    eta_hour_even: "{h2}:{m2}:{s2}",
    eta_day: "{d}d {h2}:{m2}:{s2}",
    inbox_title: "Received files",
    inbox_dir: "Saved in",
    open_folder: "Open folder",
    inbox_note: "Received files are never opened automatically.",
    arrival_toast: "{label} sent you \"{name}\"",
    queued_toast: "Queued {n} file(s) to send to {label}",
    nav_new: "new",
    dismiss: "Dismiss",
    qr_too_long: "The contact code is too long for a QR code.",
    sugg_title: "Someone not in your contacts tried to reach you",
    sugg_body: "Nothing was accepted. If you know who it is, you can add them. Compare the ID with them first.",
    sugg_item: "ID {id}, {when}",
    sugg_attempts: "{n} attempts",
    sugg_add: "Add as contact",
    sugg_ignore: "Ignore",
    sugg_prefill_note: "Added from a request. Sending and receiving stay off for this contact until you switch them on.",
    sugg_now: "just now",
    sugg_min: "{n} min ago",
    sugg_hour: "{n} h ago",
    open_missing: "The file is no longer there: {path}",
    open_failed: "Could not open it: {path} ({why})",
    saved_to: "Saved to: {path}",
    earlier_failed: "{n} earlier failed attempt(s)",
    earlier_show: "Show",
    earlier_hide: "Hide",
};

static CT_JA: ContactStrings = ContactStrings {
    tab: "連絡先",
    heading: "連絡先",
    desc: "お互いに一度登録すれば、ボタン一つでファイルを送れます。共有IDもパスワードも不要です。",
    help_title: "はじめかた",
    help_1: "1. 下の「招待メッセージをコピー」を押して、チャットやメールで相手に送ります。",
    help_2: "2. 相手から届いたメッセージを「連絡先を追加」に貼り付けて、「追加」を押します。相手にも同じようにしてもらいます。",
    help_3: "3. お互いに登録できたら、相手の行の「ファイルを送る」を押して、ファイルを選びます。",
    loading: "読み込み中です...",
    daemon_down: "Miasmaのバックグラウンド機能が止まっているため、連絡先を使えません。画面上部のボタンで起動してください。",
    push_unavailable: "連絡先はいま使えない状態です。Miasmaを閉じてから、もう一度開いてください。直らないときは、設定でレポートを保存して、サポートに送ってください。",
    old_daemon: "バックグラウンド機能が連絡先の要求に応答しません。古いバージョンかもしれません。Miasmaを完全に終了して、もう一度起動してください。直らないときは、アプリとバックグラウンド機能の両方を最新にしてください。",
    retry_now: "もう一度試す",
    my_card: "あなたの連絡先を相手に送る",
    my_code: "あなたの連絡先コード",
    my_code_hint: "人に見せても大丈夫です。パスワードではありません。",
    my_fp: "あなたの確認用コード",
    my_fp_hint: "相手に電話などで読み上げて、相手の画面の「確認用コード」と同じか見比べてもらってください。違っていたら、その連絡先を削除してもらってください。",
    copy_code: "連絡先コードをコピー",
    copy_invite: "招待メッセージをコピー",
    copied: "コピーしました",
    show_qr: "QRコードを表示",
    hide_qr: "QRコードを隠す",
    qr_note: "スマホのカメラで読み取ると、連絡先コードが文字で表示されます。その文字をパソコンに送って貼り付けてください。",
    add_title: "連絡先を追加",
    add_hint: "相手から届いたメッセージを、そのまま貼り付けてください。連絡先コードは自動で見つかります。",
    add_paste: "届いたメッセージ、または連絡先コード",
    add_label: "名前",
    add_label_hint: "覚えやすい名前（例: 田中さん）",
    add_button: "追加",
    add_busy: "追加しています...",
    added_title: "{label} を追加しました",
    added_compare: "相手に「あなたの確認用コード」を読み上げてもらい、上のコードと同じか見比べてください。違っていたら、この連絡先を削除してください。",
    label_required: "名前を入力してください。",
    err_bad_code: "Miasmaの連絡先コードが見つかりません。届いたメッセージ全体か、miasma-contact: で始まる行を貼り付けてください。",
    err_this_is_me: "これはあなた自身の連絡先コードです。相手から届いたものを貼り付けてください。",
    err_already_exists: "この相手は、もう登録されています。",
    err_label_taken: "その名前は、ほかの連絡先で使われています。別の名前にしてください。",
    err_bad_label: "名前が空か、長すぎます。64文字までにしてください。",
    err_unavailable: "連絡先はいま使えない状態です。Miasmaを閉じてから、もう一度開いてください。",
    err_too_many: "連絡先が多すぎます。使っていない連絡先を先に削除してください。",
    err_unknown_contact: "その連絡先は、もうありません。",
    err_send_disabled: "送信がオフです。「この人にファイルを送る」をオンにしてください。",
    err_bad_file: "このファイルは送れません。フォルダは送れないので、ファイルを選んでください。",
    err_queue_full: "送信待ちのファイルが多すぎます。いくつか終わるまで待ってください。",
    err_not_found: "その転送は、もう動いていません。",
    err_internal: "Miasmaの内部で問題が起きました。もう一度試してください。直らないときは、ログを確認してください。",
    err_other: "処理を完了できませんでした",
    list_title: "登録した連絡先",
    list_empty: "まだ連絡先がありません。上の「連絡先を追加」から登録してください。",
    chip_registered: "登録済み",
    chip_not_registered: "相手はまだあなたを登録していません",
    hint_not_registered: "直前のファイルは相手に断られました。相手のMiasmaで、あなたを連絡先に追加してもらってください。招待メッセージをもう一度送ると便利です。",
    allow_receive: "この人からファイルを受け取る",
    allow_send: "この人にファイルを送る",
    max_size: "最大ファイルサイズ（GiB）",
    max_size_hint: "空欄なら制限なし",
    max_size_invalid: "2 や 0.5 のような数字（GiB）を入れるか、空欄にしてください。",
    rename: "名前を変更",
    save: "保存",
    cancel: "キャンセル",
    remove: "削除",
    remove_title: "この連絡先を削除しますか？",
    remove_body: "「{label}」との転送のうち、実行中のものは中止され、途中までのファイルも削除されます。すでに受け取ったファイルは、受信フォルダに残ります。",
    remove_confirm: "削除する",
    send_files: "ファイルを送る",
    pick_title: "送るファイルを選んでください",
    drop_hint: "ファイルをここにドロップすると送れます",
    drop_folder: "フォルダは送れません。ファイルをドロップするか、フォルダをzipにまとめてから送ってください。",
    drop_pick_contact: "送る相手が分かるように、連絡先の行の上にファイルをドロップしてください。",
    fingerprint: "確認用コード",
    send_disabled_note: "この人には送らない設定です。",
    tr_title: "ファイルの転送",
    tr_empty: "転送はまだありません。",
    dir_out: "送り先",
    dir_in: "送り主",
    st_queued: "待機中",
    st_preparing: "準備中",
    st_connecting: "接続中",
    st_sending: "転送中",
    st_verifying: "確認中",
    st_done: "完了",
    st_failed: "失敗",
    st_rejected: "断られました",
    st_cancelled: "中止",
    st_waiting: "再試行待ち",
    btn_try_now: "今すぐ試す",
    btn_cancel: "中止",
    btn_retry: "もう一度送る",
    btn_open_file: "ファイルを開く",
    btn_show_folder: "フォルダで表示",
    btn_clear_finished: "終わったものを消す",
    eta: "あと {t}",
    rej_too_large: "相手に断られました。ファイルが、相手の受け取れるサイズより大きいです。",
    rej_no_space: "相手に断られました。相手のパソコンの空き容量が足りません。",
    rej_not_allowed: "相手はまだあなたを登録していません。相手のMiasmaで、あなたの連絡先コードを追加してもらってください。",
    rej_busy: "相手がほかの転送で手一杯です。少し待ってから、もう一度試してください。",
    rej_bad_name: "相手が、このファイル名を受け付けませんでした。ファイル名を変えて、もう一度試してください。",
    rej_bad_request: "相手が要求を理解できませんでした。お互いのMiasmaのバージョンが違うのかもしれません。",
    fail_unreachable: "相手に届きませんでした。相手のMiasmaが起動しているか確認してください。相手が起動しているのに届かないときは、ネットワークが直接の通信を止めているかもしれません。",
    fail_relay_down: "このコンピューターがリレーに接続できていないため、まだ送れません。「ノードステータス」を確認してください。",
    fail_other: "転送に失敗しました",
    fail_lost_in: "通信が途切れました。相手が再び送ると、続きから受け取れます。",
    fail_peer_cancelled: "相手が転送を中止しました。",
    fail_source_changed: "ファイルが、送信を予約したあとに変更または差し替えられたため、送りませんでした。もう一度送ってください。",
    wait_retry: "再試行待ち(次の試行は{t}後、{n}回目)",
    wait_offline: "一時停止中: 相手がオフラインです。",
    wait_in_sec: "{n} 秒",
    wait_in_min: "{n} 分",
    wait_in_hour: "{n} 時間",
    max_size_default_hint: "空欄 = 既定の上限（{limit}）",
    eta_sec: "{s} 秒",
    eta_min: "{m} 分 {s} 秒",
    eta_min_even: "{m} 分",
    eta_hour: "{h} 時間 {m} 分",
    eta_hour_even: "{h} 時間",
    eta_day: "{d} 日 {h} 時間",
    inbox_title: "受け取ったファイル",
    inbox_dir: "保存先",
    open_folder: "フォルダを開く",
    inbox_note: "受け取ったファイルが、自動で開かれることはありません。",
    arrival_toast: "{label} から「{name}」が届きました",
    queued_toast: "{n} 件のファイルを {label} への送信待ちにしました",
    nav_new: "新着",
    dismiss: "閉じる",
    qr_too_long: "連絡先コードが長すぎて、QRコードにできません。",
    sugg_title: "連絡先にない人があなたに接続しようとしました",
    sugg_body: "何も受け付けていません。心当たりがあれば連絡先に追加できます。追加する前に、相手とIDを確認してください。",
    sugg_item: "ID {id}、{when}",
    sugg_attempts: "{n}回",
    sugg_add: "連絡先に追加",
    sugg_ignore: "無視",
    sugg_prefill_note: "接続の履歴から追加します。この連絡先は、あなたが許可を入れるまで、送信も受信もオフです。",
    sugg_now: "たった今",
    sugg_min: "{n}分前",
    sugg_hour: "{n}時間前",
    open_missing: "ファイルが見つかりません。移動または削除された可能性があります: {path}",
    open_failed: "開けませんでした: {path} ({why})",
    saved_to: "保存先: {path}",
    earlier_failed: "以前の失敗 {n} 件",
    earlier_show: "表示",
    earlier_hide: "隠す",
};

// zh-CN
static CT_ZH_CN: ContactStrings = ContactStrings {
    tab: "联系人",
    heading: "联系人",
    desc: "互相添加一次联系人后，只需点一下就能向对方发送文件。不需要共享 ID，也不需要密码。",
    help_title: "开始使用",
    help_1: "1. 点击下方的“复制邀请消息”，通过聊天或邮件发给对方。",
    help_2: "2. 把对方发来的消息粘贴到“添加联系人”中，然后点击“添加”。也请对方同样操作。",
    help_3: "3. 双方都添加完成后，点击对方那一行的“发送文件”，选择要发送的文件。",
    loading: "正在加载...",
    daemon_down: "Miasma 的后台功能没有运行，因此无法使用联系人。请点击窗口上方的按钮启动它。",
    push_unavailable: "联系人功能暂时无法使用。请关闭 Miasma 后重新打开。若仍然无法解决，请在设置中保存报告并联系支持。",
    old_daemon: "后台功能没有响应联系人请求，可能是旧版本。请完全关闭 Miasma 后重新打开。若仍然无法解决，请将应用和后台功能都更新到最新版。",
    retry_now: "重试",
    my_card: "把你的联系人发给对方",
    my_code: "你的联系人代码",
    my_code_hint: "可以放心给别人看，它不是密码。",
    my_fp: "你的验证码",
    my_fp_hint: "请通过电话等方式把它念给对方，让对方与自己屏幕上的“验证码”核对。如果不一致，请让对方删除此联系人。",
    copy_code: "复制联系人代码",
    copy_invite: "复制邀请消息",
    copied: "已复制",
    show_qr: "显示二维码",
    hide_qr: "隐藏二维码",
    qr_note: "用手机相机扫描即可看到文字形式的联系人代码，再把这段文字发到电脑上。",
    add_title: "添加联系人",
    add_hint: "请把对方发来的消息原样粘贴进来，联系人代码会被自动找到。",
    add_paste: "粘贴的消息或联系人代码",
    add_label: "名称",
    add_label_hint: "起一个你能认出的名称，例如 小明",
    add_button: "添加",
    add_busy: "正在添加...",
    added_title: "已添加 {label}",
    added_compare: "请让对方念出“你的验证码”，并与上面的验证码核对。如果不一致，请删除此联系人。",
    label_required: "请输入名称。",
    err_bad_code: "没有找到 Miasma 联系人代码。请粘贴完整的消息，或以 miasma-contact: 开头的那一行。",
    err_this_is_me: "这是你自己的联系人代码。请粘贴从对方那里收到的代码。",
    err_already_exists: "此人已在你的联系人中。",
    err_label_taken: "已有其他联系人使用了这个名称。请换一个名称。",
    err_bad_label: "名称为空或太长。请使用不超过 64 个字符的名称。",
    err_unavailable: "联系人功能暂时无法使用。请关闭 Miasma 后重新打开。",
    err_too_many: "联系人太多了。请先删除一个不再使用的联系人。",
    err_unknown_contact: "该联系人已不存在。",
    err_send_disabled: "已关闭向此联系人发送。请先打开“向此人发送文件”。",
    err_bad_file: "无法发送该文件。文件夹不能发送，请选择文件。",
    err_queue_full: "等待发送的文件太多。请等一部分完成后再试。",
    err_not_found: "该传输已不再进行。",
    err_internal: "Miasma 内部出现问题。请重试。若仍然如此，请在设置中保存报告并联系支持。",
    err_other: "无法完成该请求",
    list_title: "你的联系人",
    list_empty: "还没有联系人。请使用上方的“添加联系人”添加。",
    chip_registered: "已登记",
    chip_not_registered: "对方还没有添加你",
    hint_not_registered: "你上一个文件被拒绝了。请让对方在 Miasma 的“联系人”中添加你。再次发送邀请消息会有帮助。",
    allow_receive: "接收此人发来的文件",
    allow_send: "向此人发送文件",
    max_size: "文件大小上限 (GiB)",
    max_size_hint: "留空 = 不限制",
    max_size_invalid: "请输入 2 或 0.5 这样的数字 (GiB)，或留空。",
    rename: "重命名",
    save: "保存",
    cancel: "取消",
    remove: "删除",
    remove_title: "删除此联系人？",
    remove_body: "与“{label}”正在进行的传输将被取消，未完成的文件会被删除。已经收到的文件仍保留在收件箱中。",
    remove_confirm: "删除",
    send_files: "发送文件",
    pick_title: "选择要发送的文件",
    drop_hint: "把文件拖到这里即可发送",
    drop_folder: "不能发送文件夹。请拖入文件，或先把文件夹压缩。",
    drop_pick_contact: "请把文件拖到某个联系人那一行上，这样 Miasma 才知道发给谁。",
    fingerprint: "验证码",
    send_disabled_note: "已关闭向此人发送。",
    tr_title: "文件传输",
    tr_empty: "还没有传输。",
    dir_out: "发送给",
    dir_in: "接收自",
    st_queued: "等待中",
    st_preparing: "准备中",
    st_connecting: "连接中",
    st_sending: "传输中",
    st_verifying: "检查中",
    st_done: "完成",
    st_failed: "失败",
    st_rejected: "被拒绝",
    st_cancelled: "已取消",
    st_waiting: "等待重试",
    btn_try_now: "立即重试",
    btn_cancel: "取消",
    btn_retry: "重新发送",
    btn_open_file: "打开文件",
    btn_show_folder: "在文件夹中显示",
    btn_clear_finished: "清除已完成",
    eta: "还剩 {t}",
    rej_too_large: "对方拒绝了：文件超过了对方接受的大小。",
    rej_no_space: "对方拒绝了：对方电脑的可用磁盘空间不足。",
    rej_not_allowed: "对方还没有添加你。请让对方在 Miasma 的“联系人”中添加你的联系人代码。",
    rej_busy: "对方正忙于其他传输。请稍后再试。",
    rej_bad_name: "对方不接受这个文件名。请重命名文件后重试。",
    rej_bad_request: "对方无法理解该请求。双方的 Miasma 版本可能不同。",
    fail_unreachable: "无法连接到对方。请确认对方的 Miasma 正在运行。如果对方在线仍无法连接，可能是网络阻止了直接连接。",
    fail_relay_down: "本机未连接到中继服务器，暂时无法发送。请查看“节点状态”。",
    fail_other: "传输失败",
    fail_lost_in: "连接中断了。如果对方重新发送，会从中断处继续。",
    fail_peer_cancelled: "发送方取消了此传输。",
    fail_source_changed: "文件在加入队列后被修改或替换，因此未发送。请重新发送。",
    wait_retry: "等待重试（{t}后进行下一次尝试，第 {n} 次）",
    wait_offline: "已暂停：对方不在线。",
    wait_in_sec: "{n} 秒",
    wait_in_min: "{n} 分钟",
    wait_in_hour: "{n} 小时",
    max_size_default_hint: "留空 = 默认上限 ({limit})",
    eta_sec: "00:00:{s2}",
    eta_min: "00:{m2}:{s2}",
    eta_min_even: "00:{m2}:{s2}",
    eta_hour: "{h2}:{m2}:{s2}",
    eta_hour_even: "{h2}:{m2}:{s2}",
    eta_day: "{d}d {h2}:{m2}:{s2}",
    inbox_title: "收到的文件",
    inbox_dir: "保存位置",
    open_folder: "打开文件夹",
    inbox_note: "收到的文件不会被自动打开。",
    arrival_toast: "{label} 向你发送了“{name}”",
    queued_toast: "已将 {n} 个文件加入发送给 {label} 的队列",
    nav_new: "新",
    dismiss: "关闭",
    qr_too_long: "内容太长，无法生成二维码。",
    sugg_title: "联系人以外的人尝试联系了你",
    sugg_body: "没有接受任何内容。如果你认识对方，可以添加。添加前请先与对方核对ID。",
    sugg_item: "ID {id}，{when}",
    sugg_attempts: "{n}次",
    sugg_add: "添加为联系人",
    sugg_ignore: "忽略",
    sugg_prefill_note: "由联系请求添加。在你打开权限之前，此联系人的发送和接收均保持关闭。",
    sugg_now: "刚刚",
    sugg_min: "{n}分钟前",
    sugg_hour: "{n}小时前",
    open_missing: "找不到该文件，可能已被移动或删除：{path}",
    open_failed: "无法打开：{path}（{why}）",
    saved_to: "保存位置：{path}",
    earlier_failed: "此前失败 {n} 次",
    earlier_show: "显示",
    earlier_hide: "隐藏",
};

// ─── Chat (one-to-one messages between registered contacts) ─────────────────

/// Declares `ChatStrings` and a field listing for the completeness test from one field list.
macro_rules! chat_strings {
    ($($f:ident),* $(,)?) => {
        /// Strings of the Chat area (`chat.rs`). `{name}`-style holes are filled with
        /// `transfers::fill`.
        pub struct ChatStrings { $(pub $f: &'static str),* }
        impl ChatStrings {
            /// Every field with its name, for the completeness test.
            #[cfg(test)]
            fn all(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}

chat_strings! {
    tab, heading, desc, loading, daemon_down, unavailable, old_daemon, retry_now,
    list_title, list_empty, list_empty_no_contacts, open_contacts, new_chat,
    pick_title, pick_none, pick_send_off, pick_close,
    preview_you, preview_file, time_today, time_yesterday, time_date,
    back, empty_thread, composer_hint, composer_keys, send, send_empty_hint,
    counter_chars, counter_near, counter_over, too_long_note,
    state_sending, state_queued, state_delivered, state_failed, retry, queued_note, queued_note_relay,
    fail_not_allowed, fail_too_big, fail_rejected, fail_unsupported, fail_contact_removed,
    fail_send_disabled, fail_expired, fail_session, fail_other,
    delete_history, delete_title, delete_body, delete_confirm, delete_cancel, delete_done,
    memory_only, send_file, send_file_hint, send_off_note, loading_older, jump_latest,
    err_empty, err_too_big, err_outbox_full, err_send_disabled, err_unknown_contact,
    err_internal, err_other,
    a11y_conversations, a11y_messages, a11y_composer, a11y_send, a11y_attach, a11y_back,
    a11y_row, a11y_unread, nav_new, dismiss,
    state_read, receipts_on, receipts_off, receipts_hint, receipts_global_off, a11y_receipts,
    system_label, file_waiting, file_sending, file_done, file_failed,
}

pub fn chat_strings(locale: Locale) -> &'static ChatStrings {
    match locale {
        Locale::En => &CH_EN,
        Locale::Ja => &CH_JA,
        Locale::ZhCn => &CH_ZH_CN,
    }
}

static CH_EN: ChatStrings = ChatStrings {
    tab: "Chat",
    heading: "Chat",
    desc: "Send short text messages to the contacts you have added. To send a file, use \"Send a file\".",
    loading: "Loading...",
    daemon_down: "Miasma's background service is not running, so chat is unavailable. Start it with the button at the top of the window.",
    unavailable: "Chat is not available right now. Check that contacts work, then restart Miasma.",
    old_daemon: "The background service does not answer chat requests. It is probably an older version. Close Miasma completely and start it again. If that does not help, update both the app and the background service.",
    retry_now: "Try again",
    list_title: "Conversations",
    list_empty: "No conversations yet. Press \"New conversation\", choose a contact and send the first message.",
    list_empty_no_contacts: "You have no contacts yet. Add a contact on the Contacts tab, and you can send messages here.",
    open_contacts: "Open Contacts",
    new_chat: "New conversation",
    pick_title: "Choose a contact",
    pick_none: "No contacts yet. Add a contact on the Contacts tab first.",
    pick_send_off: "Sending to this contact is switched off.",
    pick_close: "Close",
    preview_you: "You: {text}",
    preview_file: "File: {name}",
    time_today: "Today {time}",
    time_yesterday: "Yesterday",
    time_date: "{m}/{d}",
    back: "Back to conversations",
    empty_thread: "No messages yet. Send the first one.",
    composer_hint: "Type a message",
    composer_keys: "Enter sends, Shift+Enter starts a new line.",
    send: "Send",
    send_empty_hint: "Type a message to send it.",
    counter_chars: "{n} characters",
    counter_near: "About {n} characters left",
    counter_over: "About {n} characters too long",
    too_long_note: "The message is too long. Shorten it, then send.",
    state_sending: "Sending",
    state_queued: "Sent. Waiting for them to receive it.",
    state_delivered: "Delivered",
    state_failed: "Could not send",
    retry: "Send again",
    queued_note: "It will arrive when the other person is online.",
    queued_note_relay: "This computer is not connected to the relay, so this cannot go out yet. See Node Status.",
    fail_not_allowed: "They have not added you yet. Ask them to add your contact code in their Miasma.",
    fail_too_big: "The message was too long for the other side.",
    fail_rejected: "The other side did not accept the message.",
    fail_unsupported: "The other person's Miasma is too old for chat. Ask them to update it.",
    fail_contact_removed: "The contact was removed, so the message was not sent.",
    fail_send_disabled: "Sending to this contact is switched off.",
    fail_expired: "It could not be delivered in time.",
    fail_session: "A secure connection could not be set up. Check the contact's verification code with them.",
    fail_other: "It could not be sent.",
    delete_history: "Delete this conversation's history",
    delete_title: "Delete the history of this conversation?",
    delete_body: "All messages with {name} will be deleted from this device only. This cannot be undone. The other person keeps their own copy.",
    delete_confirm: "Delete",
    delete_cancel: "Cancel",
    delete_done: "Deleted the history with {name}",
    memory_only: "This device does not keep chat history. Conversations are cleared when you close Miasma.",
    send_file: "Send a file",
    send_file_hint: "Pick files to send, as on the Contacts tab. You can follow them there.",
    send_off_note: "Sending to this contact is switched off, so messages cannot be sent. You can switch it on in Contacts.",
    loading_older: "Loading older messages...",
    jump_latest: "Go to the newest messages",
    err_empty: "Please type a message.",
    err_too_big: "The message is too long. Shorten it, then send.",
    err_outbox_full: "Too many messages are waiting to be delivered. Wait until the other person is online.",
    err_send_disabled: "Sending to this contact is switched off. You can switch it on in Contacts.",
    err_unknown_contact: "That contact no longer exists.",
    err_internal: "Something went wrong inside Miasma. Try again. If it keeps happening, check the logs.",
    err_other: "The request could not be completed. Try again.",
    a11y_conversations: "Conversations",
    a11y_messages: "Messages",
    a11y_composer: "Message input",
    a11y_send: "Send message",
    a11y_attach: "Choose a file to send",
    a11y_back: "Back to conversations",
    a11y_row: "Conversation with {name}",
    a11y_unread: "{n} unread",
    nav_new: "new",
    dismiss: "Dismiss",
    state_read: "Read",
    receipts_on: "Read receipts: on",
    receipts_off: "Read receipts: off",
    receipts_hint: "When on, this contact sees that you have read their messages, and you see when they have read yours. It works only when both of you have it on. Press to switch.",
    receipts_global_off: "Read receipts are switched off for everyone in the settings, so none are sent or shown.",
    a11y_receipts: "Switch read receipts for this contact",
    system_label: "Status",
    file_waiting: "Waiting to send: {name}",
    file_sending: "Sending: {name} ({pct}%)",
    file_done: "File sent: {name}",
    file_failed: "File not sent: {name}",
};

static CH_JA: ChatStrings = ChatStrings {
    tab: "チャット",
    heading: "チャット",
    desc: "登録した連絡先と、短い文字のメッセージをやり取りできます。ファイルは「ファイルを送る」から送れます。",
    loading: "読み込み中です...",
    daemon_down: "Miasmaのバックグラウンド機能が止まっているため、チャットを使えません。画面上部のボタンで起動してください。",
    unavailable: "チャットは、いまは使えない状態です。連絡先が使えるか確認して、Miasmaを再起動してください。",
    old_daemon: "バックグラウンド機能がチャットに応答しません。古いバージョンかもしれません。Miasmaを完全に終了して、もう一度起動してください。直らないときは、アプリとバックグラウンド機能の両方を最新にしてください。",
    retry_now: "もう一度試す",
    list_title: "会話",
    list_empty: "まだ会話がありません。「新しい会話」を押して相手を選び、最初のメッセージを送ってみましょう。",
    list_empty_no_contacts: "まだ連絡先がありません。「連絡先」タブで相手を登録すると、ここでメッセージを送れます。",
    open_contacts: "連絡先を開く",
    new_chat: "新しい会話",
    pick_title: "会話する相手を選ぶ",
    pick_none: "登録した連絡先がありません。先に「連絡先」タブで相手を登録してください。",
    pick_send_off: "この人には送らない設定です。",
    pick_close: "閉じる",
    preview_you: "あなた: {text}",
    preview_file: "ファイル: {name}",
    time_today: "今日 {time}",
    time_yesterday: "昨日",
    time_date: "{m}月{d}日",
    back: "会話一覧に戻る",
    empty_thread: "まだメッセージはありません。最初のひとことを送ってみましょう。",
    composer_hint: "メッセージを入力",
    composer_keys: "Enterで送信、Shift+Enterで改行します。",
    send: "送信",
    send_empty_hint: "メッセージを入力すると送信できます。",
    counter_chars: "{n} 文字",
    counter_near: "あと約 {n} 文字",
    counter_over: "約 {n} 文字、長すぎます",
    too_long_note: "メッセージが長すぎます。短くしてから送ってください。",
    state_sending: "送信中",
    state_queued: "送信済み（相手に届くのを待っています）",
    state_delivered: "届きました",
    state_failed: "送信に失敗しました",
    retry: "もう一度送る",
    queued_note: "相手がオンラインになると届きます。",
    queued_note_relay: "このコンピューターがリレーに接続できていないため、まだ送れません。「ノードステータス」を確認してください。",
    fail_not_allowed: "相手はまだあなたを登録していません。相手のMiasmaで、あなたの連絡先コードを追加してもらってください。",
    fail_too_big: "メッセージが長すぎて、相手が受け取れませんでした。",
    fail_rejected: "相手がメッセージを受け付けませんでした。",
    fail_unsupported: "相手のMiasmaが古く、チャットに対応していません。更新してもらってください。",
    fail_contact_removed: "連絡先を削除したため、送れませんでした。",
    fail_send_disabled: "この人には送らない設定のため、送れませんでした。",
    fail_expired: "届けられないまま、時間が過ぎました。",
    fail_session: "安全な接続を作れませんでした。相手と確認用コードを見比べてください。",
    fail_other: "送れませんでした。",
    delete_history: "この会話の履歴を削除",
    delete_title: "この会話の履歴を削除しますか？",
    delete_body: "{name} との会話の履歴を、この端末からすべて削除します。元に戻せません。相手の端末の履歴は消えません。",
    delete_confirm: "削除する",
    delete_cancel: "キャンセル",
    delete_done: "{name} との会話の履歴を削除しました",
    memory_only: "この端末には履歴を残しません。Miasmaを閉じると会話は消えます。",
    send_file: "ファイルを送る",
    send_file_hint: "連絡先タブと同じように、ファイルを選んで送れます。送った結果は連絡先タブで見られます。",
    send_off_note: "この人には送らない設定のため、メッセージを送れません。「連絡先」タブでオンにできます。",
    loading_older: "古いメッセージを読み込んでいます...",
    jump_latest: "最新のメッセージへ",
    err_empty: "メッセージを入力してください。",
    err_too_big: "メッセージが長すぎます。短くしてから送ってください。",
    err_outbox_full: "送信待ちのメッセージが多すぎます。相手がオンラインになるまでお待ちください。",
    err_send_disabled: "この人には送らない設定です。「連絡先」タブでオンにしてください。",
    err_unknown_contact: "その連絡先は、もうありません。",
    err_internal: "Miasmaの内部で問題が起きました。もう一度試してください。直らないときは、ログを確認してください。",
    err_other: "処理を完了できませんでした。もう一度試してください。",
    a11y_conversations: "会話の一覧",
    a11y_messages: "メッセージの一覧",
    a11y_composer: "メッセージを入力",
    a11y_send: "メッセージを送信",
    a11y_attach: "ファイルを選んで送る",
    a11y_back: "会話一覧に戻る",
    a11y_row: "{name} との会話",
    a11y_unread: "{n}件の未読",
    nav_new: "新着",
    dismiss: "閉じる",
    state_read: "既読",
    receipts_on: "既読表示: オン",
    receipts_off: "既読表示: オフ",
    receipts_hint: "オンにすると、あなたがメッセージを読んだことが相手に伝わり、相手が読んだこともあなたに表示されます。お互いにオンのときだけ働きます。押すと切り替わります。",
    receipts_global_off: "設定で、すべての相手への既読表示がオフになっています。既読は送られず、表示もされません。",
    a11y_receipts: "この人との既読表示を切り替える",
    system_label: "状況",
    file_waiting: "送信待ち: {name}",
    file_sending: "送信中: {name} ({pct}%)",
    file_done: "ファイルを送りました: {name}",
    file_failed: "ファイルを送れませんでした: {name}",
};

// zh-CN: a first translation; to be reviewed by a native speaker before it is called finished.
static CH_ZH_CN: ChatStrings = ChatStrings {
    tab: "聊天",
    heading: "聊天",
    desc: "可以与已添加的联系人互发简短的文字消息。发送文件请使用“发送文件”。",
    loading: "加载中...",
    daemon_down: "Miasma 的后台服务未运行，无法使用聊天。请点击窗口顶部的按钮启动。",
    unavailable: "聊天目前不可用。请确认联系人功能正常，然后重启 Miasma。",
    old_daemon: "后台服务不响应聊天请求，可能是旧版本。请完全退出 Miasma 后重新启动。若仍不行，请将应用和后台服务都更新到最新版本。",
    retry_now: "重试",
    list_title: "会话",
    list_empty: "还没有会话。点击“新会话”，选择联系人并发送第一条消息。",
    list_empty_no_contacts: "还没有联系人。在“联系人”页添加联系人后，即可在这里发消息。",
    open_contacts: "打开联系人",
    new_chat: "新会话",
    pick_title: "选择联系人",
    pick_none: "还没有联系人。请先在“联系人”页添加。",
    pick_send_off: "已关闭向此联系人发送。",
    pick_close: "关闭",
    preview_you: "你: {text}",
    preview_file: "文件：{name}",
    time_today: "今天 {time}",
    time_yesterday: "昨天",
    time_date: "{m}月{d}日",
    back: "返回会话列表",
    empty_thread: "还没有消息。发送第一条吧。",
    composer_hint: "输入消息",
    composer_keys: "按 Enter 发送，按 Shift+Enter 换行。",
    send: "发送",
    send_empty_hint: "输入消息后即可发送。",
    counter_chars: "{n} 个字",
    counter_near: "还可输入约 {n} 个字",
    counter_over: "约超出 {n} 个字",
    too_long_note: "消息太长。请缩短后再发送。",
    state_sending: "发送中",
    state_queued: "已发送（等待对方接收）",
    state_delivered: "已送达",
    state_failed: "发送失败",
    retry: "重新发送",
    queued_note: "对方上线后即可收到。",
    queued_note_relay: "本机未连接到中继服务器，暂时无法发出。请查看“节点状态”。",
    fail_not_allowed: "对方还没有添加你。请让对方在其 Miasma 中添加你的联系人码。",
    fail_too_big: "消息太长，对方无法接收。",
    fail_rejected: "对方没有接受这条消息。",
    fail_unsupported: "对方的 Miasma 版本过旧，不支持聊天。请让对方更新。",
    fail_contact_removed: "联系人已删除，消息未发送。",
    fail_send_disabled: "已关闭向此联系人发送，消息未发送。",
    fail_expired: "一直未能送达，已超时。",
    fail_session: "无法建立安全连接。请与对方核对确认用码。",
    fail_other: "无法发送。",
    delete_history: "删除此会话的记录",
    delete_title: "删除此会话的记录？",
    delete_body: "将从本设备删除与 {name} 的全部消息。无法恢复。对方设备上的记录仍会保留。",
    delete_confirm: "删除",
    delete_cancel: "取消",
    delete_done: "已删除与 {name} 的记录",
    memory_only: "本设备不保存聊天记录。关闭 Miasma 后会话将被清除。",
    send_file: "发送文件",
    send_file_hint: "与联系人页相同，可选择文件发送，并可在联系人页查看进度。",
    send_off_note: "已关闭向此联系人发送，无法发消息。可在“联系人”页重新开启。",
    loading_older: "正在加载更早的消息...",
    jump_latest: "回到最新消息",
    err_empty: "请输入消息内容。",
    err_too_big: "消息太长。请缩短后再发送。",
    err_outbox_full: "待发送的消息过多。请等对方上线后再试。",
    err_send_disabled: "已关闭向此联系人发送。可在“联系人”页重新开启。",
    err_unknown_contact: "该联系人已不存在。",
    err_internal: "Miasma 内部出现问题。请重试；若仍然如此，请查看日志。",
    err_other: "无法完成操作，请重试。",
    a11y_conversations: "会话列表",
    a11y_messages: "消息列表",
    a11y_composer: "消息输入框",
    a11y_send: "发送消息",
    a11y_attach: "选择要发送的文件",
    a11y_back: "返回会话列表",
    a11y_row: "与 {name} 的会话",
    a11y_unread: "{n} 条未读",
    nav_new: "新消息",
    dismiss: "关闭",
    state_read: "已读",
    receipts_on: "已读回执：开",
    receipts_off: "已读回执：关",
    receipts_hint: "开启后，对方会看到你已读其消息，你也会看到对方已读你的消息。只有双方都开启时才会生效。点击可切换。",
    receipts_global_off: "已在设置中对所有人关闭已读回执，因此不会发送也不会显示。",
    a11y_receipts: "切换与此联系人的已读回执",
    system_label: "状态",
    file_waiting: "等待发送：{name}",
    file_sending: "正在发送：{name}（{pct}%）",
    file_done: "文件已发送：{name}",
    file_failed: "文件未能发送：{name}",
};

// ─── Logs (memory-only logging, opt-in diagnostic logging) ──────────────────

/// Declares `LogStrings` and a field listing for the completeness test from one field list.
macro_rules! log_strings {
    ($($f:ident),* $(,)?) => {
        /// Strings of the Logs section in Settings, the diagnostic-logging banner and the
        /// old-log-files notice.
        pub struct LogStrings { $(pub $f: &'static str),* }
        impl LogStrings {
            /// Every field with its name, for the completeness test.
            #[cfg(test)]
            fn all(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}

log_strings! {
    heading, memory_only, diag_label, diag_warning, diag_banner, diag_save_failed,
    show_logs, hide_logs, refresh, copy, copied, clear, memory_note,
    daemon_title, desktop_title, empty, unsupported, unavailable,
    legacy_title, legacy_body, legacy_delete, legacy_keep, legacy_deleted, legacy_failed,
}

pub fn log_strings(locale: Locale) -> &'static LogStrings {
    match locale {
        Locale::En => &LG_EN,
        Locale::Ja => &LG_JA,
        Locale::ZhCn => &LG_ZH_CN,
    }
}

static LG_EN: LogStrings = LogStrings {
    heading: "Logs",
    memory_only: "memory only (nothing is written to disk)",
    diag_label: "Diagnostic logging",
    diag_warning: "Turning on diagnostic logging leaves a record of your use in files. Some times and details about the other party are kept on this computer, so turn it on only while investigating a problem and always turn it off afterwards (the files are deleted when you turn it off).",
    diag_banner: "Diagnostic logging is on. A record of your use is being written to files on this computer. Turn it off in Settings when you are done.",
    diag_save_failed: "The setting could not be saved. Please try again.",
    show_logs: "Show logs",
    hide_logs: "Hide logs",
    refresh: "Refresh",
    copy: "Copy",
    copied: "Logs copied to the clipboard.",
    clear: "Clear",
    memory_note: "These lines are kept only in memory and disappear when Miasma closes.",
    daemon_title: "Background service",
    desktop_title: "This window",
    empty: "(no lines)",
    unsupported: "not supported by this older background service",
    unavailable: "background service not running",
    legacy_title: "Old log files were found",
    legacy_body: "Miasma no longer writes logs to files. Old log files were found on this computer. They show when Miasma was used. You can delete them securely now, or keep them.",
    legacy_delete: "Delete now",
    legacy_keep: "Keep",
    legacy_deleted: "Old log files deleted: {n}",
    legacy_failed: "Could not delete {n} file(s). Close other programs that use them and try again from the next start.",
};

static LG_JA: LogStrings = LogStrings {
    heading: "ログ",
    memory_only: "メモリ上のみ(ディスクには何も書き込まれません)",
    diag_label: "診断ログ",
    diag_warning: "診断ログを有効にすると、使った記録がファイルに残ります。使った日時や相手の情報の一部がパソコンに残るため、不具合を調べるときだけ有効にし、終わったら必ず無効にしてください(無効にするとファイルは削除されます)。",
    diag_banner: "診断ログが有効です。使った記録がこのパソコンのファイルに書き込まれています。確認が終わったら、設定で無効にしてください。",
    diag_save_failed: "設定を保存できませんでした。もう一度お試しください。",
    show_logs: "ログを表示",
    hide_logs: "ログを隠す",
    refresh: "更新",
    copy: "コピー",
    copied: "ログをクリップボードにコピーしました。",
    clear: "消去",
    memory_note: "これらの行はメモリ上にだけあり、Miasma を閉じると消えます。",
    daemon_title: "バックグラウンドサービス",
    desktop_title: "このウィンドウ",
    empty: "(行がありません)",
    unsupported: "古いバックグラウンドサービスのため、対応していません",
    unavailable: "バックグラウンドサービスが起動していません",
    legacy_title: "古いログファイルが見つかりました",
    legacy_body: "Miasma はログをファイルに書き込まなくなりました。このパソコンに古いログファイルが見つかりました。ログファイルには、Miasma を使った日時が残っています。今すぐ安全に削除するか、そのまま残すかを選んでください。",
    legacy_delete: "今すぐ削除",
    legacy_keep: "残す",
    legacy_deleted: "古いログファイルを削除しました: {n} 件",
    legacy_failed: "{n} 件を削除できませんでした。使用中のほかのプログラムを閉じて、次回の起動時にもう一度お試しください。",
};

static LG_ZH_CN: LogStrings = LogStrings {
    heading: "日志",
    memory_only: "仅在内存中（不会向磁盘写入任何内容）",
    diag_label: "诊断日志",
    diag_warning: "启用诊断日志后，您的使用记录会保存在文件中。使用时间和对方信息的一部分会留在这台电脑上，因此请仅在排查问题时启用，并在结束后务必关闭（关闭后文件会被删除）。",
    diag_banner: "诊断日志已启用。您的使用记录正在写入这台电脑上的文件。完成后请在“设置”中关闭。",
    diag_save_failed: "无法保存该设置。请重试。",
    show_logs: "显示日志",
    hide_logs: "隐藏日志",
    refresh: "刷新",
    copy: "复制",
    copied: "日志已复制到剪贴板。",
    clear: "清除",
    memory_note: "这些行仅保存在内存中，关闭 Miasma 后即消失。",
    daemon_title: "后台服务",
    desktop_title: "此窗口",
    empty: "（没有内容）",
    unsupported: "此较旧的后台服务不支持",
    unavailable: "后台服务未运行",
    legacy_title: "发现旧的日志文件",
    legacy_body: "Miasma 不再将日志写入文件。在这台电脑上发现了旧的日志文件，其中记录了使用 Miasma 的时间。您可以现在安全删除，也可以保留。",
    legacy_delete: "立即删除",
    legacy_keep: "保留",
    legacy_deleted: "已删除旧日志文件：{n} 个",
    legacy_failed: "有 {n} 个文件无法删除。请关闭正在使用它们的其他程序，下次启动时再试。",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_log_string_exists_in_every_locale() {
        for lang in Locale::ALL {
            for (name, value) in log_strings(lang).all() {
                assert!(!value.trim().is_empty(), "{lang:?} logs.{name} is empty");
            }
            let l = log_strings(lang);
            assert!(l.legacy_deleted.contains("{n}"), "{lang:?}");
            assert!(l.legacy_failed.contains("{n}"), "{lang:?}");
        }
        assert!(log_strings(Locale::Ja)
            .diag_warning
            .starts_with("診断ログを有効にすると、使った記録がファイルに残ります。"));
    }

    #[test]
    fn every_contact_string_exists_in_every_locale() {
        for lang in Locale::ALL {
            for (name, value) in contact_strings(lang).all() {
                assert!(
                    !value.trim().is_empty(),
                    "{lang:?} contacts.{name} is empty"
                );
            }
        }
    }

    #[test]
    fn every_chat_string_exists_in_every_locale() {
        for lang in Locale::ALL {
            for (name, value) in chat_strings(lang).all() {
                assert!(!value.trim().is_empty(), "{lang:?} chat.{name} is empty");
            }
        }
    }

    #[test]
    fn japanese_chat_texts_use_the_words_of_the_contacts_tab() {
        let ja = chat_strings(Locale::Ja);
        for (name, value) in ja.all() {
            for bad in [
                "指紋",
                "カード",
                "デーモン",
                "iroh",
                "フィンガープリント",
                "ratchet",
                "mailbox",
                "DHT",
            ] {
                assert!(!value.contains(bad), "ja chat.{name} says {bad}");
            }
        }
        // The same words as the Contacts tab for the same things.
        let ct = contact_strings(Locale::Ja);
        assert_eq!(ja.send_file, ct.send_files);
        assert!(ja.daemon_down.contains("バックグラウンド機能"));
        assert!(ja.fail_session.contains("確認用コード"));
        assert!(ja.fail_not_allowed.contains("連絡先コード"));
        // The states the owner asked for, word for word.
        assert_eq!(ja.state_sending, "送信中");
        assert_eq!(ja.state_queued, "送信済み（相手に届くのを待っています）");
        assert_eq!(ja.state_delivered, "届きました");
        assert_eq!(ja.state_read, "既読");
        assert_eq!(ja.state_failed, "送信に失敗しました");
        assert_eq!(ja.retry, "もう一度送る");
        assert_eq!(
            ja.memory_only.split('。').next(),
            Some("この端末には履歴を残しません")
        );
        assert_eq!(ja.time_yesterday, "昨日");
    }

    #[test]
    fn chat_placeholders_survive_translation() {
        for lang in Locale::ALL {
            let c = chat_strings(lang);
            assert!(c.preview_you.contains("{text}"), "{lang:?}");
            assert!(c.preview_file.contains("{name}"), "{lang:?}");
            assert!(c.time_today.contains("{time}"), "{lang:?}");
            assert!(
                c.time_date.contains("{m}") && c.time_date.contains("{d}"),
                "{lang:?}"
            );
            assert!(c.delete_body.contains("{name}"), "{lang:?}");
            assert!(c.delete_done.contains("{name}"), "{lang:?}");
            assert!(c.a11y_row.contains("{name}"), "{lang:?}");
            assert!(c.a11y_unread.contains("{n}"), "{lang:?}");
            assert!(c.counter_chars.contains("{n}"), "{lang:?}");
            assert!(c.counter_near.contains("{n}"), "{lang:?}");
            assert!(c.counter_over.contains("{n}"), "{lang:?}");
        }
    }

    #[test]
    fn japanese_contact_texts_avoid_literal_translation_words() {
        // The owner rejected the literal "指紋" (fingerprint) and "カード" (card): the short
        // identifier is the "確認用コード", the long one the "連絡先コード".
        let ja = contact_strings(Locale::Ja);
        for (name, value) in ja.all() {
            assert!(!value.trim().is_empty(), "ja contacts.{name} is empty");
            assert!(!value.contains("指紋"), "ja contacts.{name} says 指紋");
            assert!(!value.contains("カード"), "ja contacts.{name} says カード");
            assert!(!value.contains("フィンガープリント"), "ja contacts.{name}");
        }
        assert_eq!(ja.fingerprint, "確認用コード");
        assert_eq!(ja.my_fp, "あなたの確認用コード");
        assert_eq!(ja.my_code, "あなたの連絡先コード");
    }

    #[test]
    fn contact_placeholders_and_owner_sentences_survive_translation() {
        for lang in Locale::ALL {
            let c = contact_strings(lang);
            assert!(c.added_title.contains("{label}"), "{lang:?}");
            assert!(c.remove_body.contains("{label}"), "{lang:?}");
            assert!(c.arrival_toast.contains("{label}") && c.arrival_toast.contains("{name}"));
            assert!(c.queued_toast.contains("{label}") && c.queued_toast.contains("{n}"));
            assert!(c.eta.contains("{t}"), "{lang:?} eta lost {{t}}");
            assert!(
                c.max_size_default_hint.contains("{limit}"),
                "{lang:?} max_size_default_hint lost {{limit}}"
            );
        }
        // Owner requirement: no online-only / future-plan sentence anywhere; the unreachable
        // error still tells the person to check that the other Miasma is running.
        for lang in Locale::ALL {
            for (name, v) in contact_strings(lang).all() {
                assert!(
                    !v.contains("預かり") && !v.contains("store-and-forward"),
                    "{name}"
                );
                assert!(
                    !v.contains("不在") && !v.contains("while they are away"),
                    "{name}"
                );
            }
        }
        let ja = contact_strings(Locale::Ja);
        assert!(ja
            .fail_unreachable
            .contains("相手のMiasmaが起動しているか確認してください"));
        let en = contact_strings(Locale::En);
        assert!(en.fail_unreachable.contains("their Miasma is running"));
    }

    #[test]
    fn every_transfer_string_exists_in_every_locale() {
        for lang in Locale::ALL {
            let t = transfer_strings(lang);
            for (name, value) in t.all() {
                assert!(
                    !value.trim().is_empty(),
                    "{lang:?} transfers.{name} is empty"
                );
            }
        }
    }

    #[test]
    fn transfer_placeholders_survive_translation() {
        // A translation that drops a placeholder would silently show a blank in the UI.
        type Getter = fn(&TransferStrings) -> &'static str;
        let need: [(&str, Getter, &[&str]); 9] = [
            ("strip_resumed", |t| t.strip_resumed, &["{n}"]),
            ("strip_per_cell", |t| t.strip_per_cell, &["{n}"]),
            ("split_recv", |t| t.split_recv, &["{a}", "{b}", "{c}"]),
            ("split_send", |t| t.split_send, &["{a}", "{b}", "{c}"]),
            ("pieces_fmt", |t| t.pieces_fmt, &["{ok}", "{bad}"]),
            ("easy_running", |t| t.easy_running, &["{pct}"]),
            (
                "easy_running_eta",
                |t| t.easy_running_eta,
                &["{pct}", "{eta}"],
            ),
            ("red_row", |t| t.red_row, &["{kn}", "{x}", "{loss}"]),
            ("recv_folder_note", |t| t.recv_folder_note, &["{path}"]),
        ];
        for lang in Locale::ALL {
            let t = transfer_strings(lang);
            for (name, get, holes) in need {
                for h in holes {
                    assert!(get(t).contains(h), "{lang:?} transfers.{name} lost {h}");
                }
            }
            assert!(
                t.easy_paused.contains("{pct}"),
                "{lang:?} easy_paused lost {{pct}}"
            );
        }
    }

    #[test]
    fn transfer_easy_and_technical_wording_differs_in_english() {
        let t = transfer_strings(Locale::En);
        assert_ne!(t.mid_label, t.mid_label_easy);
        assert_ne!(t.red_label, t.red_label_easy);
    }

    #[test]
    fn all_locales_return_non_empty_strings() {
        for lang in Locale::ALL {
            let s = strings(lang);
            // Spot-check key fields are non-empty across all locales.
            assert!(!s.tab_store.is_empty(), "{lang:?} tab_store empty");
            assert!(!s.tab_retrieve.is_empty(), "{lang:?} tab_retrieve empty");
            assert!(!s.welcome_title.is_empty(), "{lang:?} welcome_title empty");
            assert!(
                !s.welcome_title_easy.is_empty(),
                "{lang:?} welcome_title_easy empty"
            );
            assert!(!s.store_heading.is_empty(), "{lang:?} store_heading empty");
            assert!(
                !s.store_heading_easy.is_empty(),
                "{lang:?} store_heading_easy empty"
            );
            assert!(
                !s.retrieve_heading.is_empty(),
                "{lang:?} retrieve_heading empty"
            );
            assert!(
                !s.retrieve_heading_easy.is_empty(),
                "{lang:?} retrieve_heading_easy empty"
            );
            assert!(
                !s.status_heading.is_empty(),
                "{lang:?} status_heading empty"
            );
            assert!(
                !s.settings_heading.is_empty(),
                "{lang:?} settings_heading empty"
            );
            assert!(
                !s.wipe_confirm_title.is_empty(),
                "{lang:?} wipe_confirm_title empty"
            );
            assert!(
                !s.wipe_confirm_button.is_empty(),
                "{lang:?} wipe_confirm_button empty"
            );
            assert!(
                !s.settings_language.is_empty(),
                "{lang:?} settings_language empty"
            );
            assert!(!s.settings_mode.is_empty(), "{lang:?} settings_mode empty");
            for (name, v) in [
                ("settings_theme", s.settings_theme),
                ("settings_theme_system", s.settings_theme_system),
                ("settings_theme_light", s.settings_theme_light),
                ("settings_theme_dark", s.settings_theme_dark),
            ] {
                assert!(!v.is_empty(), "{lang:?} {name} empty");
            }
            // Import strings.
            assert!(!s.tab_import.is_empty(), "{lang:?} tab_import empty");
            assert!(
                !s.import_heading.is_empty(),
                "{lang:?} import_heading empty"
            );
            assert!(!s.import_button.is_empty(), "{lang:?} import_button empty");
            assert!(
                !s.import_complete.is_empty(),
                "{lang:?} import_complete empty"
            );
            // Diagnostics export strings.
            assert!(
                !s.status_save_diag.is_empty(),
                "{lang:?} status_save_diag empty"
            );
            assert!(
                !s.status_diag_saved.is_empty(),
                "{lang:?} status_diag_saved empty"
            );
            // Nav and dashboard strings.
            assert!(!s.nav_brand.is_empty(), "{lang:?} nav_brand empty");
            assert!(
                !s.nav_brand_easy.is_empty(),
                "{lang:?} nav_brand_easy empty"
            );
            assert!(
                !s.dashboard_quick_status.is_empty(),
                "{lang:?} dashboard_quick_status empty"
            );
        }
    }

    #[test]
    fn relay_status_placeholders_survive_translation() {
        for lang in Locale::ALL {
            let s = strings(lang);
            assert!(s.relay_down_s.contains("{n}"), "{lang:?} relay_down_s");
            assert!(s.relay_down_min.contains("{n}"), "{lang:?} relay_down_min");
            assert!(
                s.relay_down_h.contains("{h}") && s.relay_down_h.contains("{m}"),
                "{lang:?} relay_down_h"
            );
            assert!(
                s.relay_cert_trusted.contains("{ca}"),
                "{lang:?} relay_cert_trusted"
            );
            assert!(
                s.relay_cert_untrusted.contains("{ca}"),
                "{lang:?} relay_cert_untrusted"
            );
        }
    }

    #[test]
    fn locale_display_names_are_unique() {
        let names: Vec<&str> = Locale::ALL.iter().map(|l| l.display_name()).collect();
        for (i, a) in names.iter().enumerate() {
            for (j, b) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "duplicate display_name");
                }
            }
        }
    }

    #[test]
    fn locale_serde_roundtrip() {
        for lang in Locale::ALL {
            let json = serde_json::to_string(&lang).unwrap();
            let back: Locale = serde_json::from_str(&json).unwrap();
            assert_eq!(lang, back);
        }
    }

    #[test]
    fn easy_and_technical_labels_differ_in_english() {
        let s = strings(Locale::En);
        // Key differentiators between modes should have distinct wording.
        assert_ne!(s.tab_store, s.tab_store_easy);
        assert_ne!(s.tab_retrieve, s.tab_retrieve_easy);
        assert_ne!(s.welcome_title, s.welcome_title_easy);
        assert_ne!(s.store_heading, s.store_heading_easy);
        assert_ne!(s.retrieve_heading, s.retrieve_heading_easy);
        assert_ne!(s.stopped_title, s.stopped_title_easy);
        assert_ne!(s.stopped_button, s.stopped_button_easy);
    }

    #[test]
    fn all_three_locales_covered() {
        assert_eq!(Locale::ALL.len(), 3);
        assert!(Locale::ALL.contains(&Locale::En));
        assert!(Locale::ALL.contains(&Locale::Ja));
        assert!(Locale::ALL.contains(&Locale::ZhCn));
    }

    #[test]
    fn dialog_and_confirmation_strings_exist_in_every_locale() {
        for lang in Locale::ALL {
            let s = strings(lang);
            for (name, v) in [
                ("wipe_desc", s.wipe_desc),
                ("wipe_button", s.wipe_button),
                ("wipe_confirm_title", s.wipe_confirm_title),
                ("wipe_confirm_line1", s.wipe_confirm_line1),
                ("wipe_confirm_line2", s.wipe_confirm_line2),
                ("wipe_confirm_button", s.wipe_confirm_button),
                ("wipe_cancel", s.wipe_cancel),
                ("wipe_done", s.wipe_done),
                ("wipe_confirm_kept", s.wipe_confirm_kept),
                ("wipe_confirm_offline", s.wipe_confirm_offline),
                ("wipe_offline_note", s.wipe_offline_note),
                ("close_title", s.close_title),
                ("close_body", s.close_body),
                ("close_confirm", s.close_confirm),
                ("close_cancel", s.close_cancel),
                ("dialog_cancel", s.dialog_cancel),
                ("inbox_revoke_button", s.inbox_revoke_button),
                ("inbox_revoke_title", s.inbox_revoke_title),
                ("inbox_revoke_body", s.inbox_revoke_body),
                ("inbox_revoke_confirm", s.inbox_revoke_confirm),
                ("inbox_revoke_done", s.inbox_revoke_done),
                ("outbox_revoke_button", s.outbox_revoke_button),
                ("outbox_revoke_title", s.outbox_revoke_title),
                ("outbox_revoke_body", s.outbox_revoke_body),
                ("outbox_revoke_confirm", s.outbox_revoke_confirm),
                ("outbox_revoke_done", s.outbox_revoke_done),
                ("dismiss", s.dismiss),
            ] {
                assert!(!v.trim().is_empty(), "{lang:?} {name} is empty");
            }
            // The confirming button names what it does, not just "OK".
            assert_ne!(s.wipe_confirm_button, s.wipe_cancel, "{lang:?}");
            assert_ne!(s.close_confirm, s.close_cancel, "{lang:?}");
            // The wipe dialog says what is and is not erased, and that it is irreversible.
            assert_ne!(s.wipe_confirm_line1, s.wipe_confirm_kept, "{lang:?}");
            // The two names for the same action are gone: the dialog's confirm button carries the
            // button's own word, so what was clicked is what is confirmed.
            assert_eq!(s.inbox_revoke_button, s.inbox_revoke_confirm, "{lang:?}");
            assert_eq!(s.outbox_revoke_button, s.outbox_revoke_confirm, "{lang:?}");
            // No leftover leading dash from the old one-line layout.
            assert!(!s.wipe_desc.starts_with('—'), "{lang:?}");
        }
    }

    #[test]
    fn japanese_wipe_and_close_texts_say_what_matters() {
        let s = strings(Locale::Ja);
        assert_eq!(s.wipe_confirm_button, "すべて消去する");
        assert_eq!(s.close_confirm, "閉じる");
        assert_eq!(s.close_cancel, "キャンセル");
        assert!(s
            .close_body
            .contains("転送中です。閉じると転送が止まります。"));
        assert!(s.close_body.contains("続きから再開"));
        assert!(s.wipe_confirm_line2.contains("元に戻せません"));
        assert!(s.wipe_confirm_kept.contains("すでに相手に送ったコピー"));
        // Plain words for people who are not engineers.
        for v in [
            s.wipe_desc,
            s.wipe_confirm_line1,
            s.wipe_confirm_line2,
            s.wipe_confirm_kept,
        ] {
            assert!(!v.contains("マスター暗号鍵"), "{v}");
        }
        // Inbox says "decline", outbox says "revoke": one word each, never "delete".
        assert!(!s.inbox_revoke_button.contains("削除"));
        assert_ne!(s.inbox_revoke_button, s.outbox_revoke_button);
    }

    #[test]
    fn default_locale_is_english() {
        assert_eq!(Locale::default(), Locale::En);
    }
}
