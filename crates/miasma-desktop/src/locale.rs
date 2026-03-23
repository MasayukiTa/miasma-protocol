/// Localization — translatable UI strings for the desktop app.
///
/// Three locales: English, Japanese, Simplified Chinese.
/// Each locale provides both Technical and Easy variants for key strings.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    En,
    Ja,
    ZhCn,
}

impl Default for Locale {
    fn default() -> Self {
        Self::En
    }
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
    wipe_desc: "— permanently destroys all stored content",
    wipe_button: "Wipe All Shares",
    wipe_confirm_title: "Confirm Emergency Wipe",
    wipe_confirm_line1: "This will permanently destroy the master encryption key.",
    wipe_confirm_line2: "All stored shares will become unreadable immediately.\nThis action cannot be undone.",
    wipe_confirm_button: "Wipe Now",
    wipe_cancel: "Cancel",
    wipe_done: "Wiped. All shares are now permanently unreadable.",

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
    inbox_revoke_button: "Delete",
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

    dismiss: "dismiss",
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
    wipe_desc: "— 保存されたすべてのコンテンツを完全に破棄します",
    wipe_button: "全データを消去",
    wipe_confirm_title: "緊急消去の確認",
    wipe_confirm_line1: "マスター暗号鍵を完全に破棄します。",
    wipe_confirm_line2: "保存されたすべてのデータが即座に読み取り不能になります。\nこの操作は取り消せません。",
    wipe_confirm_button: "消去する",
    wipe_cancel: "キャンセル",
    wipe_done: "消去しました。すべてのデータが読み取り不能になりました。",

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
    inbox_revoke_button: "削除",
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
    outbox_revoke_button: "取り消し",
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
    wipe_desc: "— 永久销毁所有已保存的内容",
    wipe_button: "擦除所有数据",
    wipe_confirm_title: "确认紧急擦除",
    wipe_confirm_line1: "这将永久销毁主加密密钥。",
    wipe_confirm_line2: "所有已保存的数据将立即变为不可读。\n此操作无法撤销。",
    wipe_confirm_button: "立即擦除",
    wipe_cancel: "取消",
    wipe_done: "已擦除。所有数据已变为不可读。",

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
    inbox_revoke_button: "删除",
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn default_locale_is_english() {
        assert_eq!(Locale::default(), Locale::En);
    }
}
