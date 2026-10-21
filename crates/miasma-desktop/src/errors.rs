//! Errors the person sees: a stable kind plus a short detail, written out in the UI language.
//!
//! The worker thread turns whatever went wrong (a typed core error, an IPC error string, an
//! `anyhow` chain, an I/O error) into a [`UiError`]. The window then looks the kind up in the
//! tables below, so the text is in the person's language and says what to do next. The original
//! wording stays in `detail`; it is shown only in Technical mode (as a small monospace line) and
//! in the diagnostics report, never in Easy mode.
//!
//! Kinds are matched on error *types* first (`MiasmaError`, `io::Error`, the launcher's own
//! `LaunchError`) and on known stable substrings of the daemon's text second.

use crate::locale::Locale;

/// What went wrong, in terms that decide the text. The `code()` strings are stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrorKind {
    RuntimeStartFailed,
    DaemonAutostartFailed,
    InitDaemonFailed,
    InitFailed,
    DaemonStartFailed,
    DaemonAlreadyRunning,
    DaemonNotReady,
    DaemonUnreachable,
    BackendMissing,
    SpawnBlocked,
    SpawnFailedMac,
    BridgeMissing,
    BridgeStartFailed,
    BridgeFailed,
    UnexpectedResponse,
    FileNotFound,
    InvalidRetention,
    EraseFailed,
    Unauthorized,
    InvalidId,
    WrongPassword,
    PasswordRequired,
    WeakPassword,
    NotEnoughShares,
    DataDamaged,
    NetworkFailed,
    DiskError,
    OutputRejected,
    SharingUnavailable,
    WipeNotConfirmed,
    NoSuchTransfer,
    PushNoReply,
    UpdateCheckFailed,
    UpdateVerifyFailed,
    UpdateApplyFailed,
    UpdateBusy,
    UpdateNotWritable,
    /// Anything not recognised. Keep last: the completeness test counts on it.
    Other,
}

impl ErrorKind {
    /// Every kind, for the completeness tests.
    #[cfg(test)]
    pub const ALL: [ErrorKind; 38] = [
        Self::RuntimeStartFailed,
        Self::DaemonAutostartFailed,
        Self::InitDaemonFailed,
        Self::InitFailed,
        Self::DaemonStartFailed,
        Self::DaemonAlreadyRunning,
        Self::DaemonNotReady,
        Self::DaemonUnreachable,
        Self::BackendMissing,
        Self::SpawnBlocked,
        Self::SpawnFailedMac,
        Self::BridgeMissing,
        Self::BridgeStartFailed,
        Self::BridgeFailed,
        Self::UnexpectedResponse,
        Self::FileNotFound,
        Self::InvalidRetention,
        Self::EraseFailed,
        Self::Unauthorized,
        Self::InvalidId,
        Self::WrongPassword,
        Self::PasswordRequired,
        Self::WeakPassword,
        Self::NotEnoughShares,
        Self::DataDamaged,
        Self::NetworkFailed,
        Self::DiskError,
        Self::OutputRejected,
        Self::SharingUnavailable,
        Self::WipeNotConfirmed,
        Self::NoSuchTransfer,
        Self::PushNoReply,
        Self::UpdateCheckFailed,
        Self::UpdateVerifyFailed,
        Self::UpdateApplyFailed,
        Self::UpdateBusy,
        Self::UpdateNotWritable,
        Self::Other,
    ];

    /// Stable code for logs, the diagnostics report and tests. Never shown as the message.
    pub fn code(self) -> &'static str {
        match self {
            Self::RuntimeStartFailed => "runtime_start_failed",
            Self::DaemonAutostartFailed => "daemon_autostart_failed",
            Self::InitDaemonFailed => "init_done_daemon_failed",
            Self::InitFailed => "init_failed",
            Self::DaemonStartFailed => "daemon_start_failed",
            Self::DaemonAlreadyRunning => "daemon_already_running",
            Self::DaemonNotReady => "daemon_not_ready",
            Self::DaemonUnreachable => "daemon_unreachable",
            Self::BackendMissing => "backend_missing",
            Self::SpawnBlocked => "backend_spawn_blocked",
            Self::SpawnFailedMac => "backend_spawn_failed_mac",
            Self::BridgeMissing => "bridge_missing",
            Self::BridgeStartFailed => "bridge_start_failed",
            Self::BridgeFailed => "bridge_failed",
            Self::UnexpectedResponse => "unexpected_response",
            Self::FileNotFound => "file_not_found",
            Self::InvalidRetention => "invalid_retention",
            Self::EraseFailed => "erase_failed",
            Self::Unauthorized => "unauthorized",
            Self::InvalidId => "invalid_id",
            Self::WrongPassword => "wrong_password",
            Self::PasswordRequired => "password_required",
            Self::WeakPassword => "weak_password",
            Self::NotEnoughShares => "not_enough_shares",
            Self::DataDamaged => "data_damaged",
            Self::NetworkFailed => "network_failed",
            Self::DiskError => "disk_error",
            Self::OutputRejected => "output_rejected",
            Self::SharingUnavailable => "sharing_unavailable",
            Self::WipeNotConfirmed => "wipe_not_confirmed",
            Self::NoSuchTransfer => "no_such_transfer",
            Self::PushNoReply => "push_no_reply",
            Self::UpdateCheckFailed => "update_check_failed",
            Self::UpdateVerifyFailed => "update_verify_failed",
            Self::UpdateApplyFailed => "update_apply_failed",
            Self::UpdateBusy => "update_busy",
            Self::UpdateNotWritable => "update_not_writable",
            Self::Other => "other",
        }
    }

    /// `[English, Japanese, Simplified Chinese]` text: what happened and what to do next.
    /// No shell commands: the app is the only tool the person is assumed to have.
    fn texts(self) -> [&'static str; 3] {
        match self {
            Self::RuntimeStartFailed => [
                "Miasma could not start its internal worker. Close Miasma and open it again.",
                "Miasmaの内部処理を開始できませんでした。Miasmaを閉じてから、もう一度開いてください。",
                "Miasma 无法启动内部处理。请关闭 Miasma 后重新打开。",
            ],
            Self::DaemonAutostartFailed => [
                "The background service could not start by itself. Close Miasma and open it again.",
                "バックグラウンド機能を自動で起動できませんでした。Miasmaを閉じてから、もう一度開いてください。",
                "后台服务无法自动启动。请关闭 Miasma 后重新打开。",
            ],
            Self::InitDaemonFailed => [
                "Setup is complete, but the background service did not start. Press Start at the top of the window.",
                "初期設定は完了しましたが、バックグラウンド機能を起動できませんでした。画面上部の「起動」を押してください。",
                "初始设置已完成，但后台服务未能启动。请点击窗口顶部的“启动”。",
            ],
            Self::InitFailed => [
                "Setup could not finish. Check that the data folder can be written to, then try again.",
                "初期設定を完了できませんでした。保存先のフォルダに書き込めるか確認して、もう一度お試しください。",
                "初始设置未能完成。请确认可以写入数据文件夹，然后重试。",
            ],
            Self::DaemonStartFailed => [
                "The background service could not start. Wait a moment, then press Start again.",
                "バックグラウンド機能を起動できませんでした。しばらく待ってから、もう一度「起動」を押してください。",
                "后台服务无法启动。请稍等片刻，然后再次点击“启动”。",
            ],
            Self::DaemonAlreadyRunning => [
                "The background service is already running.",
                "バックグラウンド機能はすでに動いています。",
                "后台服务已在运行。",
            ],
            Self::DaemonNotReady => [
                "The background service is slow to start. Wait a moment, then press Start again. Antivirus software may be checking it.",
                "バックグラウンド機能の準備に時間がかかっています。少し待ってから「起動」を押してください。ウイルス対策ソフトが確認している場合もあります。",
                "后台服务启动较慢。请稍等片刻后再次点击“启动”。杀毒软件可能正在检查它。",
            ],
            Self::DaemonUnreachable => [
                "Not connected to the background service. Press Start at the top of the window. If it still does not work, close all Miasma windows and open Miasma again.",
                "バックグラウンド機能に接続できません。画面上部の「起動」を押してください。直らないときは、Miasmaのウィンドウをすべて閉じてから、もう一度開いてください。",
                "未连接到后台服务。请点击窗口顶部的“启动”。如果仍无法解决，请关闭所有 Miasma 窗口后重新打开。",
            ],
            Self::BackendMissing => [
                "Miasma's background component was not found. Reinstall Miasma.",
                "Miasmaのバックグラウンド機能が見つかりません。Miasmaを入れ直してください。",
                "找不到 Miasma 的后台组件。请重新安装 Miasma。",
            ],
            Self::SpawnBlocked => [
                "The background service could not start. Antivirus software or SmartScreen may be blocking miasma.exe. Allow it, then try again.",
                "バックグラウンド機能を起動できませんでした。ウイルス対策ソフトやSmartScreenが miasma.exe を止めている可能性があります。許可してから、もう一度お試しください。",
                "后台服务无法启动。杀毒软件或 SmartScreen 可能拦截了 miasma.exe。请允许它运行后重试。",
            ],
            Self::SpawnFailedMac => [
                "The background service could not start. Reinstall Miasma.app.",
                "バックグラウンド機能を起動できませんでした。Miasma.app を入れ直してください。",
                "后台服务无法启动。请重新安装 Miasma.app。",
            ],
            Self::BridgeMissing => [
                "The import component was not found. Reinstall Miasma.",
                "インポート用の部品が見つかりません。Miasmaを入れ直してください。",
                "找不到导入组件。请重新安装 Miasma。",
            ],
            Self::BridgeStartFailed => [
                "The import could not start. Close Miasma, open it again and retry.",
                "インポートを始められませんでした。Miasmaを開き直して、もう一度お試しください。",
                "无法开始导入。请重新打开 Miasma 后重试。",
            ],
            Self::BridgeFailed => [
                "The import failed. Check the file or link, then try again.",
                "インポートに失敗しました。ファイルやリンクの内容を確認して、もう一度お試しください。",
                "导入失败。请检查文件或链接后重试。",
            ],
            Self::UnexpectedResponse => [
                "The background service answered in an unexpected way. Close Miasma completely and open it again. If it keeps happening, reinstall the latest Miasma.",
                "バックグラウンド機能の応答が想定と異なります。Miasmaを完全に閉じてから開き直してください。直らないときは、最新のMiasmaを入れ直してください。",
                "后台服务的响应不符合预期。请完全退出 Miasma 后重新打开。若仍然如此，请重新安装最新版 Miasma。",
            ],
            Self::FileNotFound => [
                "The file was not found. Check where it is and choose it again.",
                "ファイルが見つかりません。場所を確認して、もう一度選んでください。",
                "找不到文件。请确认其位置后重新选择。",
            ],
            Self::InvalidRetention => [
                "The storage period is not valid. Choose it again.",
                "保存期間の指定が正しくありません。選び直してください。",
                "保存期限无效。请重新选择。",
            ],
            Self::EraseFailed => [
                "The data could not be erased. Close Miasma, open it again and retry.",
                "データを消去できませんでした。Miasmaを開き直して、もう一度お試しください。",
                "无法清除数据。请重新打开 Miasma 后重试。",
            ],
            Self::Unauthorized => [
                "The background service did not accept this window. Close Miasma and open it again.",
                "バックグラウンド機能との接続を確認できませんでした。Miasmaを閉じてから、もう一度開いてください。",
                "后台服务未接受此窗口的连接。请关闭 Miasma 后重新打开。",
            ],
            Self::InvalidId => [
                "The share ID is not in the right format. Copy it again and retry.",
                "共有IDの形式が正しくありません。コピーし直して、もう一度お試しください。",
                "共享 ID 的格式不正确。请重新复制后重试。",
            ],
            Self::WrongPassword => [
                "The password is wrong. Enter it again.",
                "パスワードが違います。もう一度入力してください。",
                "密码错误。请重新输入。",
            ],
            Self::PasswordRequired => [
                "This data is protected by a password. Enter the password.",
                "このデータはパスワードで保護されています。パスワードを入力してください。",
                "此数据受密码保护。请输入密码。",
            ],
            Self::WeakPassword => [
                "The password is too short or too simple. Use a longer one and mix in other kinds of characters.",
                "パスワードが短すぎるか、単純すぎます。長くして、記号なども混ぜてください。",
                "密码太短或太简单。请使用更长的密码，并混合不同类型的字符。",
            ],
            Self::NotEnoughShares => [
                "Not enough pieces could be collected to restore the data. Check that the sender's Miasma is running, wait a while and try again.",
                "データを復元するための断片が集まりませんでした。相手のMiasmaが起動しているか確認し、しばらくしてからもう一度お試しください。",
                "收集到的数据片段不足，无法还原数据。请确认对方的 Miasma 正在运行，稍后再试。",
            ],
            Self::DataDamaged => [
                "The received data is damaged or does not match the share ID. Check the share ID and try again.",
                "受け取ったデータが壊れているか、共有IDと一致しません。共有IDを確認して、もう一度お試しください。",
                "收到的数据已损坏，或与共享 ID 不一致。请检查共享 ID 后重试。",
            ],
            Self::NetworkFailed => [
                "The network could not be reached. Check your internet connection and try again.",
                "ネットワークにつながりませんでした。インターネットの接続を確認して、もう一度お試しください。",
                "无法连接网络。请检查网络连接后重试。",
            ],
            Self::DiskError => [
                "Reading or writing the file failed. Check the free space and the permission of the folder, then try again.",
                "ファイルの読み書きに失敗しました。空き容量とフォルダの権限を確認して、もう一度お試しください。",
                "读取或写入文件失败。请检查可用空间和文件夹权限后重试。",
            ],
            Self::OutputRejected => [
                "The file cannot be saved there. Choose another folder.",
                "この場所には保存できません。別のフォルダを選んでください。",
                "无法保存到此位置。请选择其他文件夹。",
            ],
            Self::SharingUnavailable => [
                "Sharing is not available right after erasing. Close Miasma and open it again.",
                "消去した直後は共有できません。Miasmaを閉じてから、もう一度開いてください。",
                "清除后无法立即共享。请关闭 Miasma 后重新打开。",
            ],
            Self::WipeNotConfirmed => [
                "The erase was not confirmed. Start it again.",
                "消去の確認が完了しませんでした。もう一度操作してください。",
                "清除未得到确认。请重新操作。",
            ],
            Self::NoSuchTransfer => [
                "That transfer was not found. Refresh the list and try again.",
                "その転送は見つかりません。一覧を更新して、もう一度お試しください。",
                "找不到该传输。请刷新列表后重试。",
            ],
            Self::PushNoReply => [
                "The contacts feature did not respond. Close Miasma and open it again.",
                "連絡先の機能から応答がありません。Miasmaを閉じてから、もう一度開いてください。",
                "联系人功能没有响应。请关闭 Miasma 后重新打开。",
            ],
            Self::UpdateCheckFailed => [
                "Could not check for updates. Check your internet connection. Miasma keeps working as it is.",
                "更新を確認できませんでした。インターネットの接続を確認してください。Miasmaはそのまま使えます。",
                "无法检查更新。请检查网络连接。Miasma 仍可照常使用。",
            ],
            Self::UpdateVerifyFailed => [
                "The update was refused because it could not be verified. Nothing was changed. Try again later.",
                "更新ファイルを検証できなかったため、更新を取りやめました。何も変更していません。しばらくしてからもう一度お試しください。",
                "无法验证更新文件，已取消更新。未做任何更改。请稍后重试。",
            ],
            Self::UpdateApplyFailed => [
                "The update could not be installed, and the current version was kept. Try again later.",
                "更新をインストールできませんでした。現在のバージョンのまま使えます。しばらくしてからもう一度お試しください。",
                "无法安装更新，已保留当前版本。请稍后重试。",
            ],
            Self::UpdateBusy => [
                "Miasma is busy sending or receiving. The update waits until it is idle.",
                "Miasmaは送受信の最中です。終わってから更新します。",
                "Miasma 正在收发数据。将在空闲后再更新。",
            ],
            Self::UpdateNotWritable => [
                "This installation cannot be updated from here. Install the new version yourself.",
                "このインストール先はここから更新できません。新しいバージョンを自分でインストールしてください。",
                "无法从此处更新当前安装。请自行安装新版本。",
            ],
            Self::Other => [
                "Something went wrong. Try again. If it keeps happening, save the report in Settings and contact support.",
                "うまくいきませんでした。もう一度お試しください。直らないときは、設定でレポートを保存して、サポートに送ってください。",
                "出现问题。请重试。若仍然如此，请在设置中保存报告并联系支持。",
            ],
        }
    }

    /// The text in `locale`.
    pub fn text(self, locale: Locale) -> &'static str {
        let t = self.texts();
        match locale {
            Locale::En => t[0],
            Locale::Ja => t[1],
            Locale::ZhCn => t[2],
        }
    }
}

/// What the worker hands to the window instead of a raw string.
#[derive(Clone, PartialEq, Eq)]
pub struct UiError {
    pub kind: ErrorKind,
    /// The original wording (first line, bounded). Technical mode and the report only.
    pub detail: String,
}

/// Longest detail kept, in characters.
const DETAIL_MAX: usize = 240;

impl std::fmt::Debug for UiError {
    // The detail can hold a file path, so a debug print carries its length only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UiError")
            .field("kind", &self.kind.code())
            .field("detail_len", &self.detail.len())
            .finish()
    }
}

impl From<String> for UiError {
    fn from(detail: String) -> Self {
        Self::from_text(detail)
    }
}

impl From<&str> for UiError {
    fn from(detail: &str) -> Self {
        Self::from_text(detail)
    }
}

impl UiError {
    pub fn new(kind: ErrorKind, detail: impl AsRef<str>) -> Self {
        Self {
            kind,
            detail: shorten(detail.as_ref()),
        }
    }

    /// A kind with no further detail.
    pub fn of(kind: ErrorKind) -> Self {
        Self {
            kind,
            detail: String::new(),
        }
    }

    /// Classify a daemon or core message by its stable wording.
    pub fn from_text(text: impl AsRef<str>) -> Self {
        let text = text.as_ref();
        Self::new(classify_message(text), text)
    }

    /// The daemon could not be reached at all.
    pub fn is_daemon_down(&self) -> bool {
        self.kind == ErrorKind::DaemonUnreachable
    }

    /// The text for the window. Technical mode adds the original wording on a second line.
    pub fn text(&self, locale: Locale, technical: bool) -> String {
        let base = self.kind.text(locale);
        if technical && !self.detail.is_empty() {
            format!("{base}\n{}", self.detail)
        } else {
            base.to_owned()
        }
    }

    /// The localized text alone.
    pub fn plain(&self, locale: Locale) -> &'static str {
        self.kind.text(locale)
    }

    /// One line for the diagnostics report (which stays in English for support).
    pub fn report_line(&self) -> String {
        if self.detail.is_empty() {
            format!("[{}]", self.kind.code())
        } else {
            format!("[{}] {}", self.kind.code(), self.detail)
        }
    }

    /// The reply to a response of the wrong type (a daemon of another version).
    pub fn unexpected(other: &impl std::fmt::Debug) -> Self {
        // Only the variant name: the payload can hold data nobody asked to see.
        let dbg = format!("{other:?}");
        let name: String = dbg
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        Self::new(
            ErrorKind::UnexpectedResponse,
            format!("unexpected response: {name}"),
        )
    }
}

/// First line only, at most [`DETAIL_MAX`] characters.
fn shorten(s: &str) -> String {
    let line = s.trim().lines().next().unwrap_or("").trim();
    if line.chars().count() > DETAIL_MAX {
        let mut out: String = line.chars().take(DETAIL_MAX).collect();
        out.push('\u{2026}');
        out
    } else {
        line.to_owned()
    }
}

/// Kind of a message by its stable wording. The order matters: the first match wins.
pub fn classify_message(msg: &str) -> ErrorKind {
    let m = msg.to_ascii_lowercase();
    let has = |s: &str| m.contains(s);
    if crate::worker::is_daemon_down(msg) {
        ErrorKind::DaemonUnreachable
    } else if has("unauthorized") {
        ErrorKind::Unauthorized
    } else if has("wipe not confirmed") {
        ErrorKind::WipeNotConfirmed
    } else if has("directed sharing unavailable") {
        ErrorKind::SharingUnavailable
    } else if has("no such transfer") || has("no running transfer") {
        ErrorKind::NoSuchTransfer
    } else if has("invalid mid") || has("invalid share id") || has("share id mismatch") {
        ErrorKind::InvalidId
    } else if has("wrong password") {
        ErrorKind::WrongPassword
    } else if has("password is required") || has("password-protected") {
        ErrorKind::PasswordRequired
    } else if has("weak password") {
        ErrorKind::WeakPassword
    } else if has("insufficient shares") {
        ErrorKind::NotEnoughShares
    } else if has("hash mismatch")
        || has("integrity check failed")
        || has("invalid transfer manifest")
        || has("decryption failed")
    {
        ErrorKind::DataDamaged
    } else if has("output path rejected") {
        ErrorKind::OutputRejected
    } else if has("cannot read file")
        || has("cannot write to")
        || has("i/o error")
        || has("storage error")
        || has("inbox open failed")
        || has("outbox open failed")
    {
        ErrorKind::DiskError
    } else if has("network error")
        || has("dht error")
        || has("timed out")
        || has("cannot reach")
        || has("connection")
    {
        ErrorKind::NetworkFailed
    } else {
        ErrorKind::Other
    }
}

/// Kind of a core error by its type.
fn classify_core(e: &miasma_core::MiasmaError) -> ErrorKind {
    use miasma_core::MiasmaError as E;
    match e {
        E::InvalidMid(_) | E::InvalidShareId(_) | E::ShareMismatch(_) => ErrorKind::InvalidId,
        E::InsufficientShares { .. } => ErrorKind::NotEnoughShares,
        E::HashMismatch | E::ShareIntegrity | E::Decryption(_) | E::InvalidManifest(_) => {
            ErrorKind::DataDamaged
        }
        E::WrongPassword => ErrorKind::WrongPassword,
        E::PasswordRequired => ErrorKind::PasswordRequired,
        E::WeakPassword(_) => ErrorKind::WeakPassword,
        E::Network(_) | E::Dht(_) => ErrorKind::NetworkFailed,
        E::Io(_) | E::Storage(_) => ErrorKind::DiskError,
        _ => ErrorKind::Other,
    }
}

/// Kind of an I/O error that says the daemon is not there to answer.
fn io_means_daemon_down(e: &std::io::Error) -> bool {
    use std::io::ErrorKind as K;
    matches!(
        e.kind(),
        K::ConnectionRefused | K::ConnectionReset | K::ConnectionAborted | K::NotConnected
    )
}

/// Classify an `anyhow` chain: types first, wording second.
pub fn classify_anyhow(e: &anyhow::Error) -> UiError {
    let detail = format!("{e:#}");
    for cause in e.chain() {
        if let Some(l) = cause.downcast_ref::<crate::worker::LaunchError>() {
            return UiError::new(l.kind(), detail);
        }
        if let Some(c) = cause.downcast_ref::<miasma_core::MiasmaError>() {
            let kind = classify_core(c);
            if kind != ErrorKind::Other {
                return UiError::new(kind, detail);
            }
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io_means_daemon_down(io) {
                return UiError::new(ErrorKind::DaemonUnreachable, detail);
            }
        }
    }
    let kind = classify_message(&detail);
    if kind == ErrorKind::Other {
        // A bare I/O error with no better explanation is still a file problem.
        if e.chain()
            .any(|c| c.downcast_ref::<std::io::Error>().is_some())
        {
            return UiError::new(ErrorKind::DiskError, detail);
        }
    }
    UiError::new(kind, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_lists_every_kind_once_with_other_last() {
        let distinct: HashSet<_> = ErrorKind::ALL.iter().map(|k| k.code()).collect();
        assert_eq!(distinct.len(), ErrorKind::Other as usize + 1);
        assert_eq!(*ErrorKind::ALL.last().unwrap(), ErrorKind::Other);
    }

    #[test]
    fn every_kind_has_text_in_every_language() {
        for k in ErrorKind::ALL {
            for l in Locale::ALL {
                let t = k.text(l);
                assert!(!t.trim().is_empty(), "{} / {l:?}", k.code());
            }
            // The three languages are not copies of each other.
            let [en, ja, zh] = k.texts();
            assert_ne!(en, ja, "{}", k.code());
            assert_ne!(en, zh, "{}", k.code());
            assert_ne!(ja, zh, "{}", k.code());
        }
    }

    #[test]
    fn japanese_texts_use_the_product_words_and_no_commands() {
        for k in ErrorKind::ALL {
            let ja = k.text(Locale::Ja);
            for banned in [
                "デーモン",
                "指紋",
                "カード",
                "iroh",
                "netcheck",
                "`",
                "daemon",
            ] {
                assert!(!ja.contains(banned), "{}: {banned}", k.code());
            }
            assert!(
                ja.ends_with('。'),
                "{} should end like a sentence: {ja}",
                k.code()
            );
            // Not English left behind: at least one Japanese character.
            assert!(
                ja.chars().any(|c| ('\u{3040}'..='\u{30ff}').contains(&c)),
                "{}: {ja}",
                k.code()
            );
        }
    }

    #[test]
    fn no_text_tells_the_person_to_run_a_command() {
        for k in ErrorKind::ALL {
            for l in Locale::ALL {
                let t = k.text(l);
                for banned in ["miasma daemon", "miasma netcheck", "iroh_mode", "cargo "] {
                    assert!(!t.contains(banned), "{} / {l:?}: {banned}", k.code());
                }
            }
        }
    }

    #[test]
    fn chinese_texts_are_chinese() {
        for k in ErrorKind::ALL {
            let zh = k.text(Locale::ZhCn);
            assert!(
                zh.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                "{}: {zh}",
                k.code()
            );
        }
    }

    #[test]
    fn easy_text_hides_the_detail_and_technical_text_shows_it() {
        let e = UiError::new(ErrorKind::FileNotFound, "File not found: C:/x/y.txt");
        assert_eq!(
            e.text(Locale::En, false),
            ErrorKind::FileNotFound.text(Locale::En)
        );
        let t = e.text(Locale::Ja, true);
        assert!(t.starts_with(ErrorKind::FileNotFound.text(Locale::Ja)));
        assert!(t.ends_with("File not found: C:/x/y.txt"));
    }

    #[test]
    fn debug_print_does_not_leak_the_detail() {
        let e = UiError::new(
            ErrorKind::FileNotFound,
            "File not found: C:/private/secret.txt",
        );
        let shown = format!("{e:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("file_not_found"));
    }

    #[test]
    fn detail_is_one_bounded_line() {
        let e = UiError::new(
            ErrorKind::Other,
            format!("first\nsecond {}", "x".repeat(500)),
        );
        assert_eq!(e.detail, "first");
        let long = UiError::new(ErrorKind::Other, "y".repeat(500));
        assert_eq!(long.detail.chars().count(), DETAIL_MAX + 1);
    }

    #[test]
    fn messages_map_to_kinds() {
        let cases: &[(&str, ErrorKind)] = &[
            (
                "daemon.token not found - is the miasma daemon running?",
                ErrorKind::DaemonUnreachable,
            ),
            (
                "daemon.port not found \u{2014} is the miasma daemon running?",
                ErrorKind::DaemonUnreachable,
            ),
            (
                "cannot connect to daemon on 127.0.0.1:9 \u{2014} is it running?",
                ErrorKind::DaemonUnreachable,
            ),
            ("Daemon not running", ErrorKind::DaemonUnreachable),
            (
                "unauthorized: missing or invalid control token (see daemon.token in the data dir)",
                ErrorKind::Unauthorized,
            ),
            (
                "wipe not confirmed: missing, expired or wrong confirmation nonce",
                ErrorKind::WipeNotConfirmed,
            ),
            (
                "directed sharing unavailable after distress wipe",
                ErrorKind::SharingUnavailable,
            ),
            ("no such transfer: send:x", ErrorKind::NoSuchTransfer),
            ("no running transfer: x", ErrorKind::NoSuchTransfer),
            ("invalid MID: bad prefix", ErrorKind::InvalidId),
            ("invalid share ID: checksum", ErrorKind::InvalidId),
            ("wrong password", ErrorKind::WrongPassword),
            (
                "this transfer is password-protected; a password is required",
                ErrorKind::PasswordRequired,
            ),
            (
                "weak password: too_short,no_symbol",
                ErrorKind::WeakPassword,
            ),
            (
                "insufficient shares: need 10, got 3",
                ErrorKind::NotEnoughShares,
            ),
            (
                "hash mismatch: content does not match MID",
                ErrorKind::DataDamaged,
            ),
            ("share integrity check failed", ErrorKind::DataDamaged),
            ("output path rejected: outside", ErrorKind::OutputRejected),
            ("cannot read file C:/a: denied", ErrorKind::DiskError),
            ("cannot write to C:/a: full", ErrorKind::DiskError),
            ("I/O error: disk full", ErrorKind::DiskError),
            ("network error: no route", ErrorKind::NetworkFailed),
            ("open stream timed out", ErrorKind::NetworkFailed),
            ("something nobody wrote down", ErrorKind::Other),
            ("", ErrorKind::Other),
        ];
        for (msg, want) in cases {
            assert_eq!(classify_message(msg), *want, "{msg}");
        }
        assert_eq!(
            UiError::from("wrong password").kind,
            ErrorKind::WrongPassword
        );
    }

    #[test]
    fn typed_errors_map_before_their_wording_is_read() {
        use miasma_core::MiasmaError as E;
        // Wording that would say "other" or something else: the type decides.
        let e = anyhow::Error::new(E::HashMismatch).context("while reading");
        assert_eq!(classify_anyhow(&e).kind, ErrorKind::DataDamaged);
        let e = anyhow::Error::new(E::WrongPassword);
        assert_eq!(classify_anyhow(&e).kind, ErrorKind::WrongPassword);
        let e = anyhow::Error::new(E::InsufficientShares { need: 10, got: 2 });
        assert_eq!(classify_anyhow(&e).kind, ErrorKind::NotEnoughShares);
        let e = anyhow::Error::new(E::Network("x".into()));
        assert_eq!(classify_anyhow(&e).kind, ErrorKind::NetworkFailed);
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let e = anyhow::Error::new(refused).context("send request");
        assert_eq!(classify_anyhow(&e).kind, ErrorKind::DaemonUnreachable);
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            classify_anyhow(&anyhow::Error::new(denied)).kind,
            ErrorKind::DiskError
        );
        assert_eq!(
            classify_anyhow(&anyhow::anyhow!("odd")).kind,
            ErrorKind::Other
        );
    }

    #[test]
    fn launcher_errors_keep_their_own_kind() {
        use crate::worker::LaunchError as L;
        let cases = [
            (
                L::AlreadyRunning { port: 1 },
                ErrorKind::DaemonAlreadyRunning,
            ),
            (L::BackendMissing, ErrorKind::BackendMissing),
            (L::NotReady { secs: 30 }, ErrorKind::DaemonNotReady),
        ];
        for (err, want) in cases {
            let e = anyhow::Error::new(err);
            assert_eq!(classify_anyhow(&e).kind, want);
        }
        let spawn = anyhow::Error::new(L::Spawn(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )));
        let want = if cfg!(target_os = "macos") {
            ErrorKind::SpawnFailedMac
        } else {
            ErrorKind::SpawnBlocked
        };
        assert_eq!(classify_anyhow(&spawn).kind, want);
    }

    #[test]
    fn a_response_of_the_wrong_type_names_only_the_variant() {
        #[derive(Debug)]
        #[allow(dead_code)]
        enum R {
            Published { mid: String },
        }
        let e = UiError::unexpected(&R::Published {
            mid: "secret-mid".into(),
        });
        assert_eq!(e.kind, ErrorKind::UnexpectedResponse);
        assert!(e.detail.ends_with("Published"), "{}", e.detail);
        assert!(!e.detail.contains("secret"));
    }
}
