//! User-facing text of the transfer commands, in English and Japanese.
//!
//! Everything a person reads from `network-publish`, `network-get -o`,
//! `transfers`, `transfer-cancel` and `redundancy-bench` lives in [`Msg`], and
//! each variant carries both languages in one `match`, so a translation pass is
//! a diff of this file. Not translated on purpose: log lines (tracing),
//! protocol identifiers, subcommand and flag names, JSON fields, and the text
//! of errors that the daemon (`miasma-core`) produces, except the two password
//! errors that a person can act on (see [`localize_daemon_error`]).
//!
//! English is the default and its text is byte-identical to what the CLI
//! printed before this table existed: `scripts/transfer-e2e.{sh,ps1}` grep it.
//!
//! Language choice (first hit wins):
//! 1. `--lang en|ja`
//! 2. env `MIASMA_LANG` (`ja`, `en`, also `ja_JP`, `ja-JP`, `ja_JP.UTF-8`; case-insensitive;
//!    any other non-empty value means English)
//! 3. the OS UI language: Windows `GetUserDefaultUILanguage`
//! 4. `LC_ALL`, `LC_MESSAGES`, `LANG` (the first one that is set decides)
//! 5. English

use std::sync::OnceLock;

use miasma_core::transfer::bench::BenchRow;
use miasma_core::transfer::TransferState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ja,
}

static LANG: OnceLock<Lang> = OnceLock::new();

/// The language for this process. Detected once, on first use.
pub fn lang() -> Lang {
    *LANG.get_or_init(|| detect_with(&|k| std::env::var(k).ok(), os_ui_language()))
}

/// Fix the language from `--lang`. Call before anything prints; a later call,
/// or one after [`lang`] has already run, is ignored.
pub fn set_lang(l: Lang) {
    let _ = LANG.set(l);
}

/// `ja`, `ja_JP`, `ja-JP`, `JA_jp.UTF-8` -> Ja; `en`, `en-US`, ... -> En; else None.
pub fn parse_selection(s: &str) -> Option<Lang> {
    match primary_language(s).as_str() {
        "ja" => Some(Lang::Ja),
        "en" => Some(Lang::En),
        _ => None,
    }
}

/// clap `value_parser` for `--lang`.
pub fn parse_lang_arg(s: &str) -> Result<Lang, String> {
    parse_selection(s).ok_or_else(|| format!("'{s}' is not a supported language; use en or ja"))
}

/// `ja_JP.UTF-8@x` -> `ja`; lower-cased.
fn primary_language(tag: &str) -> String {
    let t = tag.trim().to_ascii_lowercase();
    let t = t.split(['.', '@']).next().unwrap_or("");
    t.split(['_', '-']).next().unwrap_or("").to_owned()
}

/// The pure part of the language choice, so it can be tested without touching
/// the real environment. `os_ui` is what the OS API said, if there is one.
pub fn detect_with(env: &dyn Fn(&str) -> Option<String>, os_ui: Option<Lang>) -> Lang {
    if let Some(v) = env("MIASMA_LANG") {
        if !v.trim().is_empty() {
            // Chosen explicitly: an unsupported value is English, not "ask the OS".
            return parse_selection(&v).unwrap_or(Lang::En);
        }
    }
    if let Some(l) = os_ui {
        return l;
    }
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(v) = env(key) {
            if !v.trim().is_empty() {
                // "C" / "POSIX" / another language all mean English here.
                return parse_selection(&v).unwrap_or(Lang::En);
            }
        }
    }
    Lang::En
}

/// The OS UI language, where the OS has an API for it. None elsewhere (the
/// caller then reads the locale environment variables).
#[cfg(windows)]
fn os_ui_language() -> Option<Lang> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    // SAFETY: no arguments, no pointers; returns a LANGID (0 on failure).
    let langid = unsafe { GetUserDefaultUILanguage() };
    if langid == 0 {
        return None;
    }
    // Primary language id is the low 10 bits; LANG_JAPANESE = 0x11.
    Some(if langid & 0x3ff == 0x11 {
        Lang::Ja
    } else {
        Lang::En
    })
}

#[cfg(not(windows))]
fn os_ui_language() -> Option<Lang> {
    None
}

/// Display columns of `s` in a terminal: ASCII is one, everything else two
/// (kana, kanji and full-width punctuation). Used to blank the tail of the
/// progress line, where `str::len` (bytes) or `chars().count()` would be wrong.
pub fn display_width(s: &str) -> usize {
    s.chars().map(|c| if c.is_ascii() { 1 } else { 2 }).sum()
}

// The two password errors a person can act on. Both come from `miasma-core`'s
// `MiasmaError`; a test pins these needles to the real messages.
const CORE_WRONG_PASSWORD: &str = "wrong password";
const CORE_PASSWORD_REQUIRED: &str = "a password is required";

/// A daemon-side error text for a person in `lang`. Only the two password
/// errors are translated; everything else is passed through untouched.
pub fn localize_daemon_error(e: &str, lang: Lang) -> String {
    if lang == Lang::Ja {
        if e.contains(CORE_WRONG_PASSWORD) {
            return Msg::WrongPassword.text(lang);
        }
        if e.contains(CORE_PASSWORD_REQUIRED) {
            return Msg::PasswordRequired.text(lang);
        }
        // Control-channel refusals from the daemon (miasma-core daemon module).
        if e.starts_with("unauthorized:") {
            return "制御トークンが無効か未指定です（データディレクトリの daemon.token を確認してください）".to_owned();
        }
        if e.starts_with("output path rejected:") {
            return "出力先は絶対パスで指定してください（'..' を含めることはできません）"
                .to_owned();
        }
    }
    e.to_owned()
}

/// One user-facing message. `text(lang)` renders it.
#[derive(Debug, Clone)]
pub enum Msg {
    // ---- progress line ----
    LookingUpRecord,
    PreparingSend,
    Hashing {
        done: String,
        total: String,
    },
    VerifyingPartialFile {
        done: String,
    },
    VerifyingPublished {
        done: String,
    },
    CheckingWholeFile,
    AnnouncingRecord,
    SegmentProgress {
        done: u32,
        total: u32,
    },
    Eta {
        eta: String,
    },
    SplitReceive {
        fetch: f64,
        decode: f64,
        write: f64,
    },
    SplitSend {
        store_push: f64,
        dissolve: f64,
    },
    RejectedPieces {
        n: u64,
    },
    Retries {
        n: u64,
    },

    // ---- `miasma transfers` ----
    NoTransfers,
    HeadingReceive {
        mid: String,
        name: String,
    },
    HeadingSendHashing {
        name: String,
    },
    HeadingSend {
        name: String,
        mid: String,
    },
    State {
        state: TransferState,
    },
    LastError {
        e: String,
    },
    Resumable {
        hint: String,
    },
    ResumeHintReceive {
        mid: String,
        name: String,
    },
    ResumeHintSend {
        name: String,
    },

    // ---- network-publish ----
    CannotResolvePath {
        path: String,
    },
    PublishStart {
        path: String,
        size: String,
    },
    PublishParams {
        k: usize,
        n: usize,
        factor: f64,
    },
    RunAgainToWatch,
    StartedCheckWith,
    Published {
        mid: String,
    },
    PublishedStats {
        size: String,
        secs: f64,
        avg: String,
    },
    PasswordProtectedNote,
    RetrieveHint {
        mid: String,
    },

    // ---- network-get -o ----
    PasswordOnlyToFile,
    Receiving {
        id: String,
    },
    ReceiveTo {
        path: String,
    },
    ReceiveKeepsGoing,
    ReceiveDone {
        size: String,
        secs: f64,
        path: String,
    },
    ReceiveStats {
        rate: String,
        fetch_ms: u64,
        decode_ms: u64,
        write_ms: u64,
    },

    // ---- watching a transfer ----
    Paused {
        reason: Option<String>,
    },
    Cancelled,
    TransferFailed {
        reason: Option<String>,
    },
    CancelRequested,
    CancelError {
        e: String,
    },

    // ---- daemon answers ----
    DaemonError {
        e: String,
    },
    UnexpectedResponse {
        debug: String,
    },
    WrongPassword,
    PasswordRequired,

    // ---- password input ----
    CannotReadPasswordFile {
        path: String,
    },
    CannotReadPasswordStdin,
    PasswordEmpty,

    // ---- redundancy-bench ----
    BenchDebugBuildNote,
    BenchRunning {
        count: usize,
        size_mib: usize,
        store_dir: Option<String>,
    },
    BenchStageTimes,
    BenchHeadings,
    BenchStoreHeading,
    BenchVerifiedYes,
    BenchVerifiedNo,
    PresetNotKOverN {
        s: String,
    },
    PresetBadK {
        s: String,
    },
    PresetBadN {
        s: String,
    },
    PresetOutOfRange {
        s: String,
    },
}

impl Msg {
    /// In the process language.
    pub fn t(&self) -> String {
        self.text(lang())
    }

    pub fn text(&self, lang: Lang) -> String {
        match lang {
            Lang::En => self.en(),
            Lang::Ja => self.ja(),
        }
    }

    fn en(&self) -> String {
        use Msg::*;
        match self {
            LookingUpRecord => "looking up the record and manifest...".into(),
            PreparingSend => "preparing...".into(),
            Hashing { done, total } => {
                format!("hashing the source file to get its MID: {done} / {total}")
            }
            VerifyingPartialFile { done } => {
                format!("verifying the partial file already on disk: {done}")
            }
            VerifyingPublished { done } => {
                format!("verifying the segments already published: {done}")
            }
            CheckingWholeFile => "checking the whole file against its MID...".into(),
            AnnouncingRecord => "announcing the record and manifest...".into(),
            SegmentProgress { done, total } => format!("seg {done}/{total}"),
            Eta { eta } => format!("ETA {eta}"),
            SplitReceive {
                fetch,
                decode,
                write,
            } => format!("fetch {fetch:.0}% decode {decode:.0}% write {write:.0}%"),
            SplitSend {
                store_push,
                dissolve,
            } => format!("store+push {store_push:.0}% dissolve {dissolve:.0}%"),
            RejectedPieces { n } => format!("rejected pieces: {n}"),
            Retries { n } => format!("retries: {n}"),

            NoTransfers => "No transfers.".into(),
            HeadingReceive { mid, name } => format!("receive  {mid}  ->  {name}"),
            HeadingSendHashing { name } => format!("send     {name}"),
            HeadingSend { name, mid } => format!("send     {name}  ({mid})"),
            // The Debug name, as `miasma transfers` always printed it.
            State { state } => format!("{state:?}"),
            LastError { e } => format!("last error: {e}"),
            Resumable { hint } => format!("resumable: {hint}"),
            ResumeHintReceive { mid, name } => {
                format!("run `miasma network-get {mid} -o {name}` again (same password)")
            }
            ResumeHintSend { name } => format!(
                "run `miasma network-publish {name}` again with the same options (same password)"
            ),

            CannotResolvePath { path } => format!("cannot resolve path: {path}"),
            PublishStart { path, size } => format!("Publishing {path} ({size})"),
            PublishParams { k, n, factor } => format!(
                "  k={k}, n={n}: the file is stored {factor:.2}x. The daemon keeps going if you press Ctrl-C."
            ),
            RunAgainToWatch => "  Run the same command to watch or resume it.".into(),
            StartedCheckWith => "  Started. Check it with: miasma transfers".into(),
            Published { mid } => format!("Published. MID: {mid}"),
            PublishedStats { size, secs, avg } => {
                format!("  {size} in {secs:.1}s ({avg}/s average)")
            }
            PasswordProtectedNote => {
                "  Password-protected: the receiver needs the MID and the password.".into()
            }
            RetrieveHint { mid } => format!("  Retrieve: miasma network-get {mid} -o output.bin"),

            PasswordOnlyToFile => "a password only applies when receiving to a file: pass -o/--output. \
                                   (Protected content is never written to stdout.)"
                .into(),
            Receiving { id } => format!("Receiving {id}"),
            ReceiveTo { path } => format!("  -> {path}"),
            ReceiveKeepsGoing => "  The daemon keeps going if you press Ctrl-C. Run the same command to watch or resume it.".into(),
            ReceiveDone { size, secs, path } => {
                format!("Done: {size} in {secs:.1}s. Written to {path}")
            }
            ReceiveStats {
                rate,
                fetch_ms,
                decode_ms,
                write_ms,
            } => format!(
                "  {rate}/s average this session  (fetch {fetch_ms} ms, decode {decode_ms} ms, write {write_ms} ms)"
            ),

            Paused { reason } => format!(
                "paused: {}\n  The partial work and progress are kept. Run the same command to resume.",
                reason.as_deref().unwrap_or("no reason recorded")
            ),
            Cancelled => "cancelled. Run the same command to resume.".into(),
            TransferFailed { reason } => reason.as_deref().unwrap_or("transfer failed").to_owned(),
            CancelRequested => {
                "Cancel requested; it stops at the next safe point and stays resumable.".into()
            }
            CancelError { e } => e.clone(),

            DaemonError { e } => format!("daemon error: {e}"),
            UnexpectedResponse { debug } => format!("unexpected response: {debug}"),
            WrongPassword => CORE_WRONG_PASSWORD.into(),
            PasswordRequired => "this transfer is password-protected; a password is required".into(),

            CannotReadPasswordFile { path } => format!("cannot read password file {path}"),
            CannotReadPasswordStdin => "cannot read the password from standard input".into(),
            PasswordEmpty => "the password is empty; refusing to publish with no protection".into(),

            BenchDebugBuildNote => "NOTE: this is a debug build. Storage factor and loss tolerance are exact, but the\n      throughput figures are not representative. Build with --release for those.".into(),
            BenchRunning {
                count,
                size_mib,
                store_dir,
            } => format!(
                "Running {count} setting(s) over {size_mib} MiB each{}...",
                store_dir
                    .as_ref()
                    .map_or(String::new(), |d| format!(", writing shares under {d}"))
            ),
            BenchStageTimes => {
                "Stage times on the first segment (encrypt / Reed-Solomon / Shamir):".into()
            }
            BenchHeadings => "| k/n | stored per byte (nominal / measured) | lost pieces tolerated | tolerance verified | dissolve MiB/s | recover MiB/s |".into(),
            BenchStoreHeading => " local store MiB/s |".into(),
            BenchVerifiedYes => "yes".into(),
            BenchVerifiedNo => "NO".into(),
            PresetNotKOverN { s } => format!("'{s}' is not of the form k/n, e.g. 10/12"),
            PresetBadK { s } => format!("bad k in '{s}'"),
            PresetBadN { s } => format!("bad n in '{s}'"),
            PresetOutOfRange { s } => format!("'{s}': need 1 <= k <= n <= 255"),
        }
    }

    fn ja(&self) -> String {
        use Msg::*;
        match self {
            LookingUpRecord => "レコードとマニフェストを探しています...".into(),
            PreparingSend => "準備しています...".into(),
            Hashing { done, total } => {
                format!("元のファイルのハッシュを計算しています (MID の算出): {done} / {total}")
            }
            VerifyingPartialFile { done } => {
                format!("ディスク上の受信済みの部分を検証しています: {done}")
            }
            VerifyingPublished { done } => {
                format!("公開済みのセグメントを検証しています: {done}")
            }
            CheckingWholeFile => "ファイル全体を MID と照合しています...".into(),
            AnnouncingRecord => "レコードとマニフェストを通知しています...".into(),
            SegmentProgress { done, total } => format!("セグメント {done}/{total}"),
            Eta { eta } => format!("ETA {eta}"),
            SplitReceive {
                fetch,
                decode,
                write,
            } => format!("取得 {fetch:.0}% 復元 {decode:.0}% 書き込み {write:.0}%"),
            SplitSend {
                store_push,
                dissolve,
            } => format!("保存+送信 {store_push:.0}% 分割処理 {dissolve:.0}%"),
            RejectedPieces { n } => format!("検証に失敗したピース: {n}"),
            Retries { n } => format!("再試行: {n}"),

            NoTransfers => "転送はありません。".into(),
            HeadingReceive { mid, name } => format!("受信  {mid}  ->  {name}"),
            HeadingSendHashing { name } => format!("送信  {name}"),
            HeadingSend { name, mid } => format!("送信  {name}  ({mid})"),
            State { state } => match state {
                TransferState::Running => "実行中",
                TransferState::Paused => "一時停止",
                TransferState::Complete => "完了",
                TransferState::Failed => "失敗",
                TransferState::Cancelled => "中止",
            }
            .into(),
            LastError { e } => format!("最後のエラー: {e}"),
            Resumable { hint } => format!("再開できます: {hint}"),
            ResumeHintReceive { mid, name } => format!(
                "同じパスワードで `miasma network-get {mid} -o {name}` をもう一度実行してください"
            ),
            ResumeHintSend { name } => format!(
                "同じオプションと同じパスワードで `miasma network-publish {name}` をもう一度実行してください"
            ),

            CannotResolvePath { path } => format!("パスを解決できません: {path}"),
            PublishStart { path, size } => format!("公開を開始します: {path} ({size})"),
            PublishParams { k, n, factor } => format!(
                "  k={k}, n={n}: ファイルは元の {factor:.2} 倍の容量で保存されます。Ctrl-C を押しても、裏で動くデーモンは公開を続けます。"
            ),
            RunAgainToWatch => "  同じコマンドをもう一度実行すると、進み具合を見たり続きから再開したりできます。".into(),
            StartedCheckWith => "  開始しました。状況の確認: miasma transfers".into(),
            Published { mid } => format!("公開しました。MID: {mid}"),
            PublishedStats { size, secs, avg } => {
                format!("  {size} を {secs:.1} 秒で公開 (平均 {avg}/s)")
            }
            PasswordProtectedNote => {
                "  パスワードで保護されています。受信する人には MID とパスワードの両方が必要です。".into()
            }
            RetrieveHint { mid } => format!("  受信するには: miasma network-get {mid} -o output.bin"),

            PasswordOnlyToFile => "パスワードはファイルへ受信するときだけ使えます。-o/--output を指定してください。(保護されたデータを標準出力へ書き出すことはありません。)".into(),
            Receiving { id } => format!("受信しています: {id}"),
            ReceiveTo { path } => format!("  -> {path}"),
            ReceiveKeepsGoing => "  Ctrl-C を押しても、裏で動くデーモンは受信を続けます。同じコマンドをもう一度実行すると、進み具合を見たり続きから再開したりできます。".into(),
            ReceiveDone { size, secs, path } => {
                format!("完了: {size} を {secs:.1} 秒で受信しました。保存先: {path}")
            }
            ReceiveStats {
                rate,
                fetch_ms,
                decode_ms,
                write_ms,
            } => format!(
                "  今回の平均 {rate}/s  (取得 {fetch_ms} ms, 復元 {decode_ms} ms, 書き込み {write_ms} ms)"
            ),

            Paused { reason } => format!(
                "一時停止しました: {}\n  途中までの作業と進み具合は保存されています。同じコマンドをもう一度実行すると続きから再開します。",
                reason
                    .as_deref()
                    .map(|r| localize_daemon_error(r, Lang::Ja))
                    .unwrap_or_else(|| "理由は記録されていません".into())
            ),
            Cancelled => "中止しました。同じコマンドをもう一度実行すると続きから再開します。".into(),
            TransferFailed { reason } => reason
                .as_deref()
                .map(|r| localize_daemon_error(r, Lang::Ja))
                .unwrap_or_else(|| "転送に失敗しました".into()),
            CancelRequested => {
                "中止を依頼しました。次の安全な区切りで止まり、あとで再開できます。".into()
            }
            CancelError { e } => localize_daemon_error(e, Lang::Ja),

            DaemonError { e } => format!("デーモンのエラー: {}", localize_daemon_error(e, Lang::Ja)),
            UnexpectedResponse { debug } => format!("想定外の応答です: {debug}"),
            WrongPassword => "パスワードが違います。送信した人に確認して、もう一度お試しください。".into(),
            PasswordRequired => "この転送はパスワードで保護されています。--password-file か --password-stdin でパスワードを指定してください。".into(),

            CannotReadPasswordFile { path } => {
                format!("パスワードファイルを読み込めません: {path}")
            }
            CannotReadPasswordStdin => "標準入力からパスワードを読み込めません".into(),
            PasswordEmpty => "パスワードが空です。保護なしでは公開しません".into(),

            BenchDebugBuildNote => "注意: これはデバッグビルドです。保存倍率と欠損への耐性は正確ですが、\n      速度の数値は参考になりません。速度を測るには --release でビルドしてください。".into(),
            BenchRunning {
                count,
                size_mib,
                store_dir,
            } => format!(
                "{count} 通りの設定を、それぞれ {size_mib} MiB で測定します{}...",
                store_dir
                    .as_ref()
                    .map_or(String::new(), |d| format!(" (シェアの書き込み先: {d})"))
            ),
            BenchStageTimes => {
                "最初のセグメントの処理時間の内訳 (暗号化 / Reed-Solomon / Shamir):".into()
            }
            BenchHeadings => "| k/n | 1 バイトあたりの保存量 (理論値 / 実測値) | 失っても復元できるピース数 | 耐性の検証 | 分割 MiB/s | 復元 MiB/s |".into(),
            BenchStoreHeading => " ローカル保存 MiB/s |".into(),
            BenchVerifiedYes => "はい".into(),
            BenchVerifiedNo => "いいえ".into(),
            PresetNotKOverN { s } => format!("'{s}' は k/n の形式ではありません。例: 10/12"),
            PresetBadK { s } => format!("'{s}' の k が正しくありません"),
            PresetBadN { s } => format!("'{s}' の n が正しくありません"),
            PresetOutOfRange { s } => format!("'{s}': 1 <= k <= n <= 255 にしてください"),
        }
    }
}

/// The `redundancy-bench` table. English is `miasma-core`'s own output,
/// unchanged; Japanese has the same columns and numbers.
pub fn format_bench_table(rows: &[BenchRow], lang: Lang) -> String {
    if lang == Lang::En {
        return miasma_core::transfer::bench::format_table(rows);
    }
    let with_store = rows.iter().any(|r| r.store.is_some());
    let mut out = String::new();
    out.push_str(&Msg::BenchHeadings.text(lang));
    if with_store {
        out.push_str(&Msg::BenchStoreHeading.text(lang));
    }
    out.push('\n');
    out.push_str("|---|---|---|---|---|---|");
    if with_store {
        out.push_str("---|");
    }
    out.push('\n');
    for r in rows {
        let verified = if r.survives_tolerated_loss && r.fails_cleanly_beyond_tolerance {
            Msg::BenchVerifiedYes
        } else {
            Msg::BenchVerifiedNo
        }
        .text(lang);
        out.push_str(&format!(
            "| {}/{} | {:.2}x / {:.3}x | {} | {} | {:.1} | {:.1} |",
            r.data_shards,
            r.total_shards,
            r.nominal_factor,
            r.measured_factor,
            r.tolerated_losses,
            verified,
            r.dissolve_mib_s(),
            r.recover_mib_s()
        ));
        if with_store {
            out.push_str(&format!(" {:.1} |", r.store_mib_s().unwrap_or(0.0)));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Adding a variant to `Msg` breaks this match, which is the reminder to add
    /// it to `golden()` too (no wildcard on purpose).
    fn covered(m: &Msg) -> &'static str {
        use Msg::*;
        match m {
            LookingUpRecord => "LookingUpRecord",
            PreparingSend => "PreparingSend",
            Hashing { .. } => "Hashing",
            VerifyingPartialFile { .. } => "VerifyingPartialFile",
            VerifyingPublished { .. } => "VerifyingPublished",
            CheckingWholeFile => "CheckingWholeFile",
            AnnouncingRecord => "AnnouncingRecord",
            SegmentProgress { .. } => "SegmentProgress",
            Eta { .. } => "Eta",
            SplitReceive { .. } => "SplitReceive",
            SplitSend { .. } => "SplitSend",
            RejectedPieces { .. } => "RejectedPieces",
            Retries { .. } => "Retries",
            NoTransfers => "NoTransfers",
            HeadingReceive { .. } => "HeadingReceive",
            HeadingSendHashing { .. } => "HeadingSendHashing",
            HeadingSend { .. } => "HeadingSend",
            State { .. } => "State",
            LastError { .. } => "LastError",
            Resumable { .. } => "Resumable",
            ResumeHintReceive { .. } => "ResumeHintReceive",
            ResumeHintSend { .. } => "ResumeHintSend",
            CannotResolvePath { .. } => "CannotResolvePath",
            PublishStart { .. } => "PublishStart",
            PublishParams { .. } => "PublishParams",
            RunAgainToWatch => "RunAgainToWatch",
            StartedCheckWith => "StartedCheckWith",
            Published { .. } => "Published",
            PublishedStats { .. } => "PublishedStats",
            PasswordProtectedNote => "PasswordProtectedNote",
            RetrieveHint { .. } => "RetrieveHint",
            PasswordOnlyToFile => "PasswordOnlyToFile",
            Receiving { .. } => "Receiving",
            ReceiveTo { .. } => "ReceiveTo",
            ReceiveKeepsGoing => "ReceiveKeepsGoing",
            ReceiveDone { .. } => "ReceiveDone",
            ReceiveStats { .. } => "ReceiveStats",
            Paused { .. } => "Paused",
            Cancelled => "Cancelled",
            TransferFailed { .. } => "TransferFailed",
            CancelRequested => "CancelRequested",
            CancelError { .. } => "CancelError",
            DaemonError { .. } => "DaemonError",
            UnexpectedResponse { .. } => "UnexpectedResponse",
            WrongPassword => "WrongPassword",
            PasswordRequired => "PasswordRequired",
            CannotReadPasswordFile { .. } => "CannotReadPasswordFile",
            CannotReadPasswordStdin => "CannotReadPasswordStdin",
            PasswordEmpty => "PasswordEmpty",
            BenchDebugBuildNote => "BenchDebugBuildNote",
            BenchRunning { .. } => "BenchRunning",
            BenchStageTimes => "BenchStageTimes",
            BenchHeadings => "BenchHeadings",
            BenchStoreHeading => "BenchStoreHeading",
            BenchVerifiedYes => "BenchVerifiedYes",
            BenchVerifiedNo => "BenchVerifiedNo",
            PresetNotKOverN { .. } => "PresetNotKOverN",
            PresetBadK { .. } => "PresetBadK",
            PresetBadN { .. } => "PresetBadN",
            PresetOutOfRange { .. } => "PresetOutOfRange",
        }
    }

    /// Messages that are the same in both languages: an ETA is kept as `ETA`,
    /// a path line is only a path, and a daemon error other than the two
    /// password ones is the daemon's own text passed through.
    fn reads_the_same(m: &Msg) -> bool {
        matches!(
            m,
            Msg::Eta { .. }
                | Msg::ReceiveTo { .. }
                | Msg::CancelError { .. }
                | Msg::TransferFailed { reason: Some(_) }
        )
    }

    fn s(x: &str) -> String {
        x.to_owned()
    }

    /// Every message once, with the English text the CLI printed before this
    /// table existed (copied from the old `eprintln!`/`bail!` literals).
    fn golden() -> Vec<(Msg, &'static str)> {
        use Msg::*;
        vec![
            (LookingUpRecord, "looking up the record and manifest..."),
            (PreparingSend, "preparing..."),
            (
                Hashing { done: s("5.0 GiB"), total: s("100.0 GiB") },
                "hashing the source file to get its MID: 5.0 GiB / 100.0 GiB",
            ),
            (
                VerifyingPartialFile { done: s("1.0 GiB") },
                "verifying the partial file already on disk: 1.0 GiB",
            ),
            (
                VerifyingPublished { done: s("1.0 GiB") },
                "verifying the segments already published: 1.0 GiB",
            ),
            (CheckingWholeFile, "checking the whole file against its MID..."),
            (AnnouncingRecord, "announcing the record and manifest..."),
            (SegmentProgress { done: 27, total: 64 }, "seg 27/64"),
            (Eta { eta: s("00:00:42") }, "ETA 00:00:42"),
            (
                SplitReceive { fetch: 60.0, decode: 8.0, write: 32.0 },
                "fetch 60% decode 8% write 32%",
            ),
            (
                SplitSend { store_push: 70.0, dissolve: 30.0 },
                "store+push 70% dissolve 30%",
            ),
            (RejectedPieces { n: 3 }, "rejected pieces: 3"),
            (Retries { n: 2 }, "retries: 2"),
            (NoTransfers, "No transfers."),
            (
                HeadingReceive { mid: s("miasma:abc"), name: s("D:/recv/file.bin") },
                "receive  miasma:abc  ->  D:/recv/file.bin",
            ),
            (HeadingSendHashing { name: s("/data/big.bin") }, "send     /data/big.bin"),
            (
                HeadingSend { name: s("/data/big.bin"), mid: s("miasma:xyz") },
                "send     /data/big.bin  (miasma:xyz)",
            ),
            (State { state: TransferState::Paused }, "Paused"),
            (LastError { e: s("boom") }, "last error: boom"),
            (Resumable { hint: s("do it") }, "resumable: do it"),
            (
                ResumeHintReceive { mid: s("miasma:abc"), name: s("out.bin") },
                "run `miasma network-get miasma:abc -o out.bin` again (same password)",
            ),
            (
                ResumeHintSend { name: s("big.bin") },
                "run `miasma network-publish big.bin` again with the same options (same password)",
            ),
            (CannotResolvePath { path: s("x") }, "cannot resolve path: x"),
            (
                PublishStart { path: s("/a/b.bin"), size: s("1.0 MiB") },
                "Publishing /a/b.bin (1.0 MiB)",
            ),
            (
                PublishParams { k: 2, n: 3, factor: 1.5 },
                "  k=2, n=3: the file is stored 1.50x. The daemon keeps going if you press Ctrl-C.",
            ),
            (RunAgainToWatch, "  Run the same command to watch or resume it."),
            (StartedCheckWith, "  Started. Check it with: miasma transfers"),
            (Published { mid: s("miasma:abc") }, "Published. MID: miasma:abc"),
            (
                PublishedStats { size: s("40.0 MiB"), secs: 2.0, avg: s("20.0 MiB") },
                "  40.0 MiB in 2.0s (20.0 MiB/s average)",
            ),
            (
                PasswordProtectedNote,
                "  Password-protected: the receiver needs the MID and the password.",
            ),
            (
                RetrieveHint { mid: s("miasma:abc") },
                "  Retrieve: miasma network-get miasma:abc -o output.bin",
            ),
            (
                PasswordOnlyToFile,
                "a password only applies when receiving to a file: pass -o/--output. (Protected content is never written to stdout.)",
            ),
            (Receiving { id: s("miasma:abc") }, "Receiving miasma:abc"),
            (ReceiveTo { path: s("/o.bin") }, "  -> /o.bin"),
            (
                ReceiveKeepsGoing,
                "  The daemon keeps going if you press Ctrl-C. Run the same command to watch or resume it.",
            ),
            (
                ReceiveDone { size: s("40.0 MiB"), secs: 2.0, path: s("/o.bin") },
                "Done: 40.0 MiB in 2.0s. Written to /o.bin",
            ),
            (
                ReceiveStats { rate: s("20.0 MiB"), fetch_ms: 1, decode_ms: 2, write_ms: 3 },
                "  20.0 MiB/s average this session  (fetch 1 ms, decode 2 ms, write 3 ms)",
            ),
            (
                Paused { reason: Some(s("disk full")) },
                "paused: disk full\n  The partial work and progress are kept. Run the same command to resume.",
            ),
            (
                Paused { reason: None },
                "paused: no reason recorded\n  The partial work and progress are kept. Run the same command to resume.",
            ),
            (Cancelled, "cancelled. Run the same command to resume."),
            (TransferFailed { reason: Some(s("bad")) }, "bad"),
            (TransferFailed { reason: None }, "transfer failed"),
            (
                CancelRequested,
                "Cancel requested; it stops at the next safe point and stays resumable.",
            ),
            (CancelError { e: s("no such transfer") }, "no such transfer"),
            (DaemonError { e: s("wrong password") }, "daemon error: wrong password"),
            (UnexpectedResponse { debug: s("Foo") }, "unexpected response: Foo"),
            (WrongPassword, "wrong password"),
            (
                PasswordRequired,
                "this transfer is password-protected; a password is required",
            ),
            (
                CannotReadPasswordFile { path: s("p.txt") },
                "cannot read password file p.txt",
            ),
            (
                CannotReadPasswordStdin,
                "cannot read the password from standard input",
            ),
            (
                PasswordEmpty,
                "the password is empty; refusing to publish with no protection",
            ),
            (
                BenchDebugBuildNote,
                "NOTE: this is a debug build. Storage factor and loss tolerance are exact, but the\n      throughput figures are not representative. Build with --release for those.",
            ),
            (
                BenchRunning { count: 5, size_mib: 256, store_dir: None },
                "Running 5 setting(s) over 256 MiB each...",
            ),
            (
                BenchRunning { count: 5, size_mib: 256, store_dir: Some(s("D:/s")) },
                "Running 5 setting(s) over 256 MiB each, writing shares under D:/s...",
            ),
            (
                BenchStageTimes,
                "Stage times on the first segment (encrypt / Reed-Solomon / Shamir):",
            ),
            (
                BenchHeadings,
                "| k/n | stored per byte (nominal / measured) | lost pieces tolerated | tolerance verified | dissolve MiB/s | recover MiB/s |",
            ),
            (BenchStoreHeading, " local store MiB/s |"),
            (BenchVerifiedYes, "yes"),
            (BenchVerifiedNo, "NO"),
            (
                PresetNotKOverN { s: s("10") },
                "'10' is not of the form k/n, e.g. 10/12",
            ),
            (PresetBadK { s: s("a/b") }, "bad k in 'a/b'"),
            (PresetBadN { s: s("1/b") }, "bad n in '1/b'"),
            (
                PresetOutOfRange { s: s("0/5") },
                "'0/5': need 1 <= k <= n <= 255",
            ),
        ]
    }

    #[test]
    fn every_message_has_english_and_japanese_text() {
        let table = golden();
        assert!(table.len() >= 50);
        for (m, _) in &table {
            let en = m.text(Lang::En);
            let ja = m.text(Lang::Ja);
            assert!(!en.trim().is_empty(), "{} has no English", covered(m));
            assert!(!ja.trim().is_empty(), "{} has no Japanese", covered(m));
        }
        // A translation is never the English text (a copy-paste left behind),
        // except where both languages legitimately read the same.
        for (m, _) in &table {
            if reads_the_same(m) {
                continue;
            }
            assert_ne!(
                m.text(Lang::En),
                m.text(Lang::Ja),
                "{} is not translated",
                covered(m)
            );
        }
    }

    #[test]
    fn english_text_is_what_the_cli_printed_before() {
        for (m, expected) in golden() {
            assert_eq!(m.text(Lang::En), expected, "{}", covered(&m));
        }
    }

    #[test]
    fn japanese_text_contains_kana_or_kanji_where_it_is_prose() {
        for (m, _) in golden() {
            if reads_the_same(&m) {
                continue;
            }
            let ja = m.text(Lang::Ja);
            assert!(!ja.is_ascii(), "{}: {ja}", covered(&m));
        }
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn miasma_lang_selects_the_language() {
        for v in ["ja", "JA", "Ja", "ja_JP", "ja-JP", "ja_JP.UTF-8", " ja "] {
            let env = env_of(&[("MIASMA_LANG", v)]);
            assert_eq!(detect_with(&env, None), Lang::Ja, "{v:?}");
        }
        for v in ["en", "EN", "en_US", "en-GB", "en_US.UTF-8"] {
            let env = env_of(&[("MIASMA_LANG", v)]);
            assert_eq!(detect_with(&env, Some(Lang::Ja)), Lang::En, "{v:?}");
        }
    }

    #[test]
    fn miasma_lang_beats_the_os_and_an_unknown_value_is_english() {
        let env = env_of(&[("MIASMA_LANG", "fr"), ("LANG", "ja_JP.UTF-8")]);
        assert_eq!(detect_with(&env, Some(Lang::Ja)), Lang::En);
        // Empty means "not set".
        let env = env_of(&[("MIASMA_LANG", "  ")]);
        assert_eq!(detect_with(&env, Some(Lang::Ja)), Lang::Ja);
    }

    #[test]
    fn without_miasma_lang_the_os_language_then_the_locale_variables_decide() {
        let none = env_of(&[]);
        assert_eq!(detect_with(&none, Some(Lang::Ja)), Lang::Ja);
        assert_eq!(detect_with(&none, Some(Lang::En)), Lang::En);
        assert_eq!(detect_with(&none, None), Lang::En);

        let env = env_of(&[("LANG", "ja_JP.UTF-8")]);
        assert_eq!(detect_with(&env, None), Lang::Ja);
        // LC_ALL outranks LANG, and "C" is English, not "keep looking".
        let env = env_of(&[("LC_ALL", "C"), ("LANG", "ja_JP.UTF-8")]);
        assert_eq!(detect_with(&env, None), Lang::En);
        let env = env_of(&[("LC_MESSAGES", "ja_JP"), ("LANG", "en_US.UTF-8")]);
        assert_eq!(detect_with(&env, None), Lang::Ja);
        let env = env_of(&[("LC_ALL", ""), ("LANG", "ja_JP.UTF-8")]);
        assert_eq!(detect_with(&env, None), Lang::Ja);
    }

    #[test]
    fn the_lang_flag_accepts_the_same_spellings_and_refuses_the_rest() {
        assert_eq!(parse_lang_arg("ja"), Ok(Lang::Ja));
        assert_eq!(parse_lang_arg("EN"), Ok(Lang::En));
        assert_eq!(parse_lang_arg("ja-JP"), Ok(Lang::Ja));
        assert!(parse_lang_arg("fr").is_err());
        assert!(parse_lang_arg("").is_err());
    }

    #[test]
    fn the_password_errors_are_matched_against_the_real_core_messages() {
        use miasma_core::MiasmaError;
        assert_eq!(
            MiasmaError::WrongPassword.to_string(),
            Msg::WrongPassword.text(Lang::En)
        );
        assert!(MiasmaError::PasswordRequired
            .to_string()
            .contains(CORE_PASSWORD_REQUIRED));
        assert_eq!(
            MiasmaError::PasswordRequired.to_string(),
            Msg::PasswordRequired.text(Lang::En)
        );
    }

    #[test]
    fn daemon_password_errors_are_translated_only_in_japanese() {
        let wrong = "wrong password";
        let need = "this transfer is password-protected; a password is required";
        assert_eq!(localize_daemon_error(wrong, Lang::En), wrong);
        assert_eq!(localize_daemon_error(need, Lang::En), need);
        assert_eq!(
            localize_daemon_error(wrong, Lang::Ja),
            Msg::WrongPassword.text(Lang::Ja)
        );
        assert_eq!(
            localize_daemon_error(need, Lang::Ja),
            Msg::PasswordRequired.text(Lang::Ja)
        );
        // Anything else is the daemon's own text, untouched.
        assert_eq!(localize_daemon_error("disk full", Lang::Ja), "disk full");
        // And it reaches the messages that show daemon text.
        assert!(DaemonErrorProbe::ja(wrong).contains("パスワード"));
    }

    struct DaemonErrorProbe;
    impl DaemonErrorProbe {
        fn ja(e: &str) -> String {
            Msg::DaemonError { e: e.to_owned() }.text(Lang::Ja)
        }
    }

    #[test]
    fn display_width_counts_wide_characters_as_two_columns() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("セグメント"), 10);
        assert_eq!(display_width("seg 1"), 5);
    }
}
