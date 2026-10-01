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

/// One password-policy violation code (from miasma-core) as a clause.
pub fn policy_problem(code: &str, lang: Lang) -> String {
    match (code, lang) {
        ("too_short", Lang::En) => "it is shorter than 6 characters".into(),
        ("too_long", Lang::En) => "it is longer than 1024 characters".into(),
        ("no_digit", Lang::En) => "it has no digit (0-9)".into(),
        ("no_letter", Lang::En) => "it has no letter (a-z, A-Z)".into(),
        ("no_symbol", Lang::En) => "it has no symbol such as ! # $ %".into(),
        ("too_short", Lang::Ja) => "6 文字未満です".into(),
        ("too_long", Lang::Ja) => "1024 文字を超えています".into(),
        ("no_digit", Lang::Ja) => "数字 (0-9) がありません".into(),
        ("no_letter", Lang::Ja) => "英字 (a-z, A-Z) がありません".into(),
        ("no_symbol", Lang::Ja) => "記号 (! # $ % など) がありません".into(),
        (other, _) => other.to_owned(),
    }
}

/// A daemon-side error text for a person in `lang`. The password errors (and
/// the publish-side weak-password refusal) are translated; everything else is
/// passed through untouched.
pub fn localize_daemon_error(e: &str, lang: Lang) -> String {
    if lang == Lang::Ja {
        if let Some(codes) = miasma_core::transfer::password_policy::parse_codes(e) {
            return Msg::WeakPassword {
                codes: codes.into_iter().map(str::to_owned).collect(),
            }
            .text(lang);
        }
        if e.contains(CORE_WRONG_PASSWORD) {
            return Msg::WrongPassword.text(lang);
        }
        if e.contains(CORE_PASSWORD_REQUIRED) {
            return Msg::PasswordRequired.text(lang);
        }
        // iroh direct transport (receive by share ID alone): the dial failures a
        // person can act on. The English text follows as the detail.
        if let Some(at) = e.find("cannot reach the sender over iroh") {
            let detail = &e[at..];
            let why = if detail.contains("not connected to a relay server") {
                "この PC が iroh のリレーサーバに接続できていません。プロキシ（環境変数 HTTPS_PROXY）や社内ネットワークの制限が原因の可能性があります。リレーの TLS 証明書が信頼されていない可能性もあります（TLS 検査を行うプロキシの内側にいる場合は、そのプロキシの CA を OS の証明書ストアにインストールするか --ca-cert を指定してください）。"
            } else if detail.contains("no connection within") {
                "時間内に送信者へ接続できませんでした。送信者のデーモンが起動していて iroh が有効か（transport.iroh_mode）、送信者がオンラインかを確認してください。"
            } else {
                "送信者へ接続できませんでした。"
            };
            return format!("iroh で送信者に到達できません。{why}（詳細: {detail}）");
        }
        if e.contains("the peer that answered is not the publisher named in the share ID") {
            return format!(
                "応答した相手が共有 ID の公開者の鍵と一致しません。接続を拒否しました（詳細: {e}）"
            );
        }
        if e.contains("iroh is switched off") {
            return format!("iroh はオフです（transport.iroh_mode = off）（詳細: {e}）");
        }
        // Control-channel refusals from the daemon (miasma-core daemon module).
        if e.starts_with("unauthorized:") {
            return "制御トークンが無効か未指定です（データディレクトリの daemon.token を確認してください）".to_owned();
        }
        if e.starts_with("output path rejected:") {
            if let Some(rest) = e.split_once("the output path ").map(|(_, r)| r) {
                if let Some((path, _)) = rest.split_once(" is a folder, not a file") {
                    return format!(
                        "出力先 {path} はフォルダです。フォルダの中のファイル名まで指定してください（例: {path}\\received.bin）"
                    );
                }
            }
            // A path that cannot be written: the daemon's text names the path and the OS error.
            if e.contains("cannot ") || e.contains("no file name") || e.contains("not a folder") {
                return format!(
                    "出力先に書き込めません（詳細: {}）",
                    e.trim_start_matches("output path rejected:").trim()
                );
            }
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
    /// The ID to give the receiver: binds the publisher, the protection state
    /// and the content. Printed in addition to (never instead of) the MID line.
    ShareIdLine {
        id: String,
    },
    ShareIdHint,
    ShareIdNeedsOutput,
    /// A receive started from a bare MID: it cannot tell who published.
    UnauthenticatedMid,

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

    // ---- removing finished transfers ----
    TransfersRemoved {
        removed: u32,
        kept_partial: u32,
    },
    RemoveNotFound {
        id: String,
    },
    RemoveRunning,
    RemovePaused,
    RemoveHasPartial,

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
    /// A new protected transfer's password fails the policy. `codes` are the
    /// stable violation codes from miasma-core (`too_short`, `no_digit`, ...).
    WeakPassword {
        codes: Vec<String>,
    },
    /// Compliant but shorter than 12 characters: a warning, not a refusal.
    PasswordShortWarning,
    /// Printed to stderr after `password-generate` (the password itself goes
    /// to stdout alone).
    PasswordGeneratedNote,

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

    // ---- web ----
    WebNoBridge {
        detail: String,
    },
    WebLinkNote,
    WebOpening,
    WebOpenFailed {
        e: String,
    },

    // ---- direct receive over a tunnel (--via) and `miasma tunnel` ----
    ViaNeedsOutput,
    ViaReceiveFrom {
        urls: String,
    },
    CannotReadCaFile {
        path: String,
    },
    DaemonExposeHint {
        port: u16,
    },
    TunnelNoPort,
    TunnelCloudflaredMissing,
    TunnelStarting {
        port: u16,
    },
    TunnelReady {
        url: String,
    },
    TunnelRunning,
    TunnelNoUrl,

    // ---- iroh direct transport (receive by share ID alone) ----
    /// Printed once when the daemon starts with iroh discovery via n0 enabled.
    DaemonIrohNotice,
    /// `miasma status` line when an iroh endpoint is running.
    StatusIroh {
        mode: String,
        endpoint: String,
        relay: Option<String>,
        connected: bool,
        error: Option<String>,
    },
    /// `miasma status` line when iroh is off.
    StatusIrohOff,
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
            ShareIdLine { id } => format!("Share ID: {id}"),
            ShareIdHint => "  Give the receiver the Share ID (and the password): it also lets them \
                            check who published the file, which the MID alone cannot."
                .into(),
            ShareIdNeedsOutput => "a share ID is verified while receiving to a file: pass -o/--output \
                                   (writing to stdout takes the MID, which cannot check who published)."
                .into(),
            UnauthenticatedMid => "publisher not authenticated: use the share ID".into(),

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
            TransfersRemoved { removed, kept_partial } => {
                let mut t = format!(
                    "Removed {removed} finished transfer(s) from the list. Received files and source files are not touched; a file you sent stays available to peers."
                );
                if *kept_partial > 0 {
                    t.push_str(&format!(
                        "\n  {kept_partial} stopped transfer(s) still hold partial data and were kept; remove one with `miasma transfer-remove <id> --discard-partial`."
                    ));
                }
                t
            }
            RemoveNotFound { id } => format!("no such transfer: {id}"),
            RemoveRunning => "that transfer is still running; cancel it first (`miasma transfer-cancel <id>`).".into(),
            RemovePaused => "that transfer is paused and can be resumed, so it is not finished; run the same command to resume it.".into(),
            RemoveHasPartial => "that transfer stopped with partial data; removing it discards that data. Run again with --discard-partial to do so.".into(),

            DaemonError { e } => format!("daemon error: {e}"),
            UnexpectedResponse { debug } => format!("unexpected response: {debug}"),
            WrongPassword => CORE_WRONG_PASSWORD.into(),
            PasswordRequired => "this transfer is password-protected; a password is required".into(),

            CannotReadPasswordFile { path } => format!("cannot read password file {path}"),
            CannotReadPasswordStdin => "cannot read the password from standard input".into(),
            PasswordEmpty => "the password is empty; refusing to publish with no protection".into(),
            WeakPassword { codes } => format!(
                "this password is not accepted for a new protected transfer: {}. A password needs at least 6 characters with a digit (0-9), a letter (a-z, A-Z) and a symbol such as ! # $ % (a space does not count). Run `miasma password-generate` for a strong one.",
                codes
                    .iter()
                    .map(|c| policy_problem(c, Lang::En))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            PasswordShortWarning => "warning: short password. A password that meets the rules is still easy to guess at 6 to 11 characters, and anyone holding the manifest can try guesses offline. Use 12+ characters or run `miasma password-generate`.".into(),
            PasswordGeneratedNote => "Store this password somewhere safe: it is not saved anywhere and cannot be recovered. The receiver needs it in addition to the MID; share it over a different channel than the MID.".into(),

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

            WebNoBridge { detail } => format!(
                "the web bridge of the daemon is not available: {detail}
  start it with `miasma daemon`"
            ),
            WebLinkNote => "Open the link above in a browser on this computer. The token is in the part after '#', which the browser never sends to the server and keeps for this tab only.
Anyone who has this link can control this node until the daemon restarts: do not share it or paste it into chat.".into(),
            WebOpening => "Opening it in the default browser...".into(),
            WebOpenFailed { e } => format!("could not open the browser ({e}); open the link by hand"),

            ViaNeedsOutput => "--via receives into a file: pass -o/--output.".into(),
            ViaReceiveFrom { urls } => {
                format!("  Fetching directly from {urls} (no DHT lookup, no peers needed).")
            }
            CannotReadCaFile { path } => format!("cannot read CA file {path}"),
            DaemonExposeHint { port } => format!(
                "WebSocket share server: 127.0.0.1:{port} (plain WS; put a tunnel in front of it, the tunnel terminates TLS)\n\
                 To let a receiver behind a firewall fetch from this node with no open port:\n\
                 \x20 cloudflared tunnel --url http://127.0.0.1:{port}\n\
                 (or run `miasma tunnel`), then give the receiver your MID and the wss:// URL it prints:\n\
                 \x20 miasma network-get <MID> -o <file> --via wss://<host>"
            ),
            TunnelNoPort => "the daemon has no WebSocket server port; start it with `miasma daemon --wss-port N`, or pass --port N".into(),
            TunnelCloudflaredMissing => "cloudflared was not found on PATH. Install it (macOS: brew install cloudflared; Windows/Linux: download it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) and run this again. Nothing is downloaded or started automatically.".into(),
            TunnelStarting { port } => format!("Starting cloudflared for http://127.0.0.1:{port} ..."),
            TunnelReady { url } => format!(
                "Tunnel ready. Give the receiver this URL (and the MID):\n  {url}\n\
                 Receiver: miasma network-get <MID> -o <file> --via {url}"
            ),
            TunnelRunning => "The tunnel is running. Press Ctrl-C to stop it.".into(),
            TunnelNoUrl => "cloudflared did not report a tunnel URL; is it able to reach the internet?".into(),

            DaemonIrohNotice => "iroh discovery via n0 is enabled: your endpoint id and addresses are published to n0; disable with transport.iroh_mode=off".into(),
            StatusIroh { mode, endpoint, relay, connected, error } => format!(
                "iroh: {mode} endpoint {endpoint}… home relay {} ({})",
                relay.as_deref().unwrap_or("none"),
                match (connected, error) {
                    (true, _) => "connected".to_owned(),
                    (false, Some(e)) => format!("not connected: {e}"),
                    (false, None) => "not connected".to_owned(),
                }
            ),
            StatusIrohOff => "iroh: off".into(),
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
            ShareIdLine { id } => format!("共有ID: {id}"),
            ShareIdHint => "  受信する人には共有ID(とパスワード)を渡してください。共有IDがあれば、誰が公開したファイルかも確認できます(MIDだけでは確認できません)。".into(),
            ShareIdNeedsOutput => "共有IDの確認はファイルへ受信するときに行われます。-o/--output を指定してください(標準出力へ書き出すにはMIDを使いますが、MIDでは発行元を確認できません)。".into(),
            UnauthenticatedMid => "発行元は確認されていません。共有IDを使ってください".into(),

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
            TransfersRemoved { removed, kept_partial } => {
                let mut t = format!(
                    "完了・失敗・中止した転送を {removed} 件、一覧から外しました。受信したファイルや送信元ファイルには触れていません。送信したファイルは引き続き相手が受け取れます。"
                );
                if *kept_partial > 0 {
                    t.push_str(&format!(
                        "\n  {kept_partial} 件は途中までのデータが残っているため残しました。外すには `miasma transfer-remove <id> --discard-partial` を使います。"
                    ));
                }
                t
            }
            RemoveNotFound { id } => format!("そのような転送はありません: {id}"),
            RemoveRunning => "その転送はまだ実行中です。先に中止してください（`miasma transfer-cancel <id>`）。".into(),
            RemovePaused => "その転送は一時停止中で再開できるため、完了していません。同じコマンドをもう一度実行すると再開します。".into(),
            RemoveHasPartial => "その転送は途中までのデータを残して止まっています。外すとそのデータも破棄されます。破棄してよければ --discard-partial を付けて再実行してください。".into(),

            DaemonError { e } => format!("デーモンのエラー: {}", localize_daemon_error(e, Lang::Ja)),
            UnexpectedResponse { debug } => format!("想定外の応答です: {debug}"),
            WrongPassword => "パスワードが違います。送信した人に確認して、もう一度お試しください。".into(),
            PasswordRequired => "この転送はパスワードで保護されています。--password-file か --password-stdin でパスワードを指定してください。".into(),

            CannotReadPasswordFile { path } => {
                format!("パスワードファイルを読み込めません: {path}")
            }
            CannotReadPasswordStdin => "標準入力からパスワードを読み込めません".into(),
            PasswordEmpty => "パスワードが空です。保護なしでは公開しません".into(),
            WeakPassword { codes } => format!(
                "このパスワードは新しい保護付き転送には使えません: {}。パスワードは 6 文字以上で、数字 (0-9)、英字 (a-z, A-Z)、記号 (! # $ % など) をそれぞれ 1 つ以上含めてください（空白は記号に数えません）。`miasma password-generate` で強いパスワードを作れます。",
                codes
                    .iter()
                    .map(|c| policy_problem(c, Lang::Ja))
                    .collect::<Vec<_>>()
                    .join("、")
            ),
            PasswordShortWarning => "注意: 短いパスワードです。規則を満たしていても 6〜11 文字では推測されやすく、マニフェストを持つ人はオフラインで何度でも試せます。12 文字以上にするか、`miasma password-generate` を使ってください。".into(),
            PasswordGeneratedNote => "このパスワードは安全な場所に保管してください。どこにも保存されず、失くすと復元できません。受信する人には MID とは別の経路で伝えてください。".into(),

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

            WebNoBridge { detail } => format!(
                "デーモンのWebブリッジを利用できません: {detail}
  `miasma daemon` で起動してください"
            ),
            WebLinkNote => "上のリンクを、このコンピュータのブラウザで開いてください。トークンは「#」より後ろにあり、ブラウザはそれをサーバへ送らず、このタブの間だけ保持します。
このリンクを持つ人は、デーモンが再起動されるまでこのノードを操作できます。共有したりチャットに貼り付けたりしないでください。".into(),
            WebOpening => "既定のブラウザで開いています...".into(),
            WebOpenFailed { e } => format!("ブラウザを開けませんでした（{e}）。リンクを手で開いてください"),

            ViaNeedsOutput => "--via はファイルへ受信するときに使います。-o/--output を指定してください。".into(),
            ViaReceiveFrom { urls } => {
                format!("  {urls} から直接取得します（DHT の検索も、ほかのピアも不要です）。")
            }
            CannotReadCaFile { path } => format!("CA ファイル {path} を読めません"),
            DaemonExposeHint { port } => format!(
                "WebSocket 共有サーバ: 127.0.0.1:{port}（平文の WS です。前段にトンネルを置いてください。TLS はトンネルが終端します）\n\
                 ファイアウォールの内側の受信者が、開放ポートなしでこのノードから取得できるようにするには:\n\
                 \x20 cloudflared tunnel --url http://127.0.0.1:{port}\n\
                 （または `miasma tunnel` を実行）。表示された wss:// の URL と MID を受信者へ伝えてください:\n\
                 \x20 miasma network-get <MID> -o <file> --via wss://<host>"
            ),
            TunnelNoPort => "デーモンに WebSocket サーバのポートがありません。`miasma daemon --wss-port N` で起動するか、--port N を指定してください".into(),
            TunnelCloudflaredMissing => "PATH に cloudflared が見つかりません。インストールしてからもう一度実行してください（macOS: brew install cloudflared / Windows・Linux: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ からダウンロード）。ダウンロードや起動は自動では行いません。".into(),
            TunnelStarting { port } => format!("http://127.0.0.1:{port} 向けに cloudflared を起動しています..."),
            TunnelReady { url } => format!(
                "トンネルの準備ができました。この URL（と MID）を受信者へ伝えてください:\n  {url}\n\
                 受信側: miasma network-get <MID> -o <file> --via {url}"
            ),
            TunnelRunning => "トンネルは動作中です。止めるには Ctrl-C を押してください。".into(),
            TunnelNoUrl => "cloudflared がトンネルの URL を報告しませんでした。インターネットに接続できていますか？".into(),

            DaemonIrohNotice => "iroh の探索に n0 を使います: このノードのエンドポイント ID とアドレスが n0 に公開されます。無効にするには transport.iroh_mode=off を設定してください".into(),
            StatusIroh { mode, endpoint, relay, connected, error } => format!(
                "iroh: {mode} エンドポイント {endpoint}… ホームリレー {} ({})",
                relay.as_deref().unwrap_or("なし"),
                match (connected, error) {
                    (true, _) => "接続中".to_owned(),
                    (false, Some(e)) => format!("未接続: {e}"),
                    (false, None) => "未接続".to_owned(),
                }
            ),
            StatusIrohOff => "iroh: オフ".into(),
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

/// The text of `miasma netcheck` (a few lines per fact, plus the verdict).
pub fn format_netcheck(r: &miasma_core::transport::netcheck::NetcheckReport, lang: Lang) -> String {
    use miasma_core::transport::netcheck::{Note, Verdict};
    let ja = lang == Lang::Ja;
    let yn = |b: bool| match (b, ja) {
        (true, false) => "yes",
        (false, false) => "no",
        (true, true) => "はい",
        (false, true) => "いいえ",
    };
    let mut o = String::new();
    let mut line = |en: String, jp: String| {
        o.push_str(if ja { &jp } else { &en });
        o.push('\n');
    };
    line(
        format!("UDP (IPv4 / IPv6):     {} / {}", yn(r.udp_v4), yn(r.udp_v6)),
        format!("UDP(IPv4 / IPv6):      {} / {}", yn(r.udp_v4), yn(r.udp_v6)),
    );
    let varies = |en: bool| match (r.nat_mapping_varies, en) {
        (Some(true), true) => "varies by destination (hole punching unlikely)",
        (Some(false), true) => "stable (hole punching likely)",
        (None, true) => "unknown",
        (Some(true), false) => "宛先ごとに変わる(穴あけは通りにくい)",
        (Some(false), false) => "安定(穴あけが通りやすい)",
        (None, false) => "測れませんでした",
    };
    line(
        format!("NAT mapping:           {}", varies(true)),
        format!("NAT の割り当て:        {}", varies(false)),
    );
    line(
        format!("Relay connection:      {}", yn(r.relay_connected)),
        format!("中継サーバーへの接続:  {}", yn(r.relay_connected)),
    );
    for (url, ms) in &r.relay_latency {
        line(
            format!("  relay {url}  {ms} ms"),
            format!("  中継 {url}  {ms} ms"),
        );
    }
    for p in &r.tcp {
        let res = match (p.ok, p.millis, p.error.as_deref()) {
            (true, Some(ms), _) => format!("OK {ms} ms"),
            (_, _, Some(e)) => format!("NG ({e})"),
            _ => "NG".to_owned(),
        };
        line(
            format!("  TCP {}:{}  {res}", p.host, p.port),
            format!("  TCP {}:{}  {res}", p.host, p.port),
        );
    }
    line(String::new(), String::new());
    let (en, jp) = match r.verdict {
        Verdict::DirectLikely => (
            "Verdict: a direct path is likely; the relay is the backup.",
            "判定: 直接つながる見込みがあります(中継サーバーは予備です)。",
        ),
        Verdict::RelayOnly => (
            "Verdict: relay only. Transfers work but are slow (about 1 MiB/s on the public relay).",
            "判定: 中継サーバー経由のみ。転送はできますが遅くなります(公開の中継で約 1 MiB/s)。",
        ),
        Verdict::HttpsOnly => (
            "Verdict: only HTTPS gets out. Receive through a tunnel: ask the sender to run `miasma tunnel` and use --via wss://…",
            "判定: HTTPS だけが通ります。トンネル経由で受け取ってください(送る側が `miasma tunnel` を実行し、--via wss://… を使う)。",
        ),
        Verdict::Offline => (
            "Verdict: no network path found. Check the connection, proxy and VPN.",
            "判定: 経路が見つかりません。接続、プロキシ、VPN を確認してください。",
        ),
    };
    line(en.to_owned(), jp.to_owned());
    for n in &r.notes {
        let (en, jp) = match n {
            Note::UdpBlocked => (
                "- UDP is blocked: no direct path; the relay carries the data.",
                "- UDP が止められています。直接の経路は使えず、中継サーバーがデータを運びます。",
            ),
            Note::NatMappingVaries => (
                "- The NAT assigns a different public port per destination (symmetric): hole punching rarely works.",
                "- NAT が宛先ごとに別の公開ポートを割り当てています(対称型)。穴あけはほぼ通りません。",
            ),
            Note::CaptivePortal => (
                "- A captive portal may intercept HTTP: sign in to the network first.",
                "- キャプティブポータルが HTTP を横取りしている可能性があります。先にネットワークへのサインインを済ませてください。",
            ),
            Note::ProxyInUse => (
                "- HTTP(S)_PROXY is set: relay and discovery traffic goes through it.",
                "- HTTP(S)_PROXY が設定されています。中継と探索の通信はそれを通ります。",
            ),
            Note::RelayTcpButNoRelay => (
                "- The relay host answers on 443 but the relay connection failed: TLS inspection? Install the proxy's CA in the OS store or pass --ca-cert.",
                "- 中継サーバーの 443 には届きますが、中継への接続に失敗しました。TLS 検査の可能性があります。その CA を OS のストアに入れるか、--ca-cert を指定してください。",
            ),
            Note::TunnelApiUnreachable => (
                "- api.trycloudflare.com is unreachable: `miasma tunnel` will not work from here.",
                "- api.trycloudflare.com に届きません。ここからは `miasma tunnel` が使えません。",
            ),
        };
        line(en.to_owned(), jp.to_owned());
    }
    o
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
            ShareIdLine { .. } => "ShareIdLine",
            ShareIdHint => "ShareIdHint",
            ShareIdNeedsOutput => "ShareIdNeedsOutput",
            UnauthenticatedMid => "UnauthenticatedMid",
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
            TransfersRemoved { .. } => "TransfersRemoved",
            RemoveNotFound { .. } => "RemoveNotFound",
            RemoveRunning => "RemoveRunning",
            RemovePaused => "RemovePaused",
            RemoveHasPartial => "RemoveHasPartial",
            DaemonError { .. } => "DaemonError",
            UnexpectedResponse { .. } => "UnexpectedResponse",
            WrongPassword => "WrongPassword",
            PasswordRequired => "PasswordRequired",
            CannotReadPasswordFile { .. } => "CannotReadPasswordFile",
            CannotReadPasswordStdin => "CannotReadPasswordStdin",
            PasswordEmpty => "PasswordEmpty",
            WeakPassword { .. } => "WeakPassword",
            PasswordShortWarning => "PasswordShortWarning",
            PasswordGeneratedNote => "PasswordGeneratedNote",
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
            WebNoBridge { .. } => "WebNoBridge",
            WebLinkNote => "WebLinkNote",
            WebOpening => "WebOpening",
            WebOpenFailed { .. } => "WebOpenFailed",
            ViaNeedsOutput => "ViaNeedsOutput",
            ViaReceiveFrom { .. } => "ViaReceiveFrom",
            CannotReadCaFile { .. } => "CannotReadCaFile",
            DaemonExposeHint { .. } => "DaemonExposeHint",
            TunnelNoPort => "TunnelNoPort",
            TunnelCloudflaredMissing => "TunnelCloudflaredMissing",
            TunnelStarting { .. } => "TunnelStarting",
            TunnelReady { .. } => "TunnelReady",
            TunnelRunning => "TunnelRunning",
            TunnelNoUrl => "TunnelNoUrl",
            DaemonIrohNotice => "DaemonIrohNotice",
            StatusIroh { .. } => "StatusIroh",
            StatusIrohOff => "StatusIrohOff",
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
                ShareIdLine { id: s("miasma-share:abc") },
                "Share ID: miasma-share:abc",
            ),
            (
                ShareIdHint,
                "  Give the receiver the Share ID (and the password): it also lets them check who published the file, which the MID alone cannot.",
            ),
            (
                ShareIdNeedsOutput,
                "a share ID is verified while receiving to a file: pass -o/--output (writing to stdout takes the MID, which cannot check who published).",
            ),
            (
                UnauthenticatedMid,
                "publisher not authenticated: use the share ID",
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
            (
                TransfersRemoved { removed: 2, kept_partial: 0 },
                "Removed 2 finished transfer(s) from the list. Received files and source files are not touched; a file you sent stays available to peers.",
            ),
            (
                TransfersRemoved { removed: 1, kept_partial: 3 },
                "Removed 1 finished transfer(s) from the list. Received files and source files are not touched; a file you sent stays available to peers.\n  3 stopped transfer(s) still hold partial data and were kept; remove one with `miasma transfer-remove <id> --discard-partial`.",
            ),
            (RemoveNotFound { id: s("miasma:x") }, "no such transfer: miasma:x"),
            (
                RemoveRunning,
                "that transfer is still running; cancel it first (`miasma transfer-cancel <id>`).",
            ),
            (
                RemovePaused,
                "that transfer is paused and can be resumed, so it is not finished; run the same command to resume it.",
            ),
            (
                RemoveHasPartial,
                "that transfer stopped with partial data; removing it discards that data. Run again with --discard-partial to do so.",
            ),
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
                WeakPassword { codes: vec![s("too_short"), s("no_symbol")] },
                "this password is not accepted for a new protected transfer: it is shorter than 6 characters; it has no symbol such as ! # $ %. A password needs at least 6 characters with a digit (0-9), a letter (a-z, A-Z) and a symbol such as ! # $ % (a space does not count). Run `miasma password-generate` for a strong one.",
            ),
            (
                PasswordShortWarning,
                "warning: short password. A password that meets the rules is still easy to guess at 6 to 11 characters, and anyone holding the manifest can try guesses offline. Use 12+ characters or run `miasma password-generate`.",
            ),
            (
                PasswordGeneratedNote,
                "Store this password somewhere safe: it is not saved anywhere and cannot be recovered. The receiver needs it in addition to the MID; share it over a different channel than the MID.",
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
            (
                WebNoBridge { detail: s("no daemon.http") },
                "the web bridge of the daemon is not available: no daemon.http
  start it with `miasma daemon`",
            ),
            (
                WebLinkNote,
                "Open the link above in a browser on this computer. The token is in the part after '#', which the browser never sends to the server and keeps for this tab only.
Anyone who has this link can control this node until the daemon restarts: do not share it or paste it into chat.",
            ),
            (WebOpening, "Opening it in the default browser..."),
            (
                WebOpenFailed { e: s("boom") },
                "could not open the browser (boom); open the link by hand",
            ),
            (ViaNeedsOutput, "--via receives into a file: pass -o/--output."),
            (
                ViaReceiveFrom { urls: s("wss://h.example") },
                "  Fetching directly from wss://h.example (no DHT lookup, no peers needed).",
            ),
            (
                CannotReadCaFile { path: s("ca.pem") },
                "cannot read CA file ca.pem",
            ),
            (
                DaemonExposeHint { port: 8443 },
                "WebSocket share server: 127.0.0.1:8443 (plain WS; put a tunnel in front of it, the tunnel terminates TLS)\nTo let a receiver behind a firewall fetch from this node with no open port:\n  cloudflared tunnel --url http://127.0.0.1:8443\n(or run `miasma tunnel`), then give the receiver your MID and the wss:// URL it prints:\n  miasma network-get <MID> -o <file> --via wss://<host>",
            ),
            (
                TunnelNoPort,
                "the daemon has no WebSocket server port; start it with `miasma daemon --wss-port N`, or pass --port N",
            ),
            (
                TunnelCloudflaredMissing,
                "cloudflared was not found on PATH. Install it (macOS: brew install cloudflared; Windows/Linux: download it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) and run this again. Nothing is downloaded or started automatically.",
            ),
            (
                TunnelStarting { port: 8443 },
                "Starting cloudflared for http://127.0.0.1:8443 ...",
            ),
            (
                TunnelReady { url: s("wss://h.trycloudflare.com") },
                "Tunnel ready. Give the receiver this URL (and the MID):\n  wss://h.trycloudflare.com\nReceiver: miasma network-get <MID> -o <file> --via wss://h.trycloudflare.com",
            ),
            (TunnelRunning, "The tunnel is running. Press Ctrl-C to stop it."),
            (
                TunnelNoUrl,
                "cloudflared did not report a tunnel URL; is it able to reach the internet?",
            ),
            (
                DaemonIrohNotice,
                "iroh discovery via n0 is enabled: your endpoint id and addresses are published to n0; disable with transport.iroh_mode=off",
            ),
            (
                StatusIroh {
                    mode: s("n0"),
                    endpoint: s("0123456789ab"),
                    relay: Some(s("https://relay.example./")),
                    connected: true,
                    error: None,
                },
                "iroh: n0 endpoint 0123456789ab… home relay https://relay.example./ (connected)",
            ),
            (
                StatusIroh {
                    mode: s("custom"),
                    endpoint: s("0123456789ab"),
                    relay: None,
                    connected: false,
                    error: Some(s("unable to connect")),
                },
                "iroh: custom endpoint 0123456789ab… home relay none (not connected: unable to connect)",
            ),
            (StatusIrohOff, "iroh: off"),
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

    #[test]
    fn the_weak_password_message_names_each_problem_in_english_and_japanese() {
        use miasma_core::transfer::password_policy::{check, codes};
        // Three letters only: too short, no digit, no symbol (but a letter).
        let v = check(&compose_pw(3, 0, 0)).unwrap_err();
        let codes: Vec<String> = codes(&v).split(',').map(str::to_owned).collect();
        let en = Msg::WeakPassword {
            codes: codes.clone(),
        }
        .text(Lang::En);
        // The failure messages below are static text: no password, and nothing
        // derived from one, is ever formatted into them.
        assert!(
            en.contains("shorter than 6 characters"),
            "english: too short"
        );
        assert!(en.contains("no digit"), "english: no digit");
        assert!(en.contains("no symbol"), "english: no symbol");
        assert!(!en.contains("no letter"), "english: a letter is present");
        assert!(en.contains("password-generate"), "english: generator hint");
        let ja = Msg::WeakPassword { codes }.text(Lang::Ja);
        assert!(ja.contains("6 文字未満"), "japanese: too short");
        assert!(ja.contains("数字"), "japanese: no digit");
        assert!(
            !ja.contains("英字 (a-z, A-Z) がありません"),
            "japanese: a letter is present"
        );
    }

    #[test]
    fn a_daemon_weak_password_refusal_is_translated_from_its_codes() {
        // Letters and digits, no symbol.
        let e = miasma_core::MiasmaError::WeakPassword(
            miasma_core::transfer::password_policy::check(&compose_pw(3, 4, 0)).unwrap_err(),
        )
        .to_string();
        assert!(
            e == "weak password: no_symbol",
            "unexpected daemon error text"
        );
        assert!(
            localize_daemon_error(&e, Lang::En) == e,
            "english is untouched"
        );
        let ja = localize_daemon_error(&format!("daemon error: {e}"), Lang::Ja);
        assert!(ja.contains("記号"), "japanese: no symbol");
        assert!(ja.contains("password-generate"), "japanese: generator hint");
    }

    /// A password of the given shape built at run time from random draws, so no
    /// test carries a literal password. Order is irrelevant to the policy.
    fn compose_pw(letters: usize, digits: usize, symbols: usize) -> String {
        use std::hash::{BuildHasher, Hasher};
        fn draw(set: Vec<u8>, n: usize) -> String {
            (0..n)
                .map(|_| {
                    let h = std::collections::hash_map::RandomState::new()
                        .build_hasher()
                        .finish();
                    set[(h % set.len() as u64) as usize] as char
                })
                .collect()
        }
        let letters_set: Vec<u8> = (b'a'..=b'z').chain(b'A'..=b'Z').collect();
        let digits_set: Vec<u8> = (b'0'..=b'9').collect();
        let symbols_set: Vec<u8> = (0x21u8..=0x7e).filter(u8::is_ascii_punctuation).collect();
        draw(letters_set, letters) + &draw(digits_set, digits) + &draw(symbols_set, symbols)
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
