//! The Contacts area: trusted-contact push in the desktop app.
//!
//! Everything the daemon knows (contacts, my card, transfers, inbox folder) is read through
//! `WorkerCmd::Push` on the worker thread; this file never touches the network or the disk
//! except to open a folder/file the person clicked. The first half is pure view-model logic
//! (no egui context) and unit-tested headless; the second half draws it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use miasma_core::contacts_suggest::SuggestionInfo;
use miasma_core::push::{
    ContactInfo, Direction, HistoryEntry, PushRequest, PushResponse, PushState, PushTransferInfo,
};

use crate::a11y::CollapsingExt as _;
use crate::app::{card_frame, danger_button};
use crate::locale::{ContactStrings, Locale};
use crate::open_path::{self, Action, Resolved};
use crate::theme::{self, Palette};
use crate::transfers::{fill, format_bytes, format_eta};
use crate::ui_kit::{self as kit, Confirm, Level, ListRow, MenuItem};
use crate::worker::PushFail;

fn pal() -> Palette {
    theme::palette()
}

// ─── Pure: numbers and names ────────────────────────────────────────────────

/// Seconds left at the current rate, or `None` when it cannot be known (no rate yet, or done).
pub fn eta_secs(size: u64, bytes: u64, rate_bps: u64) -> Option<u64> {
    if rate_bps == 0 || bytes >= size {
        return None;
    }
    Some((size - bytes).div_ceil(rate_bps))
}

/// The remaining time in the person's language, compact: `あと 5 秒`, `あと 3 分 12 秒`,
/// `あと 1 時間 5 分` (English keeps `hh:mm:ss`). The words come from `ContactStrings::eta_*`.
pub fn eta_text(c: &ContactStrings, secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86_400,
        (secs % 86_400) / 3600,
        (secs % 3600) / 60,
        secs % 60,
    );
    if d > 999 {
        return format_eta(Some(secs), "d");
    }
    let tpl = if d > 0 {
        c.eta_day
    } else if h > 0 {
        if m == 0 {
            c.eta_hour_even
        } else {
            c.eta_hour
        }
    } else if m > 0 {
        if s == 0 {
            c.eta_min_even
        } else {
            c.eta_min
        }
    } else {
        c.eta_sec
    };
    let (d, h, m, s) = (d.to_string(), h.to_string(), m.to_string(), s.to_string());
    let (h2, m2, s2) = (
        format!("{:0>2}", h),
        format!("{:0>2}", m),
        format!("{:0>2}", s),
    );
    fill(
        tpl,
        &[
            ("d", &d),
            ("h2", &h2),
            ("m2", &m2),
            ("s2", &s2),
            ("h", &h),
            ("m", &m),
            ("s", &s),
        ],
    )
}

/// Progress as `0.0..=1.0`; an empty file is complete only when the transfer is.
pub fn fraction(size: u64, bytes: u64, done: bool) -> f32 {
    if done {
        return 1.0;
    }
    if size == 0 {
        return 0.0;
    }
    ((bytes.min(size) as f64) / (size as f64)) as f32
}

/// Shorten a long (Japanese or otherwise) file name to at most `max` characters, keeping the start
/// and the extension: `とても長い…名前.pdf`. Counts characters, never cuts inside one.
pub fn shorten_name(name: &str, max: usize) -> String {
    let chars: Vec<char> = name.chars().collect();
    if max < 5 || chars.len() <= max {
        return name.to_owned();
    }
    // Keep a short extension (".pdf", ".tar.gz" keeps ".gz") whole.
    let ext_len = match name.rfind('.') {
        Some(i) => {
            let e = name[i..].chars().count();
            if e <= 8 {
                e
            } else {
                0
            }
        }
        None => 0,
    };
    let tail = ext_len + 2.min(max / 4);
    let head = max - tail - 1;
    let head_s: String = chars[..head].iter().collect();
    let tail_s: String = chars[chars.len() - tail..].iter().collect();
    format!("{head_s}…{tail_s}")
}

/// Shorten a contact name (no extension to keep): the start, then `…`. The full name is always
/// available as hover text.
pub fn shorten_label(name: &str, max: usize) -> String {
    let n = name.chars().count();
    if max < 2 || n <= max {
        return name.to_owned();
    }
    let head: String = name.chars().take(max - 1).collect();
    format!("{}…", head.trim_end())
}

/// The last component of a path from either OS.
pub fn base_name(path: &str) -> String {
    crate::transfers::file_name_of(path)
}

/// Parse the max-size box: GiB as a decimal number, `""` = no limit (`Ok(None)`).
/// Accepts an optional unit (`MiB`, `GiB`, `MB`, `GB`, `KiB`). Zero means no limit, too.
/// A per-contact limit above this (100 GiB) gets a warning: it is far more than a disk usually has free.
const VERY_LARGE_LIMIT: u64 = 100 * (1u64 << 30);

pub fn parse_size_limit(text: &str) -> Result<Option<u64>, ()> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let lower = t.to_ascii_lowercase();
    let (num, mult): (&str, f64) = if let Some(n) = lower.strip_suffix("gib") {
        (n, (1u64 << 30) as f64)
    } else if let Some(n) = lower.strip_suffix("gb") {
        (n, (1u64 << 30) as f64)
    } else if let Some(n) = lower.strip_suffix("mib") {
        (n, (1u64 << 20) as f64)
    } else if let Some(n) = lower.strip_suffix("mb") {
        (n, (1u64 << 20) as f64)
    } else if let Some(n) = lower.strip_suffix("kib") {
        (n, 1024.0)
    } else {
        (lower.as_str(), (1u64 << 30) as f64)
    };
    let v: f64 = num.trim().replace(',', ".").parse().map_err(|_| ())?;
    if !v.is_finite() || v < 0.0 || v * mult > 1e18 {
        return Err(());
    }
    let bytes = (v * mult) as u64;
    Ok(if bytes == 0 { None } else { Some(bytes) })
}

/// The box text for an existing limit (GiB, up to 2 decimals).
pub fn size_limit_text(limit: Option<u64>) -> String {
    match limit {
        None => String::new(),
        Some(b) => {
            let g = b as f64 / (1u64 << 30) as f64;
            let s = format!("{g:.2}");
            s.trim_end_matches('0').trim_end_matches('.').to_owned()
        }
    }
}

/// A limit as the person reads it: whole GiB as `20 GiB`, anything else like `512.0 MiB`.
pub fn format_limit(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    if bytes >= GIB && bytes % GIB == 0 {
        format!("{} GiB", bytes / GIB)
    } else {
        format_bytes(bytes)
    }
}

/// Grey hint of the empty max-size box: what applies when it stays empty. `default_limit` is
/// what the daemon reported (0 = unknown, e.g. an older daemon: the built-in default is shown).
pub fn max_size_hint_text(c: &ContactStrings, default_limit: u64) -> String {
    let limit = if default_limit == 0 {
        miasma_core::config::DEFAULT_PUSH_MAX_FILE_SIZE
    } else {
        default_limit
    };
    fill(c.max_size_default_hint, &[("limit", &format_limit(limit))])
}

// ─── Pure: contact card texts ───────────────────────────────────────────────

/// The message to paste into chat or e-mail. Bilingual, and it carries only public things: the
/// contact code is public by design, the verification code is a digest of it. No secret ever
/// goes here. The English and Japanese windows write Japanese plus English; the Simplified
/// Chinese window writes Chinese plus English. The code line is the same in all of them, so any
/// build finds it again.
pub fn invitation_message(code: &str, fingerprint: &str, locale: Locale) -> String {
    match locale {
        Locale::ZhCn => format!(
            "我把我的 Miasma 联系人发给你。 / Here is my Miasma contact.\n\
             \n\
             {code}\n\
             \n\
             安全码 / Verification code: {fingerprint}\n\
             \n\
             使用方法：打开 Miasma 的“联系人”，把整条消息原样粘贴到“添加联系人”，然后点击“添加”。\n\
             How to: open Miasma > Contacts, paste this whole message into \"Add a contact\", then press Add.\n\
             \n\
             联系人代码可以放心分享，它不是密码。\n\
             The contact code is safe to share. It is not a password.\n"
        ),
        Locale::En | Locale::Ja => format!(
            "Miasma の連絡先を送ります。 / Here is my Miasma contact.\n\
             \n\
             {code}\n\
             \n\
             確認用コード / Verification code: {fingerprint}\n\
             \n\
             使い方: Miasma の「連絡先」を開き、「連絡先を追加」にこのメッセージをそのまま貼り付けて、「追加」を押してください。\n\
             How to: open Miasma > Contacts, paste this whole message into \"Add a contact\", then press Add.\n\
             \n\
             連絡先コードは人に見せても大丈夫です。パスワードではありません。\n\
             The contact code is safe to share. It is not a password.\n"
        ),
    }
}

/// Text for the QR code: a plain-text header so a phone camera shows a Text banner instead of
/// "no usable data" for an unknown scheme (same approach as the Share ID QR).
pub fn qr_payload(code: &str) -> String {
    format!("Miasma Contact\n{code}")
}

// ─── Pure: errors ───────────────────────────────────────────────────────────

/// Plain-language text for an `Error{kind, message}` answer. Unknown kinds fall back to the
/// generic text plus the daemon's own message, so nothing is hidden.
/// Full wording (as Technical mode shows it); the window itself calls [`error_text_for`].
#[cfg(test)]
pub fn error_text(c: &ContactStrings, kind: &str, message: &str) -> String {
    error_text_for(c, kind, message, true)
}

/// [`error_text`], with the daemon's own wording after an unknown kind only when `technical`.
pub fn error_text_for(c: &ContactStrings, kind: &str, message: &str, technical: bool) -> String {
    let t = match kind {
        "bad_code" => c.err_bad_code,
        "this_is_me" => c.err_this_is_me,
        "already_exists" => c.err_already_exists,
        "label_taken" => c.err_label_taken,
        "bad_label" => c.err_bad_label,
        "unavailable" => c.err_unavailable,
        "too_many" => c.err_too_many,
        "unknown_contact" => c.err_unknown_contact,
        "send_disabled" => c.err_send_disabled,
        "bad_file" => c.err_bad_file,
        "queue_full" => c.err_queue_full,
        "not_found" => c.err_not_found,
        "internal" => c.err_internal,
        _ => {
            return if !technical || message.trim().is_empty() {
                c.err_other.to_owned()
            } else {
                format!("{}: {}", c.err_other, message.trim())
            }
        }
    };
    t.to_owned()
}

/// What kind of failure a transfer's free-text `error` describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClass {
    /// The other side could not be reached (offline, or the network blocks direct connections).
    Unreachable,
    Other,
}

/// `error_kind` values of the core that mean "the other side could not be reached / answered".
fn kind_is_unreachable(kind: &str) -> bool {
    matches!(kind, "unreachable" | "connection_lost" | "timed_out")
}

/// An inbound transfer that stopped because the connection broke or the sender fell silent.
/// Rows saved by an older daemon have no `error_kind`; their English text is recognised instead.
fn lost_inbound(r: &Row) -> bool {
    match r.error_kind.as_deref() {
        Some(k) => matches!(k, "connection_lost" | "timed_out"),
        None => {
            let e = r.error.as_deref().unwrap_or("").to_ascii_lowercase();
            e.contains("connection lost")
                || e.contains("sender stopped sending")
                || e.contains("sender ended early")
        }
    }
}

/// The core's diagnosis for "this computer is not connected to a relay server".
pub fn error_is_local_relay(error: &str) -> bool {
    error.contains("not connected to a relay server")
}

pub fn classify_failure(error: &str) -> FailClass {
    let e = error.to_ascii_lowercase();
    if e.contains("cannot reach")
        || e.contains("did not reply")
        || e.contains("timed out")
        || e.contains("did not confirm")
        || e.contains("connect")
    {
        FailClass::Unreachable
    } else {
        FailClass::Other
    }
}

// ─── Pure: transfer rows ────────────────────────────────────────────────────

/// One line of the transfer list, from the live board or from persisted history.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub id: String,
    pub outbound: bool,
    pub contact_id: String,
    pub contact_label: String,
    pub name: String,
    pub size: u64,
    pub bytes: u64,
    pub rate_bps: u64,
    pub state: PushState,
    pub error: Option<String>,
    pub reject_reason: Option<String>,
    /// Stable kind of a non-rejection ending, from the daemon (see core `error_kind`).
    pub error_kind: Option<String>,
    /// Outbound: the file this row sent, when the daemon knows it (rows of older daemons: no).
    pub source_path: Option<String>,
    pub saved_as: Option<String>,
    /// Last change, milliseconds since the epoch.
    pub at_ms: u64,
    /// Waiting to retry: when the next attempt is made (ms since the epoch).
    pub next_attempt_at_ms: Option<u64>,
    /// Waiting to retry: how many attempts in a row have failed.
    pub attempt: Option<u32>,
    /// Live speed / path (daemons that predate it: none).
    pub stats: Option<miasma_core::push::stats::TransferStats>,
}

impl Row {
    pub fn finished(&self) -> bool {
        self.state.is_finished()
    }
}

impl From<&PushTransferInfo> for Row {
    fn from(t: &PushTransferInfo) -> Self {
        Row {
            id: t.id.clone(),
            outbound: t.direction == Direction::Out,
            contact_id: t.contact_id.clone(),
            contact_label: t.contact_label.clone(),
            name: t.name.clone(),
            size: t.size,
            bytes: t.bytes,
            rate_bps: t.rate_bps,
            state: t.state,
            error: t.error.clone(),
            reject_reason: t.reject_reason.clone(),
            error_kind: t.error_kind.clone(),
            source_path: t.source_path.clone(),
            saved_as: t.saved_as.clone(),
            at_ms: t.updated_at_ms,
            next_attempt_at_ms: t.next_attempt_at_ms,
            attempt: t.attempt,
            stats: t.stats.clone(),
        }
    }
}

impl From<&HistoryEntry> for Row {
    fn from(h: &HistoryEntry) -> Self {
        Row {
            id: h.id.clone(),
            outbound: h.direction == Direction::Out,
            contact_id: h.contact_id.clone(),
            contact_label: h.contact_label.clone(),
            name: h.name.clone(),
            size: h.size,
            bytes: if h.state == PushState::Done {
                h.size
            } else {
                0
            },
            rate_bps: 0,
            state: h.state,
            error: h.error.clone(),
            reject_reason: h.reject_reason.clone(),
            error_kind: h.error_kind.clone(),
            source_path: h.source_path.clone(),
            saved_as: h.saved_as.clone(),
            at_ms: h.finished_at_ms,
            next_attempt_at_ms: None,
            attempt: None,
            stats: None,
        }
    }
}

/// Live board plus history, one row per id (the live entry wins), unfinished first (oldest
/// first, so the one being sent is on top), then finished ones newest first.
pub fn merge_rows(board: &[PushTransferInfo], history: &[HistoryEntry]) -> Vec<Row> {
    let mut rows: Vec<Row> = board.iter().map(Row::from).collect();
    let have: HashSet<&str> = board.iter().map(|t| t.id.as_str()).collect();
    rows.extend(
        history
            .iter()
            .filter(|h| !have.contains(h.id.as_str()))
            .map(Row::from),
    );
    rows.sort_by(|a, b| match (a.finished(), b.finished()) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        (false, false) => a.at_ms.cmp(&b.at_ms).then_with(|| a.id.cmp(&b.id)),
        (true, true) => b.at_ms.cmp(&a.at_ms).then_with(|| a.id.cmp(&b.id)),
    });
    rows
}

pub fn state_label(c: &ContactStrings, s: PushState) -> &'static str {
    match s {
        PushState::Queued => c.st_queued,
        PushState::Preparing => c.st_preparing,
        PushState::Connecting => c.st_connecting,
        PushState::Sending => c.st_sending,
        PushState::Verifying => c.st_verifying,
        PushState::Done => c.st_done,
        PushState::Failed => c.st_failed,
        PushState::Rejected => c.st_rejected,
        PushState::Cancelled => c.st_cancelled,
        PushState::Waiting => c.st_waiting,
    }
}

/// "2 min", "40 s", "3 h": the wait until `at_ms`, rounded up, in the person's language.
fn wait_in_text(c: &ContactStrings, at_ms: u64, now_ms: u64) -> String {
    let s = at_ms.saturating_sub(now_ms).div_ceil(1000);
    let (tpl, n) = if s < 90 {
        (c.wait_in_sec, s.max(1))
    } else if s < 120 * 60 {
        (c.wait_in_min, s.div_ceil(60))
    } else {
        (c.wait_in_hour, s.div_ceil(3600))
    };
    fill(tpl, &[("n", &n.to_string())])
}

/// What a send that is waiting to retry says: that it keeps trying by itself, when it tries
/// next, and, when the other side is simply offline, that.
pub fn waiting_text(c: &ContactStrings, r: &Row, now_ms: u64) -> String {
    let t = r
        .next_attempt_at_ms
        .map(|at| wait_in_text(c, at, now_ms))
        .unwrap_or_default();
    let mut s = fill(
        c.wait_retry,
        &[("t", &t), ("n", &r.attempt.unwrap_or(1).to_string())],
    );
    // "The other side is offline" would be wrong when it is this computer's relay link that is down.
    let local_relay = r.error.as_deref().is_some_and(error_is_local_relay);
    if r.error_kind.as_deref() == Some("unreachable") && !local_relay {
        s.push(' ');
        s.push_str(c.wait_offline);
    }
    s
}

fn clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Guidance for a finished row that did not succeed, or the live retry note for a row that is
/// still trying. `None` when there is nothing to add.
/// Full wording (as Technical mode shows it); the window itself calls [`row_guidance_for`].
#[cfg(test)]
pub fn row_guidance(c: &ContactStrings, r: &Row) -> Option<String> {
    row_guidance_for(c, r, true)
}

/// [`row_guidance`], with the core's own wording only when `technical`.
pub fn row_guidance_for(c: &ContactStrings, r: &Row, technical: bool) -> Option<String> {
    row_guidance_at(c, r, technical, clock_ms())
}

/// [`row_guidance_for`] at a given time (the countdown of a waiting send depends on it).
pub fn row_guidance_at(
    c: &ContactStrings,
    r: &Row,
    technical: bool,
    now_ms: u64,
) -> Option<String> {
    // The core says so in its error when this computer's own relay link is the problem.
    let local_relay = r.outbound && r.error.as_deref().is_some_and(error_is_local_relay);
    if local_relay
        && matches!(
            r.state,
            PushState::Failed | PushState::Queued | PushState::Connecting
        )
    {
        return Some(c.fail_relay_down.to_owned());
    }
    match r.state {
        PushState::Waiting if r.outbound => {
            let mut s = waiting_text(c, r, now_ms);
            if local_relay {
                s.push(' ');
                s.push_str(c.fail_relay_down);
            }
            Some(s)
        }
        PushState::Failed if r.outbound && r.error_kind.as_deref() == Some("source_changed") => {
            Some(c.fail_source_changed.to_owned())
        }
        PushState::Rejected => Some(
            match r.reject_reason.as_deref() {
                Some("too_large") => c.rej_too_large,
                Some("no_space") => c.rej_no_space,
                Some("not_allowed") => c.rej_not_allowed,
                Some("busy") => c.rej_busy,
                Some("bad_name") => c.rej_bad_name,
                Some("bad_request") => c.rej_bad_request,
                _ => c.st_rejected,
            }
            .to_owned(),
        ),
        // Received files: the other side is the sender. "Could not reach them / is their Miasma
        // running" is about sending, so it is never used for an inbound row.
        PushState::Failed if !r.outbound && lost_inbound(r) => Some(c.fail_lost_in.to_owned()),
        PushState::Cancelled
            if !r.outbound && r.error_kind.as_deref() == Some("peer_cancelled") =>
        {
            Some(c.fail_peer_cancelled.to_owned())
        }
        PushState::Failed => {
            let e = r.error.as_deref().unwrap_or("");
            let unreachable = if r.outbound {
                r.error_kind
                    .as_deref()
                    .map(kind_is_unreachable)
                    .unwrap_or_else(|| classify_failure(e) == FailClass::Unreachable)
            } else {
                false
            };
            Some(if unreachable {
                c.fail_unreachable.to_owned()
            } else if !technical || e.trim().is_empty() {
                c.fail_other.to_owned()
            } else {
                format!("{}: {}", c.fail_other, e.trim())
            })
        }
        // A queued/connecting transfer that carries an error is retrying after one.
        PushState::Queued | PushState::Connecting
            if r.outbound && r.error.as_deref().is_some_and(|e| !e.trim().is_empty()) =>
        {
            let e = r.error.as_deref().unwrap_or("");
            match classify_failure(e) {
                FailClass::Unreachable => Some(c.fail_unreachable.to_owned()),
                FailClass::Other if technical => Some(e.trim().to_owned()),
                FailClass::Other => None,
            }
        }
        _ => None,
    }
}

/// Contacts (by id) that have not registered me: the latest finished outbound transfer to them
/// was refused with `not_allowed`. A later success clears it.
pub fn not_allowed_contacts(rows: &[Row]) -> HashSet<String> {
    let mut latest: HashMap<&str, &Row> = HashMap::new();
    for r in rows.iter().filter(|r| r.outbound && r.finished()) {
        match latest.get(r.contact_id.as_str()) {
            Some(p) if p.at_ms >= r.at_ms => {}
            _ => {
                latest.insert(r.contact_id.as_str(), r);
            }
        }
    }
    latest
        .into_iter()
        .filter(|(_, r)| {
            r.state == PushState::Rejected && r.reject_reason.as_deref() == Some("not_allowed")
        })
        .map(|(k, _)| k.to_owned())
        .collect()
}

/// The muted line under a contact's name. The most pressing thing wins: the other side has not
/// added me (a problem, in the warning colour), sending to them is turned off, a transfer with
/// them is running or waiting, and otherwise they are ready. `rows` are the merged transfers.
pub fn row_status(
    c: &ContactStrings,
    ct: &ContactInfo,
    not_registered: bool,
    rows: &[Row],
) -> (&'static str, Level) {
    if not_registered {
        return (c.chip_not_registered, Level::Warn);
    }
    if !ct.allow_send {
        return (c.send_disabled_note, Level::Muted);
    }
    match rows.iter().find(|r| r.contact_id == ct.id && !r.finished()) {
        Some(r) if r.state == PushState::Waiting => (state_label(c, r.state), Level::Warn),
        Some(r) => (state_label(c, r.state), Level::Info),
        None => (c.row_ready, Level::Muted),
    }
}

/// Inbound transfers that finished successfully and have not been announced yet. `seen` is
/// updated. With `baseline` the current ones are recorded silently (first load: what arrived
/// before the app looked is not news).
pub fn new_arrivals<'a>(
    seen: &mut HashSet<String>,
    rows: &'a [Row],
    baseline: bool,
) -> Vec<&'a Row> {
    let mut fresh = Vec::new();
    for r in rows
        .iter()
        .filter(|r| !r.outbound && r.state == PushState::Done)
    {
        if seen.insert(r.id.clone()) && !baseline {
            fresh.push(r);
        }
    }
    fresh
}

/// One row of the list with the earlier unsuccessful attempts at the same file folded under it.
#[derive(Debug, Clone, PartialEq)]
pub struct Group<'a> {
    pub row: &'a Row,
    pub earlier: Vec<&'a Row>,
}

fn unsuccessful(r: &Row) -> bool {
    matches!(
        r.state,
        PushState::Failed | PushState::Rejected | PushState::Cancelled
    )
}

fn same_file(a: &Row, b: &Row) -> bool {
    a.contact_id == b.contact_id && a.outbound == b.outbound && a.name == b.name && a.size == b.size
}

/// Fold unsuccessful attempts that a later attempt at the same file (same contact, direction,
/// name and size) replaced: the later attempt is running or done. They are listed under that
/// attempt instead of among the rows. Nothing is deleted anywhere; a file that only ever failed
/// keeps its row (with "send again"), and a different file is never touched.
pub fn fold_attempts<'a>(rows: &[&'a Row]) -> Vec<Group<'a>> {
    let mut folded_into: HashMap<&str, &'a Row> = HashMap::new();
    for r in rows.iter().copied().filter(|r| unsuccessful(r)) {
        let host = rows
            .iter()
            .copied()
            .filter(|h| !unsuccessful(h) && h.id != r.id && same_file(h, r) && h.at_ms >= r.at_ms)
            .max_by(|a, b| a.at_ms.cmp(&b.at_ms).then_with(|| a.id.cmp(&b.id)));
        if let Some(h) = host {
            folded_into.insert(r.id.as_str(), h);
        }
    }
    let mut groups: Vec<Group<'a>> = rows
        .iter()
        .copied()
        .filter(|r| !folded_into.contains_key(r.id.as_str()))
        .map(|row| Group {
            row,
            earlier: Vec::new(),
        })
        .collect();
    for r in rows.iter().copied() {
        if let Some(h) = folded_into.get(r.id.as_str()) {
            if let Some(g) = groups.iter_mut().find(|g| g.row.id == h.id) {
                g.earlier.push(r);
            }
        }
    }
    groups
}

/// Cap how many finished rows are drawn. Unfinished rows are always kept. (Deleting finished
/// rows is the daemon's job: [`PushRequest::ClearFinished`]; nothing is hidden here.)
pub fn visible_rows(rows: &[Row], max_finished: usize) -> Vec<&Row> {
    let mut finished = 0usize;
    rows.iter()
        .filter(|r| {
            if !r.finished() {
                return true;
            }
            finished += 1;
            finished <= max_finished
        })
        .collect()
}

/// Which contact row a dropped file belongs to: the row under the pointer, else the only
/// contact. `None` = ask the person to drop it on a row.
pub fn drop_target(
    rects: &[(String, egui::Rect)],
    pos: Option<egui::Pos2>,
    n: usize,
) -> Option<&str> {
    if let Some(p) = pos {
        if let Some((id, _)) = rects.iter().find(|(_, r)| r.contains(p)) {
            return Some(id.as_str());
        }
    }
    if n == 1 {
        return rects.first().map(|(id, _)| id.as_str());
    }
    None
}

// ─── State ──────────────────────────────────────────────────────────────────

// ─── Pure: what became of a file sent from the chat screen ──────────────────

/// A file the person picked to send from the chat screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentFile {
    pub name: String,
    pub path: String,
}

/// Where a file sent from the chat screen stands, read from the push rows. The chat shows
/// "sent" only for [`FileStatus::Done`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    /// Queued, preparing or connecting (or the push row has not appeared yet).
    Waiting,
    Sending {
        percent: u8,
    },
    Done,
    /// Did not go through; `reason` is in the UI language.
    Failed {
        reason: String,
    },
}

/// A clock difference between the chat note and the daemon's row that is still the same send.
const NOTE_SLACK_MS: u64 = 10_000;

fn is_that_file(r: &Row, contact_id: &str, path: &str) -> bool {
    r.outbound
        && r.contact_id == contact_id
        && match r.source_path.as_deref() {
            Some(sp) => sp == path,
            // An older daemon does not report the source: fall back to the file name.
            None => r.name == base_name(path),
        }
}

/// The status of `path` sent to `contact_id` at or after `since_ms`: the newest matching push
/// row decides; with no row yet, a refusal of the send request itself (`failures`) decides.
pub fn file_status_in(
    rows: &[Row],
    failures: &HashMap<(String, String), String>,
    c: &ContactStrings,
    technical: bool,
    contact_id: &str,
    path: &str,
    since_ms: u64,
) -> FileStatus {
    let newest = rows
        .iter()
        .filter(|r| is_that_file(r, contact_id, path) && r.at_ms + NOTE_SLACK_MS >= since_ms)
        .max_by(|a, b| a.at_ms.cmp(&b.at_ms).then_with(|| a.id.cmp(&b.id)));
    match newest {
        Some(r) => match r.state {
            PushState::Queued
            | PushState::Preparing
            | PushState::Connecting
            | PushState::Waiting => FileStatus::Waiting,
            PushState::Sending | PushState::Verifying => FileStatus::Sending {
                percent: (fraction(r.size, r.bytes, false) * 100.0).min(99.0) as u8,
            },
            PushState::Done => FileStatus::Done,
            PushState::Failed | PushState::Rejected | PushState::Cancelled => FileStatus::Failed {
                reason: row_guidance_for(c, r, technical)
                    .unwrap_or_else(|| state_label(c, r.state).to_owned()),
            },
        },
        None => match failures.get(&(contact_id.to_owned(), path.to_owned())) {
            Some(reason) => FileStatus::Failed {
                reason: reason.clone(),
            },
            None => FileStatus::Waiting,
        },
    }
}

/// Most ignored suggestions remembered for the session.
pub const MAX_IGNORED: usize = 64;
/// Most suggestions shown at once (the core keeps at most 16).
pub const MAX_SUGGESTIONS_SHOWN: usize = 16;

/// "just now", "5 min ago", "3 h ago".
pub fn when_text(c: &ContactStrings, now_ms: u64, at_ms: u64) -> String {
    let mins = now_ms.saturating_sub(at_ms) / 60_000;
    if mins < 1 {
        c.sugg_now.to_owned()
    } else if mins < 60 {
        fill(c.sugg_min, &[("n", &mins.to_string())])
    } else {
        fill(c.sugg_hour, &[("n", &(mins / 60).to_string())])
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether the daemon can do contacts at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// Nothing answered yet.
    Unknown,
    Ok,
    /// The daemon is not running.
    DaemonDown,
    /// The daemon runs but iroh is off (push is `unavailable`).
    NoIroh,
    /// The daemon closed the connection on a push request: an older build without push.
    OldDaemon,
}

const POLL_ACTIVE: Duration = Duration::from_millis(500);
const POLL_IDLE: Duration = Duration::from_secs(3);
const RETRY_UNAVAILABLE: Duration = Duration::from_secs(5);
const LIST_EVERY: Duration = Duration::from_secs(5);
const HISTORY_EVERY: Duration = Duration::from_secs(30);
const MAX_FINISHED_SHOWN: usize = 30;
const SUGGEST_EVERY: Duration = Duration::from_secs(10);

pub struct ContactsUi {
    availability: Availability,
    ever_ok: bool,
    was_connected: bool,
    initial_sent: bool,

    contacts: Vec<ContactInfo>,
    contacts_loaded: bool,
    board: Vec<PushTransferInfo>,
    history: Vec<HistoryEntry>,
    rows: Vec<Row>,
    my_code: Option<(String, String)>,
    inbox_dir: Option<String>,

    out: VecDeque<PushRequest>,
    status_in_flight: Option<Instant>,
    last_status: Instant,
    last_list: Instant,
    last_history: Instant,
    last_try: Instant,
    /// Transfer id -> source path, so a failed outbound transfer can be retried.
    paths: HashMap<String, PathBuf>,

    // arrivals
    seen: HashSet<String>,
    baseline_done: bool,
    unseen: u32,
    notices: Vec<String>,
    /// The "delete finished transfers" confirmation is open.
    clear_confirm: bool,

    // "My invitation" dialog
    invite_open: bool,
    show_qr: bool,
    copied_at: Option<Instant>,
    invite_copied_at: Option<Instant>,

    // "Add a contact" dialog
    add_open: bool,
    add_text: String,
    add_label: String,
    add_busy: bool,
    add_error: Option<String>,
    add_result: Option<(String, String)>,

    // list
    edits: HashMap<String, String>,
    max_error: HashSet<String>,
    renaming: Option<(String, String)>,
    /// The contact whose verification code is shown in a dialog, and the one whose permissions
    /// are.
    verify_target: Option<String>,
    perm_target: Option<String>,
    row_rects: Vec<(String, egui::Rect)>,
    page_msg: Option<(String, bool)>,
    /// "Send files" was pressed on this contact's row; the app opens the send flow for them.
    send_request: Option<String>,

    /// Failures of "Open file" / "Show in folder" reported by the helper thread.
    open_tx: std::sync::mpsc::Sender<String>,
    open_rx: std::sync::mpsc::Receiver<String>,
    /// The path the last open was aimed at (named in the notice if it fails).
    last_open: String,
    /// The notice was just set: bring it into view once.
    scroll_to_msg: bool,
    /// Hosts whose folded earlier attempts are expanded.
    show_earlier: HashSet<String>,

    // people who tried to reach me without being a contact
    suggestions: Vec<SuggestionInfo>,
    /// Endpoint ids the person chose to ignore this session (never saved), oldest first.
    ignored: Vec<String>,
    last_suggest: Instant,
    /// The code the add form was filled from a suggestion with: such a contact starts with
    /// sending and receiving off.
    add_from_suggestion: Option<String>,
    /// Chat file sends the daemon refused outright: (contact id, path) -> reason.
    send_failures: HashMap<(String, String), String>,

    /// Dev-only screenshot fixtures: show what was set up, never ask the daemon.
    frozen: bool,

    /// How a daemon failure is worded: the UI language, and whether Technical mode adds the
    /// original wording. Set by the app before it hands over a reply.
    err_locale: Locale,
    err_technical: bool,

    /// Speed units, the sparklines' data, and the UI language for their words.
    speed: crate::speed::SpeedUi,
}

impl Default for ContactsUi {
    fn default() -> Self {
        let now = Instant::now();
        let (open_tx, open_rx) = std::sync::mpsc::channel();
        Self {
            open_tx,
            open_rx,
            last_open: String::new(),
            scroll_to_msg: false,
            show_earlier: HashSet::new(),
            availability: Availability::Unknown,
            ever_ok: false,
            was_connected: false,
            initial_sent: false,
            contacts: Vec::new(),
            contacts_loaded: false,
            board: Vec::new(),
            history: Vec::new(),
            rows: Vec::new(),
            my_code: None,
            inbox_dir: None,
            out: VecDeque::new(),
            status_in_flight: None,
            last_status: now,
            last_list: now,
            last_history: now,
            last_try: now,
            paths: HashMap::new(),
            seen: HashSet::new(),
            baseline_done: false,
            unseen: 0,
            notices: Vec::new(),
            clear_confirm: false,
            invite_open: false,
            show_qr: false,
            copied_at: None,
            invite_copied_at: None,
            add_open: false,
            add_text: String::new(),
            add_label: String::new(),
            add_busy: false,
            add_error: None,
            add_result: None,
            edits: HashMap::new(),
            max_error: HashSet::new(),
            renaming: None,
            verify_target: None,
            perm_target: None,
            row_rects: Vec::new(),
            page_msg: None,
            send_request: None,
            suggestions: Vec::new(),
            ignored: Vec::new(),
            last_suggest: now,
            add_from_suggestion: None,
            send_failures: HashMap::new(),
            frozen: false,
            err_locale: Locale::En,
            err_technical: false,
            speed: Default::default(),
        }
    }
}

fn recent(t: Option<Instant>) -> bool {
    t.is_some_and(|t| t.elapsed() < Duration::from_secs(2))
}

impl ContactsUi {
    /// Arrivals not yet looked at (the badge on the navigation item).
    pub fn unseen(&self) -> u32 {
        self.unseen
    }

    /// The Contacts area is open: the arrivals are seen.
    pub fn mark_seen(&mut self) {
        self.unseen = 0;
    }

    /// Texts for the app's toast, oldest first.
    pub fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
    }

    /// The registered contacts as last read from the service (the Chat area lists them).
    pub fn contact_list(&self) -> &[ContactInfo] {
        &self.contacts
    }

    /// Queue `paths` for contact `id` (the send flow's way to a registered contact). Returns the
    /// files that were queued (folders are refused and not returned; an unknown contact queues
    /// nothing).
    pub fn queue_files(
        &mut self,
        c: &ContactStrings,
        id: &str,
        paths: Vec<PathBuf>,
    ) -> Vec<SentFile> {
        if !self.contacts.iter().any(|x| x.id == id) {
            return Vec::new();
        }
        let sent: Vec<SentFile> = paths
            .iter()
            .filter(|p| !p.is_dir())
            .map(|p| SentFile {
                name: base_name(&p.to_string_lossy()),
                path: p.to_string_lossy().into_owned(),
            })
            .collect();
        self.send_paths(c, id, paths);
        sent
    }

    /// The contact whose "Send files" button was pressed since the last call: the app opens the
    /// send flow for them.
    pub fn take_send_request(&mut self) -> Option<String> {
        self.send_request.take()
    }

    /// The contact a drop at `pos` is meant for: the row under the pointer, else the only
    /// contact. `None` = the person picks in the send flow.
    pub fn drop_contact(&self, pos: Option<egui::Pos2>) -> Option<String> {
        drop_target(&self.row_rects, pos, self.contacts.len()).map(str::to_owned)
    }

    /// Whether `id` is a registered contact the person may send to.
    pub fn can_send_to(&self, id: &str) -> bool {
        self.contacts.iter().any(|x| x.id == id && x.allow_send)
    }

    /// Where a file sent from the chat screen stands (see [`FileStatus`]).
    pub fn file_status(
        &self,
        c: &ContactStrings,
        contact_id: &str,
        path: &str,
        since_ms: u64,
    ) -> FileStatus {
        file_status_in(
            &self.rows,
            &self.send_failures,
            c,
            self.err_technical,
            contact_id,
            path,
            since_ms,
        )
    }

    /// "Send again" for a chat file line: the same file to the same contact. The failed attempt
    /// is dropped from the lists until the new one shows up.
    pub fn resend_file(&mut self, contact_id: &str, path: &str) {
        self.send_failures
            .remove(&(contact_id.to_owned(), path.to_owned()));
        let old: Vec<String> = self
            .rows
            .iter()
            .filter(|r| is_that_file(r, contact_id, path) && r.finished())
            .map(|r| r.id.clone())
            .collect();
        for id in old {
            self.cleared_ids_hide(&id);
        }
        self.out.push_back(PushRequest::Send {
            contact: contact_id.to_owned(),
            path: path.to_owned(),
        });
        self.refresh_soon();
    }

    // ─── Opening received files ─────────────────────────────────────────────

    fn inbox_root(&self) -> Option<PathBuf> {
        self.inbox_dir.as_deref().map(PathBuf::from)
    }

    /// "Open file" / "Show in folder" for a received row. The path is rebuilt and checked first;
    /// a file that is gone opens its folder and says so, and a launcher that fails is reported
    /// with the path that was tried.
    fn open_received(&mut self, c: &ContactStrings, r: &Row, action: Action) {
        // A received file is in the inbox; a sent one is where it was sent from.
        let Some(sa) = (if r.outbound {
            r.source_path.as_deref()
        } else {
            r.saved_as.as_deref()
        }) else {
            return;
        };
        let contact_dir = self
            .contacts
            .iter()
            .find(|x| x.id == r.contact_id && !r.outbound)
            .map(|x| PathBuf::from(&x.inbox_dir));
        match open_path::resolve_saved(sa, contact_dir.as_deref(), self.inbox_root().as_deref()) {
            Resolved::Found(p) => {
                self.last_open = crate::transfers::plain_path(&p.to_string_lossy()).to_owned();
                open_path::launch(action, p, self.open_tx.clone());
            }
            Resolved::Missing { tried, folder } => {
                let shown = crate::transfers::plain_path(&tried.to_string_lossy()).to_owned();
                self.say(fill(c.open_missing, &[("path", &shown)]), true);
                if let Some(f) = folder {
                    self.last_open = crate::transfers::plain_path(&f.to_string_lossy()).to_owned();
                    open_path::launch(Action::Open, f, self.open_tx.clone());
                }
            }
        }
    }

    /// Open a folder, or say it is not there.
    fn open_dir(&mut self, c: &ContactStrings, dir: &str) {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            self.last_open = crate::transfers::plain_path(dir).to_owned();
            open_path::launch(Action::Open, p, self.open_tx.clone());
        } else {
            self.say(
                fill(
                    c.open_missing,
                    &[("path", crate::transfers::plain_path(dir))],
                ),
                true,
            );
        }
    }

    /// Show a notice at the top of the page and scroll it into view (the button that caused it
    /// is usually far below, and a notice nobody sees is the same as nothing happening).
    fn say(&mut self, text: String, is_err: bool) {
        self.page_msg = Some((text, is_err));
        self.scroll_to_msg = true;
    }

    /// Failures reported by the launcher threads become a visible notice.
    fn collect_open_failures(&mut self, c: &ContactStrings) {
        while let Ok(why) = self.open_rx.try_recv() {
            let text = fill(c.open_failed, &[("path", &self.last_open), ("why", &why)]);
            self.say(text, true);
        }
    }

    // ─── Suggestions: people who are not contacts ───────────────────────────

    /// The suggestions to show: not ignored, not already a contact, newest first.
    pub fn visible_suggestions(&self) -> Vec<&SuggestionInfo> {
        self.suggestions
            .iter()
            .filter(|s| !self.ignored.contains(&s.endpoint_id))
            .filter(|s| !self.contacts.iter().any(|c| c.endpoint_id == s.endpoint_id))
            .take(MAX_SUGGESTIONS_SHOWN)
            .collect()
    }

    /// Hide a suggestion for the rest of this session.
    pub fn ignore_suggestion(&mut self, endpoint_id: &str) {
        if self.ignored.iter().any(|i| i == endpoint_id) {
            return;
        }
        self.ignored.push(endpoint_id.to_owned());
        if self.ignored.len() > MAX_IGNORED {
            self.ignored.remove(0);
        }
    }

    /// "Add as contact": fill the add form with the code. Nothing is added until the person
    /// gives a label and presses the form's button, and then with sending and receiving off.
    pub fn add_from_suggestion(&mut self, endpoint_id: &str) {
        let Some(s) = self
            .suggestions
            .iter()
            .find(|s| s.endpoint_id == endpoint_id)
        else {
            return;
        };
        self.add_text = s.code.clone();
        self.add_from_suggestion = Some(s.code.clone());
        self.add_label.clear();
        self.add_error = None;
        self.add_result = None;
        self.add_open = true;
    }

    /// "Add as contact" from outside this tab (a group member): fill the add form with the
    /// contact code. As with a suggestion, nothing is added until the person gives a label and
    /// presses the form's button, and then with sending and receiving off.
    pub fn prefill_add(&mut self, code: &str) {
        self.add_text = code.trim().to_owned();
        self.add_from_suggestion = Some(self.add_text.clone());
        self.add_label.clear();
        self.add_error = None;
        self.add_result = None;
        self.add_open = true;
    }

    fn has_active(&self) -> bool {
        self.rows.iter().any(|r| !r.finished())
    }

    /// How many pushes are not finished, sending or receiving.
    pub fn active_count(&self) -> usize {
        self.rows.iter().filter(|r| !r.finished()).count()
    }

    /// Ask for more data when it is due. Cheap: when the area is closed and nothing is running
    /// this is one small request every 3 s (so arrivals are noticed).
    pub fn tick(&mut self, area_open: bool, connected: bool) {
        if self.frozen {
            return;
        }
        if connected && !self.was_connected {
            // (Re)connected: read everything again.
            self.initial_sent = false;
            self.status_in_flight = None;
        }
        self.was_connected = connected;
        if !connected {
            return;
        }
        if self
            .status_in_flight
            .is_some_and(|t| t.elapsed() > Duration::from_secs(20))
        {
            self.status_in_flight = None;
        }
        if self.status_in_flight.is_some() {
            return;
        }
        let now = Instant::now();
        if !self.initial_sent {
            self.initial_sent = true;
            self.request_all();
            self.last_try = now;
            return;
        }
        if self.availability != Availability::Ok {
            // Not usable: look again now and then (the daemon may have been started meanwhile).
            if now.duration_since(self.last_try) >= RETRY_UNAVAILABLE {
                self.last_try = now;
                self.request_all();
            }
            return;
        }
        let every = if area_open || self.has_active() {
            POLL_ACTIVE
        } else {
            POLL_IDLE
        };
        if now.duration_since(self.last_status) >= every {
            self.last_status = now;
            self.status_in_flight = Some(now);
            self.out.push_back(PushRequest::Status { id: None });
        }
        if area_open && now.duration_since(self.last_list) >= LIST_EVERY {
            self.last_list = now;
            self.out.push_back(PushRequest::ContactList);
        }
        if now.duration_since(self.last_history) >= HISTORY_EVERY {
            self.last_history = now;
            self.out
                .push_back(PushRequest::History { limit: Some(200) });
        }
        if now.duration_since(self.last_suggest) >= SUGGEST_EVERY {
            self.last_suggest = now;
            self.out.push_back(PushRequest::Suggestions);
        }
    }

    fn request_all(&mut self) {
        let now = Instant::now();
        self.status_in_flight = Some(now);
        self.last_status = now;
        self.last_list = now;
        self.last_history = now;
        self.last_suggest = now;
        self.out.push_back(PushRequest::ContactCode);
        self.out.push_back(PushRequest::ContactList);
        self.out.push_back(PushRequest::Suggestions);
        self.out.push_back(PushRequest::Inbox);
        self.out
            .push_back(PushRequest::History { limit: Some(200) });
        self.out.push_back(PushRequest::Status { id: None });
    }

    /// Hand queued requests to the worker; stops at the first one the channel does not take.
    pub fn drain(&mut self, mut try_send: impl FnMut(PushRequest) -> bool) {
        while let Some(req) = self.out.front().cloned() {
            if try_send(req) {
                self.out.pop_front();
            } else {
                break;
            }
        }
    }

    fn refresh_soon(&mut self) {
        // Next tick polls at once.
        self.last_status = Instant::now() - Duration::from_secs(10);
        self.out.push_back(PushRequest::ContactList);
    }

    fn rebuild_rows(&mut self) {
        self.rows = merge_rows(&self.board, &self.history);
        self.speed
            .sparks
            .observe(miasma_core::push::state::now_ms(), &self.rows);
    }

    /// Speed units and language, set by the app from its settings.
    pub fn speed_mut(&mut self) -> &mut crate::speed::SpeedUi {
        &mut self.speed
    }

    /// Say how failures are worded from now on (UI language; Technical adds the original text).
    pub fn set_error_context(&mut self, locale: Locale, technical: bool) {
        self.err_locale = locale;
        self.err_technical = technical;
    }

    /// Process the daemon's answer to a request this UI made.
    pub fn on_reply(
        &mut self,
        c: &ContactStrings,
        req: PushRequest,
        reply: Result<PushResponse, PushFail>,
    ) {
        if self.frozen {
            return;
        }
        let is_status = matches!(req, PushRequest::Status { id: None });
        if is_status {
            self.status_in_flight = None;
        }
        if matches!(req, PushRequest::Suggestions)
            && !matches!(reply, Ok(PushResponse::Suggestions(_)))
        {
            // A daemon that predates suggestions (or a hiccup): nothing to show, nothing to say.
            return;
        }
        let resp = match reply {
            Ok(r) => r,
            Err(f) => {
                if f.daemon_down {
                    self.availability = Availability::DaemonDown;
                } else if !self.ever_ok {
                    // Answered with a closed connection or an error frame: no push in that daemon.
                    self.availability = Availability::OldDaemon;
                }
                let text = if matches!(req, PushRequest::ClearFinished { .. }) && !f.daemon_down {
                    // A daemon from before this request answers that it does not know it (or
                    // drops the connection): say so, nothing was deleted.
                    let mut t = c.clear_old_daemon.to_owned();
                    if self.err_technical {
                        t.push_str(&format!(
                            " ({})",
                            f.message.text(self.err_locale, self.err_technical)
                        ));
                    }
                    t
                } else {
                    f.message.text(self.err_locale, self.err_technical)
                };
                self.fail_request(&req, text);
                return;
            }
        };
        match resp {
            PushResponse::Error { kind, message } => {
                if kind == "unavailable" {
                    self.availability = Availability::NoIroh;
                }
                let text = error_text_for(c, &kind, &message, self.err_technical);
                self.fail_request(&req, text);
            }
            other => {
                self.ever_ok = true;
                self.availability = Availability::Ok;
                self.apply(c, req, other);
            }
        }
    }

    fn fail_request(&mut self, req: &PushRequest, text: String) {
        match req {
            PushRequest::ContactAdd { .. } | PushRequest::ContactAddOff { .. } => {
                self.add_busy = false;
                self.add_error = Some(text);
            }
            PushRequest::Send { contact, path } => {
                if self.send_failures.len() >= 64 {
                    self.send_failures.clear();
                }
                self.send_failures
                    .insert((contact.clone(), path.clone()), text.clone());
                self.page_msg = Some((text, true));
                self.refresh_soon();
            }
            PushRequest::ContactRemove { .. }
            | PushRequest::ContactUpdate { .. }
            | PushRequest::Cancel { .. }
            | PushRequest::RetryNow { .. }
            | PushRequest::ClearFinished { .. } => {
                self.page_msg = Some((text, true));
                self.refresh_soon();
            }
            _ => {}
        }
    }

    fn apply(&mut self, c: &ContactStrings, req: PushRequest, resp: PushResponse) {
        match resp {
            PushResponse::Code {
                code, fingerprint, ..
            } => self.my_code = Some((code, fingerprint)),
            PushResponse::Contacts(list) => {
                self.contacts = list;
                self.contacts_loaded = true;
            }
            PushResponse::Suggestions(list) => {
                self.suggestions = list;
                self.suggestions.truncate(MAX_SUGGESTIONS_SHOWN);
            }
            PushResponse::Contact(info) => {
                if matches!(
                    req,
                    PushRequest::ContactAdd { .. } | PushRequest::ContactAddOff { .. }
                ) {
                    self.add_busy = false;
                    self.add_error = None;
                    self.add_text.clear();
                    self.add_label.clear();
                    self.add_from_suggestion = None;
                    self.add_result = Some((info.label.clone(), info.fingerprint.clone()));
                    self.suggestions
                        .retain(|s| s.endpoint_id != info.endpoint_id);
                }
                if let Some(slot) = self.contacts.iter_mut().find(|x| x.id == info.id) {
                    *slot = info;
                } else {
                    self.contacts.push(info);
                }
                self.out.push_back(PushRequest::ContactList);
            }
            PushResponse::Removed => {
                self.refresh_soon();
            }
            PushResponse::Queued { id } => {
                if let PushRequest::Send { path, .. } = &req {
                    self.paths.insert(id, PathBuf::from(path));
                }
                self.refresh_soon();
            }
            PushResponse::Transfers(list) => {
                self.board = list;
                self.rebuild_rows();
                let baseline = !self.baseline_done;
                self.baseline_done = true;
                // Only the live board counts: history holds older arrivals, not news.
                let live: Vec<Row> = self.board.iter().map(Row::from).collect();
                let fresh: Vec<(String, String)> = new_arrivals(&mut self.seen, &live, baseline)
                    .into_iter()
                    .map(|r| (r.contact_label.clone(), r.name.clone()))
                    .collect();
                for (label, name) in fresh {
                    self.unseen += 1;
                    self.notices.push(fill(
                        c.arrival_toast,
                        &[("label", &label), ("name", &shorten_name(&name, 60))],
                    ));
                }
            }
            PushResponse::Transfer(_) => {}
            PushResponse::Cancelled | PushResponse::Retrying => self.refresh_soon(),
            PushResponse::History(h) => {
                self.history = h;
                self.rebuild_rows();
            }
            PushResponse::Inbox { dir } => self.inbox_dir = Some(dir),
            PushResponse::Cleared {
                transfers, history, ..
            } => {
                // The daemon deleted them; drop what this screen still holds of them and read
                // the lists again so only what the daemon has is shown.
                self.board.retain(|t| !t.state.is_finished());
                self.history.clear();
                self.rebuild_rows();
                let n = transfers.max(history);
                self.page_msg = Some((fill(c.clear_done, &[("n", &n.to_string())]), false));
                self.refresh_soon();
                self.last_history = Instant::now();
                self.out
                    .push_back(PushRequest::History { limit: Some(200) });
            }
            PushResponse::Error { .. } => {}
        }
    }

    // ─── Actions ────────────────────────────────────────────────────────────

    /// Queue `paths` for contact `id`. Folders are refused with a message.
    fn send_paths(&mut self, c: &ContactStrings, id: &str, paths: Vec<PathBuf>) {
        let Some(contact) = self.contacts.iter().find(|x| x.id == id).cloned() else {
            return;
        };
        let mut n = 0u32;
        let mut folder = false;
        for p in paths {
            if p.is_dir() {
                folder = true;
                continue;
            }
            self.out.push_back(PushRequest::Send {
                contact: contact.id.clone(),
                path: p.to_string_lossy().into_owned(),
            });
            n += 1;
        }
        if folder {
            self.page_msg = Some((c.drop_folder.to_owned(), true));
        }
        if n > 0 {
            self.notices.push(fill(
                c.queued_toast,
                &[("n", &n.to_string()), ("label", &contact.label)],
            ));
            self.refresh_soon();
        }
    }

    /// The file a row sent: remembered by this session, else what the daemon recorded.
    fn source_of(&self, r: &Row) -> Option<PathBuf> {
        self.paths
            .get(&r.id)
            .cloned()
            .or_else(|| r.source_path.as_deref().map(PathBuf::from))
    }

    fn retry(&mut self, r: &Row) {
        if let Some(path) = self.source_of(r) {
            self.out.push_back(PushRequest::Send {
                contact: r.contact_id.clone(),
                path: path.to_string_lossy().into_owned(),
            });
            // The failed attempt is replaced by the new one.
            self.cleared_ids_hide(&r.id);
            self.refresh_soon();
        }
    }

    fn cleared_ids_hide(&mut self, id: &str) {
        if let Some(row) = self.rows.iter_mut().find(|x| x.id == id) {
            row.at_ms = 0;
        }
        // Rows at 0 are older than any cutoff only after "Clear finished"; keep it simple and
        // drop the row from the lists until the next refresh brings the new attempt.
        self.board.retain(|t| t.id != id);
        self.history.retain(|h| h.id != id);
        self.rebuild_rows();
    }

    /// "Send again": an outbound transfer that did not complete (failed, refused or cancelled),
    /// whose file is known and whose contact still exists. Not when the other side has not
    /// registered me (`not_allowed`): sending again cannot help until they add me, so the row
    /// shows the guidance only.
    fn can_retry(&self, r: &Row) -> bool {
        r.outbound
            && matches!(
                r.state,
                PushState::Failed | PushState::Rejected | PushState::Cancelled
            )
            && r.reject_reason.as_deref() != Some("not_allowed")
            && self.source_of(r).is_some()
            && self.contacts.iter().any(|c| c.id == r.contact_id)
    }

    fn update_contact(
        &mut self,
        id: &str,
        label: Option<String>,
        allow_send: Option<bool>,
        allow_receive: Option<bool>,
        max_size: Option<u64>,
    ) {
        self.out.push_back(PushRequest::ContactUpdate {
            contact: id.to_owned(),
            label,
            allow_send,
            allow_receive,
            max_size,
        });
    }

    // ─── Drawing ────────────────────────────────────────────────────────────

    /// Draw the whole area: the list of people first, with "Add a contact" and "My invitation"
    /// as two buttons in the title row (each opens a dialog). `technical` adds endpoint ids and
    /// the folder to the verification dialog.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        c: &ContactStrings,
        connected: bool,
        technical: bool,
    ) {
        self.err_technical = technical;
        self.collect_open_failures(c);
        let ready = connected && self.availability == Availability::Ok;
        let buttons = ready && !self.contacts.is_empty();
        let (mut open_add, mut open_invite) = (false, false);
        kit::page_actions(
            ui,
            c.heading,
            None,
            |ui| {
                // Right to left: the first one added is the rightmost.
                if buttons {
                    open_add = ui.add(kit::secondary_button(c.add_title)).clicked();
                    open_invite = ui.add(kit::secondary_button(c.invite_btn)).clicked();
                }
            },
            |ui| self.body(ui, c, connected, technical),
        );
        if open_add {
            self.open_add_dialog();
        }
        if open_invite {
            self.invite_open = true;
        }
    }

    fn open_add_dialog(&mut self) {
        self.add_open = true;
        self.add_result = None;
        self.add_error = None;
    }

    fn body(&mut self, ui: &mut egui::Ui, c: &ContactStrings, connected: bool, technical: bool) {
        if !connected || self.availability == Availability::DaemonDown {
            self.notice_card(ui, c.daemon_down, pal().warning, None);
            return;
        }
        match self.availability {
            Availability::NoIroh => {
                self.notice_card(ui, c.push_unavailable, pal().warning, Some(c.retry_now));
                if technical {
                    // The command is for Technical mode only; Easy mode never names one.
                    ui.add(egui::Label::new(
                        egui::RichText::new("miasma netcheck")
                            .monospace()
                            .color(pal().muted),
                    ));
                }
                return;
            }
            Availability::OldDaemon => {
                self.notice_card(ui, c.old_daemon, pal().warning, Some(c.retry_now));
                return;
            }
            Availability::Unknown => {
                ui.label(egui::RichText::new(c.loading).color(pal().muted));
                return;
            }
            _ => {}
        }

        self.page_message(ui, c);
        self.suggestions_ui(ui, c);

        if self.contacts.is_empty() {
            if self.contacts_loaded {
                let mut invite = false;
                let add = kit::empty_state_with(ui, c.empty_line, c.add_title, |ui| {
                    invite = ui.add(kit::quiet_button(c.invite_btn)).clicked();
                });
                if add {
                    self.open_add_dialog();
                }
                if invite {
                    self.invite_open = true;
                }
            } else {
                ui.label(egui::RichText::new(c.loading).color(pal().muted));
            }
        } else {
            self.list_ui(ui, c);
        }
        // Transfers and the inbox folder are not the point of this page: closed until opened.
        if !self.contacts.is_empty() || !self.rows.is_empty() {
            ui.add_space(kit::GAP_GROUP);
            egui::CollapsingHeader::new(kit::section_text(c.tr_title))
                .id_source("contacts_transfers")
                .default_open(self.has_active())
                .show_a11y(ui, |ui| self.transfers_ui(ui, c));
            egui::CollapsingHeader::new(kit::section_text(c.inbox_title))
                .id_source("contacts_inbox")
                .default_open(false)
                .show_a11y(ui, |ui| self.inbox_ui(ui, c));
        }
        self.dialogs(ui.ctx(), c, technical);
        self.clear_dialog(ui.ctx(), c);
    }

    /// A message about the last action, on one line near the list, with a quiet "Dismiss".
    fn page_message(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        let Some((msg, is_err)) = self.page_msg.clone() else {
            return;
        };
        let top = ui.cursor().min;
        let level = if is_err { Level::Error } else { Level::Ok };
        if kit::inline_message(ui, level, &msg, Some(c.dismiss)) {
            self.page_msg = None;
        }
        if std::mem::take(&mut self.scroll_to_msg) {
            let rect = egui::Rect::from_min_max(
                top,
                egui::pos2(top.x + ui.available_width(), ui.cursor().min.y),
            );
            ui.scroll_to_rect(rect, Some(egui::Align::TOP));
        }
        ui.add_space(kit::SP_2);
    }

    fn notice_card(
        &mut self,
        ui: &mut egui::Ui,
        text: &str,
        color: egui::Color32,
        retry: Option<&str>,
    ) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(egui::RichText::new(text).color(color)).wrap(true));
            if let Some(label) = retry {
                ui.add_space(6.0);
                if ui.button(label).clicked() {
                    self.initial_sent = false;
                    self.availability = Availability::Unknown;
                }
            }
        });
    }

    // ─── Dialogs ────────────────────────────────────────────────────────────

    fn dialogs(&mut self, ctx: &egui::Context, c: &ContactStrings, technical: bool) {
        self.add_dialog(ctx, c);
        self.invite_dialog(ctx, c);
        self.verify_dialog(ctx, c, technical);
        self.perm_dialog(ctx, c);
        self.rename_dialog(ctx, c);
    }

    /// "My invitation": the message to send, the contact code, the QR code and the code to read
    /// out. Behind a button, because a person needs it once per contact.
    fn invite_dialog(&mut self, ctx: &egui::Context, c: &ContactStrings) {
        const KEY: &str = "contact_invite";
        if !self.invite_open {
            return;
        }
        let mut close = false;
        let mine = self.my_code.clone();
        let shown = kit::dialog(ctx, KEY, c.invite_btn, |ui| {
            let Some((code, fp)) = mine else {
                ui.label(egui::RichText::new(c.loading).color(pal().muted));
                return;
            };
            kit::paragraph_muted(ui, c.invite_lead);
            ui.add_space(kit::SP_3);
            let l = if recent(self.invite_copied_at) {
                c.copied
            } else {
                c.copy_invite
            };
            if kit::primary(ui, true, l).clicked() {
                let msg = invitation_message(&code, &fp, c.locale);
                ui.output_mut(|o| o.copied_text = msg);
                self.invite_copied_at = Some(Instant::now());
            }
            ui.add_space(kit::SP_3);
            ui.label(label_text(c.my_code));
            let code_edit = kit::code_display(ui, &code);
            crate::form_check::name(
                &code_edit,
                crate::locale::audit_strings(c.locale).a11y_my_code,
            );
            hint(ui, c.my_code_hint);
            ui.horizontal(|ui| {
                let l = if recent(self.copied_at) {
                    c.copied
                } else {
                    c.copy_code
                };
                if ui.add(kit::quiet_button(l)).clicked() {
                    ui.output_mut(|o| o.copied_text = code.clone());
                    self.copied_at = Some(Instant::now());
                }
                let l = if self.show_qr { c.hide_qr } else { c.show_qr };
                if ui.add(kit::quiet_button(l)).clicked() {
                    self.show_qr = !self.show_qr;
                }
            });
            if self.show_qr {
                ui.add_space(kit::SP_2);
                let qr_name = crate::locale::audit_strings(c.locale).a11y_qr;
                if !crate::transfers::draw_qr(ui, &qr_payload(&code), 240.0, qr_name) {
                    ui.label(egui::RichText::new(c.qr_too_long).color(pal().danger));
                }
                ui.add_space(kit::SP_1);
                hint(ui, c.qr_note);
            }
            ui.add_space(kit::SP_3);
            ui.label(label_text(c.my_fp));
            kit::mono(ui, &fp);
            hint(ui, c.my_fp_hint);
            ui.add_space(kit::SP_3);
            if ui.add(kit::quiet_button(c.done_btn)).clicked() {
                close = true;
            }
        });
        if shown.is_none() || close {
            self.invite_open = false;
            self.show_qr = false;
            if shown.is_some() {
                crate::a11y::dialog_leave(ctx, KEY);
            }
        }
    }

    /// "Add a contact": one field for what they sent; the name is asked once there is something
    /// to add. After the add, the verification code to compare.
    fn add_dialog(&mut self, ctx: &egui::Context, c: &ContactStrings) {
        const KEY: &str = "contact_add";
        if !self.add_open {
            return;
        }
        let mut close = false;
        let shown = kit::dialog(ctx, KEY, c.add_title, |ui| {
            if let Some((label, fp)) = self.add_result.clone() {
                kit::notice(
                    ui,
                    Level::Ok,
                    &fill(c.added_title, &[("label", &shorten_label(&label, 40))]),
                );
                ui.add_space(kit::SP_2);
                ui.label(label_text(c.fingerprint));
                kit::mono(ui, &fp);
                ui.add_space(kit::SP_1);
                hint(ui, c.added_compare);
                ui.add_space(kit::SP_3);
                if kit::primary(ui, true, c.done_btn).clicked() {
                    close = true;
                }
                return;
            }
            if self.add_is_from_suggestion() {
                kit::notice(ui, Level::Warn, c.sugg_prefill_note);
                ui.add_space(kit::SP_2);
            }
            ui.label(label_text(c.paste_what));
            let au = crate::locale::audit_strings(c.locale);
            let add_edit = ui.add(
                kit::input_multiline(&mut self.add_text)
                    .desired_rows(3)
                    .hint_text(c.add_paste),
            );
            crate::form_check::name(&add_edit, au.a11y_add_code);
            let mut label_edit: Option<egui::Response> = None;
            if !self.add_text.trim().is_empty() {
                ui.add_space(kit::SP_2);
                ui.label(label_text(c.add_label));
                let r = ui.add(kit::input(&mut self.add_label).hint_text(c.add_label_hint));
                crate::form_check::name(&r, au.a11y_add_label);
                label_edit = Some(r);
            }
            if let Some(e) = self.add_error.clone() {
                ui.add_space(kit::SP_2);
                kit::notice(ui, Level::Error, &e);
            }
            ui.add_space(kit::SP_3);
            let needs = [crate::form_check::Need::new(
                &add_edit,
                !self.add_text.trim().is_empty(),
                au.need_contact,
            )];
            let attempt = label_edit
                .as_ref()
                .is_some_and(crate::form_check::submitted);
            ui.horizontal(|ui| {
                let l = if self.add_busy {
                    c.add_busy
                } else {
                    c.add_button
                };
                if crate::form_check::primary_with_reason(ui, l, &needs, !self.add_busy, attempt) {
                    let label = self.add_label.trim().to_owned();
                    self.add_result = None;
                    if label.is_empty() {
                        self.add_error = Some(c.label_required.to_owned());
                    } else {
                        self.add_error = None;
                        self.add_busy = true;
                        self.queue_add(label);
                    }
                }
                if ui.add(kit::quiet_button(c.cancel)).clicked() {
                    close = true;
                }
            });
        });
        if shown.is_none() || close {
            self.add_open = false;
            self.add_result = None;
            self.add_error = None;
            self.add_text.clear();
            self.add_label.clear();
            self.add_from_suggestion = None;
            if shown.is_some() {
                crate::a11y::dialog_leave(ctx, KEY);
            }
        }
    }

    /// The verification code of one contact, and how to compare it. Technical mode adds the
    /// endpoint id and the folder.
    fn verify_dialog(&mut self, ctx: &egui::Context, c: &ContactStrings, technical: bool) {
        const KEY: &str = "contact_verify";
        let Some(id) = self.verify_target.clone() else {
            return;
        };
        let Some(ct) = self.contacts.iter().find(|x| x.id == id).cloned() else {
            self.verify_target = None;
            crate::a11y::dialog_leave(ctx, KEY);
            return;
        };
        let not_registered = not_allowed_contacts(&self.rows).contains(&id);
        let mut close = false;
        let shown = kit::dialog(ctx, KEY, c.fingerprint, |ui| {
            let body = fill(c.verify_body, &[("label", &shorten_label(&ct.label, 28))]);
            kit::paragraph(ui, &body);
            ui.add_space(kit::SP_3);
            kit::mono(ui, &ct.fingerprint);
            if not_registered {
                ui.add_space(kit::SP_3);
                kit::notice(ui, Level::Warn, c.hint_not_registered);
            }
            if technical {
                // Identifiers and the folder on this computer are not part of checking the code:
                // they are behind a closed header, each on its own labelled line.
                ui.add_space(kit::SP_3);
                let tech_title = kit::muted_text(crate::uitext::technical_details(c.locale));
                egui::CollapsingHeader::new(tech_title)
                    .id_source("verify_technical")
                    .default_open(false)
                    .show_a11y(ui, |ui| {
                        ui.label(label_text(crate::uitext::endpoint_label(c.locale)));
                        kit::mono(ui, &shorten_name(&ct.endpoint_id, 24));
                        ui.label(label_text(crate::uitext::folder_label(c.locale)));
                        kit::mono(ui, &crate::transfers::plain_path(&ct.inbox_dir));
                    });
            }
            ui.add_space(kit::SP_3);
            if kit::primary(ui, true, c.done_btn).clicked() {
                close = true;
            }
        });
        if shown.is_none() || close {
            self.verify_target = None;
            if shown.is_some() {
                crate::a11y::dialog_leave(ctx, KEY);
            }
        }
    }

    /// Send and receive permissions and the size limit of one contact.
    fn perm_dialog(&mut self, ctx: &egui::Context, c: &ContactStrings) {
        const KEY: &str = "contact_perm";
        let Some(id) = self.perm_target.clone() else {
            return;
        };
        let Some(ct) = self.contacts.iter().find(|x| x.id == id).cloned() else {
            self.perm_target = None;
            crate::a11y::dialog_leave(ctx, KEY);
            return;
        };
        let mut close = false;
        let shown = kit::dialog(ctx, KEY, c.menu_permissions, |ui| {
            ui.add(
                egui::Label::new(kit::section_text(shorten_label(&ct.label, 40))).truncate(true),
            );
            ui.add_space(kit::SP_2);
            let mut recv = ct.allow_receive;
            if ui.checkbox(&mut recv, c.allow_receive).changed() {
                self.set_local(&ct.id, |x| x.allow_receive = recv);
                self.update_contact(&ct.id, None, None, Some(recv), None);
            }
            let mut send = ct.allow_send;
            if ui.checkbox(&mut send, c.allow_send).changed() {
                self.set_local(&ct.id, |x| x.allow_send = send);
                self.update_contact(&ct.id, None, Some(send), None, None);
            }
            ui.add_space(kit::SP_3);
            ui.label(label_text(c.max_size));
            let init = size_limit_text(ct.max_file_size);
            let buf = self
                .edits
                .entry(ct.id.clone())
                .or_insert_with(|| init.clone());
            ui.horizontal(|ui| {
                let w = kit::input_width_beside_button(ui);
                let size_edit = ui.add(
                    kit::input(buf)
                        .desired_width(w)
                        .hint_text(max_size_hint_text(c, ct.default_max_file_size)),
                );
                let size_name = fill(
                    crate::locale::audit_strings(c.locale).a11y_max_size,
                    &[("name", &ct.label)],
                );
                crate::form_check::name(&size_edit, &size_name);
            });
            // Common sizes in one click, what the number means in words, and a warning when it is
            // far more than anyone sends.
            ui.horizontal_wrapped(|ui| {
                for (label, value) in [
                    (crate::uitext::size_preset_default(c.locale), ""),
                    ("1 GiB", "1"),
                    ("10 GiB", "10"),
                    ("100 GiB", "100"),
                ] {
                    if ui.add(kit::compact_button(label)).clicked() {
                        *buf = value.to_owned();
                    }
                }
            });
            match parse_size_limit(buf) {
                Ok(Some(bytes)) if bytes > 0 => {
                    hint(ui, &format!("= {}", format_limit(bytes)));
                    if bytes > VERY_LARGE_LIMIT {
                        kit::notice(
                            ui,
                            Level::Warn,
                            &crate::uitext::size_very_large(c.locale, &format_limit(bytes)),
                        );
                    }
                }
                _ => {}
            }
            let dirty = *buf != init;
            let text = buf.clone();
            // The two check boxes act at once; the size is kept when Done is pressed (one
            // button, no separate Save), and an invalid size keeps the dialog open.
            ui.add_space(kit::SP_3);
            let mut done = kit::primary(ui, true, c.done_btn).clicked();
            if done && dirty {
                match parse_size_limit(&text) {
                    Ok(limit) => {
                        self.max_error.remove(&ct.id);
                        // `Some(0)` clears the limit on the daemon.
                        self.update_contact(&ct.id, None, None, None, Some(limit.unwrap_or(0)));
                        self.set_local(&ct.id, |x| x.max_file_size = limit);
                        self.edits.remove(&ct.id);
                    }
                    Err(()) => {
                        self.max_error.insert(ct.id.clone());
                        done = false;
                    }
                }
            }
            if self.max_error.contains(&ct.id) {
                kit::notice(ui, Level::Error, c.max_size_invalid);
            }
            if done {
                close = true;
            }
        });
        if shown.is_none() || close {
            self.perm_target = None;
            if shown.is_some() {
                crate::a11y::dialog_leave(ctx, KEY);
            }
        }
    }

    fn rename_dialog(&mut self, ctx: &egui::Context, c: &ContactStrings) {
        const KEY: &str = "contact_rename";
        if self.renaming.is_none() {
            return;
        }
        let (mut commit, mut close) = (false, false);
        let old_label = self
            .renaming
            .as_ref()
            .and_then(|(id, _)| self.contacts.iter().find(|x| x.id == *id))
            .map(|x| x.label.clone())
            .unwrap_or_default();
        let shown = kit::dialog(ctx, KEY, c.rename, |ui| {
            if let Some((_, text)) = self.renaming.as_mut() {
                let edit = ui.add(kit::input(text));
                let field_name = fill(
                    crate::locale::audit_strings(c.locale).a11y_rename,
                    &[("name", &old_label)],
                );
                crate::form_check::name(&edit, &field_name);
                let ok = !text.trim().is_empty();
                ui.add_space(kit::SP_3);
                ui.horizontal(|ui| {
                    if kit::primary(ui, ok, c.save).clicked()
                        || (ok
                            && crate::form_check::edit_keys(&edit)
                                == crate::form_check::EditKey::Save)
                    {
                        commit = true;
                    }
                    if ui.add(kit::quiet_button(c.cancel)).clicked() {
                        close = true;
                    }
                });
            }
        });
        if commit {
            if let Some((id, text)) = self.renaming.take() {
                self.update_contact(&id, Some(text.trim().to_owned()), None, None, None);
            }
        }
        if shown.is_none() || close || commit {
            self.renaming = None;
            if shown.is_some() {
                crate::a11y::dialog_leave(ctx, KEY);
            }
        }
    }

    /// A dialog of this screen is open (the app switches the page behind it off).
    pub fn modal_open(&self) -> bool {
        self.invite_open
            || self.add_open
            || self.verify_target.is_some()
            || self.perm_target.is_some()
            || self.renaming.is_some()
            || self.clear_confirm
    }

    /// Ask the daemon to add the contact of the form: switched off when it came from a suggestion.
    fn queue_add(&mut self, label: String) {
        let code = self.add_text.clone();
        self.out.push_back(if self.add_is_from_suggestion() {
            PushRequest::ContactAddOff {
                code,
                label: Some(label),
            }
        } else {
            PushRequest::ContactAdd {
                code,
                label: Some(label),
            }
        });
    }

    /// The form still holds the code a suggestion filled in (not edited into something else).
    fn add_is_from_suggestion(&self) -> bool {
        self.add_from_suggestion
            .as_deref()
            .is_some_and(|code| code == self.add_text.trim())
    }

    /// People who are not contacts and tried to reach me: a short list, one row each.
    fn suggestions_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        let items: Vec<SuggestionInfo> = self.visible_suggestions().into_iter().cloned().collect();
        if items.is_empty() {
            return;
        }
        let now = unix_ms();
        let mut add: Option<String> = None;
        let mut ignore: Option<String> = None;
        ui.label(kit::section_text(c.sugg_title));
        kit::hint(ui, c.sugg_body);
        ui.add_space(kit::SP_1);
        for s in &items {
            let mut line = fill(
                c.sugg_item,
                &[("id", &s.short_id), ("when", &when_text(c, now, s.last_ms))],
            );
            if s.attempts > 1 {
                line.push_str(", ");
                line.push_str(&fill(c.sugg_attempts, &[("n", &s.attempts.to_string())]));
            }
            kit::list_row(
                ui,
                ListRow {
                    avatar: None,
                    title: &line,
                    subtitle: None,
                },
                |ui| {
                    // Right to left: the first one added is the rightmost.
                    if ui.add(kit::secondary_button(c.sugg_add)).clicked() {
                        add = Some(s.endpoint_id.clone());
                    }
                    if ui.add(kit::quiet_button(c.sugg_ignore)).clicked() {
                        ignore = Some(s.endpoint_id.clone());
                    }
                },
            );
        }
        kit::divider(ui);
        if let Some(id) = add {
            self.add_from_suggestion(&id);
        }
        if let Some(id) = ignore {
            self.ignore_suggestion(&id);
        }
        ui.add_space(kit::GAP_GROUP);
    }

    /// The people, one compact row each: initial circle, name, a muted status line, a quiet
    /// "Send" and a "..." menu (Rename, Verify, Permissions, Remove). Nothing else is drawn per
    /// contact, so ten contacts are ten short rows.
    fn list_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        #[derive(Clone, Copy)]
        enum Act {
            Send,
            Rename,
            Verify,
            Permissions,
            Remove,
        }
        let contacts = self.contacts.clone();
        let not_allowed = not_allowed_contacts(&self.rows);
        let mut rects = Vec::new();
        let mut act: Option<(String, String, Act)> = None;
        for ct in &contacts {
            let (status, level) = row_status(c, ct, not_allowed.contains(&ct.id), &self.rows);
            let remove_body = fill(c.remove_body, &[("label", &shorten_label(&ct.label, 40))]);
            let out = kit::list_row(
                ui,
                ListRow {
                    avatar: Some(&ct.label),
                    title: &ct.label,
                    subtitle: Some((status, level)),
                },
                |ui| {
                    // Right to left: the menu is the rightmost, "Send" sits left of it.
                    let items = [
                        MenuItem::new(c.rename),
                        MenuItem::new(c.menu_verify),
                        MenuItem::new(c.menu_permissions),
                        MenuItem::destructive(
                            c.remove,
                            Confirm {
                                title: c.remove_title,
                                body: &remove_body,
                                confirm: c.remove_confirm,
                                cancel: c.cancel,
                            },
                        ),
                    ];
                    if let Some(i) = kit::row_menu(ui, &ct.id, c.menu_more, &items) {
                        let which = match i {
                            0 => Act::Rename,
                            1 => Act::Verify,
                            2 => Act::Permissions,
                            _ => Act::Remove,
                        };
                        act = Some((ct.id.clone(), ct.label.clone(), which));
                    }
                    let send = crate::form_check::add_enabled(
                        ui,
                        ct.allow_send,
                        kit::quiet_button(c.send_short),
                    )
                    .on_hover_text(c.send_files)
                    .on_disabled_hover_text(c.send_disabled_note);
                    // "Send" alone is the same word on every row: name the person for a screen reader.
                    send.widget_info(|| {
                        egui::WidgetInfo::labeled(
                            egui::WidgetType::Button,
                            format!("{} {}", c.send_files, ct.label),
                        )
                    });
                    if send.clicked() {
                        act = Some((ct.id.clone(), ct.label.clone(), Act::Send));
                    }
                },
            );
            rects.push((ct.id.clone(), out.rect));
        }
        kit::divider(ui);
        self.row_rects = rects;
        let Some((id, label, which)) = act else {
            return;
        };
        match which {
            Act::Send => {
                self.send_request = Some(id);
            }
            Act::Rename => self.renaming = Some((id, label)),
            Act::Verify => self.verify_target = Some(id),
            Act::Permissions => self.perm_target = Some(id),
            Act::Remove => {
                self.out.push_back(PushRequest::ContactRemove {
                    contact: id.clone(),
                });
                self.contacts.retain(|x| x.id != id);
                self.edits.remove(&id);
            }
        }
    }

    fn set_local(&mut self, id: &str, f: impl FnOnce(&mut ContactInfo)) {
        if let Some(x) = self.contacts.iter_mut().find(|x| x.id == id) {
            f(x);
        }
    }

    /// Confirm deleting the history of finished transfers (it is deleted in the daemon, on disk).
    fn clear_dialog(&mut self, ctx: &egui::Context, c: &ContactStrings) {
        if !self.clear_confirm {
            return;
        }
        crate::a11y::dialog_enter(ctx, "clear_finished");
        if crate::a11y::esc_pressed(ctx) {
            self.clear_confirm = false;
            crate::a11y::dialog_leave(ctx, "clear_finished");
            return;
        }
        crate::a11y::dialog_title(ctx, c.clear_title);
        egui::Window::new(c.clear_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(380.0)
            .max_width(420.0)
            .show(ctx, |ui| {
                ui.set_max_width(400.0);
                ui.add(egui::Label::new(c.clear_body).wrap(true));
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.add(danger_button(c.clear_confirm)).clicked() {
                        self.out
                            .push_back(PushRequest::ClearFinished { contact: None });
                        self.clear_confirm = false;
                        crate::a11y::dialog_leave(ui.ctx(), "clear_finished");
                    }
                    let cancel = ui.button(c.cancel);
                    crate::a11y::dialog_focus_safe_button(ui.ctx(), "clear_finished", &cancel);
                    if cancel.clicked() {
                        self.clear_confirm = false;
                        crate::a11y::dialog_leave(ui.ctx(), "clear_finished");
                    }
                });
            });
    }

    fn transfers_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        // The title is the collapsing header above; no card around the rows.
        ui.scope(|ui| {
            ui.horizontal_wrapped(|ui| {
                if let Some(t) = self.speed.header_total(&self.rows, ui.max_rect().width()) {
                    ui.label(egui::RichText::new(t).color(pal().muted));
                }
                if self.rows.iter().any(|r| r.finished())
                    && ui.add(kit::quiet_button(c.btn_clear_finished)).clicked()
                {
                    self.clear_confirm = true;
                }
            });
            let rows: Vec<Row> = visible_rows(&self.rows, MAX_FINISHED_SHOWN)
                .into_iter()
                .cloned()
                .collect();
            if rows.is_empty() {
                ui.add(
                    egui::Label::new(egui::RichText::new(c.tr_empty).color(pal().muted)).wrap(true),
                );
                return;
            }
            let refs: Vec<&Row> = rows.iter().collect();
            for (i, g) in fold_attempts(&refs).into_iter().enumerate() {
                if i > 0 {
                    ui.add_space(6.0);
                }
                self.row_ui(ui, c, g.row);
                if !g.earlier.is_empty() {
                    let open = self.show_earlier.contains(&g.row.id);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(label_text(&fill(
                            c.earlier_failed,
                            &[("n", &g.earlier.len().to_string())],
                        )));
                        let l = if open { c.earlier_hide } else { c.earlier_show };
                        if ui.small_button(l).clicked() {
                            if open {
                                self.show_earlier.remove(&g.row.id);
                            } else {
                                self.show_earlier.insert(g.row.id.clone());
                            }
                        }
                    });
                    if open {
                        for e in &g.earlier {
                            ui.add_space(4.0);
                            self.row_ui(ui, c, e);
                        }
                    }
                }
            }
        });
    }

    fn row_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings, r: &Row) {
        inner_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                let (rect, arrow) =
                    ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                // The arrow is drawn with lines; say which way the file goes.
                arrow.widget_info(|| {
                    egui::WidgetInfo::labeled(
                        egui::WidgetType::Label,
                        if r.outbound { c.dir_out } else { c.dir_in },
                    )
                });
                crate::transfers::paint_arrow(ui.painter(), rect.center(), r.outbound, pal().muted);
                let name = ui.add(
                    egui::Label::new(egui::RichText::new(shorten_name(&r.name, 40)).strong())
                        .wrap(true),
                );
                name.on_hover_text(&r.name);
            });
            let who = if r.outbound { c.dir_out } else { c.dir_in };
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "{who}: {}  ·  {}",
                        shorten_label(&r.contact_label, 24),
                        format_bytes(r.size)
                    ))
                    .color(pal().muted),
                );
                let color = match r.state {
                    PushState::Waiting => pal().warning,
                    PushState::Done => pal().success,
                    PushState::Failed | PushState::Rejected => pal().danger,
                    PushState::Cancelled => pal().faint,
                    _ => pal().info,
                };
                crate::transfers::draw_chip(ui, color, state_label(c, r.state));
            });
            if !r.finished() {
                let f = fraction(r.size, r.bytes, false);
                let mut line = format!("{:.1}%", f * 100.0);
                if let Some(t) = self.speed.rate_text(r, ui.available_width()) {
                    line.push_str(&format!("  ·  {t}"));
                }
                if let Some(e) = eta_secs(r.size, r.bytes, r.rate_bps) {
                    line.push_str(&format!("  ·  {}", fill(c.eta, &[("t", &eta_text(c, e))])));
                }
                ui.add_space(2.0);
                // The track must show against the row's own background.
                ui.scope(|ui| {
                    ui.visuals_mut().extreme_bg_color = pal().surface;
                    ui.add(
                        egui::ProgressBar::new(f)
                            .desired_width(ui.available_width().max(60.0))
                            .text(line),
                    );
                });
            }
            self.speed.row_extras(ui, r);
            if let Some(g) = row_guidance_for(c, r, self.err_technical) {
                let color = if r.state == PushState::Cancelled {
                    pal().muted
                } else if r.finished() {
                    pal().danger
                } else {
                    pal().warning
                };
                ui.add_space(2.0);
                ui.add(egui::Label::new(egui::RichText::new(g).color(color)).wrap(true));
            }
            let can_cancel = !r.finished();
            let can_retry = self.can_retry(r);
            let received = !r.outbound && r.state == PushState::Done && r.saved_as.is_some();
            let can_open =
                received || (r.outbound && r.state == PushState::Done && r.source_path.is_some());
            if received {
                if let Some(sa) = r.saved_as.as_deref() {
                    let contact_dir = self
                        .contacts
                        .iter()
                        .find(|x| x.id == r.contact_id)
                        .map(|x| PathBuf::from(&x.inbox_dir));
                    let expected = open_path::expected_path(
                        sa,
                        contact_dir.as_deref(),
                        self.inbox_root().as_deref(),
                    );
                    let full = crate::transfers::plain_path(&expected.to_string_lossy()).to_owned();
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(label_text(&fill(
                            c.saved_to,
                            &[("path", &shorten_name(&full, 70))],
                        )))
                        .wrap(true),
                    )
                    .on_hover_text(full);
                }
            }
            let can_try_now = r.outbound && r.state == PushState::Waiting;
            if can_cancel || can_retry || can_try_now || can_open {
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    if can_try_now && ui.button(c.btn_try_now).clicked() {
                        self.out
                            .push_back(PushRequest::RetryNow { id: r.id.clone() });
                        self.refresh_soon();
                    }
                    if can_cancel && ui.button(c.btn_cancel).clicked() {
                        self.out.push_back(PushRequest::Cancel { id: r.id.clone() });
                    }
                    if can_retry && ui.button(c.btn_retry).clicked() {
                        self.retry(r);
                    }
                    if can_open {
                        if ui.button(c.btn_open_file).clicked() {
                            self.open_received(c, r, Action::Open);
                        }
                        if ui.button(c.btn_show_folder).clicked() {
                            self.open_received(c, r, Action::Reveal);
                        }
                    }
                });
            }
        });
    }

    fn inbox_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        ui.scope(|ui| {
            if let Some(dir) = self.inbox_dir.clone() {
                ui.label(label_text(c.inbox_dir));
                // The path in the monospace font, on its own: the Japanese UI font draws a
                // backslash as a yen sign.
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(crate::transfers::plain_path(&dir)).monospace(),
                    )
                    .wrap(true),
                );
                ui.add_space(6.0);
                if ui.button(c.open_folder).clicked() {
                    self.open_dir(c, &dir);
                }
            }
            ui.add_space(4.0);
            hint(ui, c.inbox_note);
        });
    }
}

// ─── Look: one set of sizes and frames for every section ───────────────────

/// Size of field labels and hints. Never below the app's small size.
const LABEL_SIZE: f32 = 13.0;

/// A field label.
fn label_text(text: &str) -> egui::RichText {
    egui::RichText::new(text)
        .size(LABEL_SIZE)
        .color(pal().muted)
}

/// A line of explanation under a field.
fn hint(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(label_text(text)).wrap(true));
}

/// A row inside a card (a contact, a transfer): quieter than the card itself.
fn inner_frame() -> egui::Frame {
    egui::Frame::none()
        .inner_margin(egui::Margin::same(12.0))
        .rounding(6.0)
        .fill(pal().surface_subtle)
        .stroke(egui::Stroke::new(1.0, pal().border))
}

// ─── Dev-only screenshot fixtures ───────────────────────────────────────────

/// Fixture names for the `ui-tour` screenshots and the layout unit test.
#[cfg(any(test, feature = "ui-tour"))]
pub const FIXTURES: &[&str] = &[
    "empty", "one", "two", "five", "active", "failed", "qr", "verify", "perm", "added", "adderror",
];

#[cfg(any(test, feature = "ui-tour"))]
impl ContactsUi {
    /// A Contacts area filled with fake data (no daemon). `None` for an unknown name.
    pub fn fixture(name: &str, c: &ContactStrings) -> Option<Self> {
        const LONG: &str =
            "株式会社サンプル商事 営業第二部 プロジェクト管理チーム 山田太郎さん（出張中のノートPC）";
        let contact = |id: &str, label: &str, fp: &str, send: bool, max: Option<u64>| ContactInfo {
            id: id.into(),
            label: label.into(),
            endpoint_id: "d9a3f1c07b2e4a58b6c1e0f39a7d5b24c8e61f0a9b3d7c2e5f4a8b1c6d0e3f72".into(),
            fingerprint: fp.into(),
            added_at: 0,
            allow_send: send,
            allow_receive: true,
            max_file_size: max,
            default_max_file_size: 20 << 30,
            inbox_dir: format!(r"C:\Users\Taro\AppData\Local\miasma\data\inbox\{label}"),
        };
        #[allow(clippy::too_many_arguments)]
        let xfer = |id: &str,
                    out: bool,
                    ct: &ContactInfo,
                    file: &str,
                    size: u64,
                    bytes: u64,
                    rate: u64,
                    st: PushState,
                    at: u64| PushTransferInfo {
            id: id.into(),
            direction: if out { Direction::Out } else { Direction::In },
            contact_id: ct.id.clone(),
            contact_label: ct.label.clone(),
            name: file.into(),
            size,
            bytes,
            rate_bps: rate,
            state: st,
            error: None,
            reject_reason: None,
            error_kind: None,
            source_path: None,
            saved_as: None,
            created_at_ms: at,
            updated_at_ms: at,
            next_attempt_at_ms: None,
            attempt: None,
            stats: None,
        };
        let mib = 1u64 << 20;
        let a = contact("a", "田中", "0CS3Y-09W9N-5B5WM-QMMCX", true, None);
        let b = contact("b", LONG, "7KQ2D-4HZ8M-X1N6P-V3RTA", true, Some(2 << 30));
        let mut ui = ContactsUi {
            frozen: true,
            err_locale: Locale::En,
            err_technical: false,
            availability: Availability::Ok,
            ever_ok: true,
            contacts_loaded: true,
            baseline_done: true,
            my_code: Some((
                "miasma-contact:3pg8nKBJuripJfrJxMKBKFY6JSBPhTP266EJPq6Q8RDVL2ymxw".into(),
                "0CS3Y-09W9N-5B5WM-QMMCX".into(),
            )),
            inbox_dir: Some(r"C:\Users\Taro\AppData\Local\miasma\data\inbox".into()),
            ..Default::default()
        };
        let mut board: Vec<PushTransferInfo> = Vec::new();
        match name {
            "empty" => {}
            "one" => ui.contacts = vec![a.clone()],
            "five" => {
                let more = [
                    ("c", "Ken Ito", "4PM7R-2XQ9C-8DJ1T-ZW6VB"),
                    ("d", "Mina", "9TB5L-6NH3F-1KG8S-A2EYP"),
                    ("e", "Sato Hanako", "2WC8V-5RM1J-7ZD4N-QX3GH"),
                ];
                ui.contacts = vec![a.clone(), b.clone()];
                for (id, label, fp) in more {
                    ui.contacts.push(contact(id, label, fp, true, None));
                }
            }
            "two" => {
                ui.contacts = vec![a.clone(), b.clone()];
                let mut n = xfer(
                    "1",
                    true,
                    &b,
                    "請求書_2026年10月分.pdf",
                    3 * mib,
                    0,
                    0,
                    PushState::Rejected,
                    20,
                );
                n.reject_reason = Some("not_allowed".into());
                let mut d = xfer(
                    "2",
                    false,
                    &a,
                    "写真.zip",
                    48 * mib,
                    48 * mib,
                    0,
                    PushState::Done,
                    10,
                );
                d.saved_as = Some("写真.zip".into());
                board = vec![n, d];
            }
            "active" => {
                ui.contacts = vec![a.clone(), b.clone()];
                board = vec![
                    xfer(
                        "1",
                        true,
                        &b,
                        "ミーティング資料_最終版_修正反映済み_営業部確認用_v12.pdf",
                        900 * mib,
                        333 * mib,
                        4_400_000,
                        PushState::Sending,
                        5,
                    ),
                    xfer(
                        "2",
                        false,
                        &a,
                        "backup.img",
                        4 << 30,
                        3 << 30,
                        31_000_000,
                        PushState::Sending,
                        6,
                    ),
                    xfer("3", true, &a, "memo.txt", 1000, 0, 0, PushState::Queued, 7),
                    xfer(
                        "4",
                        true,
                        &a,
                        "photo.jpg",
                        5 * mib,
                        0,
                        0,
                        PushState::Connecting,
                        8,
                    ),
                ];
            }
            "failed" => {
                let mut a2 = a.clone();
                a2.allow_send = false;
                ui.contacts = vec![a2, b.clone()];
                let mut t = 100u64;
                let mut add = |st: PushState, err: Option<&str>, rej: Option<&str>, file: &str| {
                    t += 1;
                    let mut x = xfer(&format!("f{t}"), true, &b, file, 10 * mib, 0, 0, st, t);
                    x.error = err.map(str::to_owned);
                    x.reject_reason = rej.map(str::to_owned);
                    board.push(x);
                };
                add(
                    PushState::Failed,
                    Some("cannot reach the other side: timed out"),
                    None,
                    "届かない.pdf",
                );
                add(
                    PushState::Failed,
                    Some("cannot read the file: access denied"),
                    None,
                    "読めない.pdf",
                );
                add(PushState::Failed, None, None, "原因不明.pdf");
                for r in [
                    "too_large",
                    "no_space",
                    "not_allowed",
                    "busy",
                    "bad_name",
                    "bad_request",
                    "other",
                ] {
                    add(
                        PushState::Rejected,
                        None,
                        Some(r),
                        &format!("rejected_{r}.pdf"),
                    );
                }
                add(PushState::Cancelled, None, None, "中止した.pdf");
                let mut retrying = xfer(
                    "r",
                    true,
                    &b,
                    "再試行中.pdf",
                    10 * mib,
                    0,
                    0,
                    PushState::Connecting,
                    5,
                );
                retrying.error = Some("open stream timed out".into());
                board.push(retrying);
            }
            "qr" => {
                ui.contacts = vec![a.clone()];
                ui.invite_open = true;
                ui.show_qr = true;
            }
            "verify" => {
                ui.contacts = vec![a.clone(), b.clone()];
                ui.verify_target = Some(a.id.clone());
            }
            "perm" => {
                ui.contacts = vec![a.clone(), b.clone()];
                ui.perm_target = Some(b.id.clone());
            }
            "added" => {
                ui.contacts = vec![a.clone()];
                ui.add_open = true;
                ui.add_result = Some(("田中".into(), "0CS3Y-09W9N-5B5WM-QMMCX".into()));
            }
            "adderror" => {
                ui.contacts = vec![a.clone(), b.clone()];
                ui.add_open = true;
                ui.add_text = "これは連絡先コードではありません".into();
                ui.add_label = "山田".into();
                ui.add_error = Some(c.err_bad_code.to_owned());
                ui.page_msg = Some((c.err_send_disabled.to_owned(), true));
            }
            _ => return None,
        }
        ui.board = board;
        ui.rebuild_rows();
        Some(ui)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locale::{contact_strings, Locale};

    fn t(id: &str, dir: Direction, contact: &str, state: PushState, at: u64) -> PushTransferInfo {
        PushTransferInfo {
            id: id.into(),
            direction: dir,
            contact_id: contact.into(),
            contact_label: contact.into(),
            name: format!("{id}.bin"),
            size: 100,
            bytes: 0,
            rate_bps: 0,
            state,
            error: None,
            reject_reason: None,
            error_kind: None,
            source_path: None,
            saved_as: None,
            created_at_ms: at,
            updated_at_ms: at,
            next_attempt_at_ms: None,
            attempt: None,
            stats: None,
        }
    }

    fn rows(v: Vec<PushTransferInfo>) -> Vec<Row> {
        merge_rows(&v, &[])
    }

    #[test]
    fn every_known_error_kind_has_a_specific_message_in_every_locale() {
        let kinds = [
            "bad_code",
            "this_is_me",
            "already_exists",
            "label_taken",
            "bad_label",
            "unavailable",
            "too_many",
            "unknown_contact",
            "send_disabled",
            "bad_file",
            "queue_full",
            "not_found",
            "internal",
        ];
        for lang in Locale::ALL {
            let c = contact_strings(lang);
            let mut seen = HashSet::new();
            for k in kinds {
                let m = error_text(c, k, "raw daemon text");
                assert!(!m.contains("raw daemon text"), "{k} leaked raw text");
                assert!(
                    seen.insert(m),
                    "{lang:?}: two kinds share one message ({k})"
                );
            }
        }
    }

    #[test]
    fn unknown_error_kind_keeps_the_daemon_message() {
        let c = contact_strings(Locale::En);
        assert!(error_text(c, "weird", "boom").contains("boom"));
        assert_eq!(error_text(c, "weird", "  "), c.err_other);
    }

    #[test]
    fn unavailable_says_what_to_do_without_naming_a_command() {
        for l in Locale::ALL {
            let c = contact_strings(l);
            for m in [
                error_text(c, "unavailable", ""),
                c.push_unavailable.to_owned(),
                c.fail_unreachable.to_owned(),
            ] {
                assert!(
                    !m.contains("netcheck") && !m.contains("iroh") && !m.contains("daemon"),
                    "{l:?}: {m}"
                );
            }
        }
    }

    #[test]
    fn unknown_error_kind_hides_the_daemon_message_outside_technical_mode() {
        let c = contact_strings(Locale::En);
        assert_eq!(error_text_for(c, "weird", "boom", false), c.err_other);
        assert!(error_text_for(c, "weird", "boom", true).contains("boom"));
    }

    #[test]
    fn a_local_relay_error_says_the_relay_is_not_connected() {
        let c = contact_strings(Locale::En);
        let mut info = t("r1", Direction::Out, "bob", PushState::Failed, 1);
        info.error = Some(
            "cannot reach the sender over iroh; this computer is not connected to a relay \
             server (unable to connect)"
                .into(),
        );
        let r = rows(vec![info]).remove(0);
        assert_eq!(row_guidance_for(c, &r, false).unwrap(), c.fail_relay_down);
        // The same wording on an inbound row is not about this computer's relay.
        let mut incoming = t("r2", Direction::In, "bob", PushState::Failed, 1);
        incoming.error = Some("this computer is not connected to a relay server".into());
        let r = rows(vec![incoming]).remove(0);
        assert_ne!(row_guidance_for(c, &r, false).unwrap(), c.fail_relay_down);
    }

    #[test]
    fn state_labels_differ_and_are_localised() {
        use PushState::*;
        let all = [
            Queued, Preparing, Connecting, Sending, Verifying, Done, Failed, Rejected, Cancelled,
        ];
        for lang in Locale::ALL {
            let c = contact_strings(lang);
            let set: HashSet<_> = all.iter().map(|s| state_label(c, *s)).collect();
            assert_eq!(set.len(), all.len(), "{lang:?}");
        }
        assert_eq!(state_label(contact_strings(Locale::Ja), Done), "完了");
    }

    #[test]
    fn eta_and_fraction() {
        assert_eq!(eta_secs(1000, 0, 100), Some(10));
        assert_eq!(eta_secs(1001, 0, 100), Some(11));
        assert_eq!(eta_secs(1000, 1000, 100), None);
        assert_eq!(eta_secs(1000, 10, 0), None);
        assert_eq!(fraction(0, 0, false), 0.0);
        assert_eq!(fraction(0, 0, true), 1.0);
        assert!((fraction(200, 50, false) - 0.25).abs() < 1e-6);
        assert_eq!(fraction(100, 500, false), 1.0);
        // 1 GiB+ stays exact enough and finite.
        let g = 5u64 << 30;
        assert!((fraction(g, g / 2, false) - 0.5).abs() < 1e-6);
        assert_eq!(format_eta(eta_secs(g, 0, 10 << 20), "d"), "00:08:32");
    }

    #[test]
    fn shorten_keeps_extension_and_never_splits_a_character() {
        assert_eq!(shorten_name("short.txt", 20), "short.txt");
        let long = "とても長い日本語のファイル名がここに入りますとても長い日本語のファイル名.pdf";
        let s = shorten_name(long, 24);
        assert!(s.chars().count() <= 24, "{s}");
        assert!(s.ends_with(".pdf"), "{s}");
        assert!(s.starts_with("とても"), "{s}");
        assert!(s.contains('…'));
        let noext = "あ".repeat(100);
        assert!(shorten_name(&noext, 10).chars().count() <= 10);
        assert_eq!(shorten_name("abc", 2), "abc");
        // A very long extension is treated as no extension.
        let e = format!("a{}.{}", "b".repeat(50), "x".repeat(30));
        assert!(shorten_name(&e, 20).chars().count() <= 20);
    }

    #[test]
    fn long_contact_names_keep_their_start_and_say_so() {
        let long = "株式会社サンプル商事 営業第二部 プロジェクト管理チーム 山田太郎さん（出張中のノートPC）";
        let s = shorten_label(long, 28);
        assert!(
            s.chars().count() <= 28 && s.ends_with('…') && s.starts_with("株式会社"),
            "{s}"
        );
        assert_eq!(shorten_label("田中", 28), "田中");
    }

    #[test]
    fn every_fixture_builds_and_covers_its_state() {
        for lang in crate::locale::Locale::ALL {
            let c = contact_strings(lang);
            for name in FIXTURES {
                let ui = ContactsUi::fixture(name, c).unwrap_or_else(|| panic!("{name}"));
                assert!(ui.frozen && ui.availability == Availability::Ok);
            }
            assert!(ContactsUi::fixture("nope", c).is_none());
            let two = ContactsUi::fixture("two", c).unwrap();
            assert_eq!(two.contacts.len(), 2);
            assert!(not_allowed_contacts(&two.rows).contains("b"));
            assert!(ContactsUi::fixture("active", c).unwrap().has_active());
            let qr = ContactsUi::fixture("qr", c).unwrap();
            assert!(qr.show_qr && qr.invite_open);
            assert_eq!(ContactsUi::fixture("empty", c).unwrap().contacts.len(), 0);
            assert_eq!(ContactsUi::fixture("one", c).unwrap().contacts.len(), 1);
            assert_eq!(ContactsUi::fixture("five", c).unwrap().contacts.len(), 5);
            assert!(ContactsUi::fixture("verify", c)
                .unwrap()
                .verify_target
                .is_some());
            assert!(ContactsUi::fixture("perm", c)
                .unwrap()
                .perm_target
                .is_some());
            assert!(ContactsUi::fixture("adderror", c).unwrap().add_open);
            let failed = ContactsUi::fixture("failed", c).unwrap();
            for r in failed.rows.iter().filter(|r| r.finished()) {
                assert!(row_guidance(c, r).is_some() || r.state == PushState::Cancelled);
            }
        }
    }

    #[test]
    fn base_name_handles_both_separators() {
        assert_eq!(base_name(r"C:\Users\x\レポート.pdf"), "レポート.pdf");
        assert_eq!(base_name("/Users/x/a.txt"), "a.txt");
    }

    #[test]
    fn size_limit_parsing() {
        assert_eq!(parse_size_limit(""), Ok(None));
        assert_eq!(parse_size_limit("  "), Ok(None));
        assert_eq!(parse_size_limit("0"), Ok(None));
        assert_eq!(parse_size_limit("2"), Ok(Some(2 << 30)));
        assert_eq!(parse_size_limit("0.5"), Ok(Some(1 << 29)));
        assert_eq!(parse_size_limit("1,5 GiB"), Ok(Some(3 << 29)));
        assert_eq!(parse_size_limit("512MiB"), Ok(Some(512 << 20)));
        assert!(parse_size_limit("abc").is_err());
        assert!(parse_size_limit("-1").is_err());
        assert!(parse_size_limit("1e30").is_err());
        assert_eq!(size_limit_text(None), "");
        assert_eq!(size_limit_text(Some(2 << 30)), "2");
        assert_eq!(size_limit_text(Some(3 << 29)), "1.5");
    }

    #[test]
    fn invitation_has_code_and_howto_in_every_language_and_no_secret() {
        let code = "miasma-contact:ABCDEFG";
        for locale in Locale::ALL {
            let m = invitation_message(code, "AAAAA-BBBBB-CCCCC-DDDDD", locale);
            assert!(m.contains(code), "{locale:?}");
            assert!(m.contains("Contacts"), "{locale:?}");
            assert!(m.contains("AAAAA-BBBBB-CCCCC-DDDDD"), "{locale:?}");
            assert!(!m.to_lowercase().contains("password:"), "{locale:?}");
            assert!(!m.contains("secret"), "{locale:?}");
            if locale == Locale::ZhCn {
                assert!(m.contains("联系人") && m.contains("安全码"));
                assert!(!m.contains("連絡先"));
            } else {
                assert!(m.contains("連絡先"), "{locale:?}");
            }
        }
    }

    #[test]
    fn invitation_round_trips_through_the_core_extractor() {
        // The basepoint of Ed25519 is a valid public key.
        let mut id = [0x66u8; 32];
        id[0] = 0x58;
        let code = miasma_core::push::ContactCode::new(id);
        let text = code.to_string();
        // Whatever language the sender's window uses, every build finds the same code again.
        for locale in Locale::ALL {
            let m = invitation_message(&text, &code.fingerprint(), locale);
            assert_eq!(
                miasma_core::push::extract_contact_code(&m).as_deref(),
                Some(text.as_str()),
                "{locale:?}"
            );
        }
        // The text an earlier build sent (Japanese plus English) is still read.
        let old = format!(
            "Miasma の連絡先を送ります。 / Here is my Miasma contact.\n\n{text}\n\n確認用コード / Verification code: {}\n\n使い方: Miasma の「連絡先」を開き、「連絡先を追加」にこのメッセージをそのまま貼り付けて、「追加」を押してください。\nHow to: open Miasma > Contacts, paste this whole message into \"Add a contact\", then press Add.\n\n連絡先コードは人に見せても大丈夫です。パスワードではありません。\nThe contact code is safe to share. It is not a password.\n",
            code.fingerprint()
        );
        assert_eq!(
            old,
            invitation_message(&text, &code.fingerprint(), Locale::Ja)
        );
        assert_eq!(
            miasma_core::push::extract_contact_code(&old).as_deref(),
            Some(text.as_str())
        );
        assert!(qr_payload(&text).starts_with("Miasma Contact\n"));
        assert_eq!(
            miasma_core::push::extract_contact_code(&qr_payload(&text)).as_deref(),
            Some(text.as_str())
        );
    }

    #[test]
    fn failure_classification_and_guidance() {
        let c = contact_strings(Locale::Ja);
        assert_eq!(
            classify_failure("cannot reach the other side: x. Is their Miasma running?"),
            FailClass::Unreachable
        );
        assert_eq!(
            classify_failure("the other side did not reply"),
            FailClass::Unreachable
        );
        assert_eq!(
            classify_failure("cannot read the file: denied"),
            FailClass::Other
        );
        let mut r = rows(vec![t("a", Direction::Out, "bob", PushState::Failed, 1)]).remove(0);
        r.error = Some("cannot reach the other side: timeout".into());
        let g = row_guidance(c, &r).unwrap();
        assert!(g.contains("相手のMiasmaが起動しているか確認してください"));
        r.error = Some("cannot read the file: denied".into());
        assert!(row_guidance(c, &r)
            .unwrap()
            .contains("cannot read the file"));
        r.error = None;
        assert_eq!(row_guidance(c, &r).unwrap(), c.fail_other);
        r.state = PushState::Done;
        assert!(row_guidance(c, &r).is_none());
    }

    #[test]
    fn rejection_reasons_map_to_guidance() {
        let c = contact_strings(Locale::En);
        let mut r = rows(vec![t("a", Direction::Out, "bob", PushState::Rejected, 1)]).remove(0);
        for (reason, expect) in [
            ("too_large", c.rej_too_large),
            ("no_space", c.rej_no_space),
            ("not_allowed", c.rej_not_allowed),
            ("busy", c.rej_busy),
            ("bad_name", c.rej_bad_name),
            ("bad_request", c.rej_bad_request),
            ("other", c.st_rejected),
        ] {
            r.reject_reason = Some(reason.into());
            assert_eq!(row_guidance(c, &r).unwrap(), expect);
        }
    }

    #[test]
    fn retrying_transfer_shows_its_last_error() {
        let c = contact_strings(Locale::En);
        let mut r = rows(vec![t(
            "a",
            Direction::Out,
            "bob",
            PushState::Connecting,
            1,
        )])
        .remove(0);
        assert!(row_guidance(c, &r).is_none());
        r.error = Some("open stream timed out".into());
        assert!(row_guidance(c, &r)
            .unwrap()
            .contains("their Miasma is running"));
    }

    #[test]
    fn not_allowed_hint_only_when_the_latest_push_was_refused() {
        let mut a = t("a", Direction::Out, "bob", PushState::Rejected, 10);
        a.reject_reason = Some("not_allowed".into());
        assert!(not_allowed_contacts(&rows(vec![a.clone()])).contains("bob"));
        // A later success clears it.
        let ok = t("b", Direction::Out, "bob", PushState::Done, 20);
        assert!(not_allowed_contacts(&rows(vec![a.clone(), ok])).is_empty());
        // An earlier success does not.
        let old_ok = t("c", Direction::Out, "bob", PushState::Done, 5);
        assert!(not_allowed_contacts(&rows(vec![a.clone(), old_ok])).contains("bob"));
        // Other refusal reasons, other contacts, inbound and running ones do not count.
        let mut big = t("d", Direction::Out, "carol", PushState::Rejected, 30);
        big.reject_reason = Some("too_large".into());
        let mut inbound = t("e", Direction::In, "dave", PushState::Rejected, 30);
        inbound.reject_reason = Some("not_allowed".into());
        let running = t("f", Direction::Out, "erin", PushState::Sending, 30);
        let set = not_allowed_contacts(&rows(vec![a, big, inbound, running]));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn arrivals_are_counted_once_and_baseline_is_silent() {
        let mut seen = HashSet::new();
        let first = rows(vec![
            t("old", Direction::In, "bob", PushState::Done, 1),
            t("out", Direction::Out, "bob", PushState::Done, 1),
        ]);
        assert!(new_arrivals(&mut seen, &first, true).is_empty());
        assert!(new_arrivals(&mut seen, &first, false).is_empty());
        let second = rows(vec![
            t("old", Direction::In, "bob", PushState::Done, 1),
            t("new", Direction::In, "bob", PushState::Done, 2),
            t("run", Direction::In, "bob", PushState::Sending, 2),
            t("fail", Direction::In, "bob", PushState::Failed, 2),
        ]);
        let fresh = new_arrivals(&mut seen, &second, false);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, "new");
        assert!(new_arrivals(&mut seen, &second, false).is_empty());
    }

    #[test]
    fn arrival_notice_and_badge_via_replies() {
        let c = contact_strings(Locale::Ja);
        let mut ui = ContactsUi::default();
        let list = |v| Ok(PushResponse::Transfers(v));
        ui.on_reply(
            c,
            PushRequest::Status { id: None },
            list(vec![t("x", Direction::In, "bob", PushState::Done, 1)]),
        );
        assert_eq!(ui.unseen(), 0, "first load is a baseline");
        assert!(ui.take_notices().is_empty());
        ui.on_reply(
            c,
            PushRequest::Status { id: None },
            list(vec![
                t("x", Direction::In, "bob", PushState::Done, 1),
                t("y", Direction::In, "bob", PushState::Done, 2),
            ]),
        );
        assert_eq!(ui.unseen(), 1);
        let n = ui.take_notices();
        assert_eq!(n.len(), 1);
        assert!(n[0].contains("bob") && n[0].contains("y.bin"), "{n:?}");
        ui.mark_seen();
        assert_eq!(ui.unseen(), 0);
    }

    #[test]
    fn merge_prefers_live_rows_and_orders_unfinished_first() {
        let board = vec![
            t("run", Direction::Out, "bob", PushState::Sending, 5),
            t("done", Direction::In, "bob", PushState::Done, 9),
        ];
        let hist = vec![
            HistoryEntry {
                id: "done".into(),
                direction: Direction::In,
                contact_id: "bob".into(),
                contact_label: "bob".into(),
                name: "stale".into(),
                size: 1,
                state: PushState::Done,
                error: None,
                reject_reason: None,
                error_kind: None,
                source_path: None,
                saved_as: None,
                finished_at_ms: 1,
            },
            HistoryEntry {
                id: "older".into(),
                direction: Direction::Out,
                contact_id: "bob".into(),
                contact_label: "bob".into(),
                name: "o".into(),
                size: 7,
                state: PushState::Failed,
                error: Some("x".into()),
                reject_reason: None,
                error_kind: None,
                source_path: None,
                saved_as: None,
                finished_at_ms: 3,
            },
        ];
        let r = merge_rows(&board, &hist);
        let ids: Vec<_> = r.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["run", "done", "older"]);
        assert_eq!(r[1].name, "done.bin");
    }

    #[test]
    fn visible_rows_caps_the_finished_ones_and_never_hides_by_time() {
        let mut v = vec![t("run", Direction::Out, "bob", PushState::Sending, 1)];
        for i in 0..10 {
            v.push(t(
                &format!("f{i}"),
                Direction::Out,
                "bob",
                PushState::Done,
                10 + i,
            ));
        }
        let r = rows(v);
        assert_eq!(visible_rows(&r, 100).len(), 11);
        assert_eq!(visible_rows(&r, 3).len(), 4);
        assert!(visible_rows(&r, 0).iter().all(|x| x.id == "run"));
    }

    #[test]
    fn clear_finished_asks_the_daemon_and_shows_what_it_has_afterwards() {
        let c = contact_strings(Locale::En);
        let mut ui = ContactsUi::default();
        let run = t("run", Direction::Out, "bob", PushState::Sending, 1);
        ui.on_reply(
            c,
            PushRequest::Status { id: None },
            Ok(PushResponse::Transfers(vec![
                run,
                t("done", Direction::Out, "bob", PushState::Done, 5),
            ])),
        );
        assert_eq!(ui.rows.len(), 2);
        ui.out.clear();
        // The daemon's answer: the finished row leaves, the running one stays, and the lists
        // are read again from the daemon (no local hiding).
        ui.on_reply(
            c,
            PushRequest::ClearFinished { contact: None },
            Ok(PushResponse::Cleared {
                transfers: 1,
                history: 4,
                partials: 0,
            }),
        );
        assert_eq!(ui.rows.len(), 1);
        assert_eq!(ui.rows[0].id, "run");
        assert!(ui
            .out
            .iter()
            .any(|r| matches!(r, PushRequest::History { .. })));
        let (msg, is_err) = ui.page_msg.clone().unwrap();
        assert!(!is_err && msg.contains('4'), "{msg}");
        // A daemon that still holds the rows would send them again: they show again, which is
        // the point (nothing is hidden by the screen).
        ui.on_reply(
            c,
            PushRequest::Status { id: None },
            Ok(PushResponse::Transfers(vec![
                t("run", Direction::Out, "bob", PushState::Sending, 1),
                t("done", Direction::Out, "bob", PushState::Done, 5),
            ])),
        );
        assert_eq!(ui.rows.len(), 2);
    }

    #[test]
    fn a_daemon_that_predates_clearing_is_told_apart_and_nothing_is_dropped() {
        let c = contact_strings(Locale::En);
        let mut ui = ContactsUi::default();
        ui.on_reply(
            c,
            PushRequest::Status { id: None },
            Ok(PushResponse::Transfers(vec![t(
                "done",
                Direction::Out,
                "bob",
                PushState::Done,
                5,
            )])),
        );
        ui.on_reply(
            c,
            PushRequest::ClearFinished { contact: None },
            Err(PushFail {
                message: "unknown variant `ClearFinished`".into(),
                daemon_down: false,
            }),
        );
        let (msg, is_err) = ui.page_msg.clone().unwrap();
        assert!(is_err);
        assert_eq!(msg, c.clear_old_daemon);
        assert_eq!(
            ui.rows.len(),
            1,
            "the rows are still there: nothing was deleted"
        );
        assert_eq!(ui.availability, Availability::Ok);
    }

    #[test]
    fn drop_target_prefers_the_row_under_the_pointer() {
        let r1 = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(100.0, 50.0));
        let r2 = egui::Rect::from_min_size(egui::pos2(0.0, 60.0), egui::vec2(100.0, 50.0));
        let rects = vec![("a".to_string(), r1), ("b".to_string(), r2)];
        assert_eq!(
            drop_target(&rects, Some(egui::pos2(10.0, 70.0)), 2),
            Some("b")
        );
        assert_eq!(drop_target(&rects, Some(egui::pos2(500.0, 500.0)), 2), None);
        assert_eq!(drop_target(&rects, None, 2), None);
        let one = vec![("a".to_string(), r1)];
        assert_eq!(
            drop_target(&one, Some(egui::pos2(500.0, 500.0)), 1),
            Some("a")
        );
    }

    #[test]
    fn availability_follows_replies() {
        let c = contact_strings(Locale::En);
        let mut ui = ContactsUi::default();
        // Connection closed by an old daemon before any success.
        ui.on_reply(
            c,
            PushRequest::ContactList,
            Err(PushFail {
                message: "eof".into(),
                daemon_down: false,
            }),
        );
        assert_eq!(ui.availability, Availability::OldDaemon);
        ui.on_reply(
            c,
            PushRequest::ContactList,
            Err(PushFail {
                message: "x".into(),
                daemon_down: true,
            }),
        );
        assert_eq!(ui.availability, Availability::DaemonDown);
        ui.on_reply(
            c,
            PushRequest::ContactList,
            Ok(PushResponse::Error {
                kind: "unavailable".into(),
                message: "no iroh".into(),
            }),
        );
        assert_eq!(ui.availability, Availability::NoIroh);
        ui.on_reply(
            c,
            PushRequest::ContactList,
            Ok(PushResponse::Contacts(vec![])),
        );
        assert_eq!(ui.availability, Availability::Ok);
        // After one success a dropped connection is not "old daemon".
        ui.on_reply(
            c,
            PushRequest::Status { id: None },
            Err(PushFail {
                message: "eof".into(),
                daemon_down: false,
            }),
        );
        assert_eq!(ui.availability, Availability::Ok);
    }

    #[test]
    fn daemon_failures_are_worded_in_the_ui_language_and_detail_is_technical_only() {
        use crate::errors::{ErrorKind, UiError};
        let fail = || {
            Err(PushFail {
                message: UiError::new(ErrorKind::DaemonUnreachable, "daemon.port not found"),
                daemon_down: true,
            })
        };
        let req = || PushRequest::ContactAdd {
            code: "x".into(),
            label: Some("a".into()),
        };
        let mut ui = ContactsUi::default();
        ui.set_error_context(Locale::Ja, false);
        ui.on_reply(contact_strings(Locale::Ja), req(), fail());
        let easy = ui.add_error.clone().unwrap();
        assert_eq!(easy, ErrorKind::DaemonUnreachable.text(Locale::Ja));
        assert!(!easy.contains("daemon.port"));

        let mut ui = ContactsUi::default();
        ui.set_error_context(Locale::En, true);
        ui.on_reply(contact_strings(Locale::En), req(), fail());
        let tech = ui.add_error.clone().unwrap();
        assert!(tech.ends_with("daemon.port not found"), "{tech}");
    }

    #[test]
    fn add_errors_reach_the_form_in_plain_words() {
        let c = contact_strings(Locale::Ja);
        let mut ui = ContactsUi::default();
        ui.add_busy = true;
        ui.on_reply(
            c,
            PushRequest::ContactAdd {
                code: "x".into(),
                label: Some("a".into()),
            },
            Ok(PushResponse::Error {
                kind: "label_taken".into(),
                message: "m".into(),
            }),
        );
        assert!(!ui.add_busy);
        assert_eq!(ui.add_error.as_deref(), Some(c.err_label_taken));
    }

    #[test]
    fn polling_is_light_when_idle_and_fast_when_open() {
        let c = contact_strings(Locale::En);
        let mut ui = ContactsUi::default();
        ui.tick(true, true);
        assert_eq!(ui.out.len(), 6, "first tick reads everything");
        ui.out.clear();
        ui.on_reply(
            c,
            PushRequest::Status { id: None },
            Ok(PushResponse::Transfers(vec![])),
        );
        ui.on_reply(
            c,
            PushRequest::ContactList,
            Ok(PushResponse::Contacts(vec![])),
        );
        // Not yet due: nothing.
        ui.tick(true, true);
        assert!(ui.out.is_empty());
        // Due for an open area (500 ms) but not for a closed one (3 s).
        ui.last_status = Instant::now() - Duration::from_millis(600);
        ui.tick(false, true);
        assert!(ui.out.is_empty());
        ui.tick(true, true);
        assert!(matches!(
            ui.out.front(),
            Some(PushRequest::Status { id: None })
        ));
        // One poll in flight at a time.
        ui.out.clear();
        ui.last_status = Instant::now() - Duration::from_secs(10);
        ui.tick(true, true);
        assert!(ui.out.is_empty());
    }

    #[test]
    fn drain_keeps_what_the_worker_did_not_take() {
        let mut ui = ContactsUi::default();
        ui.out.push_back(PushRequest::ContactList);
        ui.out.push_back(PushRequest::Inbox);
        let mut taken = 0;
        ui.drain(|_| {
            taken += 1;
            taken == 1
        });
        assert_eq!(ui.out.len(), 1);
    }

    #[test]
    fn sending_a_folder_is_refused_with_a_message() {
        let c = contact_strings(Locale::En);
        let mut ui = ContactsUi::default();
        ui.contacts.push(ContactInfo {
            id: "i".into(),
            label: "bob".into(),
            endpoint_id: "e".into(),
            fingerprint: "f".into(),
            added_at: 0,
            allow_send: true,
            allow_receive: true,
            max_file_size: None,
            default_max_file_size: 0,
            inbox_dir: "d".into(),
        });
        let dir = std::env::temp_dir();
        ui.send_paths(c, "i", vec![dir]);
        assert!(ui.out.is_empty());
        assert_eq!(
            ui.page_msg.as_ref().map(|m| m.0.as_str()),
            Some(c.drop_folder)
        );
    }

    fn row_of(dir: Direction, state: PushState, kind: Option<&str>, err: Option<&str>) -> Row {
        let mut r = rows(vec![t("a", dir, "bob", state, 1)]).remove(0);
        r.error_kind = kind.map(str::to_owned);
        r.error = err.map(str::to_owned);
        r
    }

    #[test]
    fn receiver_side_texts_never_say_unreachable() {
        for lang in Locale::ALL {
            let c = contact_strings(lang);
            // The sender cancelled: its own message, not a failure.
            let r = row_of(
                Direction::In,
                PushState::Cancelled,
                Some("peer_cancelled"),
                Some("the sender cancelled this transfer"),
            );
            assert_eq!(row_guidance(c, &r).unwrap(), c.fail_peer_cancelled);
            // The connection broke while receiving (new daemon: kind; old daemon: the text).
            for r in [
                row_of(
                    Direction::In,
                    PushState::Failed,
                    Some("connection_lost"),
                    Some("the connection was lost; the sender can resume"),
                ),
                row_of(
                    Direction::In,
                    PushState::Failed,
                    Some("timed_out"),
                    Some("the sender stopped sending (timed out); it can resume"),
                ),
                row_of(
                    Direction::In,
                    PushState::Failed,
                    None,
                    Some("connection lost: connection lost; it can resume"),
                ),
            ] {
                let g = row_guidance(c, &r).unwrap();
                assert_eq!(g, c.fail_lost_in);
                assert_ne!(g, c.fail_unreachable);
            }
            // Whatever the text, an inbound failure never gets the "unreachable" guidance.
            for e in ["cannot reach the other side", "did not reply", "connect"] {
                let r = row_of(Direction::In, PushState::Failed, None, Some(e));
                assert_ne!(row_guidance(c, &r).unwrap(), c.fail_unreachable, "{e}");
            }
            // Outbound keeps it.
            for k in ["unreachable", "connection_lost", "timed_out"] {
                let r = row_of(Direction::Out, PushState::Failed, Some(k), Some("x"));
                assert_eq!(row_guidance(c, &r).unwrap(), c.fail_unreachable, "{k}");
            }
            // A cancel the person made themselves on an outbound row needs no message.
            let r = row_of(Direction::Out, PushState::Cancelled, None, None);
            assert!(row_guidance(c, &r).is_none());
        }
        let ja = contact_strings(Locale::Ja);
        assert_eq!(ja.fail_peer_cancelled, "相手が転送を中止しました。");
        assert_eq!(
            ja.fail_lost_in,
            "通信が途切れました。相手が再び送ると、続きから受け取れます。"
        );
        let en = contact_strings(Locale::En);
        assert_eq!(
            en.fail_peer_cancelled,
            "The sender cancelled this transfer."
        );
        assert!(!en.fail_lost_in.contains("their Miasma is running"));
    }

    fn bob() -> ContactInfo {
        ContactInfo {
            id: "bob".into(),
            label: "bob".into(),
            endpoint_id: "e".into(),
            fingerprint: "f".into(),
            added_at: 0,
            allow_send: true,
            allow_receive: true,
            max_file_size: None,
            default_max_file_size: 0,
            inbox_dir: "d".into(),
        }
    }

    #[test]
    fn send_again_is_offered_for_failed_rejected_and_cancelled_outbound_rows() {
        let mut ui = ContactsUi::default();
        ui.contacts.push(bob());
        for st in [PushState::Failed, PushState::Rejected, PushState::Cancelled] {
            let mut r = row_of(Direction::Out, st, None, None);
            r.source_path = Some("/data/a.bin".into());
            assert!(ui.can_retry(&r), "{st:?}");
        }
        // Not for running, finished-ok or inbound rows.
        for st in [
            PushState::Queued,
            PushState::Sending,
            PushState::Verifying,
            PushState::Done,
        ] {
            let mut r = row_of(Direction::Out, st, None, None);
            r.source_path = Some("/data/a.bin".into());
            assert!(!ui.can_retry(&r), "{st:?}");
        }
        let mut inbound = row_of(Direction::In, PushState::Failed, None, None);
        inbound.source_path = Some("/data/a.bin".into());
        assert!(!ui.can_retry(&inbound));
        // Without a known file (an older daemon's row from a previous session): hidden.
        let r = row_of(Direction::Out, PushState::Failed, None, None);
        assert!(!ui.can_retry(&r));
        // ...unless this session queued it itself.
        ui.paths.insert("a".into(), PathBuf::from("/data/a.bin"));
        assert!(ui.can_retry(&r));
        // The contact is gone: nobody to send to.
        ui.contacts.clear();
        assert!(!ui.can_retry(&r));
    }

    #[test]
    fn not_allowed_rows_show_guidance_only_no_retry_loop() {
        let mut ui = ContactsUi::default();
        ui.contacts.push(bob());
        for st in [PushState::Rejected, PushState::Failed] {
            let mut r = row_of(Direction::Out, st, None, None);
            r.source_path = Some("/data/a.bin".into());
            r.reject_reason = Some("not_allowed".into());
            assert!(!ui.can_retry(&r), "{st:?}");
        }
        // Other refusals can be retried (the person may have freed space, raised the limit...).
        let mut r = row_of(Direction::Out, PushState::Rejected, None, None);
        r.source_path = Some("/data/a.bin".into());
        r.reject_reason = Some("no_space".into());
        assert!(ui.can_retry(&r));
    }

    #[test]
    fn send_again_queues_the_same_file_for_the_same_contact() {
        let mut ui = ContactsUi::default();
        ui.contacts.push(bob());
        let mut r = row_of(Direction::Out, PushState::Failed, None, Some("x"));
        r.source_path = Some("/data/報告.pdf".into());
        ui.retry(&r);
        let sends = ui
            .out
            .iter()
            .filter(|q| matches!(q, PushRequest::Send { .. }))
            .count();
        assert_eq!(sends, 1, "exactly one new send");
        match ui.out.front().unwrap() {
            PushRequest::Send { contact, path } => {
                assert_eq!(contact, "bob");
                assert_eq!(path, "/data/報告.pdf");
            }
            other => panic!("{other:?}"),
        }
        // A row from this session prefers the path it remembers.
        let mut ui = ContactsUi::default();
        ui.contacts.push(bob());
        ui.paths.insert("a".into(), PathBuf::from("/mine/b.bin"));
        let mut r = row_of(Direction::Out, PushState::Cancelled, None, None);
        r.source_path = Some("/daemon/other.bin".into());
        ui.retry(&r);
        match ui.out.front().unwrap() {
            PushRequest::Send { path, .. } => assert_eq!(path, "/mine/b.bin"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn source_path_flows_from_the_daemon_and_from_history_into_rows() {
        let mut info = t("x", Direction::Out, "bob", PushState::Failed, 5);
        info.source_path = Some("/p/x.bin".into());
        info.error_kind = Some("unreachable".into());
        let r = Row::from(&info);
        assert_eq!(r.source_path.as_deref(), Some("/p/x.bin"));
        assert_eq!(r.error_kind.as_deref(), Some("unreachable"));
        let h = HistoryEntry {
            id: "h".into(),
            direction: Direction::Out,
            contact_id: "bob".into(),
            contact_label: "bob".into(),
            name: "h.bin".into(),
            size: 3,
            state: PushState::Failed,
            error: None,
            reject_reason: None,
            error_kind: Some("connection_lost".into()),
            source_path: Some("/p/h.bin".into()),
            saved_as: None,
            finished_at_ms: 9,
        };
        let r = Row::from(&h);
        assert_eq!(r.source_path.as_deref(), Some("/p/h.bin"));
        assert_eq!(r.error_kind.as_deref(), Some("connection_lost"));
    }

    #[test]
    fn remaining_time_reads_naturally_in_japanese_and_keeps_the_english_format() {
        let ja = contact_strings(Locale::Ja);
        let en = contact_strings(Locale::En);
        for (secs, want_ja) in [
            (5, "5 秒"),
            (59, "59 秒"),
            (60, "1 分"),
            (192, "3 分 12 秒"),
            (3600, "1 時間"),
            (3900, "1 時間 5 分"),
            (90_000, "1 日 1 時間"),
        ] {
            assert_eq!(eta_text(ja, secs), want_ja, "{secs}");
            assert_eq!(
                eta_text(en, secs),
                format_eta(Some(secs), "d"),
                "en keeps hh:mm:ss ({secs})"
            );
        }
        assert_eq!(fill(ja.eta, &[("t", &eta_text(ja, 5))]), "あと 5 秒");
        assert_eq!(
            fill(ja.eta, &[("t", &eta_text(ja, 192))]),
            "あと 3 分 12 秒"
        );
        assert_eq!(
            fill(ja.eta, &[("t", &eta_text(ja, 3900))]),
            "あと 1 時間 5 分"
        );
    }

    #[test]
    fn empty_max_size_box_hints_at_the_effective_default() {
        let ja = contact_strings(Locale::Ja);
        let en = contact_strings(Locale::En);
        assert_eq!(max_size_hint_text(ja, 0), "空欄 = 既定の上限（20 GiB）");
        assert_eq!(
            max_size_hint_text(ja, 5 << 30),
            "空欄 = 既定の上限（5 GiB）"
        );
        assert_eq!(
            max_size_hint_text(ja, 1536 << 20),
            "空欄 = 既定の上限（1.5 GiB）"
        );
        assert_eq!(max_size_hint_text(en, 0), "empty = default limit (20 GiB)");
        assert_eq!(format_limit(20 << 30), "20 GiB");
    }

    /// Draw the whole Contacts page of a fixture in a column of `width` and report what it did:
    /// (the used rectangle, the available rectangle, the row rectangles).
    fn draw_page(
        fixture: &str,
        lang: Locale,
        width: f32,
    ) -> (egui::Rect, egui::Rect, Vec<(String, egui::Rect)>) {
        let ctx = egui::Context::default();
        crate::ui_kit::apply_theme(&ctx, false);
        let c = contact_strings(lang);
        let mut state = ContactsUi::fixture(fixture, c).unwrap();
        let mut seen = None;
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(width, 2400.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let avail = ui.max_rect();
                    crate::ui_kit::column(ui, |ui| state.show(ui, c, true, false));
                    seen = Some((ui.min_rect(), avail));
                });
            });
        }
        let (used, avail) = seen.unwrap();
        (used, avail, state.row_rects.clone())
    }

    #[test]
    fn the_list_is_the_page_and_every_row_is_compact_and_inside_the_window() {
        for lang in Locale::ALL {
            for width in [700.0_f32, 1200.0] {
                for (fixture, n) in [("one", 1usize), ("two", 2), ("five", 5)] {
                    let (used, avail, rects) = draw_page(fixture, lang, width);
                    assert_eq!(rects.len(), n, "{lang:?} {fixture}");
                    for (id, r) in &rects {
                        assert_eq!(
                            r.height(),
                            crate::ui_kit::ROW_H,
                            "{lang:?} {fixture} {id} at {width}"
                        );
                    }
                    // The first row starts near the top: only the title row sits above it.
                    let first = rects[0].1.top();
                    assert!(first < 100.0, "{lang:?} {fixture}: list starts at {first}");
                    assert!(
                        used.right() <= avail.right() + 1.0,
                        "{lang:?} {fixture} at {width}: overflow {used:?} vs {avail:?}"
                    );
                    // Rows are stacked without gaps.
                    for w in rects.windows(2) {
                        let gap = w[1].1.top() - w[0].1.bottom();
                        assert!(
                            (gap - 1.0).abs() < 0.5,
                            "{lang:?} {fixture}: {gap} between rows"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn five_contacts_stay_short_and_the_empty_state_has_no_rows() {
        let (_, _, rects5) = draw_page("five", Locale::En, 1200.0);
        let (_, _, rects0) = draw_page("empty", Locale::En, 1200.0);
        assert!(rects0.is_empty());
        // Title row, then five rows of 57 px: the last row ends well within one screen.
        let bottom = rects5.last().unwrap().1.bottom();
        assert!(bottom < 420.0, "last of five rows ends at {bottom}");
    }

    #[test]
    fn a_row_says_the_most_pressing_thing_about_the_contact() {
        let c = contact_strings(Locale::En);
        let mut ct = bob();
        let none: Vec<Row> = Vec::new();
        assert_eq!(
            row_status(c, &ct, false, &none),
            (c.row_ready, Level::Muted)
        );
        assert_eq!(
            row_status(c, &ct, true, &none),
            (c.chip_not_registered, Level::Warn)
        );
        // Not being registered outranks everything.
        ct.allow_send = false;
        assert_eq!(
            row_status(c, &ct, true, &none),
            (c.chip_not_registered, Level::Warn)
        );
        assert_eq!(
            row_status(c, &ct, false, &none),
            (c.send_disabled_note, Level::Muted)
        );
        ct.allow_send = true;
        let live = rows(vec![t("1", Direction::Out, &ct.id, PushState::Sending, 5)]);
        assert_eq!(
            row_status(c, &ct, false, &live),
            (c.st_sending, Level::Info)
        );
        let waiting = rows(vec![t("2", Direction::Out, &ct.id, PushState::Waiting, 6)]);
        assert_eq!(
            row_status(c, &ct, false, &waiting),
            (c.st_waiting, Level::Warn)
        );
        // A finished transfer says nothing.
        let done = rows(vec![t("3", Direction::Out, &ct.id, PushState::Done, 7)]);
        assert_eq!(
            row_status(c, &ct, false, &done),
            (c.row_ready, Level::Muted)
        );
        // Another contact's transfer does not show here.
        let other = rows(vec![t("4", Direction::Out, "zed", PushState::Sending, 8)]);
        assert_eq!(
            row_status(c, &ct, false, &other),
            (c.row_ready, Level::Muted)
        );
    }

    #[test]
    fn the_dialogs_open_from_the_buttons_and_from_outside_and_close_clean() {
        let mut ui = ContactsUi::default();
        assert!(!ui.add_open && !ui.invite_open);
        ui.open_add_dialog();
        assert!(ui.add_open);
        ui.add_open = false;
        // "Add as contact" from a group member opens the dialog with the code filled in.
        ui.prefill_add("miasma-contact:fromgroup");
        assert!(ui.add_open && ui.add_text == "miasma-contact:fromgroup");
        // A suggestion does the same.
        let mut s = with_suggestions(vec![sugg(1, 5)]);
        let id = s.suggestions[0].endpoint_id.clone();
        s.add_from_suggestion(&id);
        assert!(s.add_open);
    }

    #[test]
    fn the_new_texts_keep_their_hole_and_exist_in_every_language() {
        for lang in Locale::ALL {
            let c = contact_strings(lang);
            assert!(c.verify_body.contains("{label}"), "{lang:?}");
            for (name, v) in [
                ("invite_btn", c.invite_btn),
                ("menu_more", c.menu_more),
                ("menu_verify", c.menu_verify),
                ("menu_permissions", c.menu_permissions),
                ("send_short", c.send_short),
                ("row_ready", c.row_ready),
                ("paste_what", c.paste_what),
                ("empty_line", c.empty_line),
                ("done_btn", c.done_btn),
                ("invite_lead", c.invite_lead),
            ] {
                assert!(!v.trim().is_empty(), "{lang:?} {name}");
            }
        }
    }

    // ─── Files sent from the chat screen follow their push row ──────────────

    fn out_row(
        id: &str,
        state: PushState,
        bytes: u64,
        at: u64,
        err: Option<&str>,
    ) -> PushTransferInfo {
        PushTransferInfo {
            name: "flydesk_groom.mp4".into(),
            size: 1000,
            bytes,
            error: err.map(str::to_owned),
            source_path: Some("/v/flydesk_groom.mp4".into()),
            ..t(id, Direction::Out, "bob", state, at)
        }
    }

    #[test]
    fn a_chat_file_follows_queued_sending_failed_retry_done_and_says_sent_only_at_the_end() {
        let c = contact_strings(Locale::En);
        let none = HashMap::new();
        let st = |board: Vec<PushTransferInfo>| {
            let rows = merge_rows(&board, &[]);
            file_status_in(
                &rows,
                &none,
                c,
                false,
                "bob",
                "/v/flydesk_groom.mp4",
                10_000,
            )
        };
        // No row yet: waiting, never sent.
        assert_eq!(st(vec![]), FileStatus::Waiting);
        assert_eq!(
            st(vec![out_row("a", PushState::Queued, 0, 10_100, None)]),
            FileStatus::Waiting
        );
        assert_eq!(
            st(vec![out_row("a", PushState::Sending, 250, 10_200, None)]),
            FileStatus::Sending { percent: 25 }
        );
        // The push fails: the reason is the localised one, not "sent".
        let FileStatus::Failed { reason } = st(vec![out_row(
            "a",
            PushState::Failed,
            250,
            10_300,
            Some("could not connect"),
        )]) else {
            panic!("not failed")
        };
        assert!(!reason.is_empty());
        // Retry: the failed row is replaced by a new queued one; the newest row decides.
        let retry = vec![
            out_row(
                "a",
                PushState::Failed,
                250,
                10_300,
                Some("could not connect"),
            ),
            out_row("b", PushState::Queued, 0, 10_400, None),
        ];
        assert_eq!(st(retry.clone()), FileStatus::Waiting);
        let mut done = retry;
        done[1] = out_row("b", PushState::Done, 1000, 10_900, None);
        assert_eq!(st(done), FileStatus::Done);
        // A row from before the note (an older send of the same file) does not count.
        let rows = merge_rows(&[out_row("old", PushState::Done, 1000, 1_000, None)], &[]);
        assert_eq!(
            file_status_in(
                &rows,
                &none,
                c,
                false,
                "bob",
                "/v/flydesk_groom.mp4",
                60_000
            ),
            FileStatus::Waiting
        );
        // Another contact's row of the same name does not count either.
        let mut other = out_row("x", PushState::Done, 1000, 10_500, None);
        other.contact_id = "carol".into();
        let rows = merge_rows(&[other], &[]);
        assert_eq!(
            file_status_in(
                &rows,
                &none,
                c,
                false,
                "bob",
                "/v/flydesk_groom.mp4",
                10_000
            ),
            FileStatus::Waiting
        );
    }

    #[test]
    fn a_refused_send_request_fails_the_chat_file_and_resend_clears_it() {
        let c = contact_strings(Locale::En);
        let mut ui = ContactsUi::default();
        ui.on_reply(
            c,
            PushRequest::ContactList,
            Ok(PushResponse::Contacts(vec![bob()])),
        );
        ui.on_reply(
            c,
            PushRequest::Send {
                contact: "bob".into(),
                path: "/v/a.mp4".into(),
            },
            Ok(PushResponse::Error {
                kind: "queue_full".into(),
                message: "full".into(),
            }),
        );
        assert!(matches!(
            ui.file_status(c, "bob", "/v/a.mp4", 0),
            FileStatus::Failed { .. }
        ));
        ui.resend_file("bob", "/v/a.mp4");
        assert_eq!(ui.file_status(c, "bob", "/v/a.mp4", 0), FileStatus::Waiting);
        assert!(ui
            .out
            .iter()
            .any(|r| matches!(r, PushRequest::Send { path, .. } if path == "/v/a.mp4")));
    }

    // ─── Earlier failed attempts fold under the attempt that replaced them ───

    fn attempt(id: &str, state: PushState, at: u64) -> Row {
        Row::from(&PushTransferInfo {
            name: "x.mp4".into(),
            size: 10,
            ..t(id, Direction::Out, "bob", state, at)
        })
    }

    fn fold(rows: &[Row]) -> Vec<(String, Vec<String>)> {
        let refs: Vec<&Row> = rows.iter().collect();
        fold_attempts(&refs)
            .into_iter()
            .map(|g| {
                (
                    g.row.id.clone(),
                    g.earlier.iter().map(|r| r.id.clone()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn failed_then_retry_then_done_shows_one_row_with_one_earlier_attempt() {
        let rows = [
            attempt("a", PushState::Failed, 100),
            attempt("b", PushState::Sending, 200),
        ];
        assert_eq!(fold(&rows), [("b".to_string(), vec!["a".to_string()])]);
        let rows = [
            attempt("b", PushState::Done, 300),
            attempt("a", PushState::Failed, 100),
        ];
        assert_eq!(fold(&rows), [("b".to_string(), vec!["a".to_string()])]);
    }

    #[test]
    fn failed_failed_done_folds_both() {
        let rows = [
            attempt("c", PushState::Done, 300),
            attempt("b", PushState::Cancelled, 200),
            attempt("a", PushState::Failed, 100),
        ];
        let got = fold(&rows);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "c");
        assert_eq!(got[0].1.len(), 2);
    }

    #[test]
    fn a_file_that_only_failed_stays_visible_and_other_files_are_untouched() {
        let only = [attempt("a", PushState::Failed, 100)];
        assert_eq!(fold(&only), [("a".to_string(), Vec::<String>::new())]);
        // Two failures and no success: both stay.
        let two = [
            attempt("b", PushState::Failed, 200),
            attempt("a", PushState::Failed, 100),
        ];
        assert_eq!(fold(&two).len(), 2);
        // A different file (name, size, contact or direction) that succeeded changes nothing.
        let mut other_name = attempt("d", PushState::Done, 400);
        other_name.name = "other.mp4".into();
        let mut other_size = attempt("e", PushState::Done, 400);
        other_size.size = 11;
        let mut other_contact = attempt("f", PushState::Done, 400);
        other_contact.contact_id = "carol".into();
        let mut inbound = attempt("g", PushState::Done, 400);
        inbound.outbound = false;
        for done in [other_name, other_size, other_contact, inbound] {
            let rows = [done, attempt("a", PushState::Failed, 100)];
            let got = fold(&rows);
            assert_eq!(got.len(), 2, "{got:?}");
            assert!(got.iter().all(|(_, e)| e.is_empty()));
        }
        // A success that came before the failure does not hide it.
        let rows = [
            attempt("b", PushState::Failed, 200),
            attempt("a", PushState::Done, 100),
        ];
        assert_eq!(fold(&rows).len(), 2);
    }

    // ─── People who are not contacts ────────────────────────────────────────

    fn sugg(n: u8, last: u64) -> SuggestionInfo {
        let ep = format!("{n:02x}").repeat(32);
        SuggestionInfo {
            endpoint_id: ep,
            short_id: format!("ABC{n:02}"),
            code: format!("miasma-contact:code{n}"),
            first_ms: last,
            last_ms: last,
            attempts: 1,
        }
    }

    fn with_suggestions(list: Vec<SuggestionInfo>) -> ContactsUi {
        let c = contact_strings(Locale::En);
        let mut ui = ContactsUi::default();
        ui.on_reply(
            c,
            PushRequest::Suggestions,
            Ok(PushResponse::Suggestions(list)),
        );
        ui
    }

    #[test]
    fn suggestions_are_listed_ignored_per_session_and_hidden_once_a_contact() {
        let mut ui = with_suggestions(vec![sugg(1, 5), sugg(2, 4)]);
        assert_eq!(ui.visible_suggestions().len(), 2);
        let first = ui.visible_suggestions()[0].endpoint_id.clone();
        ui.ignore_suggestion(&first);
        ui.ignore_suggestion(&first);
        assert_eq!(ui.ignored.len(), 1);
        assert_eq!(ui.visible_suggestions().len(), 1);
        // The next poll brings it again: still hidden.
        let c = contact_strings(Locale::En);
        ui.on_reply(
            c,
            PushRequest::Suggestions,
            Ok(PushResponse::Suggestions(vec![sugg(1, 9), sugg(2, 4)])),
        );
        assert_eq!(ui.visible_suggestions().len(), 1);
        // Someone who became a contact is no longer a suggestion.
        let mut ct = bob();
        ct.endpoint_id = sugg(2, 0).endpoint_id;
        ui.on_reply(
            c,
            PushRequest::ContactList,
            Ok(PushResponse::Contacts(vec![ct])),
        );
        assert!(ui.visible_suggestions().is_empty());
    }

    #[test]
    fn the_ignore_list_is_bounded() {
        let mut ui = ContactsUi::default();
        for n in 0..(MAX_IGNORED + 20) {
            ui.ignore_suggestion(&format!("id{n}"));
        }
        assert_eq!(ui.ignored.len(), MAX_IGNORED);
        assert!(!ui.ignored.contains(&"id0".to_string()));
        assert!(ui.ignored.contains(&format!("id{}", MAX_IGNORED + 19)));
    }

    #[test]
    fn add_as_contact_fills_the_form_and_adds_with_permissions_off() {
        let mut ui = with_suggestions(vec![sugg(1, 5)]);
        let id = ui.suggestions[0].endpoint_id.clone();
        ui.add_from_suggestion(&id);
        assert_eq!(ui.add_text, "miasma-contact:code1");
        assert!(ui.add_label.is_empty(), "a name is never filled in");
        assert!(ui.add_is_from_suggestion());
        ui.queue_add("Ken".into());
        assert!(matches!(
            ui.out.back(),
            Some(PushRequest::ContactAddOff { code, label })
                if code == "miasma-contact:code1" && label.as_deref() == Some("Ken")
        ));
        // Edited by hand into another code: the ordinary add.
        ui.add_text = "miasma-contact:other".into();
        assert!(!ui.add_is_from_suggestion());
        ui.queue_add("Ken".into());
        assert!(matches!(
            ui.out.back(),
            Some(PushRequest::ContactAdd { .. })
        ));
        // When the daemon confirms, the card is gone and the form is clear.
        let c = contact_strings(Locale::En);
        let mut ct = bob();
        ct.endpoint_id = id;
        ct.allow_send = false;
        ct.allow_receive = false;
        ui.on_reply(
            c,
            PushRequest::ContactAddOff {
                code: "x".into(),
                label: None,
            },
            Ok(PushResponse::Contact(ct)),
        );
        assert!(ui.suggestions.is_empty());
        assert!(ui.add_text.is_empty() && ui.add_from_suggestion.is_none());
    }

    #[test]
    fn a_code_given_from_outside_fills_the_form_and_adds_with_permissions_off() {
        let mut ui = ContactsUi::default();
        ui.add_label = "old".into();
        ui.prefill_add("  miasma-contact:fromgroup \n");
        assert_eq!(ui.add_text, "miasma-contact:fromgroup");
        assert!(ui.add_label.is_empty(), "a name is never filled in");
        assert!(ui.add_is_from_suggestion());
        ui.queue_add("Ken".into());
        assert!(matches!(
            ui.out.back(),
            Some(PushRequest::ContactAddOff { code, .. }) if code == "miasma-contact:fromgroup"
        ));
    }

    #[test]
    fn a_daemon_without_suggestions_is_not_taken_for_an_old_daemon() {
        let c = contact_strings(Locale::En);
        let mut ui = ContactsUi::default();
        ui.on_reply(
            c,
            PushRequest::Suggestions,
            Err(PushFail {
                message: "eof".into(),
                daemon_down: false,
            }),
        );
        assert_eq!(ui.availability, Availability::Unknown);
        ui.on_reply(
            c,
            PushRequest::Suggestions,
            Ok(PushResponse::Error {
                kind: "internal".into(),
                message: "unknown variant".into(),
            }),
        );
        assert_eq!(ui.availability, Availability::Unknown);
    }

    #[test]
    fn suggestion_times_read_naturally_in_every_language() {
        for l in Locale::ALL {
            let c = contact_strings(l);
            let now = 10 * 3_600_000;
            assert_eq!(when_text(c, now, now), c.sugg_now);
            assert!(when_text(c, now, now - 5 * 60_000).contains('5'));
            assert!(when_text(c, now, now - 3 * 3_600_000).contains('3'));
            for t in [c.sugg_item, c.sugg_attempts, c.sugg_min, c.sugg_hour] {
                assert!(t.contains('{'), "{l:?}: {t}");
            }
            assert!(
                !c.sugg_title.is_empty() && !c.sugg_add.is_empty() && !c.sugg_ignore.is_empty()
            );
        }
    }

    #[test]
    fn the_suggestion_card_draws_and_fits_a_700_px_window() {
        let ctx = egui::Context::default();
        crate::ui_kit::apply_theme(&ctx, false);
        for l in Locale::ALL {
            let c = contact_strings(l);
            let mut ui_state = with_suggestions(vec![sugg(1, 5), sugg(2, 4)]);
            let mut inner = None;
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(700.0, 900.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let avail = ui.max_rect();
                    ui_state.suggestions_ui(ui, c);
                    inner = Some((avail, ui.min_rect()));
                });
            });
            let (avail, used) = inner.unwrap();
            assert!(used.height() > 40.0, "{l:?}: the card was not drawn");
            assert!(used.right() <= avail.right() + 1.0, "{l:?}: overflow");
        }
    }
}
