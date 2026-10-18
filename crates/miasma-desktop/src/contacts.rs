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

use crate::app::{card_frame, danger_button, primary_button, section_heading};
use crate::locale::{ContactStrings, Locale};
use crate::open_path::{self, Action, Resolved};
use crate::theme::{self, Palette};
use crate::transfers::{fill, format_bytes, format_eta};
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
/// goes here.
pub fn invitation_message(code: &str, fingerprint: &str) -> String {
    format!(
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
    )
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

/// Hide finished rows that were cleared (`at_ms <= cleared_before_ms`) and cap how many finished
/// rows are drawn. Unfinished rows are always kept.
pub fn visible_rows(rows: &[Row], cleared_before_ms: u64, max_finished: usize) -> Vec<&Row> {
    let mut finished = 0usize;
    rows.iter()
        .filter(|r| {
            if !r.finished() {
                return true;
            }
            if r.at_ms <= cleared_before_ms {
                return false;
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
    cleared_before_ms: u64,

    // card
    show_qr: bool,
    copied_at: Option<Instant>,
    invite_copied_at: Option<Instant>,

    // add form
    add_text: String,
    add_label: String,
    add_busy: bool,
    add_error: Option<String>,
    add_result: Option<(String, String)>,

    // list
    edits: HashMap<String, String>,
    max_error: HashSet<String>,
    renaming: Option<(String, String)>,
    remove_target: Option<(String, String)>,
    row_rects: Vec<(String, egui::Rect)>,
    page_msg: Option<(String, bool)>,

    /// Failures of "Open file" / "Show in folder" reported by the helper thread.
    open_tx: std::sync::mpsc::Sender<String>,
    open_rx: std::sync::mpsc::Receiver<String>,
    /// The path the last open was aimed at (named in the notice if it fails).
    last_open: String,
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
            cleared_before_ms: 0,
            show_qr: false,
            copied_at: None,
            invite_copied_at: None,
            add_text: String::new(),
            add_label: String::new(),
            add_busy: false,
            add_error: None,
            add_result: None,
            edits: HashMap::new(),
            max_error: HashSet::new(),
            renaming: None,
            remove_target: None,
            row_rects: Vec::new(),
            page_msg: None,
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

    /// The same file picker and queueing as the "Send files" button of a contact's row, for
    /// another screen. Returns the names of the files that were queued (none if the dialog was
    /// cancelled or only folders were picked).
    pub fn pick_and_send_files(&mut self, c: &ContactStrings, id: &str) -> Vec<SentFile> {
        if !self.contacts.iter().any(|x| x.id == id) {
            return Vec::new();
        }
        let Some(files) = rfd::FileDialog::new().set_title(c.pick_title).pick_files() else {
            return Vec::new();
        };
        let sent: Vec<SentFile> = files
            .iter()
            .filter(|p| !p.is_dir())
            .map(|p| SentFile {
                name: base_name(&p.to_string_lossy()),
                path: p.to_string_lossy().into_owned(),
            })
            .collect();
        self.send_paths(c, id, files);
        sent
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
        let Some(sa) = r.saved_as.as_deref() else {
            return;
        };
        let contact_dir = self
            .contacts
            .iter()
            .find(|x| x.id == r.contact_id)
            .map(|x| PathBuf::from(&x.inbox_dir));
        match open_path::resolve_saved(sa, contact_dir.as_deref(), self.inbox_root().as_deref()) {
            Resolved::Found(p) => {
                self.last_open = crate::transfers::plain_path(&p.to_string_lossy()).to_owned();
                open_path::launch(action, p, self.open_tx.clone());
            }
            Resolved::Missing { tried, folder } => {
                let shown = crate::transfers::plain_path(&tried.to_string_lossy()).to_owned();
                self.page_msg = Some((fill(c.open_missing, &[("path", &shown)]), true));
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
            self.page_msg = Some((
                fill(
                    c.open_missing,
                    &[("path", crate::transfers::plain_path(dir))],
                ),
                true,
            ));
        }
    }

    /// Failures reported by the launcher threads become a visible notice.
    fn collect_open_failures(&mut self, c: &ContactStrings) {
        while let Ok(why) = self.open_rx.try_recv() {
            self.page_msg = Some((
                fill(c.open_failed, &[("path", &self.last_open), ("why", &why)]),
                true,
            ));
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
                let text = f.message.text(self.err_locale, self.err_technical);
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
            | PushRequest::RetryNow { .. } => {
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

    /// Draw the whole area. `technical` adds endpoint ids and folders.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        c: &ContactStrings,
        connected: bool,
        technical: bool,
    ) {
        self.err_technical = technical;
        self.collect_open_failures(c);
        section_heading(ui, c.heading);
        ui.add_space(4.0);
        ui.add(egui::Label::new(egui::RichText::new(c.desc).color(pal().muted)).wrap(true));
        ui.add_space(GAP);

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

        self.handle_drops(ui, c);

        if let Some((msg, is_err)) = self.page_msg.clone() {
            let color = if is_err { pal().danger } else { pal().success };
            card_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(egui::Label::new(egui::RichText::new(&msg).color(color)).wrap(true));
                ui.add_space(4.0);
                if ui.button(c.dismiss).clicked() {
                    self.page_msg = None;
                }
            });
            ui.add_space(GAP);
        }

        if self.contacts.is_empty() && self.contacts_loaded {
            self.help_card(ui, c);
            ui.add_space(GAP);
        }
        self.my_card_ui(ui, c);
        ui.add_space(GAP);
        self.suggestions_ui(ui, c);
        self.add_ui(ui, c);
        ui.add_space(GAP);
        self.list_ui(ui, c, technical);
        ui.add_space(GAP);
        self.transfers_ui(ui, c);
        ui.add_space(GAP);
        self.inbox_ui(ui, c);
        self.remove_dialog(ui.ctx(), c);
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

    fn help_card(&self, ui: &mut egui::Ui, c: &ContactStrings) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, c.help_title);
            for line in [c.help_1, c.help_2, c.help_3] {
                help_step(ui, line);
                ui.add_space(2.0);
            }
        });
    }

    fn my_card_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, c.my_card);
            let Some((code, fp)) = self.my_code.clone() else {
                ui.label(egui::RichText::new(c.loading).color(pal().muted));
                return;
            };
            ui.label(label_text(c.my_code));
            // Read-only and selectable; one row high, it grows with the wrapped code only.
            let mut shown: &str = code.as_str();
            ui.add(
                egui::TextEdit::multiline(&mut shown)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(1)
                    .desired_width(f32::INFINITY),
            );
            hint(ui, c.my_code_hint);
            ui.add_space(8.0);
            ui.label(label_text(c.my_fp));
            ui.label(
                egui::RichText::new(&fp)
                    .monospace()
                    .size(26.0)
                    .strong()
                    .color(pal().text),
            );
            hint(ui, c.my_fp_hint);
            ui.add_space(8.0);
            // One primary action per card: the invitation message is what people send.
            ui.horizontal_wrapped(|ui| {
                let l = if recent(self.invite_copied_at) {
                    c.copied
                } else {
                    c.copy_invite
                };
                if ui.add(primary_button(l)).clicked() {
                    let msg = invitation_message(&code, &fp);
                    ui.output_mut(|o| o.copied_text = msg);
                    self.invite_copied_at = Some(Instant::now());
                }
                let l = if recent(self.copied_at) {
                    c.copied
                } else {
                    c.copy_code
                };
                if ui.button(l).clicked() {
                    ui.output_mut(|o| o.copied_text = code.clone());
                    self.copied_at = Some(Instant::now());
                }
                let l = if self.show_qr { c.hide_qr } else { c.show_qr };
                if ui.button(l).clicked() {
                    self.show_qr = !self.show_qr;
                }
            });
            if self.show_qr {
                ui.add_space(8.0);
                if !crate::transfers::draw_qr(ui, &qr_payload(&code), 240.0, c.qr_note) {
                    ui.label(egui::RichText::new(c.qr_too_long).color(pal().danger));
                }
                ui.add_space(2.0);
                hint(ui, c.qr_note);
            }
        });
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

    /// The card of people who are not contacts and tried to reach me.
    fn suggestions_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        let items: Vec<SuggestionInfo> = self.visible_suggestions().into_iter().cloned().collect();
        if items.is_empty() {
            return;
        }
        let now = unix_ms();
        let mut add: Option<String> = None;
        let mut ignore: Option<String> = None;
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, c.sugg_title);
            hint(ui, c.sugg_body);
            for s in &items {
                ui.add_space(8.0);
                inner_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let mut line = fill(
                        c.sugg_item,
                        &[("id", &s.short_id), ("when", &when_text(c, now, s.last_ms))],
                    );
                    if s.attempts > 1 {
                        line.push_str(", ");
                        line.push_str(&fill(c.sugg_attempts, &[("n", &s.attempts.to_string())]));
                    }
                    ui.add(
                        egui::Label::new(egui::RichText::new(line).monospace().color(pal().text))
                            .wrap(true),
                    );
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add(primary_button(c.sugg_add)).clicked() {
                            add = Some(s.endpoint_id.clone());
                        }
                        if ui.button(c.sugg_ignore).clicked() {
                            ignore = Some(s.endpoint_id.clone());
                        }
                    });
                });
            }
        });
        if let Some(id) = add {
            self.add_from_suggestion(&id);
        }
        if let Some(id) = ignore {
            self.ignore_suggestion(&id);
        }
        ui.add_space(GAP);
    }

    fn add_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, c.add_title);
            ui.add(egui::Label::new(c.add_hint).wrap(true));
            if self.add_is_from_suggestion() {
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(egui::RichText::new(c.sugg_prefill_note).color(pal().warning))
                        .wrap(true),
                );
            }
            ui.add_space(6.0);
            ui.label(label_text(c.add_paste));
            ui.add(
                egui::TextEdit::multiline(&mut self.add_text)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(4.0);
            ui.label(label_text(c.add_label));
            ui.add(
                egui::TextEdit::singleline(&mut self.add_label)
                    .hint_text(c.add_label_hint)
                    .desired_width(260.0),
            );
            ui.add_space(8.0);
            let ready = !self.add_text.trim().is_empty() && !self.add_busy;
            ui.horizontal_wrapped(|ui| {
                let l = if self.add_busy {
                    c.add_busy
                } else {
                    c.add_button
                };
                if ui.add_enabled(ready, primary_button(l)).clicked() {
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
            });
            if let Some(e) = &self.add_error {
                ui.add_space(4.0);
                ui.add(egui::Label::new(egui::RichText::new(e).color(pal().danger)).wrap(true));
            }
            if let Some((label, fp)) = &self.add_result {
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(fill(
                            c.added_title,
                            &[("label", &shorten_label(label, 40))],
                        ))
                        .strong()
                        .color(pal().success),
                    )
                    .wrap(true),
                );
                ui.label(egui::RichText::new(fp).monospace().size(26.0).strong());
                ui.add(
                    egui::Label::new(egui::RichText::new(c.added_compare).color(pal().warning))
                        .wrap(true),
                );
            }
        });
    }

    fn handle_drops(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        let ctx = ui.ctx();
        let (hovering, dropped, pos) = ctx.input(|i| {
            (
                !i.raw.hovered_files.is_empty(),
                i.raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .collect::<Vec<_>>(),
                i.pointer.hover_pos().or(i.pointer.latest_pos()),
            )
        });
        if hovering && !self.contacts.is_empty() {
            card_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(
                    egui::Label::new(egui::RichText::new(c.drop_hint).color(pal().accent))
                        .wrap(true),
                );
            });
            ui.add_space(GAP);
        }
        if dropped.is_empty() {
            return;
        }
        let target = drop_target(&self.row_rects, pos, self.contacts.len()).map(str::to_owned);
        match target {
            Some(id) => self.send_paths(c, &id, dropped),
            None if self.contacts.is_empty() => {}
            None => self.page_msg = Some((c.drop_pick_contact.to_owned(), true)),
        }
    }

    fn list_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings, technical: bool) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, c.list_title);
            if self.contacts.is_empty() {
                ui.add(
                    egui::Label::new(egui::RichText::new(c.list_empty).color(pal().muted))
                        .wrap(true),
                );
                self.row_rects.clear();
                return;
            }
            let contacts = self.contacts.clone();
            let not_allowed = not_allowed_contacts(&self.rows);
            let mut rects = Vec::new();
            for (i, ct) in contacts.iter().enumerate() {
                if i > 0 {
                    ui.add_space(8.0);
                }
                let resp = inner_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    self.contact_row(ui, c, ct, not_allowed.contains(&ct.id), technical);
                });
                rects.push((ct.id.clone(), resp.response.rect));
            }
            self.row_rects = rects;
        });
    }

    fn contact_row(
        &mut self,
        ui: &mut egui::Ui,
        c: &ContactStrings,
        ct: &ContactInfo,
        no_reg: bool,
        technical: bool,
    ) {
        // Title line: name and status chip; both wrap onto a second line when the window is narrow.
        ui.horizontal_wrapped(|ui| {
            if self.renaming.as_ref().is_some_and(|(id, _)| *id == ct.id) {
                let mut commit = false;
                let mut stop = false;
                if let Some((_, text)) = self.renaming.as_mut() {
                    ui.add(egui::TextEdit::singleline(text).desired_width(200.0));
                    let t = text.trim().to_owned();
                    if ui
                        .add_enabled(!t.is_empty(), egui::Button::new(c.save))
                        .clicked()
                    {
                        commit = true;
                    }
                }
                if ui.button(c.cancel).clicked() {
                    stop = true;
                }
                if commit {
                    if let Some((id, text)) = self.renaming.take() {
                        self.update_contact(&id, Some(text.trim().to_owned()), None, None, None);
                    }
                } else if stop {
                    self.renaming = None;
                }
            } else {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(shorten_label(&ct.label, NAME_MAX))
                            .strong()
                            .size(NAME_SIZE),
                    )
                    .wrap(true),
                )
                .on_hover_text(&ct.label);
            }
            if no_reg {
                crate::transfers::draw_chip(ui, pal().warning, c.chip_not_registered);
            } else {
                crate::transfers::draw_chip(ui, pal().success, c.chip_registered);
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(label_text(c.fingerprint));
            ui.label(egui::RichText::new(&ct.fingerprint).monospace().strong());
        });
        if technical {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(format!(
                        "{}  {}",
                        shorten_name(&ct.endpoint_id, 24),
                        crate::transfers::plain_path(&ct.inbox_dir)
                    ))
                    .size(crate::ui_kit::MIN_TEXT_PX)
                    .monospace()
                    .color(pal().faint),
                )
                .wrap(true),
            );
        }
        if no_reg {
            ui.add_space(2.0);
            ui.add(
                egui::Label::new(egui::RichText::new(c.hint_not_registered).color(pal().warning))
                    .wrap(true),
            );
        }
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            let can_send = ct.allow_send;
            if ui
                .add_enabled(can_send, primary_button(c.send_files))
                .clicked()
            {
                if let Some(files) = rfd::FileDialog::new().set_title(c.pick_title).pick_files() {
                    self.send_paths(c, &ct.id, files);
                }
            }
            if ui.button(c.rename).clicked() {
                self.renaming = Some((ct.id.clone(), ct.label.clone()));
            }
            if ui.add(danger_button(c.remove)).clicked() {
                self.remove_target = Some((ct.id.clone(), ct.label.clone()));
            }
        });
        if !ct.allow_send {
            ui.add(egui::Label::new(label_text(c.send_disabled_note)).wrap(true));
        }
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
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
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(label_text(c.max_size));
            let init = size_limit_text(ct.max_file_size);
            let buf = self
                .edits
                .entry(ct.id.clone())
                .or_insert_with(|| init.clone());
            ui.add(
                egui::TextEdit::singleline(buf)
                    .hint_text(max_size_hint_text(c, ct.default_max_file_size))
                    .desired_width(240.0),
            );
            let dirty = *buf != init;
            let text = buf.clone();
            if ui.add_enabled(dirty, egui::Button::new(c.save)).clicked() {
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
                    }
                }
            }
        });
        if self.max_error.contains(&ct.id) {
            ui.add(
                egui::Label::new(egui::RichText::new(c.max_size_invalid).color(pal().danger))
                    .wrap(true),
            );
        }
    }

    fn set_local(&mut self, id: &str, f: impl FnOnce(&mut ContactInfo)) {
        if let Some(x) = self.contacts.iter_mut().find(|x| x.id == id) {
            f(x);
        }
    }

    fn remove_dialog(&mut self, ctx: &egui::Context, c: &ContactStrings) {
        let Some((id, label)) = self.remove_target.clone() else {
            return;
        };
        crate::a11y::dialog_enter(ctx, "contact_remove");
        if crate::a11y::esc_pressed(ctx) {
            self.remove_target = None;
            crate::a11y::dialog_leave(ctx, "contact_remove");
            return;
        }
        egui::Window::new(c.remove_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(380.0)
            .max_width(420.0)
            .show(ctx, |ui| {
                ui.set_max_width(400.0);
                ui.add(
                    egui::Label::new(fill(
                        c.remove_body,
                        &[("label", &shorten_label(&label, 40))],
                    ))
                    .wrap(true),
                );
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.add(danger_button(c.remove_confirm)).clicked() {
                        self.out.push_back(PushRequest::ContactRemove {
                            contact: id.clone(),
                        });
                        self.contacts.retain(|x| x.id != id);
                        self.edits.remove(&id);
                        self.remove_target = None;
                        crate::a11y::dialog_leave(ui.ctx(), "contact_remove");
                    }
                    let cancel = ui.button(c.cancel);
                    crate::a11y::dialog_focus_safe_button(ui.ctx(), "contact_remove", &cancel);
                    if cancel.clicked() {
                        self.remove_target = None;
                        crate::a11y::dialog_leave(ui.ctx(), "contact_remove");
                    }
                });
            });
    }

    fn transfers_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                section_title(ui, c.tr_title);
                if let Some(t) = self.speed.header_total(&self.rows, ui.max_rect().width()) {
                    ui.label(egui::RichText::new(t).color(pal().muted));
                }
                if self
                    .rows
                    .iter()
                    .any(|r| r.finished() && r.at_ms > self.cleared_before_ms)
                    && ui.button(c.btn_clear_finished).clicked()
                {
                    self.cleared_before_ms = self.rows.iter().map(|r| r.at_ms).max().unwrap_or(0);
                }
            });
            let rows: Vec<Row> =
                visible_rows(&self.rows, self.cleared_before_ms, MAX_FINISHED_SHOWN)
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
            if can_cancel || can_retry || can_try_now || received {
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
                    if received {
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
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, c.inbox_title);
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

/// Space between two sections.
const GAP: f32 = 10.0;
/// Section title / contact name / body / label and hint. Never below the app's small size.
const SECTION_SIZE: f32 = 16.0;
const NAME_SIZE: f32 = 15.0;
const LABEL_SIZE: f32 = 13.0;
/// Longest contact name drawn (characters); the full name is the hover text.
const NAME_MAX: usize = 28;

/// The title of a card.
fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.add(
        egui::Label::new(
            egui::RichText::new(text)
                .strong()
                .size(SECTION_SIZE)
                .color(pal().text),
        )
        .wrap(true),
    );
    ui.add_space(4.0);
}

/// One numbered step: the number stays on the left and the text wraps in its own column, so a
/// second line starts under the text and not under the number (also at a 700 px window).
fn help_step(ui: &mut egui::Ui, line: &str) {
    let (num, body) = match line.split_once(". ") {
        Some((n, b)) if !n.is_empty() && n.chars().all(|ch| ch.is_ascii_digit()) => {
            (format!("{n}."), b)
        }
        _ => (String::new(), line),
    };
    ui.horizontal_top(|ui| {
        if !num.is_empty() {
            ui.add_sized(
                [20.0, 0.0],
                egui::Label::new(egui::RichText::new(num).strong()),
            );
        }
        ui.add(egui::Label::new(body).wrap(true));
    });
}

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
    "empty", "two", "active", "failed", "qr", "remove", "added", "adderror",
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
                ui.show_qr = true;
            }
            "remove" => {
                ui.contacts = vec![a.clone(), b.clone()];
                ui.remove_target = Some((b.id.clone(), b.label.clone()));
            }
            "added" => {
                ui.contacts = vec![a.clone()];
                ui.add_result = Some(("田中".into(), "0CS3Y-09W9N-5B5WM-QMMCX".into()));
            }
            "adderror" => {
                ui.add_text = "これは連絡先コードではありません".into();
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
            assert!(ContactsUi::fixture("remove", c)
                .unwrap()
                .remove_target
                .is_some());
            assert!(ContactsUi::fixture("qr", c).unwrap().show_qr);
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
    fn invitation_has_code_and_howto_in_both_languages_and_no_secret() {
        let code = "miasma-contact:ABCDEFG";
        let m = invitation_message(code, "AAAAA-BBBBB-CCCCC-DDDDD");
        assert!(m.contains(code));
        assert!(m.contains("連絡先") && m.contains("Contacts"));
        assert!(m.contains("AAAAA-BBBBB-CCCCC-DDDDD"));
        assert!(!m.to_lowercase().contains("password:"));
        assert!(!m.contains("secret"));
    }

    #[test]
    fn invitation_round_trips_through_the_core_extractor() {
        // The basepoint of Ed25519 is a valid public key.
        let mut id = [0x66u8; 32];
        id[0] = 0x58;
        let code = miasma_core::push::ContactCode::new(id);
        let text = code.to_string();
        let m = invitation_message(&text, &code.fingerprint());
        assert_eq!(
            miasma_core::push::extract_contact_code(&m).as_deref(),
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
    fn clear_finished_hides_old_and_caps_the_rest() {
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
        assert_eq!(visible_rows(&r, 0, 100).len(), 11);
        assert_eq!(visible_rows(&r, 0, 3).len(), 4);
        // Cleared up to 14: f0..f4 hidden, running one stays.
        let vis = visible_rows(&r, 14, 100);
        assert_eq!(vis.len(), 1 + 5);
        assert!(vis.iter().any(|x| x.id == "run"));
        assert_eq!(visible_rows(&r, 1000, 100).len(), 1);
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

    #[test]
    fn help_steps_stay_inside_a_700_px_window() {
        // Lay the three steps out in the real card at a 700 px window and check nothing pokes
        // out of the panel, in every language.
        let ctx = egui::Context::default();
        crate::ui_kit::apply_theme(&ctx, false);
        for lang in Locale::ALL {
            let c = contact_strings(lang);
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
                    ContactsUi::default().help_card(ui, c);
                    inner = Some((avail, ui.min_rect()));
                });
            });
            let (avail, used) = inner.unwrap();
            assert!(
                used.right() <= avail.right() + 1.0,
                "{lang:?}: help steps overflow ({used:?} vs {avail:?})"
            );
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
