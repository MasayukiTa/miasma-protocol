//! The Contacts area: trusted-contact push (ADR-012) in the desktop app.
//!
//! Everything the daemon knows (contacts, my card, transfers, inbox folder) is read through
//! `WorkerCmd::Push` on the worker thread; this file never touches the network or the disk
//! except to open a folder/file the person clicked. The first half is pure view-model logic
//! (no egui context) and unit-tested headless; the second half draws it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eframe::egui;
use miasma_core::push::{
    ContactInfo, Direction, HistoryEntry, PushRequest, PushResponse, PushState, PushTransferInfo,
};

use crate::app::{card_frame, danger_button, primary_button, section_heading};
use crate::locale::ContactStrings;
use crate::theme::{self, Palette};
use crate::transfers::{fill, format_bytes, format_eta, format_rate};
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

// ─── Pure: contact card texts ───────────────────────────────────────────────

/// The message to paste into chat or e-mail. Bilingual, and it carries only public things: the
/// contact code is public by design, the fingerprint is a digest of it. No secret ever goes here.
pub fn invitation_message(code: &str, fingerprint: &str) -> String {
    format!(
        "Miasma の連絡先カードです / Here is my Miasma contact card.\n\
         \n\
         {code}\n\
         \n\
         指紋 / Fingerprint: {fingerprint}\n\
         \n\
         使い方: Miasma > 連絡先 > 「連絡先を追加」に、このメッセージをそのまま貼り付けて「追加」を押してください。\n\
         How to: paste this whole message in Miasma > Contacts > Add a contact, then press Add.\n\
         (連絡先コードは公開して大丈夫です。パスワードではありません。/ The code is public, not a password.)\n"
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
pub fn error_text(c: &ContactStrings, kind: &str, message: &str) -> String {
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
            return if message.trim().is_empty() {
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
    pub saved_as: Option<String>,
    /// Last change, milliseconds since the epoch.
    pub at_ms: u64,
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
            saved_as: t.saved_as.clone(),
            at_ms: t.updated_at_ms,
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
            saved_as: h.saved_as.clone(),
            at_ms: h.finished_at_ms,
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
    }
}

/// Guidance for a finished row that did not succeed, or the live retry note for a row that is
/// still trying. `None` when there is nothing to add.
pub fn row_guidance(c: &ContactStrings, r: &Row) -> Option<String> {
    match r.state {
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
        PushState::Failed => {
            let e = r.error.as_deref().unwrap_or("");
            Some(match classify_failure(e) {
                FailClass::Unreachable => c.fail_unreachable.to_owned(),
                FailClass::Other if e.trim().is_empty() => c.fail_other.to_owned(),
                FailClass::Other => format!("{}: {}", c.fail_other, e.trim()),
            })
        }
        // A queued/connecting transfer that carries an error is retrying after one.
        PushState::Queued | PushState::Connecting
            if r.outbound && r.error.as_deref().is_some_and(|e| !e.trim().is_empty()) =>
        {
            let e = r.error.as_deref().unwrap_or("");
            Some(match classify_failure(e) {
                FailClass::Unreachable => c.fail_unreachable.to_owned(),
                FailClass::Other => e.trim().to_owned(),
            })
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

/// Where a received file is: `saved_as` if it is a path, else `<contact inbox>/<saved_as>`.
pub fn saved_path(saved_as: &str, contact_inbox: Option<&str>) -> PathBuf {
    let p = Path::new(saved_as);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    match contact_inbox {
        Some(dir) => Path::new(dir).join(saved_as),
        None => p.to_path_buf(),
    }
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

// ─── Open a file or folder (only when clicked) ──────────────────────────────

/// Open a folder in the file manager.
pub fn open_folder(dir: &str) {
    #[cfg(windows)]
    let cmd = "explorer";
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(not(any(windows, target_os = "macos")))]
    let cmd = "xdg-open";
    let _ = std::process::Command::new(cmd).arg(dir).spawn();
}

/// Show a file in its folder (selected where the OS supports it).
pub fn reveal_file(path: &Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer")
            .arg(format!("/select,{}", path.display()))
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg("-R")
            .arg(path)
            .spawn();
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        if let Some(dir) = path.parent() {
            let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
        }
    }
}

/// Open a received file with its default program. Only ever called from a button click.
pub fn open_file(path: &Path) {
    #[cfg(windows)]
    let cmd = "explorer";
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(not(any(windows, target_os = "macos")))]
    let cmd = "xdg-open";
    let _ = std::process::Command::new(cmd).arg(path).spawn();
}

// ─── State ──────────────────────────────────────────────────────────────────

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
}

impl Default for ContactsUi {
    fn default() -> Self {
        let now = Instant::now();
        Self {
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

    fn has_active(&self) -> bool {
        self.rows.iter().any(|r| !r.finished())
    }

    /// Ask for more data when it is due. Cheap: when the area is closed and nothing is running
    /// this is one small request every 3 s (so arrivals are noticed).
    pub fn tick(&mut self, area_open: bool, connected: bool) {
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
    }

    fn request_all(&mut self) {
        let now = Instant::now();
        self.status_in_flight = Some(now);
        self.last_status = now;
        self.last_list = now;
        self.last_history = now;
        self.out.push_back(PushRequest::ContactCode);
        self.out.push_back(PushRequest::ContactList);
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
    }

    /// Process the daemon's answer to a request this UI made.
    pub fn on_reply(
        &mut self,
        c: &ContactStrings,
        req: PushRequest,
        reply: Result<PushResponse, PushFail>,
    ) {
        let is_status = matches!(req, PushRequest::Status { id: None });
        if is_status {
            self.status_in_flight = None;
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
                self.fail_request(&req, f.message);
                return;
            }
        };
        match resp {
            PushResponse::Error { kind, message } => {
                if kind == "unavailable" {
                    self.availability = Availability::NoIroh;
                }
                let text = error_text(c, &kind, &message);
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
            PushRequest::ContactAdd { .. } => {
                self.add_busy = false;
                self.add_error = Some(text);
            }
            PushRequest::Send { .. }
            | PushRequest::ContactRemove { .. }
            | PushRequest::ContactUpdate { .. }
            | PushRequest::Cancel { .. } => {
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
            PushResponse::Contact(info) => {
                if let PushRequest::ContactAdd { .. } = req {
                    self.add_busy = false;
                    self.add_error = None;
                    self.add_text.clear();
                    self.add_label.clear();
                    self.add_result = Some((info.label.clone(), info.fingerprint.clone()));
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
            PushResponse::Cancelled => self.refresh_soon(),
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

    fn retry(&mut self, r: &Row) {
        if let Some(path) = self.paths.get(&r.id).cloned() {
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

    fn can_retry(&self, r: &Row) -> bool {
        r.outbound
            && matches!(r.state, PushState::Failed | PushState::Rejected)
            && self.paths.contains_key(&r.id)
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
        section_heading(ui, c.heading);
        ui.add_space(4.0);
        ui.add(egui::Label::new(egui::RichText::new(c.desc).color(pal().muted)).wrap(true));
        ui.add_space(8.0);

        if !connected || self.availability == Availability::DaemonDown {
            self.notice_card(ui, c.daemon_down, pal().warning, None);
            return;
        }
        match self.availability {
            Availability::NoIroh => {
                self.notice_card(ui, c.push_unavailable, pal().warning, Some(c.retry_now));
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
                ui.add(egui::Label::new(egui::RichText::new(&msg).color(color)).wrap(true));
                if ui.small_button(c.cancel).clicked() {
                    self.page_msg = None;
                }
            });
            ui.add_space(8.0);
        }

        if self.contacts.is_empty() && self.contacts_loaded {
            self.help_card(ui, c);
            ui.add_space(10.0);
        }
        self.my_card_ui(ui, c);
        ui.add_space(10.0);
        self.add_ui(ui, c);
        ui.add_space(10.0);
        self.list_ui(ui, c, technical);
        ui.add_space(10.0);
        self.transfers_ui(ui, c);
        ui.add_space(10.0);
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
            ui.label(egui::RichText::new(c.help_title).strong().size(15.0));
            ui.add_space(4.0);
            for line in [c.help_1, c.help_2, c.help_3] {
                ui.add(egui::Label::new(line).wrap(true));
            }
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(egui::RichText::new(c.offline_note).color(pal().muted)).wrap(true),
            );
        });
    }

    fn my_card_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new(c.my_card).strong().size(15.0));
            let Some((code, fp)) = self.my_code.clone() else {
                ui.label(egui::RichText::new(c.loading).color(pal().muted));
                return;
            };
            ui.add_space(4.0);
            ui.label(egui::RichText::new(c.my_code).small().color(pal().muted));
            let mut shown = code.clone();
            ui.add(
                egui::TextEdit::multiline(&mut shown)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(6.0);
            ui.label(egui::RichText::new(c.my_fp).small().color(pal().muted));
            ui.label(
                egui::RichText::new(&fp)
                    .monospace()
                    .size(26.0)
                    .strong()
                    .color(pal().text),
            );
            ui.add(
                egui::Label::new(egui::RichText::new(c.my_fp_hint).color(pal().muted)).wrap(true),
            );
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                let l = if recent(self.copied_at) {
                    c.copied
                } else {
                    c.copy_code
                };
                if ui.button(l).clicked() {
                    ui.output_mut(|o| o.copied_text = code.clone());
                    self.copied_at = Some(Instant::now());
                }
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
                let l = if self.show_qr { c.hide_qr } else { c.show_qr };
                if ui.button(l).clicked() {
                    self.show_qr = !self.show_qr;
                }
            });
            if self.show_qr {
                ui.add_space(6.0);
                if !crate::transfers::draw_qr(ui, &qr_payload(&code), 240.0) {
                    ui.label(egui::RichText::new("QR: too long").color(pal().danger));
                }
                ui.add(
                    egui::Label::new(egui::RichText::new(c.qr_note).small().color(pal().muted))
                        .wrap(true),
                );
            }
        });
    }

    fn add_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new(c.add_title).strong().size(15.0));
            ui.add(egui::Label::new(egui::RichText::new(c.add_hint).color(pal().muted)).wrap(true));
            ui.add_space(4.0);
            ui.label(egui::RichText::new(c.add_paste).small().color(pal().muted));
            ui.add(
                egui::TextEdit::multiline(&mut self.add_text)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY),
            );
            ui.label(egui::RichText::new(c.add_label).small().color(pal().muted));
            ui.add(
                egui::TextEdit::singleline(&mut self.add_label)
                    .hint_text(c.add_label_hint)
                    .desired_width(260.0),
            );
            ui.add_space(6.0);
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
                        self.out.push_back(PushRequest::ContactAdd {
                            code: self.add_text.clone(),
                            label: Some(label),
                        });
                    }
                }
            });
            if let Some(e) = &self.add_error {
                ui.add_space(4.0);
                ui.add(egui::Label::new(egui::RichText::new(e).color(pal().danger)).wrap(true));
            }
            if let Some((label, fp)) = &self.add_result {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(fill(c.added_title, &[("label", label)]))
                        .strong()
                        .color(pal().success),
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
                ui.colored_label(pal().accent, c.drop_hint);
            });
            ui.add_space(6.0);
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
        ui.label(egui::RichText::new(c.list_title).strong().size(15.0));
        ui.add_space(4.0);
        if self.contacts.is_empty() {
            ui.label(egui::RichText::new(c.list_empty).color(pal().muted));
            return;
        }
        let contacts = self.contacts.clone();
        let not_allowed = not_allowed_contacts(&self.rows);
        let mut rects = Vec::new();
        for ct in &contacts {
            let resp = card_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                self.contact_row(ui, c, ct, not_allowed.contains(&ct.id), technical);
            });
            rects.push((ct.id.clone(), resp.response.rect));
            ui.add_space(6.0);
        }
        self.row_rects = rects;
    }

    fn contact_row(
        &mut self,
        ui: &mut egui::Ui,
        c: &ContactStrings,
        ct: &ContactInfo,
        no_reg: bool,
        technical: bool,
    ) {
        // Title line: name, status chip, fingerprint.
        ui.horizontal_wrapped(|ui| {
            if self.renaming.as_ref().is_some_and(|(id, _)| *id == ct.id) {
                let mut commit = false;
                let mut stop = false;
                if let Some((_, text)) = self.renaming.as_mut() {
                    ui.add(egui::TextEdit::singleline(text).desired_width(180.0));
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
                ui.label(
                    egui::RichText::new(shorten_name(&ct.label, 40))
                        .strong()
                        .size(16.0),
                );
            }
            if no_reg {
                crate::transfers::draw_chip(ui, pal().warning, c.chip_not_registered);
            } else {
                crate::transfers::draw_chip(ui, pal().success, c.chip_registered);
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(c.fingerprint)
                    .small()
                    .color(pal().muted),
            );
            ui.label(egui::RichText::new(&ct.fingerprint).monospace().strong());
        });
        if technical {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(format!(
                        "{}  {}",
                        shorten_name(&ct.endpoint_id, 24),
                        ct.inbox_dir
                    ))
                    .small()
                    .monospace()
                    .color(pal().faint),
                )
                .wrap(true),
            );
        }
        if no_reg {
            ui.add(
                egui::Label::new(egui::RichText::new(c.hint_not_registered).color(pal().warning))
                    .wrap(true),
            );
        }
        ui.add_space(4.0);
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
            ui.label(
                egui::RichText::new(c.send_disabled_note)
                    .small()
                    .color(pal().muted),
            );
        }
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
            ui.label(egui::RichText::new(c.max_size).small().color(pal().muted));
            let init = size_limit_text(ct.max_file_size);
            let buf = self
                .edits
                .entry(ct.id.clone())
                .or_insert_with(|| init.clone());
            ui.add(
                egui::TextEdit::singleline(buf)
                    .hint_text(c.max_size_hint)
                    .desired_width(90.0),
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
            ui.label(
                egui::RichText::new(c.max_size_invalid)
                    .small()
                    .color(pal().danger),
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
        egui::Window::new(c.remove_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .max_width(420.0)
            .show(ctx, |ui| {
                ui.add(egui::Label::new(fill(c.remove_body, &[("label", &label)])).wrap(true));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.add(danger_button(c.remove_confirm)).clicked() {
                        self.out.push_back(PushRequest::ContactRemove {
                            contact: id.clone(),
                        });
                        self.contacts.retain(|x| x.id != id);
                        self.edits.remove(&id);
                        self.remove_target = None;
                    }
                    if ui.button(c.cancel).clicked() {
                        self.remove_target = None;
                    }
                });
            });
    }

    fn transfers_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new(c.tr_title).strong().size(15.0));
            if self
                .rows
                .iter()
                .any(|r| r.finished() && r.at_ms > self.cleared_before_ms)
                && ui.small_button(c.btn_clear_finished).clicked()
            {
                self.cleared_before_ms = self.rows.iter().map(|r| r.at_ms).max().unwrap_or(0);
            }
        });
        ui.add_space(4.0);
        let rows: Vec<Row> = visible_rows(&self.rows, self.cleared_before_ms, MAX_FINISHED_SHOWN)
            .into_iter()
            .cloned()
            .collect();
        if rows.is_empty() {
            ui.label(egui::RichText::new(c.tr_empty).color(pal().muted));
            return;
        }
        for r in &rows {
            self.row_ui(ui, c, r);
            ui.add_space(4.0);
        }
    }

    fn row_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings, r: &Row) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                crate::transfers::paint_arrow(ui.painter(), rect.center(), r.outbound, pal().muted);
                let name = ui.add(
                    egui::Label::new(egui::RichText::new(shorten_name(&r.name, 48)).strong())
                        .wrap(true),
                );
                name.on_hover_text(&r.name);
            });
            let who = if r.outbound { c.dir_out } else { c.dir_in };
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "{who}: {}  ·  {}",
                        shorten_name(&r.contact_label, 30),
                        format_bytes(r.size)
                    ))
                    .color(pal().muted),
                );
                let color = match r.state {
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
                if r.rate_bps > 0 {
                    line.push_str(&format!("  ·  {}", format_rate(r.rate_bps as f64)));
                }
                if let Some(e) = eta_secs(r.size, r.bytes, r.rate_bps) {
                    line.push_str(&format!("  ·  {} {}", format_eta(Some(e), "d"), c.eta));
                }
                ui.add(
                    egui::ProgressBar::new(f)
                        .desired_width(ui.available_width().max(60.0))
                        .text(line),
                );
            }
            if let Some(g) = row_guidance(c, r) {
                let color = if r.finished() {
                    pal().danger
                } else {
                    pal().warning
                };
                ui.add(egui::Label::new(egui::RichText::new(g).color(color)).wrap(true));
            }
            ui.horizontal_wrapped(|ui| {
                if !r.finished() && ui.button(c.btn_cancel).clicked() {
                    self.out.push_back(PushRequest::Cancel { id: r.id.clone() });
                }
                if self.can_retry(r) && ui.button(c.btn_retry).clicked() {
                    self.retry(r);
                }
                if !r.outbound && r.state == PushState::Done {
                    if let Some(sa) = &r.saved_as {
                        let inbox = self
                            .contacts
                            .iter()
                            .find(|x| x.id == r.contact_id)
                            .map(|x| x.inbox_dir.as_str());
                        let p = saved_path(sa, inbox);
                        if ui.button(c.btn_open_file).clicked() {
                            open_file(&p);
                        }
                        if ui.button(c.btn_show_folder).clicked() {
                            reveal_file(&p);
                        }
                    }
                }
            });
        });
    }

    fn inbox_ui(&mut self, ui: &mut egui::Ui, c: &ContactStrings) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new(c.inbox_title).strong().size(15.0));
            if let Some(dir) = self.inbox_dir.clone() {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!("{}: {dir}", c.inbox_dir))
                            .monospace()
                            .small(),
                    )
                    .wrap(true),
                );
                if ui.button(c.open_folder).clicked() {
                    open_folder(&dir);
                }
            }
            ui.label(egui::RichText::new(c.inbox_note).small().color(pal().muted));
        });
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
            saved_as: None,
            created_at_ms: at,
            updated_at_ms: at,
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
    fn unavailable_points_at_the_daemon_and_netcheck() {
        let m = error_text(contact_strings(Locale::En), "unavailable", "");
        assert!(m.contains("daemon") && m.contains("netcheck"));
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
        assert!(g.contains("netcheck"));
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
    fn saved_path_resolution() {
        let abs = if cfg!(windows) {
            r"C:\inbox\bob\a.txt"
        } else {
            "/inbox/bob/a.txt"
        };
        assert_eq!(saved_path(abs, Some("/x")), PathBuf::from(abs));
        assert_eq!(
            saved_path("a.txt", Some("/inbox/bob")),
            Path::new("/inbox/bob").join("a.txt")
        );
        assert_eq!(saved_path("a.txt", None), PathBuf::from("a.txt"));
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
        assert_eq!(ui.out.len(), 5, "first tick reads everything");
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
}
