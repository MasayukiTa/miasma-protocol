//! The Transfers screen: a list of resumable transfers with a detail pane and two "new transfer"
//! forms (receive / send).
//!
//! The daemon runs and remembers every transfer (see `miasma_core::transfer`); this screen only
//! starts, lists and cancels them through `WorkerCmd`, and polls the list about once a second while
//! it is visible or something is running. Nothing here blocks the egui frame.
//!
//! Layout follows a torrent client (list on top, detail below) in the app's palette: status is a
//! small chip plus text colour, the accent colour is only on primary buttons, and there are no
//! coloured rails or full-card status fills (owner rule, see `theme.rs`).
//!
//! The file has two halves: the pure functions (formatting, strip bucketing, chip mapping, the
//! redundancy table) that the unit tests at the bottom cover, and the drawing code.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use eframe::egui;
use miasma_core::transfer::{
    jobs::send_id,
    password_policy::{self, PolicyViolation, Strength},
    Phase, TransferKind, TransferState, TransferStatus,
};
use zeroize::Zeroize;

use crate::app::{card_frame, danger_button, primary_button, section_heading};
use crate::locale::TransferStrings;
use crate::theme::{self, Palette};
use crate::worker::{WorkerCmd, DEFAULT_SEND_K, DEFAULT_SEND_N};

fn pal() -> Palette {
    theme::palette()
}

// ─── Pure: numbers ──────────────────────────────────────────────────────────

/// `1536` -> `1.5 KiB`. Integer arithmetic only, so a 100 GiB job (or anything up to `u64::MAX`)
/// never goes through a float; the fraction is truncated to one decimal.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut idx = 1;
    let mut shift = 10;
    while idx < UNITS.len() - 1 && (bytes >> (shift + 10)) > 0 {
        idx += 1;
        shift += 10;
    }
    let tenths = ((bytes as u128) * 10) >> shift;
    format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[idx])
}

/// Bytes per second as text, or `-` when the rate is zero, negative or not a number (a job that
/// has not moved a byte yet, or a paused one read back from its journal).
pub fn format_rate(bps: f64) -> String {
    if !bps.is_finite() || bps < 1.0 {
        return "-".to_owned();
    }
    format!("{}/s", format_bytes(bps as u64))
}

/// `hh:mm:ss`, or `Nd hh:mm:ss` from a day up (`day` is the locale's suffix). `None` is `-`.
pub fn format_eta(secs: Option<u64>, day: &str) -> String {
    let Some(s) = secs else {
        return "-".to_owned();
    };
    let days = s / 86_400;
    if days > 999 {
        return format!(">999{day}");
    }
    let (h, m, sec) = ((s % 86_400) / 3600, (s % 3600) / 60, s % 60);
    if days > 0 {
        format!("{days}{day} {h:02}:{m:02}:{sec:02}")
    } else {
        format!("{h:02}:{m:02}:{sec:02}")
    }
}

/// Progress in tenths of a percent (`0..=1000`), or `None` when the total is unknown (a legacy
/// record without a manifest reports `bytes_total == 0`). A finished transfer is always 100 %.
pub fn permille(done: u64, total: u64, state: TransferState) -> Option<u32> {
    if state == TransferState::Complete {
        return Some(1000);
    }
    if total == 0 {
        return None;
    }
    Some(((done.min(total) as u128 * 1000) / total as u128) as u32)
}

pub fn format_permille(p: Option<u32>) -> String {
    match p {
        Some(p) => format!("{}.{}%", p / 10, p % 10),
        None => "-".to_owned(),
    }
}

/// Integer share of the three phase times, summing to 100, or `None` when nothing is measured.
pub fn time_split(fetch_ms: u64, decode_ms: u64, write_ms: u64) -> Option<[u32; 3]> {
    let total = fetch_ms as u128 + decode_ms as u128 + write_ms as u128;
    if total == 0 {
        return None;
    }
    let a = (fetch_ms as u128 * 100 / total) as u32;
    let b = (decode_ms as u128 * 100 / total) as u32;
    // The last share takes the remainder so the three always sum to 100.
    Some([a, b, 100 - a - b])
}

/// Replace `{key}` placeholders in a locale template.
pub fn fill(template: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = template.to_owned();
    for (k, v) in pairs {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

// ─── Pure: names and ids ────────────────────────────────────────────────────

/// A path without the Windows `\\?\` prefix that `canonicalize` adds.
pub fn plain_path(path: &str) -> &str {
    path.strip_prefix(r"\\?\").unwrap_or(path)
}

/// Last component of a path from either OS (the daemon may run on the other one).
pub fn file_name_of(path: &str) -> String {
    let p = plain_path(path);
    let last = p.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or(p);
    last.to_owned()
}

/// What to call a transfer in the list: its file name, or (before the daemon has reported one)
/// the start of its MID.
pub fn title_of(job: &TransferStatus) -> String {
    if !job.name.is_empty() {
        return file_name_of(&job.name);
    }
    if job.mid.is_empty() {
        return "-".to_owned();
    }
    let chars: Vec<char> = job.mid.chars().collect();
    if chars.len() <= 24 {
        job.mid.clone()
    } else {
        chars[..24].iter().collect::<String>() + "..."
    }
}

/// The id the daemon knows a transfer by (what `TransferCancel` takes): the MID for a receive, the
/// source path (prefixed) for a send.
pub fn transfer_id(s: &TransferStatus) -> String {
    match s.kind {
        TransferKind::Receive => s.mid.clone(),
        TransferKind::Send => send_id(Path::new(&s.name)),
    }
}

// ─── Pure: state, chip, order ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chip {
    Info,
    Warning,
    Success,
    Danger,
    Faint,
}

/// running = info, paused = warning, complete = success, failed = danger, cancelled = faint.
pub fn chip_for(state: TransferState) -> Chip {
    match state {
        TransferState::Running => Chip::Info,
        TransferState::Paused => Chip::Warning,
        TransferState::Complete => Chip::Success,
        TransferState::Failed => Chip::Danger,
        TransferState::Cancelled => Chip::Faint,
    }
}

fn chip_color(chip: Chip) -> egui::Color32 {
    let p = pal();
    match chip {
        Chip::Info => p.info,
        Chip::Warning => p.warning,
        Chip::Success => p.success,
        Chip::Danger => p.danger,
        Chip::Faint => p.faint,
    }
}

fn state_label(t: &TransferStrings, state: TransferState) -> &'static str {
    match state {
        TransferState::Running => t.st_running,
        TransferState::Paused => t.st_paused,
        TransferState::Complete => t.st_complete,
        TransferState::Failed => t.st_failed,
        TransferState::Cancelled => t.st_cancelled,
    }
}

/// List order: running first, then what needs attention, then finished ones.
fn sort_rank(state: TransferState) -> u8 {
    match state {
        TransferState::Running => 0,
        TransferState::Paused => 1,
        TransferState::Failed => 2,
        TransferState::Cancelled => 3,
        TransferState::Complete => 4,
    }
}

pub fn sort_jobs(jobs: &mut [TransferStatus]) {
    jobs.sort_by(|a, b| {
        sort_rank(a.state)
            .cmp(&sort_rank(b.state))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.mid.cmp(&b.mid))
    });
}

/// Something stopped can be started again with the same request (the journal is what resumes
/// it). A failed one is offered too: a wrong password fails the job, and typing it again is the fix.
pub fn can_resume(state: TransferState) -> bool {
    matches!(
        state,
        TransferState::Paused | TransferState::Cancelled | TransferState::Failed
    )
}

/// Complete, Failed or Cancelled: nothing more will happen to it on its own.
pub fn is_finished(state: TransferState) -> bool {
    matches!(
        state,
        TransferState::Complete | TransferState::Failed | TransferState::Cancelled
    )
}

/// A finished row can be taken off the list. A running or paused one cannot: paused keeps its
/// journal so it can resume, and starting it over is the existing "Start over" action.
pub fn can_remove(job: &TransferStatus) -> bool {
    is_finished(job.state)
}

/// Removing this row would throw away partial data (a stopped transfer that can still resume),
/// so it needs an explicit "Discard and remove".
pub fn remove_needs_discard(job: &TransferStatus) -> bool {
    is_finished(job.state) && job.resumable
}

/// Finished rows that "Clear finished" takes off without losing anything.
pub fn clearable(job: &TransferStatus) -> bool {
    is_finished(job.state) && !job.resumable
}

/// "Clear finished" is shown only when it would do something.
pub fn show_clear_finished(jobs: &[TransferStatus]) -> bool {
    jobs.iter().any(clearable)
}

/// The file name offered in the Save-As dialog before the transfer is looked up: `received-<first
/// 8 characters of the MID digest>.bin`, or `received.bin` when no ID has been typed yet. (The
/// original name is only known once the manifest has been fetched; a folder target uses it then,
/// see [`effective_receive_path`].) Accepts a share ID or a MID.
pub fn suggested_file_name(id: &str) -> String {
    let typed = id.trim();
    let mid_text = if typed.starts_with("miasma-share:") {
        miasma_core::transfer::ShareId::parse(typed)
            .map(|s| s.mid().to_string())
            .unwrap_or_default()
    } else {
        typed.to_owned()
    };
    let digest: String = mid_text
        .strip_prefix("miasma:")
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    if digest.is_empty() {
        "received.bin".to_owned()
    } else {
        format!("received-{digest}.bin")
    }
}

/// The path a receive is started with, and whether it is an existing folder. A folder is passed
/// on as it is: the daemon writes `<folder>/<original file name>` once the transfer's manifest
/// names the file, and refuses (never overwrites) if that file already exists.
pub fn effective_receive_path(typed: &str) -> (String, bool) {
    let typed = typed.trim();
    let is_folder = !typed.is_empty() && std::path::Path::new(typed).is_dir();
    (typed.to_owned(), is_folder)
}

// ─── Pure: the segment strip ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellState {
    Done,
    InFlight,
    Pending,
}

/// Above this many segments several are drawn as one cell, so the strip stays legible.
pub const MAX_STRIP_CELLS: u32 = 400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strip {
    pub cells: Vec<CellState>,
    /// Segments in one cell (`1` up to [`MAX_STRIP_CELLS`] segments).
    pub per_cell: u32,
    /// The cell holding the first segment this session had to fetch, when it is not the start.
    pub resume_cell: Option<usize>,
}

/// One cell per segment, or per bucket of `per_cell` segments. A cell is done only when every
/// segment in it is; the cell holding the segment being worked on (`segments_done`) is in flight
/// while the transfer runs, and pending otherwise.
pub fn build_strip(total: u32, done: u32, running: bool, resumed_from: u32) -> Strip {
    if total == 0 {
        return Strip {
            cells: Vec::new(),
            per_cell: 1,
            resume_cell: None,
        };
    }
    let done = done.min(total);
    let per_cell = total.div_ceil(MAX_STRIP_CELLS).max(1);
    let count = total.div_ceil(per_cell);
    let cells = (0..count)
        .map(|i| {
            // u64: `(i + 1) * per_cell` can pass u32::MAX for a huge total.
            let start = i as u64 * per_cell as u64;
            let end = ((i as u64 + 1) * per_cell as u64).min(total as u64);
            let (start, end, done) = (start, end, done as u64);
            if end <= done {
                CellState::Done
            } else if running && done >= start && done < end {
                CellState::InFlight
            } else {
                CellState::Pending
            }
        })
        .collect();
    // A resume position beyond what is done would contradict the counters: not drawn.
    let resume_cell = (resumed_from > 0 && resumed_from <= done)
        .then(|| ((resumed_from / per_cell).min(count - 1)) as usize);
    Strip {
        cells,
        per_cell,
        resume_cell,
    }
}

// ─── Pure: redundancy ───────────────────────────────────────────────────────

/// A `k`-of-`n` setting: any `k` of a segment's `n` pieces rebuild it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    pub k: u8,
    pub n: u8,
}

impl Preset {
    /// Storage used per byte of file, in hundredths (`n / k`; the measured values in the plan,
    /// section 6 phase 5, match: 1.000x ... 2.000x).
    pub fn multiplier_hundredths(self) -> u32 {
        self.n as u32 * 100 / self.k.max(1) as u32
    }

    /// Pieces of each segment that may be lost and still recover it.
    pub fn tolerated(self) -> u32 {
        (self.n - self.k) as u32
    }

    pub fn label(self) -> String {
        format!("{}/{}", self.k, self.n)
    }

    pub fn multiplier_text(self) -> String {
        let h = self.multiplier_hundredths();
        format!("{}.{:02}x", h / 100, h % 100)
    }
}

/// The presets measured in the redundancy experiment, least to most redundant.
pub const PRESETS: [Preset; 5] = [
    Preset { k: 10, n: 10 },
    Preset { k: 10, n: 11 },
    Preset { k: 10, n: 12 },
    Preset { k: 10, n: 15 },
    Preset { k: 10, n: 20 },
];

/// Index of the preset the CLI uses by default (`network-publish`: 10/20).
pub const DEFAULT_PRESET: usize = 4;

/// Easy mode's three plain choices, each one of the presets above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EasyChoice {
    Fastest,
    Balanced,
    Safest,
}

impl EasyChoice {
    pub const ALL: [EasyChoice; 3] = [Self::Fastest, Self::Balanced, Self::Safest];

    pub fn preset_index(self) -> usize {
        match self {
            Self::Fastest => 0,  // 10/10: nothing spare
            Self::Balanced => 2, // 10/12
            Self::Safest => 4,   // 10/20: the CLI default
        }
    }

    pub fn from_preset_index(i: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.preset_index() == i)
    }
}

// ─── State ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewForm {
    Receive,
    Send,
}

/// Poll about this often while the screen is visible or a transfer is running.
const POLL_EVERY: Duration = Duration::from_secs(1);
/// If the daemon stays unreachable, ask the worker to reconnect at most this often.
const RECOVER_EVERY: Duration = Duration::from_secs(5);
const ROW_H: f32 = 56.0;

pub struct TransfersUi {
    /// Sorted: running first.
    pub jobs: Vec<TransferStatus>,
    /// The list has been read at least once.
    loaded: bool,
    /// Text of the last failed poll and whether the daemon was unreachable.
    poll_error: Option<(String, bool)>,
    in_flight: bool,
    last_poll: Instant,
    last_recover: Instant,
    /// The developer tour draws fixed data: never poll, never overwrite it.
    mock: bool,

    selected: Option<String>,
    form: NewForm,
    form_error: Option<String>,

    recv_mid: String,
    recv_path: String,
    recv_password: String,
    /// Technical mode: fetch directly from this sender URL (`wss://...`) instead of the network.
    recv_via: String,

    send_path: String,
    send_password: String,
    send_confirm: String,
    /// The password the Generate button just made, shown in clear so it can be stored. Cleared
    /// when the field is edited away from it, or when the send starts.
    send_generated: Option<String>,
    send_preset: usize,

    /// Detail-pane prompts for the selected transfer.
    resume_open: bool,
    resume_password: String,
    restart_confirm: bool,
    /// The selected stopped transfer holds partial data: asking whether to discard it.
    discard_confirm: bool,

    /// Ids started with a password in this session (the daemon does not tell us).
    known_protected: HashSet<String>,
    pending_protected: bool,
    /// Ids started with a `via` URL in this session, so Resume goes to the same endpoint (the
    /// daemon's journal does not record it).
    known_via: HashMap<String, String>,
    pending_via: Option<String>,
    /// The start request in flight came from a "new transfer" form (so the form is cleared when
    /// it is accepted), not from the Resume button.
    from_form: bool,
    copied_at: Option<Instant>,
}

impl Default for TransfersUi {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            jobs: Vec::new(),
            loaded: false,
            poll_error: None,
            in_flight: false,
            last_poll: now,
            last_recover: now,
            mock: false,
            selected: None,
            form: NewForm::Receive,
            form_error: None,
            recv_mid: String::new(),
            recv_path: String::new(),
            recv_password: String::new(),
            recv_via: String::new(),
            send_path: String::new(),
            send_password: String::new(),
            send_confirm: String::new(),
            send_generated: None,
            send_preset: DEFAULT_PRESET,
            resume_open: false,
            resume_password: String::new(),
            restart_confirm: false,
            discard_confirm: false,
            known_protected: HashSet::new(),
            pending_protected: false,
            known_via: HashMap::new(),
            pending_via: None,
            from_form: false,
            copied_at: None,
        }
    }
}

impl Drop for TransfersUi {
    fn drop(&mut self) {
        self.zeroize_passwords();
    }
}

impl TransfersUi {
    fn zeroize_passwords(&mut self) {
        self.recv_password.zeroize();
        self.send_password.zeroize();
        self.send_confirm.zeroize();
        self.send_generated.zeroize();
        self.send_generated = None;
        self.resume_password.zeroize();
    }

    /// The Generate button: a strong random password goes into both password fields and is
    /// remembered so the form can show it once in clear.
    fn generate_send_password(&mut self) {
        let pw = password_policy::generate(password_policy::GENERATE_DEFAULT_LEN);
        self.send_password.zeroize();
        self.send_confirm.zeroize();
        self.send_generated.zeroize();
        self.send_password = pw.as_str().to_owned();
        self.send_confirm = pw.as_str().to_owned();
        self.send_generated = Some(pw.as_str().to_owned());
    }

    /// Fixed data for the developer tour: the list is shown as given and never polled.
    #[cfg_attr(not(feature = "ui-tour"), allow(dead_code))]
    pub fn set_mock(&mut self, mut jobs: Vec<TransferStatus>) {
        sort_jobs(&mut jobs);
        self.jobs = jobs;
        self.loaded = true;
        self.mock = true;
        self.poll_error = None;
    }

    #[cfg_attr(not(feature = "ui-tour"), allow(dead_code))]
    pub fn select_job(&mut self, id: Option<String>) {
        self.select_id(id);
    }

    #[cfg_attr(not(feature = "ui-tour"), allow(dead_code))]
    pub fn set_form(&mut self, form: NewForm) {
        self.form = form;
    }

    #[cfg_attr(not(feature = "ui-tour"), allow(dead_code))]
    pub fn open_resume_prompt(&mut self) {
        self.resume_open = true;
    }

    fn select_id(&mut self, id: Option<String>) {
        if self.selected != id {
            self.selected = id;
            self.resume_open = false;
            self.restart_confirm = false;
            self.discard_confirm = false;
            self.resume_password.zeroize();
        }
    }

    fn any_running(&self) -> bool {
        self.jobs.iter().any(|j| j.state == TransferState::Running)
    }

    /// Whether a `TransferPoll` should be sent now. One poll to learn the state after connecting;
    /// after that only while the screen is showing or a transfer is running.
    pub fn poll_due(&self, tab_visible: bool) -> bool {
        if self.mock || self.in_flight {
            return false;
        }
        let wanted = tab_visible || self.any_running() || !self.loaded;
        wanted && self.last_poll.elapsed() >= POLL_EVERY
    }

    pub fn note_polled(&mut self) {
        self.in_flight = true;
        self.last_poll = Instant::now();
    }

    pub fn on_list(&mut self, mut list: Vec<TransferStatus>) {
        self.in_flight = false;
        if self.mock {
            return;
        }
        sort_jobs(&mut list);
        self.jobs = list;
        self.loaded = true;
        self.poll_error = None;
        // Keep the selection on the same transfer as the order changes; otherwise pick the first.
        let still_there = self
            .selected
            .as_ref()
            .is_some_and(|id| self.jobs.iter().any(|j| &transfer_id(j) == id));
        if !still_there {
            let first = self.jobs.first().map(transfer_id);
            self.select_id(first);
        }
    }

    /// Returns true when the worker should be asked to reconnect (daemon unreachable, and not
    /// asked in the last few seconds).
    pub fn on_poll_failed(&mut self, message: String, daemon_down: bool) -> bool {
        self.in_flight = false;
        if self.mock {
            return false;
        }
        self.poll_error = Some((message, daemon_down));
        if daemon_down && self.last_recover.elapsed() >= RECOVER_EVERY {
            self.last_recover = Instant::now();
            return true;
        }
        false
    }

    /// The daemon accepted a start request: show it, and forget the form it came from.
    pub fn on_started(&mut self, id: String) {
        if self.pending_protected {
            self.known_protected.insert(id.clone());
        }
        self.pending_protected = false;
        if let Some(via) = self.pending_via.take() {
            self.known_via.insert(id.clone(), via);
        }
        self.form_error = None;
        if self.from_form {
            match self.form {
                NewForm::Receive => {
                    self.recv_mid.clear();
                    self.recv_path.clear();
                    self.recv_via.clear();
                }
                NewForm::Send => self.send_path.clear(),
            }
        }
        self.from_form = false;
        self.select_id(Some(id));
        // Read the new row now instead of waiting out the interval.
        self.last_poll = Instant::now() - POLL_EVERY;
        self.in_flight = false;
    }

    pub fn on_error(&mut self, message: String) {
        self.pending_protected = false;
        self.pending_via = None;
        self.from_form = false;
        self.form_error = Some(message);
    }

    /// Take rows off the list at once, so a poll already in flight cannot show them again for a
    /// moment. The daemon's answer to the next poll is what stays.
    fn drop_rows(&mut self, keep: impl Fn(&TransferStatus) -> bool) {
        self.jobs.retain(keep);
    }

    /// The daemon declined a remove.
    pub fn on_remove_refused(
        &mut self,
        reason: miasma_core::transfer::jobs::RemoveRefusal,
        t: &TransferStrings,
    ) {
        use miasma_core::transfer::jobs::RemoveRefusal as R;
        self.poll_soon();
        match reason {
            // It holds partial data the list did not know about: ask before discarding.
            R::HasPartialData => self.discard_confirm = true,
            R::Running => self.form_error = Some(t.err_remove_running.to_owned()),
            R::Paused => self.form_error = Some(t.err_remove_paused.to_owned()),
            // Already gone: the next poll shows that.
            R::NotFound => {}
        }
    }

    /// Ask for an immediate re-read (after a stop request).
    pub fn poll_soon(&mut self) {
        self.last_poll = Instant::now() - POLL_EVERY;
    }

    fn selected_job(&self) -> Option<&TransferStatus> {
        let id = self.selected.as_ref()?;
        self.jobs.iter().find(|j| &transfer_id(j) == id)
    }

    // ─── Drawing ────────────────────────────────────────────────────────────

    /// Draw the screen. Returns the worker commands the user's clicks asked for.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        t: &TransferStrings,
        easy: bool,
        connected: bool,
    ) -> Vec<WorkerCmd> {
        let mut cmds = Vec::new();
        // A poll that could not reach the daemon overrides what the header says: it is the newer
        // fact, and nothing here can be started or stopped without the daemon.
        let connected = connected && !self.poll_error.as_ref().is_some_and(|(_, down)| *down);

        section_heading(ui, if easy { t.heading_easy } else { t.heading });
        ui.add_space(4.0);
        ui.label(egui::RichText::new(if easy { t.desc_easy } else { t.desc }).color(pal().muted));
        ui.add_space(10.0);

        if let Some((msg, down)) = &self.poll_error {
            let shown = if *down { t.offline_note } else { msg.as_str() };
            ui.label(egui::RichText::new(shown).color(pal().warning));
            if !self.jobs.is_empty() {
                ui.label(egui::RichText::new(t.stale_note).small().color(pal().faint));
            }
            ui.add_space(6.0);
        }

        if show_clear_finished(&self.jobs) {
            ui.horizontal(|ui| {
                // Neutral: the one accent action on this screen is Start receiving / sending.
                let btn = egui::Button::new(t.btn_clear_finished);
                if ui
                    .add_enabled(connected, btn)
                    .on_hover_text(t.clear_finished_hint)
                    .clicked()
                {
                    cmds.push(WorkerCmd::TransferClearFinished);
                    self.drop_rows(|j| !clearable(j));
                }
            });
            ui.add_space(4.0);
        }
        self.list_card(ui, t, easy);
        ui.add_space(8.0);
        self.detail_card(ui, t, easy, connected, &mut cmds);
        ui.add_space(8.0);
        self.new_card(ui, t, easy, connected, &mut cmds);
        cmds
    }

    fn list_card(&mut self, ui: &mut egui::Ui, t: &TransferStrings, easy: bool) {
        let stale = self.poll_error.as_ref().is_some_and(|(_, down)| *down);
        let mut clicked: Option<String> = None;
        card_frame()
            .inner_margin(egui::Margin::same(6.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                if self.jobs.is_empty() {
                    ui.add_space(14.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new(if easy { t.empty_easy } else { t.empty })
                                .color(pal().muted),
                        );
                    });
                    ui.add_space(14.0);
                    return;
                }
                egui::ScrollArea::vertical()
                    .id_source("transfer_list")
                    .max_height(ROW_H * 5.0 + 8.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for job in &self.jobs {
                            let id = transfer_id(job);
                            let selected = self.selected.as_deref() == Some(id.as_str());
                            if job_row(ui, t, job, selected, stale) {
                                clicked = Some(id);
                            }
                        }
                    });
            });
        if let Some(id) = clicked {
            self.select_id(Some(id));
        }
    }

    fn detail_card(
        &mut self,
        ui: &mut egui::Ui,
        t: &TransferStrings,
        easy: bool,
        connected: bool,
        cmds: &mut Vec<WorkerCmd>,
    ) {
        let Some(job) = self.selected_job().cloned() else {
            if !self.jobs.is_empty() {
                card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(egui::RichText::new(t.select_hint).color(pal().muted));
                });
            }
            return;
        };
        let id = transfer_id(&job);
        let chip = chip_for(job.state);
        let color = chip_color(chip);

        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());

            // Title: file name + chip, full path under it.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(title_of(&job))
                        .size(15.0)
                        .strong()
                        .color(pal().text),
                );
                draw_chip(ui, color, state_label(t, job.state));
            });
            if !job.name.is_empty() {
                ui.label(
                    egui::RichText::new(plain_path(&job.name))
                        .small()
                        .color(pal().faint),
                );
            }
            // Why it stopped, directly under the title: this is what the person needs first.
            if let Some(err) = &job.last_error {
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!(
                            "{}: {}",
                            t.error_label,
                            localize_job_error(t, err)
                        ))
                        .color(pal().danger),
                    )
                    .wrap(true),
                );
            }
            ui.add_space(8.0);

            if easy {
                let pct = format_permille(permille(job.bytes_done, job.bytes_total, job.state));
                ui.label(easy_sentence(t, &job, &pct));
                ui.add_space(6.0);
            }

            // Where am I: one cell per segment (or per bucket).
            self.strip_section(ui, t, &job);
            ui.add_space(8.0);

            egui::Grid::new("transfer_detail")
                .num_columns(2)
                .spacing([16.0, 5.0])
                .show(ui, |ui| {
                    // The Share ID is what the receiver needs (it also lets them check who
                    // published it), so it is shown in Easy mode too, with a Copy button.
                    if let Some(share_id) = job.share_id.as_deref().filter(|s| !s.is_empty()) {
                        ui.label(egui::RichText::new(t.share_id_label).color(pal().muted));
                        ui.vertical(|ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(share_id).monospace());
                                let copied = self
                                    .copied_at
                                    .is_some_and(|c| c.elapsed() < Duration::from_secs(2));
                                let label = if copied { t.copied } else { t.copy };
                                if ui.small_button(label).clicked() {
                                    ui.output_mut(|o| o.copied_text = share_id.to_owned());
                                    self.copied_at = Some(Instant::now());
                                }
                            });
                            if job.kind == TransferKind::Send {
                                ui.label(
                                    egui::RichText::new(t.share_id_send_note)
                                        .small()
                                        .color(pal().faint),
                                );
                            }
                        });
                        ui.end_row();
                    }

                    // A receive says whether the publisher was authenticated.
                    if job.kind == TransferKind::Receive && !job.mid.is_empty() {
                        ui.label(egui::RichText::new(t.publisher_label).color(pal().muted));
                        if job.publisher_authenticated {
                            ui.label(
                                egui::RichText::new(t.publisher_verified).color(pal().success),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new(t.publisher_unverified).color(pal().warning),
                            );
                        }
                        ui.end_row();
                    }

                    // The MID: in Technical mode always; in Easy mode only where there is no
                    // Share ID to give instead (a receive, or a send from an older daemon).
                    if !easy || job.share_id.as_deref().is_none_or(str::is_empty) {
                        let mid_label = if easy { t.mid_label_easy } else { t.mid_label };
                        ui.label(egui::RichText::new(mid_label).color(pal().muted));
                        ui.horizontal_wrapped(|ui| {
                            if job.mid.is_empty() {
                                ui.label(egui::RichText::new("-").color(pal().faint));
                            } else {
                                ui.label(egui::RichText::new(job.mid.as_str()).monospace());
                                let copied = self
                                    .copied_at
                                    .is_some_and(|c| c.elapsed() < Duration::from_secs(2));
                                let label = if copied { t.copied } else { t.copy };
                                if ui.small_button(label).clicked() {
                                    ui.output_mut(|o| o.copied_text = job.mid.clone());
                                    self.copied_at = Some(Instant::now());
                                }
                            }
                        });
                        ui.end_row();
                    }

                    ui.label(egui::RichText::new(t.phase_label).color(pal().muted));
                    if easy {
                        ui.label(phase_plain(t, job.phase));
                    } else {
                        ui.label(egui::RichText::new(format!("{:?}", job.phase)).monospace());
                    }
                    ui.end_row();

                    ui.label(egui::RichText::new(t.elapsed_label).color(pal().muted));
                    // A transfer known only from its journal has no elapsed time.
                    let elapsed = (job.elapsed_secs >= 1.0).then_some(job.elapsed_secs as u64);
                    ui.label(format_eta(elapsed, t.day));
                    ui.end_row();

                    if !easy {
                        ui.label(egui::RichText::new(t.segments_label).color(pal().muted));
                        ui.label(format!("{} / {}", job.segments_done, job.segments_total));
                        ui.end_row();

                        ui.label(egui::RichText::new(t.resumed_label).color(pal().muted));
                        if job.resumed_from_segment == 0 {
                            ui.label(t.resumed_fresh);
                        } else {
                            // 1-based, like the caption under the strip.
                            ui.label((job.resumed_from_segment + 1).to_string());
                        }
                        ui.end_row();

                        ui.label(egui::RichText::new(t.split_label).color(pal().muted));
                        ui.label(split_text(t, &job));
                        ui.end_row();

                        ui.label(egui::RichText::new(t.pieces_label).color(pal().muted));
                        ui.label(fill(
                            t.pieces_fmt,
                            &[
                                ("ok", &job.pieces_fetched.to_string()),
                                ("bad", &job.pieces_rejected.to_string()),
                            ],
                        ));
                        ui.end_row();

                        ui.label(egui::RichText::new(t.retries_label).color(pal().muted));
                        ui.label(job.segment_retries.to_string());
                        ui.end_row();
                    }
                });

            // A completed transfer has nothing to resume.
            if job.state != TransferState::Complete {
                ui.add_space(10.0);
                self.detail_buttons(ui, t, &job, &id, connected, cmds);
            }
            if can_remove(&job) {
                ui.add_space(10.0);
                self.remove_section(ui, t, &job, &id, connected, cmds);
            }
        });
    }

    fn strip_section(&self, ui: &mut egui::Ui, t: &TransferStrings, job: &TransferStatus) {
        let running = job.state == TransferState::Running;
        let strip = build_strip(
            job.segments_total,
            job.segments_done,
            running,
            job.resumed_from_segment,
        );
        ui.label(
            egui::RichText::new(t.segments_label)
                .small()
                .color(pal().muted),
        );
        ui.add_space(2.0);
        if strip.cells.is_empty() {
            ui.label(
                egui::RichText::new(t.strip_unknown)
                    .small()
                    .color(pal().faint),
            );
            return;
        }
        let p = pal();
        // The outer rect leaves room for the resume marker to stick out above and below.
        let (outer, resp) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 26.0), egui::Sense::hover());
        let painter = ui.painter_at(outer);
        let rect = outer.shrink2(egui::vec2(0.0, 3.0));
        painter.rect_filled(rect, 3.0, p.border);
        let n = strip.cells.len();
        let cell_w = rect.width() / n as f32;
        let gap = if cell_w >= 4.0 { 1.0 } else { 0.0 };
        for (i, state) in strip.cells.iter().enumerate() {
            let x0 = rect.left() + cell_w * i as f32;
            let r = egui::Rect::from_min_max(
                egui::pos2(x0 + gap * 0.5, rect.top() + 1.0),
                egui::pos2(x0 + cell_w - gap * 0.5, rect.bottom() - 1.0),
            );
            let cell_color = match state {
                CellState::Done => p.success,
                CellState::InFlight => p.info,
                CellState::Pending => p.surface_subtle,
            };
            painter.rect_filled(r, 1.0, cell_color);
        }
        // Where this session started (after a resume).
        let mut marker_x = None;
        if let Some(c) = strip.resume_cell {
            let x = rect.left() + cell_w * c as f32;
            painter.line_segment(
                [
                    egui::pos2(x, rect.top() - 3.0),
                    egui::pos2(x, rect.bottom() + 3.0),
                ],
                egui::Stroke::new(2.0, p.text),
            );
            marker_x = Some(x);
        }
        // Hover: which segments the cell under the pointer stands for.
        if let Some(pos) = resp.hover_pos() {
            let i = (((pos.x - rect.left()) / cell_w) as usize).min(n - 1);
            let first = i as u64 * strip.per_cell as u64;
            let last = ((i as u64 + 1) * strip.per_cell as u64).min(job.segments_total as u64) - 1;
            let text = if first == last {
                format!("{} {}", t.segment_word, first + 1)
            } else {
                format!("{} {}-{}", t.segment_word, first + 1, last + 1)
            };
            resp.on_hover_text(text);
        }

        // Caption row: the resume marker's name and the legend.
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            for (color, label) in [
                (p.success, t.strip_done),
                (p.info, t.strip_inflight),
                (p.surface_subtle, t.strip_pending),
            ] {
                let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().rect_filled(r, 2.0, color);
                ui.painter()
                    .rect_stroke(r, 2.0, egui::Stroke::new(1.0, p.border_strong));
                ui.label(egui::RichText::new(label).small().color(pal().muted));
                ui.add_space(6.0);
            }
            if marker_x.is_some() {
                let (r, _) = ui.allocate_exact_size(egui::vec2(2.0, 12.0), egui::Sense::hover());
                ui.painter().rect_filled(r, 0.0, p.text);
                ui.label(
                    egui::RichText::new(fill(
                        t.strip_resumed,
                        &[("n", &(job.resumed_from_segment + 1).to_string())],
                    ))
                    .small()
                    .color(pal().muted),
                );
                ui.add_space(6.0);
            }
            if strip.per_cell > 1 {
                ui.label(
                    egui::RichText::new(fill(
                        t.strip_per_cell,
                        &[("n", &strip.per_cell.to_string())],
                    ))
                    .small()
                    .color(pal().faint),
                );
            }
        });
    }

    fn detail_buttons(
        &mut self,
        ui: &mut egui::Ui,
        t: &TransferStrings,
        job: &TransferStatus,
        id: &str,
        connected: bool,
        cmds: &mut Vec<WorkerCmd>,
    ) {
        let protected = self.known_protected.contains(id);
        ui.horizontal_wrapped(|ui| {
            if job.state == TransferState::Running {
                if ui
                    .add_enabled(connected, egui::Button::new(t.btn_stop))
                    .clicked()
                {
                    cmds.push(WorkerCmd::TransferCancel { id: id.to_owned() });
                    self.poll_soon();
                }
                return;
            }
            if !can_resume(job.state) {
                return;
            }
            if job.name.is_empty() {
                // Without a path there is nothing to start again into (an older daemon reported
                // none for a live receive): only a new start from the form is possible.
                ui.label(egui::RichText::new(t.no_path_hint).color(pal().muted));
                return;
            }
            let label = if job.resumable {
                t.btn_resume
            } else {
                t.btn_try_again
            };
            if !self.resume_open {
                let btn = primary_button(label);
                if ui.add_enabled(connected, btn).clicked() {
                    self.resume_open = true;
                    self.restart_confirm = false;
                }
                if ui
                    .add_enabled(connected, danger_button(t.btn_restart))
                    .clicked()
                {
                    self.restart_confirm = true;
                    self.resume_open = false;
                }
            }
        });

        if self.resume_open {
            ui.label(
                egui::RichText::new(if protected {
                    t.resume_pw_required
                } else {
                    t.resume_pw_optional
                })
                .small()
                .color(pal().muted),
            );
            ui.horizontal(|ui| {
                ui.label(if protected {
                    t.password_short
                } else {
                    t.password_label
                });
                ui.add(
                    egui::TextEdit::singleline(&mut self.resume_password)
                        .password(true)
                        .desired_width(220.0),
                );
                let needs_pw = protected && self.resume_password.is_empty();
                let go = ui.add_enabled(connected && !needs_pw, primary_button(t.resume_go));
                if go.clicked() {
                    let via = self.known_via.get(&job.mid).cloned();
                    cmds.push(with_via(
                        start_again(job, &self.resume_password, false),
                        via.as_ref(),
                    ));
                    self.pending_via = via;
                    self.resume_password.zeroize();
                    self.resume_open = false;
                    self.pending_protected = protected;
                    self.poll_soon();
                }
                if ui.button(t.btn_keep).clicked() {
                    self.resume_open = false;
                    self.resume_password.zeroize();
                }
            });
        }

        if self.restart_confirm {
            ui.label(egui::RichText::new(t.restart_confirm).color(pal().danger));
            ui.label(
                egui::RichText::new(t.resume_pw_optional)
                    .small()
                    .color(pal().muted),
            );
            ui.horizontal(|ui| {
                ui.label(t.password_label);
                ui.add(
                    egui::TextEdit::singleline(&mut self.resume_password)
                        .password(true)
                        .desired_width(220.0),
                );
                if ui
                    .add_enabled(connected, danger_button(t.restart_yes))
                    .clicked()
                {
                    let via = self.known_via.get(&job.mid).cloned();
                    cmds.push(with_via(
                        start_again(job, &self.resume_password, true),
                        via.as_ref(),
                    ));
                    self.pending_via = via;
                    self.resume_password.zeroize();
                    self.restart_confirm = false;
                    self.poll_soon();
                }
                if ui.button(t.btn_keep).clicked() {
                    self.restart_confirm = false;
                    self.resume_password.zeroize();
                }
            });
        }
    }

    /// Take a finished transfer off the list. Neutral buttons: the detail pane's accent action is
    /// Resume. The line under it says what is and is not deleted.
    fn remove_section(
        &mut self,
        ui: &mut egui::Ui,
        t: &TransferStrings,
        job: &TransferStatus,
        id: &str,
        connected: bool,
        cmds: &mut Vec<WorkerCmd>,
    ) {
        let needs_discard = remove_needs_discard(job);
        if self.discard_confirm {
            ui.label(egui::RichText::new(t.discard_confirm).color(pal().danger));
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(connected, danger_button(t.discard_yes))
                    .clicked()
                {
                    cmds.push(WorkerCmd::TransferRemove {
                        id: id.to_owned(),
                        discard_partial: true,
                    });
                    self.discard_confirm = false;
                    let gone = id.to_owned();
                    self.drop_rows(|j| transfer_id(j) != gone);
                    self.selected = None;
                }
                if ui.button(t.btn_keep).clicked() {
                    self.discard_confirm = false;
                }
            });
            return;
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(connected, egui::Button::new(t.btn_remove))
                .clicked()
            {
                if needs_discard {
                    self.discard_confirm = true;
                } else {
                    cmds.push(WorkerCmd::TransferRemove {
                        id: id.to_owned(),
                        discard_partial: false,
                    });
                    let gone = id.to_owned();
                    self.drop_rows(|j| transfer_id(j) != gone);
                    self.selected = None;
                }
            }
            let note = match (job.state, job.kind, needs_discard) {
                (_, _, true) => t.remove_note_partial,
                (TransferState::Complete, TransferKind::Send, _) => t.remove_note_send,
                (TransferState::Complete, TransferKind::Receive, _) => t.remove_note_recv,
                _ => t.remove_note_plain,
            };
            ui.label(egui::RichText::new(note).small().color(pal().muted));
        });
    }

    fn new_card(
        &mut self,
        ui: &mut egui::Ui,
        t: &TransferStrings,
        easy: bool,
        connected: bool,
        cmds: &mut Vec<WorkerCmd>,
    ) {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(t.new_heading)
                        .size(15.0)
                        .strong()
                        .color(pal().text),
                );
                ui.add_space(8.0);
                for (form, label) in [(NewForm::Receive, t.receive), (NewForm::Send, t.send)] {
                    let active = self.form == form;
                    let text = if active {
                        egui::RichText::new(label).strong().color(pal().text)
                    } else {
                        egui::RichText::new(label).color(pal().muted)
                    };
                    let btn = egui::Button::new(text)
                        .fill(if active {
                            pal().selected
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .stroke(egui::Stroke::NONE);
                    if ui.add(btn).clicked() {
                        self.form = form;
                        self.form_error = None;
                    }
                }
            });
            ui.add_space(6.0);
            if !connected {
                ui.label(egui::RichText::new(t.forms_offline).color(pal().warning));
                ui.add_space(4.0);
            }
            match self.form {
                NewForm::Receive => self.receive_form(ui, t, easy, connected, cmds),
                NewForm::Send => self.send_form(ui, t, easy, connected, cmds),
            }
            if let Some(err) = &self.form_error {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(err.as_str()).color(pal().danger));
            }
        });
    }

    fn receive_form(
        &mut self,
        ui: &mut egui::Ui,
        t: &TransferStrings,
        easy: bool,
        connected: bool,
        cmds: &mut Vec<WorkerCmd>,
    ) {
        form_row(ui, t.recv_id_label, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.recv_mid)
                    .hint_text("miasma-share:...")
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            );
        });
        form_row(ui, t.recv_path_label, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.recv_path)
                        .hint_text(t.recv_path_hint)
                        .desired_width((ui.available_width() - 110.0).max(120.0)),
                );
                if ui.button(t.browse).clicked() {
                    // A Save-As dialog with a name already filled in, so what comes back is a
                    // file path even when the person only picks a folder.
                    let mut dialog =
                        rfd::FileDialog::new().set_file_name(suggested_file_name(&self.recv_mid));
                    let current = std::path::Path::new(self.recv_path.trim());
                    let start = if current.is_dir() {
                        Some(current)
                    } else {
                        current.parent().filter(|p| p.is_dir())
                    };
                    if let Some(dir) = start {
                        dialog = dialog.set_directory(dir);
                    }
                    if let Some(p) = dialog.save_file() {
                        self.recv_path = p.to_string_lossy().into_owned();
                    }
                }
            });
        });
        // A typed or picked folder receives the file inside it, under the name it had when it
        // was sent; say so before starting.
        let (final_path, is_folder) = effective_receive_path(&self.recv_path);
        if is_folder {
            ui.label(
                egui::RichText::new(fill(t.recv_folder_note, &[("path", &final_path)]))
                    .small()
                    .color(pal().warning),
            );
        }
        form_row(ui, t.password_label, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.recv_password)
                    .password(true)
                    .desired_width(240.0),
            );
            ui.label(
                egui::RichText::new(t.password_note)
                    .small()
                    .color(pal().faint),
            );
        });
        // Technical mode only: Easy mode shows nothing new.
        if !easy {
            form_row(ui, t.via_label, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.recv_via)
                        .hint_text(t.via_hint)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
                ui.label(egui::RichText::new(t.via_note).small().color(pal().faint));
            });
        }
        ui.add_space(8.0);
        let ready =
            connected && !self.recv_mid.trim().is_empty() && !self.recv_path.trim().is_empty();
        if ui
            .add_enabled(ready, primary_button(t.recv_button))
            .clicked()
        {
            let mid = self.recv_mid.trim().to_owned();
            // One parse of what was typed, before anything is sent: a mistyped share ID stops
            // here (its checksum), a MID is accepted but cannot authenticate the publisher.
            let parsed = miasma_core::transfer::parse_transfer_id(&mid);
            if let Err(e) = &parsed {
                self.form_error = Some(
                    match e {
                        miasma_core::MiasmaError::InvalidShareId(_) => t.err_share_id,
                        _ => t.err_mid,
                    }
                    .to_owned(),
                );
            } else {
                let password = (!self.recv_password.is_empty()).then(|| self.recv_password.clone());
                self.pending_protected = password.is_some();
                self.from_form = true;
                self.recv_password.zeroize();
                self.form_error = None;
                // Only Technical mode has the field; Easy mode never sends one.
                let via = (!easy)
                    .then(|| self.recv_via.trim().to_owned())
                    .filter(|v| !v.is_empty());
                self.pending_via = via.clone();
                cmds.push(WorkerCmd::TransferStartReceive {
                    mid,
                    output_path: final_path.into(),
                    password,
                    restart: false,
                    via: via.into_iter().collect(),
                });
            }
        }
    }

    fn send_form(
        &mut self,
        ui: &mut egui::Ui,
        t: &TransferStrings,
        easy: bool,
        connected: bool,
        cmds: &mut Vec<WorkerCmd>,
    ) {
        form_row(ui, t.send_path_label, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.send_path)
                        .hint_text(t.send_path_hint)
                        .desired_width((ui.available_width() - 110.0).max(120.0)),
                );
                if ui.button(t.browse).clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.send_path = p.to_string_lossy().into_owned();
                    }
                }
            });
        });
        // Generate fills both fields; done after the row so the closure borrows stay simple.
        let mut generate = false;
        form_row(ui, t.password_label, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.send_password)
                        .password(true)
                        .desired_width(240.0),
                );
                if ui.button(t.pw_generate).clicked() {
                    generate = true;
                }
            });
            ui.label(
                egui::RichText::new(t.pw_policy_note)
                    .small()
                    .color(pal().faint),
            );
        });
        if generate {
            self.generate_send_password();
        }
        // The generated password is shown in clear only while it is still what is in the field.
        if self.send_generated.as_deref() != Some(self.send_password.as_str()) {
            self.send_generated.zeroize();
            self.send_generated = None;
        }
        if let Some(pw) = self.send_generated.clone() {
            form_row(ui, "", |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new(pw.as_str()).monospace());
                    let copied = self
                        .copied_at
                        .is_some_and(|c| c.elapsed() < Duration::from_secs(2));
                    if ui
                        .small_button(if copied { t.copied } else { t.copy })
                        .clicked()
                    {
                        ui.output_mut(|o| o.copied_text = pw.clone());
                        self.copied_at = Some(Instant::now());
                    }
                });
                ui.label(
                    egui::RichText::new(t.pw_generated_note)
                        .small()
                        .color(pal().muted),
                );
            });
        }
        form_row(ui, t.confirm_label, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.send_confirm)
                    .password(true)
                    .desired_width(240.0),
            );
        });
        form_row(
            ui,
            if easy { t.red_label_easy } else { t.red_label },
            |ui| self.redundancy_picker(ui, t, easy),
        );

        let mismatch = self.send_password != self.send_confirm;
        if mismatch && !self.send_confirm.is_empty() {
            ui.label(egui::RichText::new(t.mismatch).small().color(pal().danger));
        }
        // The same rule the daemon enforces: a weak password blocks the button and says why;
        // a compliant but short one only gets a warning.
        let pw_state = send_password_state(&self.send_password);
        match &pw_state {
            SendPassword::Weak(v) => {
                ui.label(
                    egui::RichText::new(weak_password_text(t, &violation_codes(v)))
                        .small()
                        .color(pal().danger),
                );
            }
            SendPassword::Short => {
                ui.label(
                    egui::RichText::new(t.pw_short_warning)
                        .small()
                        .color(pal().muted),
                );
            }
            SendPassword::Unprotected | SendPassword::Good => {}
        }
        ui.add_space(8.0);
        let ready = send_ready(connected, &self.send_path, mismatch, &pw_state);
        if ui
            .add_enabled(ready, primary_button(t.send_button))
            .clicked()
        {
            let password = (!self.send_password.is_empty()).then(|| self.send_password.clone());
            self.pending_protected = password.is_some();
            self.from_form = true;
            self.send_password.zeroize();
            self.send_confirm.zeroize();
            self.send_generated.zeroize();
            self.send_generated = None;
            self.form_error = None;
            let preset = PRESETS[self.send_preset.min(PRESETS.len() - 1)];
            cmds.push(WorkerCmd::TransferStartPublish {
                file_path: self.send_path.trim().into(),
                password,
                data_shards: preset.k,
                total_shards: preset.n,
                restart: false,
            });
        }
        ui.add_space(6.0);
        // The one thing a sender must know before starting.
        ui.label(egui::RichText::new(t.send_hint).small().color(pal().muted));
    }

    fn redundancy_picker(&mut self, ui: &mut egui::Ui, t: &TransferStrings, easy: bool) {
        // Tight rows: five presets should not push the send button off the screen.
        ui.spacing_mut().item_spacing.y = 1.0;
        if easy {
            // A preset picked in Technical mode that has no plain name selects none of the three.
            let current = EasyChoice::from_preset_index(self.send_preset);
            for choice in EasyChoice::ALL {
                let (label, desc) = match choice {
                    EasyChoice::Fastest => (t.easy_fast, t.easy_fast_desc),
                    EasyChoice::Balanced => (t.easy_bal, t.easy_bal_desc),
                    EasyChoice::Safest => (t.easy_safe, t.easy_safe_desc),
                };
                ui.horizontal(|ui| {
                    if ui.radio(current == Some(choice), label).clicked() {
                        self.send_preset = choice.preset_index();
                    }
                    ui.label(egui::RichText::new(desc).small().color(pal().muted));
                });
            }
        } else {
            for (i, preset) in PRESETS.iter().enumerate() {
                let mut text = fill(
                    t.red_row,
                    &[
                        ("kn", &preset.label()),
                        ("x", &preset.multiplier_text()),
                        ("loss", &preset.tolerated().to_string()),
                    ],
                );
                if i == DEFAULT_PRESET {
                    text.push_str("  ");
                    text.push_str(t.red_default);
                }
                if ui.radio(self.send_preset == i, text).clicked() {
                    self.send_preset = i;
                }
            }
        }
    }
}

// ─── Pure: the send password ────────────────────────────────────────────────

/// What the send form knows about the password in its field.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SendPassword {
    /// Empty: the transfer is not protected (passwords stay optional).
    Unprotected,
    /// Not acceptable for a new protected transfer; the button stays disabled.
    Weak(Vec<PolicyViolation>),
    /// Acceptable but under 12 characters: a warning, not a block.
    Short,
    Good,
}

/// The publish-side policy, evaluated on the field. The daemon applies the same rule and is the
/// authority; this only spares a round trip and lets the message be localised.
fn send_password_state(password: &str) -> SendPassword {
    if password.is_empty() {
        return SendPassword::Unprotected;
    }
    match password_policy::check(password) {
        Err(v) => SendPassword::Weak(v),
        Ok(()) => match password_policy::strength_hint(password) {
            Strength::Short => SendPassword::Short,
            Strength::Ok => SendPassword::Good,
        },
    }
}

/// Whether the Start sending button is enabled.
fn send_ready(connected: bool, path: &str, mismatch: bool, pw: &SendPassword) -> bool {
    connected && !path.trim().is_empty() && !mismatch && !matches!(pw, SendPassword::Weak(_))
}

fn violation_codes(v: &[PolicyViolation]) -> Vec<&'static str> {
    v.iter().map(PolicyViolation::code).collect()
}

fn violation_text(t: &TransferStrings, code: &str) -> Option<&'static str> {
    Some(match code {
        "too_short" => t.pw_err_too_short,
        "too_long" => t.pw_err_too_long,
        "no_digit" => t.pw_err_no_digit,
        "no_letter" => t.pw_err_no_letter,
        "no_symbol" => t.pw_err_no_symbol,
        _ => return None,
    })
}

/// `Password not accepted: it is shorter than 6 characters; it has no digit`.
fn weak_password_text(t: &TransferStrings, codes: &[&str]) -> String {
    let reasons: Vec<&str> = codes.iter().filter_map(|c| violation_text(t, c)).collect();
    format!("{} {}", t.pw_weak_prefix, reasons.join(t.pw_err_sep))
}

/// A job's last error for display: the daemon's weak-password refusal (`weak password:
/// too_short,no_symbol`) is shown in the UI language; any other text is passed through.
fn localize_job_error(t: &TransferStrings, err: &str) -> String {
    match password_policy::parse_codes(err) {
        Some(codes) => weak_password_text(t, &codes),
        None => err.to_owned(),
    }
}

/// The request that starts a stopped transfer again with the same arguments (the password is
/// never stored, so it is passed in). `restart` discards the partial transfer instead.
fn start_again(job: &TransferStatus, password: &str, restart: bool) -> WorkerCmd {
    let password = (!password.is_empty()).then(|| password.to_owned());
    match job.kind {
        TransferKind::Receive => WorkerCmd::TransferStartReceive {
            // The share ID it was started from, so a resume keeps verifying the publisher.
            mid: job.share_id.clone().unwrap_or_else(|| job.mid.clone()),
            output_path: plain_path(&job.name).into(),
            password,
            restart,
            via: Vec::new(),
        },
        TransferKind::Send if restart => WorkerCmd::TransferStartPublish {
            // A restart begins again, so the settings come from the current defaults.
            file_path: job.name.clone().into(),
            password,
            data_shards: DEFAULT_SEND_K,
            total_shards: DEFAULT_SEND_N,
            restart: true,
        },
        TransferKind::Send => WorkerCmd::TransferResumePublish {
            file_path: job.name.clone().into(),
            password,
        },
    }
}

/// A resumed receive goes to the endpoint it was started with, if this session knows it.
fn with_via(mut cmd: WorkerCmd, via: Option<&String>) -> WorkerCmd {
    if let (WorkerCmd::TransferStartReceive { via: v, .. }, Some(url)) = (&mut cmd, via) {
        *v = vec![url.clone()];
    }
    cmd
}

fn phase_plain(t: &TransferStrings, phase: Phase) -> &'static str {
    match phase {
        Phase::Preparing => t.ph_preparing,
        Phase::Hashing => t.ph_hashing,
        Phase::Verifying => t.ph_verifying,
        Phase::Transferring => t.ph_transferring,
        Phase::Finalizing => t.ph_finalizing,
        Phase::Done => t.ph_done,
    }
}

fn easy_sentence(t: &TransferStrings, job: &TransferStatus, pct: &str) -> String {
    match job.state {
        TransferState::Running => match job.eta_secs {
            Some(eta) => fill(
                t.easy_running_eta,
                &[("pct", pct), ("eta", &format_eta(Some(eta), t.day))],
            ),
            None => fill(t.easy_running, &[("pct", pct)]),
        },
        TransferState::Paused | TransferState::Cancelled => fill(t.easy_paused, &[("pct", pct)]),
        TransferState::Complete => t.easy_complete.to_owned(),
        TransferState::Failed => t.easy_failed.to_owned(),
    }
}

fn split_text(t: &TransferStrings, job: &TransferStatus) -> String {
    match time_split(job.fetch_ms, job.decode_ms, job.write_ms) {
        None => "-".to_owned(),
        Some([a, b, c]) => {
            let template = match job.kind {
                TransferKind::Receive => t.split_recv,
                TransferKind::Send => t.split_send,
            };
            fill(
                template,
                &[
                    ("a", &a.to_string()),
                    ("b", &b.to_string()),
                    ("c", &c.to_string()),
                ],
            )
        }
    }
}

// ─── Drawing helpers ────────────────────────────────────────────────────────

const FORM_LABEL_W: f32 = 170.0;

/// A form row: a fixed-width label column, aligned to the top so it stays next to the first
/// line of a tall control (a grid would centre it against the whole row), and the control.
fn form_row(ui: &mut egui::Ui, label: &str, content: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(FORM_LABEL_W, 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_min_width(FORM_LABEL_W);
                ui.add_space(4.0);
                ui.label(label);
            },
        );
        ui.vertical(content);
    });
    ui.add_space(2.0);
}

/// Text colour for a chip tinted with `color`: the `faint` state colour is too dim to read as
/// text on its own tint (about 3:1 in dark mode), so it is drawn in `muted`.
fn chip_fg(color: egui::Color32) -> egui::Color32 {
    if color == pal().faint {
        pal().muted
    } else {
        color
    }
}

/// A small state chip: tinted background, text in the state colour.
fn draw_chip(ui: &mut egui::Ui, color: egui::Color32, text: &str) {
    egui::Frame::none()
        .inner_margin(egui::Margin::symmetric(8.0, 2.0))
        .rounding(4.0)
        .fill(color.linear_multiply(0.15))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(text)
                    .small()
                    .strong()
                    .color(chip_fg(color)),
            );
        });
}

/// Trim `text` with `...` until it is at most `max_w` wide.
fn fit_text(painter: &egui::Painter, text: &str, font: &egui::FontId, max_w: f32) -> String {
    let width = |s: &str| {
        painter
            .layout_no_wrap(s.to_owned(), font.clone(), egui::Color32::WHITE)
            .size()
            .x
    };
    if width(text) <= max_w {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    let (mut lo, mut hi) = (0usize, chars.len());
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let candidate: String = chars[..mid].iter().collect::<String>() + "...";
        if width(&candidate) <= max_w {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    chars[..lo].iter().collect::<String>() + "..."
}

/// An up (send) or down (receive) arrow drawn with lines, so it needs no font glyph.
fn paint_arrow(painter: &egui::Painter, c: egui::Pos2, up: bool, color: egui::Color32) {
    let s = egui::Stroke::new(1.6, color);
    let (tip, tail) = if up {
        (egui::pos2(c.x, c.y - 6.0), egui::pos2(c.x, c.y + 6.0))
    } else {
        (egui::pos2(c.x, c.y + 6.0), egui::pos2(c.x, c.y - 6.0))
    };
    let dy = if up { 4.0 } else { -4.0 };
    painter.line_segment([tail, tip], s);
    painter.line_segment([tip, egui::pos2(c.x - 4.0, tip.y + dy)], s);
    painter.line_segment([tip, egui::pos2(c.x + 4.0, tip.y + dy)], s);
}

/// One list row: arrow + name + chip on the first line; bar, percent, sizes, speed and ETA on the
/// second. Returns true when clicked.
fn job_row(
    ui: &mut egui::Ui,
    t: &TransferStrings,
    job: &TransferStatus,
    selected: bool,
    stale: bool,
) -> bool {
    let p = pal();
    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), ROW_H),
        egui::Sense::click(),
    );
    let painter = ui.painter_at(rect);
    if selected {
        painter.rect_filled(rect, 6.0, p.selected);
    } else if resp.hovered() {
        painter.rect_filled(rect, 6.0, p.text.gamma_multiply(0.05));
    }

    let chip = chip_for(job.state);
    let color = chip_color(chip);
    let text_color = if stale { p.faint } else { p.text };
    let muted = if stale { p.faint } else { p.muted };
    let left = rect.left() + 12.0;
    let right = rect.right() - 12.0;

    // Line 1.
    let y1 = rect.top() + 17.0;
    paint_arrow(
        &painter,
        egui::pos2(left + 5.0, y1),
        job.kind == TransferKind::Send,
        muted,
    );
    let dir = if job.kind == TransferKind::Send {
        t.send
    } else {
        t.receive
    };
    let small = egui::FontId::proportional(11.5);
    let dir_rect = painter.text(
        egui::pos2(left + 18.0, y1),
        egui::Align2::LEFT_CENTER,
        dir,
        small.clone(),
        muted,
    );

    // The chip sits at the right edge; its width is measured, not guessed.
    let chip_galley = painter.layout_no_wrap(
        state_label(t, job.state).to_owned(),
        egui::FontId::proportional(11.5),
        chip_fg(color),
    );
    let chip_w = chip_galley.size().x + 16.0;
    let chip_rect = egui::Rect::from_min_size(
        egui::pos2(right - chip_w, y1 - 10.0),
        egui::vec2(chip_w, 20.0),
    );
    painter.rect_filled(chip_rect, 4.0, color.linear_multiply(0.15));
    painter.galley(
        egui::pos2(
            chip_rect.left() + 8.0,
            chip_rect.center().y - chip_galley.size().y * 0.5,
        ),
        chip_galley,
        chip_fg(color),
    );

    let name_font = egui::FontId::proportional(14.0);
    let name_left = dir_rect.right() + 10.0;
    let name = fit_text(
        &painter,
        &title_of(job),
        &name_font,
        (chip_rect.left() - 12.0 - name_left).max(20.0),
    );
    painter.text(
        egui::pos2(name_left, y1),
        egui::Align2::LEFT_CENTER,
        name,
        name_font,
        text_color,
    );

    // Line 2.
    let y2 = rect.top() + 39.0;
    let avail = right - left;
    let bar_w = (avail * 0.36).clamp(110.0, 280.0).min(avail);
    let bar = egui::Rect::from_min_size(egui::pos2(left, y2 - 4.0), egui::vec2(bar_w, 8.0));
    // border_strong, not border: on the selected row `border` is nearly the row colour in dark mode.
    painter.rect_filled(bar, 4.0, p.border_strong);
    let pm = permille(job.bytes_done, job.bytes_total, job.state);
    if let Some(pm) = pm {
        let w = bar.width() * pm as f32 / 1000.0;
        if w > 0.5 {
            let fill_rect =
                egui::Rect::from_min_size(bar.min, egui::vec2(w.max(3.0), bar.height()));
            painter.rect_filled(fill_rect, 4.0, if stale { p.faint } else { color });
        }
    }
    let pct_rect = painter.text(
        egui::pos2(bar.right() + 8.0, y2),
        egui::Align2::LEFT_CENTER,
        format_permille(pm),
        small.clone(),
        text_color,
    );

    // Sizes, speed, ETA: as much as fits, most important first.
    let bytes = if job.bytes_total > 0 {
        format!(
            "{} / {}",
            format_bytes(job.bytes_done),
            format_bytes(job.bytes_total)
        )
    } else {
        format_bytes(job.bytes_done)
    };
    let running = job.state == TransferState::Running;
    let full = format!(
        "{bytes}     {}     {} {}",
        format_rate(job.rate_bps),
        t.eta,
        format_eta(job.eta_secs, t.day)
    );
    let mid = format!("{bytes}     {} {}", t.eta, format_eta(job.eta_secs, t.day));
    let room = right - (pct_rect.right() + 16.0);
    let width_of = |s: &str| {
        painter
            .layout_no_wrap(s.to_owned(), small.clone(), muted)
            .size()
            .x
    };
    let info = if !running {
        bytes.clone()
    } else if width_of(&full) <= room {
        full
    } else if width_of(&mid) <= room {
        mid
    } else {
        bytes
    };
    painter.text(
        egui::pos2(right, y2),
        egui::Align2::RIGHT_CENTER,
        info,
        small,
        muted,
    );

    resp.clicked()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh random password, for tests: no test carries a fixed secret.
    fn random_test_password() -> String {
        use std::hash::{BuildHasher, Hasher};
        let h = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        // Always satisfies the password policy: a digit, letters and a symbol.
        format!("pw-1{h:016x}")
    }

    // ── The send password policy and Generate ───────────────────────────────

    #[test]
    fn a_weak_send_password_disables_the_button_and_explains_why() {
        use crate::locale::{transfer_strings, Locale};
        // Three letters only: too short, no digit, no symbol.
        let weak = SendPassword::Weak(match send_password_state(&compose_pw(3, 0, 0, 0)) {
            SendPassword::Weak(v) => v,
            _ => panic!("expected a weak verdict"),
        });
        assert!(!send_ready(true, "C:\\f.bin", false, &weak));
        // Everything else ready: only the password blocks it.
        assert!(send_ready(true, "C:\\f.bin", false, &SendPassword::Good));
        assert!(send_ready(true, "C:\\f.bin", false, &SendPassword::Short));
        assert!(send_ready(
            true,
            "C:\\f.bin",
            false,
            &SendPassword::Unprotected
        ));
        // The other gates are unchanged.
        assert!(!send_ready(false, "C:\\f.bin", false, &SendPassword::Good));
        assert!(!send_ready(true, "  ", false, &SendPassword::Good));
        assert!(!send_ready(true, "C:\\f.bin", true, &SendPassword::Good));

        let SendPassword::Weak(v) = &weak else {
            unreachable!()
        };
        for lang in Locale::ALL {
            let t = transfer_strings(lang);
            let msg = weak_password_text(t, &violation_codes(v));
            // Static failure text only: nothing derived from a password.
            assert!(msg.starts_with(t.pw_weak_prefix), "{lang:?}: prefix");
            assert!(msg.contains(t.pw_err_too_short), "{lang:?}: too short");
            assert!(msg.contains(t.pw_err_no_digit), "{lang:?}: no digit");
            assert!(msg.contains(t.pw_err_no_symbol), "{lang:?}: no symbol");
            assert!(!msg.contains(t.pw_err_no_letter), "{lang:?}: has a letter");
        }
    }

    /// A password of the given shape built at run time from random draws (plus
    /// `spaces` ASCII spaces), so no test carries a literal password.
    fn compose_pw(letters: usize, digits: usize, symbols: usize, spaces: usize) -> String {
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
        draw(letters_set, letters)
            + &draw(digits_set, digits)
            + &draw(symbols_set, symbols)
            + &" ".repeat(spaces)
    }

    #[test]
    fn the_send_password_states_follow_the_policy() {
        assert!(send_password_state(&String::new()) == SendPassword::Unprotected);
        // Five characters in every class: too short to accept.
        assert!(matches!(
            send_password_state(&compose_pw(3, 1, 1, 0)),
            SendPassword::Weak(_)
        ));
        // Space is not a symbol.
        assert!(matches!(
            send_password_state(&compose_pw(3, 3, 0, 2)),
            SendPassword::Weak(_)
        ));
        // 6 and 11 characters are compliant but short; 12 is good.
        assert!(send_password_state(&compose_pw(4, 1, 1, 0)) == SendPassword::Short);
        assert!(send_password_state(&compose_pw(9, 1, 1, 0)) == SendPassword::Short);
        assert!(send_password_state(&compose_pw(10, 1, 1, 0)) == SendPassword::Good);
    }

    #[test]
    fn generate_fills_both_fields_with_a_compliant_password_and_shows_it_once() {
        let mut ui = TransfersUi::default();
        ui.generate_send_password();
        assert!(ui.send_password == ui.send_confirm);
        assert!(ui.send_generated.as_deref() == Some(ui.send_password.as_str()));
        assert_eq!(ui.send_password.chars().count(), 16);
        assert!(password_policy::check(&ui.send_password).is_ok());
        assert!(send_password_state(&ui.send_password) == SendPassword::Good);
        // A new press makes a different one.
        let first = ui.send_password.clone();
        ui.generate_send_password();
        assert!(first != ui.send_password);
        // Wiped with the rest of the form's secrets.
        ui.zeroize_passwords();
        assert!(ui.send_generated.is_none());
        assert!(ui.send_password.is_empty());
    }

    #[test]
    fn a_daemon_weak_password_error_is_shown_in_the_ui_language() {
        use crate::locale::{transfer_strings, Locale};
        let ja = transfer_strings(Locale::Ja);
        let shown = localize_job_error(ja, "weak password: too_short,no_symbol");
        assert!(shown.starts_with(ja.pw_weak_prefix), "translated prefix");
        assert!(shown.contains(ja.pw_err_no_symbol), "translated no-symbol");
        // Anything else is untouched.
        assert_eq!(localize_job_error(ja, "disk full"), "disk full");
        assert_eq!(localize_job_error(ja, "wrong password"), "wrong password");
    }

    fn status(kind: TransferKind, state: TransferState) -> TransferStatus {
        TransferStatus {
            mid: "miasma:abc".into(),
            kind,
            name: r"\\?\C:\data\big.iso".into(),
            phase: Phase::Transferring,
            state,
            segments_done: 3,
            segments_total: 10,
            bytes_done: 300,
            bytes_total: 1000,
            rate_bps: 0.0,
            eta_secs: None,
            elapsed_secs: 0.0,
            fetch_ms: 0,
            decode_ms: 0,
            write_ms: 0,
            pieces_fetched: 0,
            pieces_rejected: 0,
            segment_retries: 0,
            resumed_from_segment: 0,
            last_error: None,
            resumable: false,
            share_id: None,
            share_id_checked: false,
            publisher_authenticated: false,
        }
    }

    #[test]
    fn bytes_are_formatted_with_integer_math() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(40 * 1024 * 1024), "40.0 MiB");
        assert_eq!(format_bytes(100 * 1024 * 1024 * 1024), "100.0 GiB");
        assert_eq!(
            format_bytes(37 * 1024 * 1024 * 1024 + 512 * 1024 * 1024),
            "37.5 GiB"
        );
        // 1 MiB - 1 byte stays in KiB and never rounds up into a wrong unit.
        assert_eq!(format_bytes(1024 * 1024 - 1), "1023.9 KiB");
    }

    #[test]
    fn huge_byte_counts_do_not_overflow() {
        assert_eq!(format_bytes(u64::MAX), "15.9 EiB");
        assert!(format_bytes(1 << 62).ends_with("EiB"));
        assert_eq!(format_bytes(1 << 50), "1.0 PiB");
    }

    #[test]
    fn rate_zero_unknown_and_nonsense_show_a_dash() {
        assert_eq!(format_rate(0.0), "-");
        assert_eq!(format_rate(0.4), "-");
        assert_eq!(format_rate(-5.0), "-");
        assert_eq!(format_rate(f64::NAN), "-");
        assert_eq!(format_rate(f64::INFINITY), "-");
        assert_eq!(format_rate(12.5 * 1024.0 * 1024.0), "12.5 MiB/s");
        assert_eq!(format_rate(2.0 * 1024.0), "2.0 KiB/s");
    }

    #[test]
    fn eta_is_hh_mm_ss_then_days() {
        assert_eq!(format_eta(None, "d"), "-");
        assert_eq!(format_eta(Some(0), "d"), "00:00:00");
        assert_eq!(format_eta(Some(59), "d"), "00:00:59");
        assert_eq!(format_eta(Some(3661), "d"), "01:01:01");
        assert_eq!(format_eta(Some(86_399), "d"), "23:59:59");
        assert_eq!(format_eta(Some(86_400), "d"), "1d 00:00:00");
        assert_eq!(
            format_eta(Some(2 * 86_400 + 3 * 3600 + 20 * 60 + 11), "日"),
            "2日 03:20:11"
        );
        assert_eq!(format_eta(Some(u64::MAX), "d"), ">999d");
    }

    #[test]
    fn percent_never_divides_by_zero_or_exceeds_100() {
        assert_eq!(permille(5, 0, TransferState::Running), None);
        assert_eq!(permille(0, 0, TransferState::Complete), Some(1000));
        assert_eq!(permille(0, 100, TransferState::Running), Some(0));
        assert_eq!(permille(37, 100, TransferState::Running), Some(370));
        assert_eq!(permille(500, 100, TransferState::Running), Some(1000));
        // 37 % of 100 GiB, no float rounding.
        let total = 100u64 << 30;
        assert_eq!(
            permille(total / 100 * 37, total, TransferState::Running),
            Some(370)
        );
        assert_eq!(
            permille(u64::MAX, u64::MAX, TransferState::Running),
            Some(1000)
        );
        assert_eq!(format_permille(Some(370)), "37.0%");
        assert_eq!(format_permille(Some(1000)), "100.0%");
        assert_eq!(format_permille(None), "-");
    }

    #[test]
    fn time_split_sums_to_100() {
        assert_eq!(time_split(0, 0, 0), None);
        assert_eq!(time_split(70, 20, 10), Some([70, 20, 10]));
        let s = time_split(1, 1, 1).unwrap();
        assert_eq!(s.iter().sum::<u32>(), 100);
        let s = time_split(u64::MAX, u64::MAX, u64::MAX).unwrap();
        assert_eq!(s.iter().sum::<u32>(), 100);
    }

    #[test]
    fn strip_is_one_cell_per_segment_when_small() {
        let s = build_strip(10, 3, true, 0);
        assert_eq!(s.per_cell, 1);
        assert_eq!(s.cells.len(), 10);
        assert_eq!(&s.cells[..3], &[CellState::Done; 3]);
        assert_eq!(s.cells[3], CellState::InFlight);
        assert!(s.cells[4..].iter().all(|c| *c == CellState::Pending));
        assert_eq!(s.resume_cell, None);
    }

    #[test]
    fn strip_paused_has_nothing_in_flight() {
        let s = build_strip(10, 3, false, 0);
        assert!(!s.cells.contains(&CellState::InFlight));
        assert_eq!(s.cells.iter().filter(|c| **c == CellState::Done).count(), 3);
    }

    #[test]
    fn strip_buckets_a_100_gib_job() {
        // 100 GiB at 64 MiB per segment = 1600 segments, 37 % done.
        let done = 592;
        let s = build_strip(1600, done, true, 0);
        assert_eq!(s.per_cell, 4);
        assert_eq!(s.cells.len(), 400);
        // 592 / 4 = 148 whole buckets done, the 149th holds segment 592 and is in flight.
        assert_eq!(
            s.cells.iter().filter(|c| **c == CellState::Done).count(),
            148
        );
        assert_eq!(s.cells[148], CellState::InFlight);
        assert_eq!(
            s.cells
                .iter()
                .filter(|c| **c == CellState::InFlight)
                .count(),
            1
        );
    }

    #[test]
    fn strip_bucket_with_a_partial_count_is_in_flight_not_done() {
        // 401 segments -> 2 per cell, 201 cells; 5 done = 2 whole buckets + half of the third.
        let s = build_strip(401, 5, true, 0);
        assert_eq!(s.per_cell, 2);
        assert_eq!(s.cells.len(), 201);
        assert_eq!(s.cells[1], CellState::Done);
        assert_eq!(s.cells[2], CellState::InFlight);
        // The last cell is short (1 segment) and must still be reachable.
        let s = build_strip(401, 401, false, 0);
        assert!(s.cells.iter().all(|c| *c == CellState::Done));
    }

    #[test]
    fn strip_marks_the_resume_position_only_when_consistent() {
        assert_eq!(build_strip(10, 6, true, 4).resume_cell, Some(4));
        // A fresh transfer has nothing to mark.
        assert_eq!(build_strip(10, 6, true, 0).resume_cell, None);
        // Resume position ahead of what is done contradicts the counters: not drawn.
        assert_eq!(build_strip(10, 3, true, 7).resume_cell, None);
        // In a bucketed strip it is the bucket that holds the segment.
        assert_eq!(build_strip(1600, 800, true, 402).resume_cell, Some(100));
    }

    #[test]
    fn strip_handles_degenerate_totals() {
        assert!(build_strip(0, 0, true, 0).cells.is_empty());
        // done beyond total is clamped, not a panic.
        let s = build_strip(3, 99, true, 0);
        assert!(s.cells.iter().all(|c| *c == CellState::Done));
        let s = build_strip(1, 0, true, 0);
        assert_eq!(s.cells, vec![CellState::InFlight]);
        let s = build_strip(u32::MAX, 5, true, 0);
        assert!(s.cells.len() <= MAX_STRIP_CELLS as usize);
    }

    #[test]
    fn state_maps_to_the_chip_colour_the_spec_names() {
        assert_eq!(chip_for(TransferState::Running), Chip::Info);
        assert_eq!(chip_for(TransferState::Paused), Chip::Warning);
        assert_eq!(chip_for(TransferState::Complete), Chip::Success);
        assert_eq!(chip_for(TransferState::Failed), Chip::Danger);
        assert_eq!(chip_for(TransferState::Cancelled), Chip::Faint);
    }

    #[test]
    fn running_sorts_first_then_attention_then_finished() {
        let mut jobs = vec![
            status(TransferKind::Send, TransferState::Complete),
            status(TransferKind::Receive, TransferState::Cancelled),
            status(TransferKind::Send, TransferState::Failed),
            status(TransferKind::Receive, TransferState::Paused),
            status(TransferKind::Receive, TransferState::Running),
        ];
        sort_jobs(&mut jobs);
        let order: Vec<_> = jobs.iter().map(|j| j.state).collect();
        assert_eq!(
            order,
            vec![
                TransferState::Running,
                TransferState::Paused,
                TransferState::Failed,
                TransferState::Cancelled,
                TransferState::Complete
            ]
        );
    }

    #[test]
    fn only_stopped_transfers_can_be_resumed() {
        assert!(!can_resume(TransferState::Running));
        assert!(!can_resume(TransferState::Complete));
        assert!(can_resume(TransferState::Paused));
        assert!(can_resume(TransferState::Cancelled));
        assert!(can_resume(TransferState::Failed));
    }

    #[test]
    fn preset_table_matches_the_measured_redundancy_experiment() {
        // plan section 6, phase 5: storage x and pieces a segment may lose.
        let expected = [
            (10, 10, "1.00x", 0),
            (10, 11, "1.10x", 1),
            (10, 12, "1.20x", 2),
            (10, 15, "1.50x", 5),
            (10, 20, "2.00x", 10),
        ];
        for (p, (k, n, x, loss)) in PRESETS.iter().zip(expected) {
            assert_eq!((p.k, p.n), (k, n));
            assert_eq!(p.multiplier_text(), x);
            assert_eq!(p.tolerated(), loss);
        }
    }

    #[test]
    fn the_preselected_preset_is_the_cli_default() {
        let d = PRESETS[DEFAULT_PRESET];
        assert_eq!((d.k, d.n), (DEFAULT_SEND_K, DEFAULT_SEND_N));
        assert_eq!(TransfersUi::default().send_preset, DEFAULT_PRESET);
    }

    #[test]
    fn easy_choices_map_to_presets_and_back() {
        let idx: Vec<_> = EasyChoice::ALL.iter().map(|c| c.preset_index()).collect();
        assert_eq!(idx, vec![0, 2, 4]);
        for c in EasyChoice::ALL {
            assert_eq!(EasyChoice::from_preset_index(c.preset_index()), Some(c));
        }
        assert_eq!(EasyChoice::from_preset_index(1), None);
        // Fastest has no spare pieces; Safest is the CLI default.
        assert_eq!(PRESETS[EasyChoice::Fastest.preset_index()].tolerated(), 0);
        assert_eq!(EasyChoice::Safest.preset_index(), DEFAULT_PRESET);
    }

    #[test]
    fn names_and_ids() {
        assert_eq!(plain_path(r"\\?\C:\a\b.bin"), r"C:\a\b.bin");
        assert_eq!(plain_path("/home/x"), "/home/x");
        assert_eq!(file_name_of(r"\\?\C:\a\b.bin"), "b.bin");
        assert_eq!(file_name_of("/mnt/ssd/big.iso"), "big.iso");
        assert_eq!(file_name_of("/mnt/ssd/"), "ssd");
        assert_eq!(file_name_of("plain"), "plain");
        let r = status(TransferKind::Receive, TransferState::Running);
        assert_eq!(transfer_id(&r), "miasma:abc");
        let s = status(TransferKind::Send, TransferState::Running);
        assert_eq!(transfer_id(&s), send_id(Path::new(&s.name)));
        assert!(transfer_id(&s).starts_with("send:"));
    }

    #[test]
    fn a_job_with_no_name_is_titled_by_its_mid() {
        // The daemon used to report an empty name for a live receive (fixed in `jobs.rs`); a row
        // must still never be blank.
        let mut r = status(TransferKind::Receive, TransferState::Failed);
        assert_eq!(title_of(&r), "big.iso");
        r.name = String::new();
        assert_eq!(title_of(&r), "miasma:abc");
        r.mid = "miasma:0123456789abcdefghijklmnopqrstuvwxyz".into();
        assert_eq!(title_of(&r), "miasma:0123456789abcdefg...");
        r.mid = String::new();
        assert_eq!(title_of(&r), "-");
    }

    #[test]
    fn fill_replaces_every_placeholder() {
        assert_eq!(
            fill("{a} of {b} ({a})", &[("a", "1"), ("b", "2")]),
            "1 of 2 (1)"
        );
    }

    #[test]
    fn a_resumed_receive_goes_back_to_its_via_endpoint_and_only_a_receive() {
        let r = status(TransferKind::Receive, TransferState::Paused);
        let none = String::new();
        let url = "wss://example.trycloudflare.com".to_owned();
        match with_via(start_again(&r, &none, false), Some(&url)) {
            WorkerCmd::TransferStartReceive { via, .. } => assert_eq!(via, vec![url.clone()]),
            other => panic!("wrong command: {other:?}"),
        }
        // Nothing known: the ordinary receive, as before.
        match with_via(start_again(&r, &none, false), None) {
            WorkerCmd::TransferStartReceive { via, .. } => assert!(via.is_empty()),
            other => panic!("wrong command: {other:?}"),
        }
        // A send is left alone.
        let s = status(TransferKind::Send, TransferState::Paused);
        assert!(matches!(
            with_via(start_again(&s, &none, false), Some(&url)),
            WorkerCmd::TransferResumePublish { .. }
        ));
    }

    #[test]
    fn resuming_a_share_id_receive_keeps_the_share_id() {
        let mut r = status(TransferKind::Receive, TransferState::Paused);
        r.share_id = Some("miasma-share:xyz".into());
        let none = String::new();
        match start_again(&r, &none, false) {
            WorkerCmd::TransferStartReceive { mid, .. } => assert_eq!(mid, "miasma-share:xyz"),
            other => panic!("wrong command: {other:?}"),
        }
    }

    #[test]
    fn resuming_reissues_the_same_request() {
        let mut r = status(TransferKind::Receive, TransferState::Paused);
        r.name = r"\\?\C:\out\big.iso".into();
        let pw = random_test_password();
        let none = String::new();
        match start_again(&r, &pw, false) {
            WorkerCmd::TransferStartReceive {
                mid,
                output_path,
                password,
                restart,
                via,
            } => {
                assert!(via.is_empty());
                assert_eq!(mid, "miasma:abc");
                assert_eq!(output_path, std::path::PathBuf::from(r"C:\out\big.iso"));
                assert_eq!(password.as_deref(), Some(pw.as_str()));
                assert!(!restart);
            }
            other => panic!("wrong command: {other:?}"),
        }
        // No password typed = no password sent.
        assert!(matches!(
            start_again(&r, &none, false),
            WorkerCmd::TransferStartReceive { password: None, .. }
        ));
        // A send resumes through the journal (so k/n are the ones it began with) ...
        let s = status(TransferKind::Send, TransferState::Paused);
        assert!(matches!(
            start_again(&s, &none, false),
            WorkerCmd::TransferResumePublish { .. }
        ));
        // ... and "start over" restarts.
        assert!(matches!(
            start_again(&s, &none, true),
            WorkerCmd::TransferStartPublish { restart: true, .. }
        ));
    }

    #[test]
    fn polling_is_gated_on_visibility_or_running_jobs() {
        let mut ui = TransfersUi::default();
        ui.last_poll = Instant::now() - Duration::from_secs(5);
        // Never read yet: one poll to learn the state, even when hidden.
        assert!(ui.poll_due(false));
        ui.note_polled();
        assert!(!ui.poll_due(true), "one request at a time");
        ui.on_list(vec![status(TransferKind::Receive, TransferState::Paused)]);
        ui.last_poll = Instant::now() - Duration::from_secs(5);
        assert!(
            !ui.poll_due(false),
            "hidden and nothing running: no polling"
        );
        assert!(ui.poll_due(true));
        ui.on_list(vec![status(TransferKind::Receive, TransferState::Running)]);
        ui.last_poll = Instant::now() - Duration::from_secs(5);
        assert!(
            ui.poll_due(false),
            "a running job keeps it polling while hidden"
        );
        ui.last_poll = Instant::now();
        assert!(!ui.poll_due(true), "about once a second");
    }

    #[test]
    fn a_dead_daemon_asks_for_a_reconnect_but_not_every_frame() {
        let mut ui = TransfersUi::default();
        ui.last_recover = Instant::now() - Duration::from_secs(60);
        assert!(ui.on_poll_failed("down".into(), true));
        assert!(!ui.on_poll_failed("down".into(), true));
        assert!(!ui.on_poll_failed("other".into(), false));
    }

    #[test]
    fn the_selection_follows_the_transfer_when_the_order_changes() {
        let mut ui = TransfersUi::default();
        let mut a = status(TransferKind::Receive, TransferState::Paused);
        a.mid = "miasma:a".into();
        let mut b = status(TransferKind::Receive, TransferState::Paused);
        b.mid = "miasma:b".into();
        ui.on_list(vec![a.clone(), b.clone()]);
        ui.select_id(Some("miasma:b".into()));
        b.state = TransferState::Running; // now sorts first
        ui.on_list(vec![a, b]);
        assert_eq!(ui.jobs[0].mid, "miasma:b");
        assert_eq!(ui.selected.as_deref(), Some("miasma:b"));
        // A vanished selection falls back to the first row.
        ui.on_list(vec![status(TransferKind::Receive, TransferState::Paused)]);
        assert_eq!(ui.selected.as_deref(), Some("miasma:abc"));
    }

    // ── Removing finished transfers ─────────────────────────────────────────

    fn job(state: TransferState, resumable: bool) -> TransferStatus {
        let mut j = status(TransferKind::Receive, state);
        j.resumable = resumable;
        j
    }

    #[test]
    fn only_finished_rows_can_be_removed_and_partial_data_needs_a_discard() {
        use TransferState::*;
        for (state, resumable, can, discard) in [
            (Complete, false, true, false),
            (Failed, false, true, false),
            (Cancelled, false, true, false),
            (Failed, true, true, true),
            (Cancelled, true, true, true),
            (Running, false, false, false),
            (Paused, true, false, false),
        ] {
            let j = job(state, resumable);
            assert_eq!(can_remove(&j), can, "{state:?}/{resumable}");
            assert_eq!(remove_needs_discard(&j), discard, "{state:?}/{resumable}");
        }
    }

    #[test]
    fn clear_finished_shows_only_when_something_can_be_cleared_without_loss() {
        use TransferState::*;
        assert!(!show_clear_finished(&[]));
        // Nothing finished, or only rows that hold partial data or are still alive.
        assert!(!show_clear_finished(&[
            job(Running, false),
            job(Paused, true)
        ]));
        assert!(!show_clear_finished(&[job(Cancelled, true)]));
        // One clearable row is enough.
        assert!(show_clear_finished(&[
            job(Running, false),
            job(Complete, false)
        ]));
        assert!(show_clear_finished(&[job(Failed, false)]));
    }

    #[test]
    fn a_removed_row_does_not_come_back_until_the_daemon_says_so() {
        let mut ui = TransfersUi::default();
        let mut done = job(TransferState::Complete, false);
        done.mid = "miasma:done".into();
        let mut live = job(TransferState::Running, false);
        live.mid = "miasma:live".into();
        ui.on_list(vec![done.clone(), live.clone()]);
        ui.drop_rows(|j| !clearable(j));
        assert_eq!(ui.jobs.len(), 1);
        assert_eq!(ui.jobs[0].mid, "miasma:live");
        // The daemon's next list is authoritative.
        ui.on_list(vec![live]);
        assert_eq!(ui.jobs.len(), 1);
    }

    #[test]
    fn a_refused_remove_asks_to_discard_or_says_why() {
        use miasma_core::transfer::jobs::RemoveRefusal as R;
        let t = crate::locale::transfer_strings(crate::locale::Locale::En);
        let mut ui = TransfersUi::default();
        ui.on_remove_refused(R::HasPartialData, t);
        assert!(ui.discard_confirm);
        ui.on_remove_refused(R::Running, t);
        assert_eq!(ui.form_error.as_deref(), Some(t.err_remove_running));
        ui.on_remove_refused(R::Paused, t);
        assert_eq!(ui.form_error.as_deref(), Some(t.err_remove_paused));
    }

    // ── A receive needs a file name ─────────────────────────────────────────

    #[test]
    fn the_suggested_file_name_comes_from_the_mid_digest() {
        assert_eq!(
            suggested_file_name("miasma:3vQB7B6MrGQZaxCuFg4oh"),
            "received-3vQB7B6M.bin"
        );
        assert_eq!(suggested_file_name("  miasma:abc  "), "received-abc.bin");
        // No MID yet, or not a MID: a fixed name, never a path fragment.
        assert_eq!(suggested_file_name(""), "received.bin");
        assert_eq!(suggested_file_name("nonsense"), "received.bin");
        let hostile = suggested_file_name("miasma:../../etc/passwd");
        assert!(
            !hostile.contains('/') && !hostile.contains(".."),
            "{hostile}"
        );
    }

    #[test]
    fn the_suggested_file_name_also_reads_a_share_id() {
        let mid = miasma_core::ContentId::compute(b"x", b"p");
        // The Ed25519 base point: a valid public key without any key material.
        let mut publisher = [0x66u8; 32];
        publisher[0] = 0x58;
        let share = miasma_core::transfer::ShareId::new(&mid, publisher, false).to_string();
        assert_eq!(
            suggested_file_name(&share),
            suggested_file_name(&mid.to_string())
        );
        assert_ne!(suggested_file_name(&share), "received.bin");
        // A mistyped share ID suggests the fixed name, nothing more.
        assert_eq!(suggested_file_name("miasma-share:0OIl"), "received.bin");
    }

    #[test]
    fn a_folder_is_passed_on_as_a_folder_and_a_file_path_is_kept() {
        let dir = std::env::temp_dir().join(format!("miasma-desktop-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let folder = dir.to_string_lossy().into_owned();
        // The daemon resolves <folder>/<original name>; the desktop no longer invents a name.
        assert_eq!(effective_receive_path(&folder), (folder.clone(), true));

        let file = dir.join("mine.bin").to_string_lossy().into_owned();
        assert_eq!(effective_receive_path(&file), (file, false));
        // Empty stays empty (the Start button is disabled for it).
        assert_eq!(effective_receive_path("  "), (String::new(), false));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
