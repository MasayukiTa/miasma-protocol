//! Transfer records the GUI/CLI poll, and the persisted history.
//!
//! Plain data and bookkeeping only: no networking, so it is usable (and
//! testable) without an iroh endpoint.

use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tracing::warn;

use crate::state_crypto::{self, Label, LogReader, LogRewrite, LogWriter, StateKeys};

pub const HISTORY_FILE: &str = crate::paths::PUSH_HISTORY.name;
/// Lines kept after trimming, and the size that triggers a trim.
pub const HISTORY_KEEP: usize = 1000;
const HISTORY_TRIM_AT: usize = 2000;
/// Finished transfers kept in memory for polling.
const FINISHED_KEEP: usize = 200;
/// Unfinished transfers allowed at once (queued + running).
pub const MAX_ACTIVE: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Out,
    In,
}

/// Lifecycle of a transfer. `Preparing` (hashing the file before the header
/// can be sent) and `Cancelled` are additions to the states in the design.
/// `Waiting` is not an ending: the other side cannot be reached right now and
/// the sender will try again by itself (see `PushTransferInfo::next_attempt_at_ms`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushState {
    Queued,
    Preparing,
    Connecting,
    Sending,
    Verifying,
    Done,
    Failed,
    Rejected,
    Cancelled,
    Waiting,
}

/// The states a client from before `Waiting` existed knows. The wire carries
/// one of these in `state` (a `Waiting` transfer shows as `queued` to such a
/// client) and the real state in `phase` for clients that know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LegacyState {
    Queued,
    Preparing,
    Connecting,
    Sending,
    Verifying,
    Done,
    Failed,
    Rejected,
    Cancelled,
}

impl From<PushState> for LegacyState {
    fn from(s: PushState) -> Self {
        match s {
            PushState::Queued | PushState::Waiting => Self::Queued,
            PushState::Preparing => Self::Preparing,
            PushState::Connecting => Self::Connecting,
            PushState::Sending => Self::Sending,
            PushState::Verifying => Self::Verifying,
            PushState::Done => Self::Done,
            PushState::Failed => Self::Failed,
            PushState::Rejected => Self::Rejected,
            PushState::Cancelled => Self::Cancelled,
        }
    }
}

impl From<LegacyState> for PushState {
    fn from(s: LegacyState) -> Self {
        match s {
            LegacyState::Queued => Self::Queued,
            LegacyState::Preparing => Self::Preparing,
            LegacyState::Connecting => Self::Connecting,
            LegacyState::Sending => Self::Sending,
            LegacyState::Verifying => Self::Verifying,
            LegacyState::Done => Self::Done,
            LegacyState::Failed => Self::Failed,
            LegacyState::Rejected => Self::Rejected,
            LegacyState::Cancelled => Self::Cancelled,
        }
    }
}

impl PushState {
    pub fn is_finished(self) -> bool {
        matches!(
            self,
            Self::Done | Self::Failed | Self::Rejected | Self::Cancelled
        )
    }
}

/// What a poll returns for one transfer.
///
/// On the wire the `state` field only ever holds a value that older clients
/// know; a `waiting` transfer is sent as `queued` with the real state in
/// `phase`, which older clients ignore.
#[derive(Debug, Clone, PartialEq)]
pub struct PushTransferInfo {
    pub id: String,
    pub direction: Direction,
    pub contact_id: String,
    pub contact_label: String,
    /// File name (for inbound: the sanitised name).
    pub name: String,
    pub size: u64,
    /// Bytes transferred so far (including a resumed prefix).
    pub bytes: u64,
    /// Smoothed throughput, bytes per second.
    pub rate_bps: u64,
    pub state: PushState,
    /// Human-readable failure text (while `Waiting`: why the last attempt failed).
    pub error: Option<String>,
    /// `too_large`, `no_space`, `not_allowed`, `busy`, `bad_name` when rejected.
    pub reject_reason: Option<String>,
    /// Stable machine-readable kind of a non-rejection ending, or of the
    /// failure behind a `Waiting` state (see [`error_kind`]).
    /// `error` stays the English text; UIs map this to their own words.
    pub error_kind: Option<String>,
    /// Outbound only: the file this transfer sends, so a UI (or a later
    /// session) can offer "send again" without guessing.
    pub source_path: Option<String>,
    /// Where an inbound file was saved / the name the receiver reported.
    pub saved_as: Option<String>,
    /// Milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    /// `Waiting` only: when the next attempt is made (ms since the Unix epoch).
    pub next_attempt_at_ms: Option<u64>,
    /// `Waiting` only: the number of the attempt that failed (1 = the first
    /// try failed), counted since the last time bytes moved.
    pub attempt: Option<u32>,
}

/// The JSON form of [`PushTransferInfo`]. Every field added after the first
/// release is optional, so an older reader still parses it.
#[derive(Serialize, Deserialize)]
struct InfoWire {
    id: String,
    direction: Direction,
    contact_id: String,
    contact_label: String,
    name: String,
    size: u64,
    bytes: u64,
    rate_bps: u64,
    state: LegacyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phase: Option<PushState>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    reject_reason: Option<String>,
    #[serde(default)]
    error_kind: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    saved_as: Option<String>,
    created_at_ms: u64,
    updated_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_attempt_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt: Option<u32>,
}

impl From<&PushTransferInfo> for InfoWire {
    fn from(i: &PushTransferInfo) -> Self {
        Self {
            phase: (i.state == PushState::Waiting).then_some(PushState::Waiting),
            state: i.state.into(),
            id: i.id.clone(),
            direction: i.direction,
            contact_id: i.contact_id.clone(),
            contact_label: i.contact_label.clone(),
            name: i.name.clone(),
            size: i.size,
            bytes: i.bytes,
            rate_bps: i.rate_bps,
            error: i.error.clone(),
            reject_reason: i.reject_reason.clone(),
            error_kind: i.error_kind.clone(),
            source_path: i.source_path.clone(),
            saved_as: i.saved_as.clone(),
            created_at_ms: i.created_at_ms,
            updated_at_ms: i.updated_at_ms,
            next_attempt_at_ms: i.next_attempt_at_ms,
            attempt: i.attempt,
        }
    }
}

impl From<InfoWire> for PushTransferInfo {
    fn from(w: InfoWire) -> Self {
        Self {
            state: w.phase.unwrap_or_else(|| w.state.into()),
            id: w.id,
            direction: w.direction,
            contact_id: w.contact_id,
            contact_label: w.contact_label,
            name: w.name,
            size: w.size,
            bytes: w.bytes,
            rate_bps: w.rate_bps,
            error: w.error,
            reject_reason: w.reject_reason,
            error_kind: w.error_kind,
            source_path: w.source_path,
            saved_as: w.saved_as,
            created_at_ms: w.created_at_ms,
            updated_at_ms: w.updated_at_ms,
            next_attempt_at_ms: w.next_attempt_at_ms,
            attempt: w.attempt,
        }
    }
}

impl Serialize for PushTransferInfo {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        InfoWire::from(self).serialize(s)
    }
}

impl<'de> Deserialize<'de> for PushTransferInfo {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        InfoWire::deserialize(d).map(Into::into)
    }
}

/// One persisted line of history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub direction: Direction,
    pub contact_id: String,
    pub contact_label: String,
    pub name: String,
    pub size: u64,
    pub state: PushState,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub reject_reason: Option<String>,
    #[serde(default)]
    pub error_kind: Option<String>,
    #[serde(default)]
    pub source_path: Option<String>,
    #[serde(default)]
    pub saved_as: Option<String>,
    pub finished_at_ms: u64,
}

/// Stable values of `PushTransferInfo::error_kind` / `HistoryEntry::error_kind`.
/// The English `error` text may change; these do not.
pub mod error_kind {
    /// Outbound: the other side could not be reached (offline, network blocks).
    pub const UNREACHABLE: &str = "unreachable";
    /// The connection broke mid-transfer (outbound: retries ran out). Resumable.
    pub const CONNECTION_LOST: &str = "connection_lost";
    /// Nothing moved / no answer within the time limit.
    pub const TIMED_OUT: &str = "timed_out";
    /// Inbound, state `Cancelled`: the sender stopped the transfer on purpose.
    pub const PEER_CANCELLED: &str = "peer_cancelled";
    /// The file arrived damaged (checksum mismatch).
    pub const DAMAGED: &str = "damaged";
    /// Outbound: the file could not be read or changed while being sent.
    pub const FILE_UNREADABLE: &str = "file_unreadable";
    /// Inbound: the inbox could not be written.
    pub const WRITE_FAILED: &str = "write_failed";
    /// Outbound: the contact was removed / sending to it was switched off.
    pub const CONTACT_CHANGED: &str = "contact_changed";
    /// Outbound: the file was changed, moved or replaced after it was queued,
    /// so what is on disk is no longer what was meant to be sent.
    pub const SOURCE_CHANGED: &str = "source_changed";
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Entry {
    info: PushTransferInfo,
    cancel: watch::Sender<bool>,
}

/// The set of transfers, running and recently finished.
pub struct Board {
    inner: Mutex<HashMap<String, Entry>>,
    /// Every change of a transfer's state (id, new state), for whoever wants
    /// to follow the sequence rather than poll. Slow readers miss old ones.
    changes: broadcast::Sender<(String, PushState)>,
}

impl Default for Board {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            changes: broadcast::channel(256).0,
        }
    }
}

impl Board {
    pub fn new() -> Self {
        Self::default()
    }

    /// Follow state changes of all transfers.
    pub fn subscribe(&self) -> broadcast::Receiver<(String, PushState)> {
        self.changes.subscribe()
    }

    /// Register a transfer; returns its id and a receiver that turns `true`
    /// when it is cancelled.
    pub fn create(
        &self,
        direction: Direction,
        contact_id: &str,
        contact_label: &str,
        name: &str,
        size: u64,
        state: PushState,
    ) -> (String, watch::Receiver<bool>) {
        self.create_with_id(
            hex::encode(rand::random::<[u8; 8]>()),
            direction,
            contact_id,
            contact_label,
            name,
            size,
            state,
        )
    }

    /// As [`create`](Self::create) with a given id (a transfer restored after
    /// a restart keeps the id it had).
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_id(
        &self,
        id: String,
        direction: Direction,
        contact_id: &str,
        contact_label: &str,
        name: &str,
        size: u64,
        state: PushState,
    ) -> (String, watch::Receiver<bool>) {
        let now = now_ms();
        let (tx, rx) = watch::channel(false);
        let info = PushTransferInfo {
            id: id.clone(),
            direction,
            contact_id: contact_id.to_owned(),
            contact_label: contact_label.to_owned(),
            name: name.to_owned(),
            size,
            bytes: 0,
            rate_bps: 0,
            state,
            error: None,
            reject_reason: None,
            error_kind: None,
            source_path: None,
            saved_as: None,
            created_at_ms: now,
            updated_at_ms: now,
            next_attempt_at_ms: None,
            attempt: None,
        };
        let mut g = self.inner.lock().unwrap();
        g.insert(id.clone(), Entry { info, cancel: tx });
        Self::trim(&mut g);
        let _ = self.changes.send((id.clone(), state));
        (id, rx)
    }

    fn trim(g: &mut HashMap<String, Entry>) {
        let mut finished: Vec<(u64, String)> = g
            .values()
            .filter(|e| e.info.state.is_finished())
            .map(|e| (e.info.updated_at_ms, e.info.id.clone()))
            .collect();
        if finished.len() > FINISHED_KEEP {
            finished.sort();
            for (_, id) in finished.iter().take(finished.len() - FINISHED_KEEP) {
                g.remove(id);
            }
        }
    }

    pub fn active_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .values()
            .filter(|e| !e.info.state.is_finished())
            .count()
    }

    pub fn update(&self, id: &str, f: impl FnOnce(&mut PushTransferInfo)) {
        if let Some(e) = self.inner.lock().unwrap().get_mut(id) {
            let before = e.info.state;
            f(&mut e.info);
            e.info.updated_at_ms = now_ms();
            if e.info.state != before {
                let _ = self.changes.send((e.info.id.clone(), e.info.state));
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<PushTransferInfo> {
        self.inner.lock().unwrap().get(id).map(|e| e.info.clone())
    }

    /// All transfers, newest first.
    pub fn list(&self) -> Vec<PushTransferInfo> {
        let mut v: Vec<_> = self
            .inner
            .lock()
            .unwrap()
            .values()
            .map(|e| e.info.clone())
            .collect();
        v.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms).then(a.id.cmp(&b.id)));
        v
    }

    /// Ask a transfer to stop. `true` if it exists and was not finished.
    pub fn cancel(&self, id: &str) -> bool {
        match self.inner.lock().unwrap().get(id) {
            Some(e) if !e.info.state.is_finished() => {
                let _ = e.cancel.send(true);
                true
            }
            _ => false,
        }
    }

    /// Cancel every unfinished transfer with `contact_id` in `direction`
    /// (`None` = both). Returns how many were signalled.
    pub fn cancel_contact(&self, contact_id: &str, direction: Option<Direction>) -> usize {
        let g = self.inner.lock().unwrap();
        let mut n = 0;
        for e in g.values() {
            if e.info.contact_id == contact_id
                && !e.info.state.is_finished()
                && direction.is_none_or(|d| d == e.info.direction)
            {
                let _ = e.cancel.send(true);
                n += 1;
            }
        }
        n
    }
}

/// Throughput smoother used by the transfer loops.
pub struct RateMeter {
    last: std::time::Instant,
    last_bytes: u64,
    ewma: f64,
}

impl RateMeter {
    pub fn new(start_bytes: u64) -> Self {
        Self {
            last: std::time::Instant::now(),
            last_bytes: start_bytes,
            ewma: 0.0,
        }
    }

    /// Feed the current byte count; returns the rate when a new sample was taken.
    pub fn sample(&mut self, bytes: u64) -> Option<u64> {
        let dt = self.last.elapsed().as_secs_f64();
        if dt < 0.5 {
            return None;
        }
        let inst = bytes.saturating_sub(self.last_bytes) as f64 / dt;
        self.ewma = if self.ewma == 0.0 {
            inst
        } else {
            0.6 * self.ewma + 0.4 * inst
        };
        self.last = std::time::Instant::now();
        self.last_bytes = bytes;
        Some(self.ewma as u64)
    }
}

/// Persisted history: one encrypted record per entry (see `state_crypto`),
/// capped. Reads stream the file and keep only what they return; nothing
/// loads the whole history.
pub struct History {
    path: PathBuf,
    /// `None` when the state key is unavailable (nothing is read or written).
    keys: Option<StateKeys>,
    /// The append handle, opened on first use and dropped when the file is
    /// replaced.
    writer: Mutex<Option<LogWriter>>,
}

impl History {
    pub fn open(data_dir: &Path) -> Self {
        let keys = match StateKeys::open_or_init(data_dir) {
            Ok(k) => Some(k),
            Err(e) => {
                warn!("the transfer history stays closed: {e}");
                None
            }
        };
        let h = Self {
            path: data_dir.join(HISTORY_FILE),
            keys,
            writer: Mutex::new(None),
        };
        let total = h.prepare();
        h.trim_if_needed(total);
        h
    }

    /// Convert an old plaintext history, set aside one that cannot be opened
    /// (wrong key or damage) so a fresh one can start, and return how many
    /// entries the file holds. One streaming pass.
    fn prepare(&self) -> usize {
        let Some(keys) = &self.keys else { return 0 };
        if let Err(e) = state_crypto::migrate::migrate_log(keys, Label::PushHistory, &self.path) {
            warn!("could not convert the transfer history to the protected format: {e}");
            return 0;
        }
        let mut entries = 0usize;
        let damaged = match LogReader::open(keys, Label::PushHistory, &self.path) {
            Ok(Some(mut r)) => loop {
                match r.next_record() {
                    Ok(Some(rec)) => {
                        if serde_json::from_slice::<HistoryEntry>(&rec).is_ok() {
                            entries += 1;
                        }
                    }
                    Ok(None) => break false,
                    Err(_) => break true,
                }
            },
            Ok(None) => false,
            Err(_) => true,
        };
        if damaged {
            match state_crypto::set_aside(&self.path) {
                Ok(p) => warn!("the transfer history cannot be opened; it was moved to {p:?}"),
                Err(e) => warn!("the transfer history cannot be opened: {e}"),
            }
            return 0;
        }
        entries
    }

    /// Stream the entries, oldest first, to `f`. A damaged tail ends the walk.
    fn for_each(&self, mut f: impl FnMut(HistoryEntry, &[u8])) {
        let Some(keys) = &self.keys else { return };
        let Ok(Some(mut r)) = LogReader::open(keys, Label::PushHistory, &self.path) else {
            return;
        };
        while let Ok(Some(rec)) = r.next_record() {
            if let Ok(e) = serde_json::from_slice::<HistoryEntry>(&rec) {
                f(e, &rec);
            }
        }
    }

    fn trim_if_needed(&self, total: usize) {
        let Some(keys) = &self.keys else { return };
        let mut guard = self.writer.lock().unwrap();
        *guard = None;
        if total <= HISTORY_TRIM_AT {
            return;
        }
        // Keep the newest HISTORY_KEEP entries: skip the older ones while
        // streaming into the replacement.
        let skip = total - HISTORY_KEEP;
        let tmp =
            crate::paths::PUSH_HISTORY_TMP.in_dir(self.path.parent().unwrap_or(Path::new("")));
        let Ok(mut out) = LogRewrite::begin(keys, Label::PushHistory, &self.path, &tmp) else {
            return;
        };
        let mut seen = 0usize;
        let mut ok = true;
        self.for_each(|_, raw| {
            if ok && seen >= skip && out.append(raw).is_err() {
                ok = false;
            }
            seen += 1;
        });
        if ok {
            let _ = out.commit();
        }
    }

    pub fn append(&self, e: &HistoryEntry) {
        let Some(keys) = &self.keys else { return };
        let Ok(line) = serde_json::to_vec(e) else {
            return;
        };
        let mut guard = self.writer.lock().unwrap();
        if guard.is_none() {
            match LogWriter::open_append(keys, Label::PushHistory, &self.path) {
                Ok(w) => *guard = Some(w),
                Err(err) => {
                    warn!("cannot append to the transfer history: {err}");
                    return;
                }
            }
        }
        if let Some(w) = guard.as_mut() {
            if w.append(&line).is_err() {
                *guard = None;
            }
        }
    }

    /// Newest first, at most `limit` (and never more than the cap).
    pub fn list(&self, limit: usize) -> Vec<HistoryEntry> {
        let _g = self.writer.lock().unwrap();
        let cap = limit.min(HISTORY_KEEP);
        if cap == 0 {
            return Vec::new();
        }
        let mut newest: VecDeque<HistoryEntry> = VecDeque::with_capacity(cap.min(64));
        self.for_each(|e, _| {
            if newest.len() == cap {
                newest.pop_front();
            }
            newest.push_back(e);
        });
        newest.into_iter().rev().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: usize) -> HistoryEntry {
        HistoryEntry {
            id: format!("{i:04}"),
            direction: Direction::In,
            contact_id: "c".into(),
            contact_label: "L".into(),
            name: "n".into(),
            size: 1,
            state: PushState::Done,
            error: None,
            reject_reason: None,
            error_kind: None,
            source_path: None,
            saved_as: None,
            finished_at_ms: i as u64,
        }
    }

    #[test]
    fn history_is_capped_and_survives_garbage_lines() {
        let dir = tempfile::tempdir().unwrap();
        {
            let h = History::open(dir.path());
            for i in 0..2100 {
                h.append(&entry(i));
            }
            // The process died while writing the last record.
            let p = dir.path().join(HISTORY_FILE);
            let len = std::fs::metadata(&p).unwrap().len();
            std::fs::OpenOptions::new()
                .write(true)
                .open(&p)
                .unwrap()
                .set_len(len - 5)
                .unwrap();
        }
        let h = History::open(dir.path());
        let l = h.list(5);
        assert_eq!(l.len(), 5);
        assert_eq!(l[0].id, "2098");
        let total = h.list(100_000).len();
        assert!(total <= HISTORY_KEEP, "{total}");
    }

    #[test]
    fn board_cancel_and_trim() {
        let b = Board::new();
        let (id, rx) = b.create(Direction::Out, "c1", "L", "f", 10, PushState::Queued);
        assert!(!*rx.borrow());
        assert_eq!(b.cancel_contact("c2", None), 0);
        assert_eq!(b.cancel_contact("c1", Some(Direction::In)), 0);
        assert_eq!(b.cancel_contact("c1", Some(Direction::Out)), 1);
        assert!(*rx.borrow());
        b.update(&id, |i| i.state = PushState::Cancelled);
        assert!(!b.cancel(&id));
        for _ in 0..300 {
            let (id, _rx) = b.create(Direction::In, "c", "L", "f", 1, PushState::Queued);
            b.update(&id, |i| i.state = PushState::Done);
        }
        assert!(b.list().len() <= FINISHED_KEEP + 2);
    }
}
