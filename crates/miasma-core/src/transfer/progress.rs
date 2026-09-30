//! Live progress of one transfer, readable while it runs.
//!
//! The engine updates a [`TransferProgress`] as it goes; anything that wants to
//! show it (the CLI's progress line, the desktop UI, a status IPC call) takes a
//! [`TransferStatus`] snapshot. The per-phase timings (`fetch_ms`, `decode_ms`,
//! `write_ms`) are there so throughput can be *read off* a real run rather than
//! timed by hand, which is what the speed experiment needs.

use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Fetching the record and manifest, checking the password.
    Preparing,
    /// Sending only: reading the whole source file once to compute its MID.
    Hashing,
    /// Re-reading an existing partial file to confirm what it holds.
    Verifying,
    Transferring,
    /// Whole-file MID check and the final rename.
    Finalizing,
    Done,
}

/// Which way a transfer goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferKind {
    Receive,
    Send,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferState {
    Running,
    /// Stopped with the partial file and journal kept; running the same
    /// transfer again resumes it.
    Paused,
    Complete,
    Failed,
    Cancelled,
}

/// A point-in-time copy of a transfer's progress. Plain data; safe to serialize.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferStatus {
    /// The MID. For a send it is empty until the source file has been hashed.
    pub mid: String,
    pub kind: TransferKind,
    /// A receive's output path, or a send's source path.
    pub name: String,
    pub phase: Phase,
    pub state: TransferState,
    pub segments_done: u32,
    pub segments_total: u32,
    pub bytes_done: u64,
    /// `0` when unknown (a legacy record without a manifest).
    pub bytes_total: u64,
    /// Average over bytes moved *this session* (a resumed prefix is excluded),
    /// measured across the time spent in [`Phase::Transferring`].
    pub rate_bps: f64,
    pub eta_secs: Option<u64>,
    pub elapsed_secs: f64,
    /// Where the time went. Receive: fetching pieces / RS+decrypt / writing the
    /// file. Send: pushing to peers / encrypting+RS+SSS / storing locally.
    pub fetch_ms: u64,
    pub decode_ms: u64,
    pub write_ms: u64,
    pub pieces_fetched: u64,
    /// Pieces refused because they did not match the manifest (or were
    /// self-inconsistent).
    pub pieces_rejected: u64,
    pub segment_retries: u64,
    /// First segment this session had to fetch (`0` for a fresh transfer).
    pub resumed_from_segment: u32,
    pub last_error: Option<String>,
    /// Whether running the same transfer again would pick up where it stopped.
    pub resumable: bool,
    /// The share ID (`miasma-share:...`): for a send, the thing to give the
    /// receiver once the file is published; for a receive, the one that was
    /// typed. `None` while unknown, and for a receive started from a bare MID.
    #[serde(default)]
    pub share_id: Option<String>,
    /// The receiver supplied a share ID whose checksum verified.
    #[serde(default)]
    pub share_id_checked: bool,
    /// The record and manifest were verified to come from the publisher named in
    /// the share ID. Always `false` for a receive started from a bare MID: that
    /// path cannot tell who published.
    #[serde(default)]
    pub publisher_authenticated: bool,
    /// How the data is moving when it comes over the iroh direct transport:
    /// `"direct"` (a hole-punched or LAN connection) or `"relay"` (through a
    /// relay server, which is much slower on a public relay). `None` for every
    /// other source and before a connection exists.
    #[serde(default)]
    pub path: Option<String>,
}

struct Inner {
    mid: String,
    name: String,
    share_id: Option<String>,
    share_id_checked: bool,
    publisher_authenticated: bool,
    path: Option<String>,
    phase: Phase,
    state: TransferState,
    last_error: Option<String>,
    resumable: bool,
    /// When the Transferring phase began, for the rate.
    transferring_since: Option<Instant>,
}

/// Shared, thread-safe progress cell. Cheap to update from the engine.
pub struct TransferProgress {
    kind: TransferKind,
    started: Instant,
    inner: Mutex<Inner>,
    segments_done: AtomicU32,
    segments_total: AtomicU32,
    bytes_done: AtomicU64,
    bytes_total: AtomicU64,
    /// Bytes moved this session (excludes a resumed, already-verified prefix).
    session_bytes: AtomicU64,
    fetch_ns: AtomicU64,
    decode_ns: AtomicU64,
    write_ns: AtomicU64,
    pieces_fetched: AtomicU64,
    pieces_rejected: AtomicU64,
    segment_retries: AtomicU64,
    resumed_from: AtomicU32,
    cancel: AtomicBool,
    /// Cancel by itself once this many segments are done (`0` = never).
    stop_after: AtomicU32,
}

impl TransferProgress {
    /// A receive of `mid`.
    pub fn new(mid: impl Into<String>) -> Arc<Self> {
        Self::build(TransferKind::Receive, mid.into(), String::new())
    }

    /// A send of the file at `source`. The MID is set once it is known.
    pub fn for_send(source: impl Into<String>) -> Arc<Self> {
        Self::build(TransferKind::Send, String::new(), source.into())
    }

    fn build(kind: TransferKind, mid: String, name: String) -> Arc<Self> {
        Arc::new(Self {
            kind,
            started: Instant::now(),
            inner: Mutex::new(Inner {
                mid,
                name,
                share_id: None,
                share_id_checked: false,
                publisher_authenticated: false,
                path: None,
                phase: Phase::Preparing,
                state: TransferState::Running,
                last_error: None,
                resumable: false,
                transferring_since: None,
            }),
            segments_done: AtomicU32::new(0),
            segments_total: AtomicU32::new(0),
            bytes_done: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            session_bytes: AtomicU64::new(0),
            fetch_ns: AtomicU64::new(0),
            decode_ns: AtomicU64::new(0),
            write_ns: AtomicU64::new(0),
            pieces_fetched: AtomicU64::new(0),
            pieces_rejected: AtomicU64::new(0),
            segment_retries: AtomicU64::new(0),
            resumed_from: AtomicU32::new(0),
            cancel: AtomicBool::new(false),
            stop_after: AtomicU32::new(0),
        })
    }

    pub fn set_mid(&self, mid: impl Into<String>) {
        self.inner.lock().unwrap().mid = mid.into();
    }

    pub fn set_name(&self, name: impl Into<String>) {
        self.inner.lock().unwrap().name = name.into();
    }

    /// The share ID this transfer is known by (see [`TransferStatus::share_id`]).
    pub fn set_share_id(&self, share_id: Option<String>) {
        self.inner.lock().unwrap().share_id = share_id;
    }

    /// The receiver typed a share ID and its checksum verified.
    pub fn set_share_id_checked(&self, checked: bool) {
        self.inner.lock().unwrap().share_id_checked = checked;
    }

    /// The fetched record was verified against the share ID's publisher.
    pub fn set_publisher_authenticated(&self, authenticated: bool) {
        self.inner.lock().unwrap().publisher_authenticated = authenticated;
    }

    /// The path an iroh transfer is using (`direct` / `relay`); `None` clears it.
    pub fn set_path(&self, path: Option<&str>) {
        self.inner.lock().unwrap().path = path.map(str::to_owned);
    }

    pub fn set_phase(&self, phase: Phase) {
        let mut g = self.inner.lock().unwrap();
        g.phase = phase;
        if phase == Phase::Transferring && g.transferring_since.is_none() {
            g.transferring_since = Some(Instant::now());
        }
    }

    pub fn set_state(&self, state: TransferState, error: Option<String>, resumable: bool) {
        let mut g = self.inner.lock().unwrap();
        g.state = state;
        g.resumable = resumable;
        if error.is_some() {
            g.last_error = error;
        }
        if matches!(state, TransferState::Complete) {
            g.phase = Phase::Done;
        }
    }

    pub fn note_error(&self, error: impl Into<String>) {
        self.inner.lock().unwrap().last_error = Some(error.into());
    }

    pub fn set_totals(&self, segments: u32, bytes: u64) {
        self.segments_total.store(segments, Ordering::Relaxed);
        self.bytes_total.store(bytes, Ordering::Relaxed);
    }

    /// Record the already-verified prefix a resume starts from.
    pub fn set_resumed(&self, segments_done: u32, bytes_done: u64) {
        self.segments_done.store(segments_done, Ordering::Relaxed);
        self.bytes_done.store(bytes_done, Ordering::Relaxed);
        self.resumed_from.store(segments_done, Ordering::Relaxed);
    }

    /// Bytes read while re-verifying an existing partial file.
    pub fn set_verified_bytes(&self, bytes: u64) {
        self.bytes_done.store(bytes, Ordering::Relaxed);
    }

    pub fn on_segment_done(
        &self,
        bytes: u64,
        fetch: std::time::Duration,
        decode: std::time::Duration,
        write: std::time::Duration,
    ) {
        let done = self.segments_done.fetch_add(1, Ordering::Relaxed) + 1;
        let limit = self.stop_after.load(Ordering::Relaxed);
        if limit > 0 && done >= limit {
            self.cancel();
        }
        self.bytes_done.fetch_add(bytes, Ordering::Relaxed);
        self.session_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.fetch_ns
            .fetch_add(fetch.as_nanos() as u64, Ordering::Relaxed);
        self.decode_ns
            .fetch_add(decode.as_nanos() as u64, Ordering::Relaxed);
        self.write_ns
            .fetch_add(write.as_nanos() as u64, Ordering::Relaxed);
    }

    pub fn piece_fetched(&self) {
        self.pieces_fetched.fetch_add(1, Ordering::Relaxed);
    }

    pub fn piece_rejected(&self) {
        self.pieces_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn segment_retry(&self) {
        self.segment_retries.fetch_add(1, Ordering::Relaxed);
    }

    /// Stop by itself, at the next safe point, once `segments` segments are done
    /// (counting any resumed prefix). Deterministic, unlike polling for progress
    /// and cancelling from outside, which can lose a race with a fast segment.
    pub fn stop_after_segments(&self, segments: u32) {
        self.stop_after.store(segments, Ordering::Relaxed);
    }

    /// Ask the engine to stop at the next safe point. The partial file and
    /// journal are kept.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> TransferStatus {
        let g = self.inner.lock().unwrap();
        let bytes_done = self.bytes_done.load(Ordering::Relaxed);
        let bytes_total = self.bytes_total.load(Ordering::Relaxed);
        let session_bytes = self.session_bytes.load(Ordering::Relaxed);

        let rate_bps = match g.transferring_since {
            Some(t0) => {
                let secs = t0.elapsed().as_secs_f64();
                if secs > 0.0 && session_bytes > 0 {
                    session_bytes as f64 / secs
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        let eta_secs = if rate_bps > 0.0 && bytes_total > bytes_done {
            Some(((bytes_total - bytes_done) as f64 / rate_bps).ceil() as u64)
        } else {
            None
        };

        TransferStatus {
            mid: g.mid.clone(),
            kind: self.kind,
            name: g.name.clone(),
            phase: g.phase,
            state: g.state,
            segments_done: self.segments_done.load(Ordering::Relaxed),
            segments_total: self.segments_total.load(Ordering::Relaxed),
            bytes_done,
            bytes_total,
            rate_bps,
            eta_secs,
            elapsed_secs: self.started.elapsed().as_secs_f64(),
            fetch_ms: self.fetch_ns.load(Ordering::Relaxed) / 1_000_000,
            decode_ms: self.decode_ns.load(Ordering::Relaxed) / 1_000_000,
            write_ms: self.write_ns.load(Ordering::Relaxed) / 1_000_000,
            pieces_fetched: self.pieces_fetched.load(Ordering::Relaxed),
            pieces_rejected: self.pieces_rejected.load(Ordering::Relaxed),
            segment_retries: self.segment_retries.load(Ordering::Relaxed),
            resumed_from_segment: self.resumed_from.load(Ordering::Relaxed),
            last_error: g.last_error.clone(),
            resumable: g.resumable,
            share_id: g.share_id.clone(),
            share_id_checked: g.share_id_checked,
            publisher_authenticated: g.publisher_authenticated,
            path: g.path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_fresh_transfer_reads_as_running_and_empty() {
        let p = TransferProgress::new("miasma:x");
        let s = p.snapshot();
        assert_eq!(s.state, TransferState::Running);
        assert_eq!(s.phase, Phase::Preparing);
        assert_eq!((s.segments_done, s.bytes_done), (0, 0));
        assert_eq!(s.rate_bps, 0.0);
        assert!(s.eta_secs.is_none());
        assert!(!s.resumable);
    }

    #[test]
    fn segments_accumulate_and_a_resumed_prefix_is_not_counted_as_session_rate() {
        let p = TransferProgress::new("miasma:x");
        p.set_totals(10, 1000);
        p.set_resumed(4, 400); // 4 segments already on disk and verified
        p.set_phase(Phase::Transferring);
        let d = Duration::from_millis(5);
        p.on_segment_done(100, d, d, d);
        p.on_segment_done(100, d, d, d);

        let s = p.snapshot();
        assert_eq!(s.segments_done, 6);
        assert_eq!(s.bytes_done, 600);
        assert_eq!(s.resumed_from_segment, 4);
        assert_eq!(s.fetch_ms, 10);
        assert_eq!(s.decode_ms, 10);
        assert_eq!(s.write_ms, 10);
        // Only the 200 bytes moved this session feed the rate, not the 400 resumed.
        std::thread::sleep(Duration::from_millis(20));
        let s = p.snapshot();
        assert!(s.rate_bps > 0.0);
        assert!(
            s.rate_bps < 200.0 / 0.01,
            "rate must not include the resumed prefix"
        );
        assert!(s.eta_secs.is_some());
    }

    #[test]
    fn stop_after_segments_cancels_exactly_when_that_many_are_done() {
        let p = TransferProgress::new("miasma:x");
        p.stop_after_segments(2);
        let d = Duration::ZERO;
        p.on_segment_done(10, d, d, d);
        assert!(!p.is_cancelled(), "one segment is not enough");
        p.on_segment_done(10, d, d, d);
        assert!(p.is_cancelled(), "two segments trip it");
    }

    #[test]
    fn stop_after_counts_a_resumed_prefix_and_zero_means_never() {
        let p = TransferProgress::new("miasma:x");
        p.set_resumed(3, 300);
        p.stop_after_segments(4);
        p.on_segment_done(100, Duration::ZERO, Duration::ZERO, Duration::ZERO);
        assert!(p.is_cancelled(), "3 resumed + 1 new = 4");

        let q = TransferProgress::new("miasma:y");
        for _ in 0..50 {
            q.on_segment_done(1, Duration::ZERO, Duration::ZERO, Duration::ZERO);
        }
        assert!(!q.is_cancelled(), "0 disables the hook");
    }

    #[test]
    fn cancel_is_observable() {
        let p = TransferProgress::new("miasma:x");
        assert!(!p.is_cancelled());
        p.cancel();
        assert!(p.is_cancelled());
    }

    #[test]
    fn completing_moves_the_phase_to_done() {
        let p = TransferProgress::new("miasma:x");
        p.set_state(TransferState::Complete, None, false);
        let s = p.snapshot();
        assert_eq!(s.state, TransferState::Complete);
        assert_eq!(s.phase, Phase::Done);
    }

    #[test]
    fn a_paused_transfer_reports_why_and_that_it_is_resumable() {
        let p = TransferProgress::new("miasma:x");
        p.set_state(
            TransferState::Paused,
            Some("no holder reachable".into()),
            true,
        );
        let s = p.snapshot();
        assert_eq!(s.state, TransferState::Paused);
        assert!(s.resumable);
        assert_eq!(s.last_error.as_deref(), Some("no holder reachable"));
    }

    #[test]
    fn status_round_trips_through_json() {
        let p = TransferProgress::new("miasma:x");
        p.set_totals(3, 300);
        let s = p.snapshot();
        let json = serde_json::to_string(&s).unwrap();
        let back: TransferStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}
