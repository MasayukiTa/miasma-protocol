//! RAM-only receive for mobile front ends.
//!
//! The file APIs (`retrieve_to_file`) write the verified object to a path. This
//! surface instead hands verified plaintext, a chunk at a time, to a
//! [`PlaintextSink`] the app implements, and never creates a file or a journal.
//!
//! Lifecycle, all synchronous at the FFI boundary (call `receive_stream` from a
//! background thread or dispatcher, and `cancel_receive` / `receive_progress`
//! from any other):
//!
//! 1. `start_receive_session` returns a session id for a share ID or MID.
//! 2. `receive_stream(session, sink)` blocks until the object is complete, the
//!    session was cancelled, the sink stopped it, or it failed.
//! 3. `release_receive_session` forgets the session (its final progress stays
//!    readable until then).
//!
//! What crosses the boundary, exactly:
//!
//! * Wiped by the Rust side: the segment buffer inside the core engine (it is
//!   zeroized when the segment is done, and when a wipe or a cancel drops the
//!   receive).
//! * Not wiped by the Rust side: the chunk copy made for each `on_chunk` call
//!   (`chunk.to_vec()` in `ForeignSink::accept`). The callback takes the
//!   `Vec<u8>` by value, so the generated binding consumes it while lowering it
//!   into a buffer for the foreign side; this crate has no handle left to
//!   overwrite it with, and what the binding allocates in between is outside
//!   this crate's control. Those copies are freed without being zeroized.
//! * Owned by the app: the array it receives. The app must clear it once it
//!   has used it.
//!
//! So this surface keeps plaintext off the disk and wipes the engine's own
//! buffers; it does not promise that no copy of the plaintext lingers in freed
//! memory of this process or of the app. Error values carry fixed text only,
//! never data from the object.

use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use miasma_core::{
    transfer::{
        host_for, parse_transfer_id, SegmentSink, SinkError, StreamOutcome, TransferId,
        TransferProgress, TransferState,
    },
    MiasmaError,
};
use zeroize::Zeroizing;

use super::{shared_runtime, validate_data_dir, MiasmaFfiError};

/// Largest piece of plaintext handed to the app in one callback. A segment (up
/// to 64 MiB) is delivered as several chunks so no single foreign copy is huge.
const FFI_CHUNK: usize = 256 * 1024;

/// Sessions that may exist at once (started, running or finished but not yet
/// released).
const MAX_SESSIONS: usize = 8;

/// A point-in-time view of a receive, for a progress bar.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ReceiveProgressFfi {
    /// `running`, `complete`, `failed`, `cancelled` or `paused`.
    pub state: String,
    /// `preparing`, `transferring`, `finalizing` or `done`.
    pub phase: String,
    pub segments_done: u32,
    pub segments_total: u32,
    pub bytes_done: u64,
    /// `0` when unknown.
    pub bytes_total: u64,
    pub rate_bps: f64,
    /// Pieces refused because they did not match the manifest.
    pub pieces_rejected: u64,
}

/// How a receive ended without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum StreamEndFfi {
    /// Everything arrived and the whole-object check passed.
    Complete,
    /// `cancel_receive` stopped it.
    Cancelled,
    /// The sink returned `false` from `on_chunk`.
    SinkStopped,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StreamReceiveResultFfi {
    pub end: StreamEndFfi,
    /// Whole segments handed to the sink before the end.
    pub segments_delivered: u32,
    pub bytes_delivered: u64,
}

/// Where the app receives plaintext. Implemented in Kotlin or Swift.
///
/// Exactly one of `on_complete` and `on_abort` is called once the stream ends.
/// Only `on_complete` means the object verified; on `on_abort` the app must
/// discard whatever it kept from earlier chunks.
#[uniffi::export(with_foreign)]
pub trait PlaintextSink: Send + Sync {
    /// The next chunk of plaintext, in order within `segment`. Return `false` to
    /// stop the receive. Called on the thread that is running `receive_stream`;
    /// the next chunk is not fetched until this returns (back-pressure).
    fn on_chunk(&self, segment: u32, data: Vec<u8>) -> bool;
    /// Called after every whole segment.
    fn on_progress(&self, progress: ReceiveProgressFfi);
    fn on_complete(&self, total_bytes: u64);
    fn on_abort(&self);
}

struct Session {
    data_dir: PathBuf,
    target: TransferId,
    password: Option<Zeroizing<String>>,
    progress: Arc<TransferProgress>,
    started: bool,
}

impl Session {
    /// Overwrite the password in place and drop it. Called on every way a
    /// session ends (release, wipe, node stop), so a password that was never
    /// handed to a receive does not outlive the session.
    fn scrub(&mut self) {
        if let Some(password) = self.password.as_mut() {
            zeroize::Zeroize::zeroize(&mut **password);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.scrub();
        #[cfg(test)]
        SESSIONS_DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}

/// Sessions dropped so far (tests only).
#[cfg(test)]
static SESSIONS_DROPPED: AtomicU64 = AtomicU64::new(0);

static SESSIONS: Mutex<Option<HashMap<u64, Session>>> = Mutex::new(None);
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// End every receive session of the node that uses `data_dir`: running ones are
/// cancelled, and each session's password is overwritten and dropped. Called
/// when that node is wiped or stopped. Returns how many sessions were ended.
pub(crate) fn clear_sessions_for(data_dir: &std::path::Path) -> usize {
    let ended: Vec<Session> = with_sessions(|sessions| {
        let ids: Vec<u64> = sessions
            .iter()
            .filter(|(_, s)| s.data_dir == data_dir)
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter()
            .filter_map(|id| sessions.remove(&id))
            .collect()
    });
    // Cancel and scrub outside the table lock.
    let count = ended.len();
    for session in ended {
        session.progress.cancel();
        drop(session);
    }
    count
}

fn with_sessions<R>(f: impl FnOnce(&mut HashMap<u64, Session>) -> R) -> R {
    let mut guard = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

fn progress_to_ffi(p: &TransferProgress) -> ReceiveProgressFfi {
    let s = p.snapshot();
    ReceiveProgressFfi {
        state: match s.state {
            TransferState::Running => "running",
            TransferState::Paused => "paused",
            TransferState::Complete => "complete",
            TransferState::Failed => "failed",
            TransferState::Cancelled => "cancelled",
        }
        .into(),
        phase: format!("{:?}", s.phase).to_lowercase(),
        segments_done: s.segments_done,
        segments_total: s.segments_total,
        bytes_done: s.bytes_done,
        bytes_total: s.bytes_total,
        rate_bps: s.rate_bps,
        pieces_rejected: s.pieces_rejected,
    }
}

/// Map a core error to one with fixed text. Nothing from the object, a path or
/// a peer is copied into the message.
fn stream_error(e: MiasmaError) -> MiasmaFfiError {
    match e {
        MiasmaError::PasswordRequired => MiasmaFfiError::Other {
            msg: "a password is required".into(),
        },
        MiasmaError::HashMismatch => MiasmaFfiError::Other {
            msg: "the received data did not match its identifier".into(),
        },
        other => {
            let mapped = MiasmaFfiError::from(other);
            match mapped {
                MiasmaFfiError::Other { .. } => MiasmaFfiError::Other {
                    msg: "receive failed".into(),
                },
                kept => kept,
            }
        }
    }
}

/// Forwards core segments to the app, in chunks, and reports progress.
struct ForeignSink {
    inner: Arc<dyn PlaintextSink>,
    progress: Arc<TransferProgress>,
    /// Bytes handed over before the current segment.
    delivered: u64,
}

#[async_trait]
impl SegmentSink for ForeignSink {
    async fn accept(&mut self, index: u32, data: &[u8]) -> Result<(), SinkError> {
        for chunk in data.chunks(FFI_CHUNK) {
            let owned = chunk.to_vec();
            let keep_going =
                std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.on_chunk(index, owned)))
                    .map_err(|_| SinkError::Failed)?;
            if !keep_going {
                return Err(SinkError::Closed);
            }
            if self.progress.is_cancelled() {
                return Err(SinkError::Closed);
            }
        }
        // The engine counts a segment once the sink has returned for it, which is
        // right after this call; report it as done here.
        let mut snapshot = progress_to_ffi(&self.progress);
        snapshot.segments_done = index + 1;
        snapshot.bytes_done = self.delivered + data.len() as u64;
        self.delivered = snapshot.bytes_done;
        std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.on_progress(snapshot)))
            .map_err(|_| SinkError::Failed)?;
        Ok(())
    }

    fn complete(&mut self, total_bytes: u64) {
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.on_complete(total_bytes)));
    }

    fn abort(&mut self) {
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.on_abort()));
    }
}

/// Create a receive session for a share ID (`miasma-share:...`) or a MID
/// (`miasma:...`). Nothing is fetched yet.
///
/// `password` is only for password-protected transfers. The node must have been
/// started (`start_embedded_daemon`).
#[uniffi::export]
pub fn start_receive_session(
    data_dir: String,
    id: String,
    password: Option<String>,
) -> Result<u64, MiasmaFfiError> {
    let data_path = validate_data_dir(&data_dir)?;
    open_session(data_path, &id, password)
}

pub(crate) fn open_session(
    data_path: PathBuf,
    id: &str,
    password: Option<String>,
) -> Result<u64, MiasmaFfiError> {
    let target = parse_transfer_id(id).map_err(|_| MiasmaFfiError::InvalidMid {
        reason: "invalid format".into(),
    })?;
    // The FFI string is already in memory; at least keep our copy wiped.
    let password = password.map(Zeroizing::new);
    if host_for(&data_path).is_none() {
        return Err(MiasmaFfiError::Other {
            msg: "the node is not running".into(),
        });
    }
    let progress = TransferProgress::new(target.mid().to_string());
    let session = Session {
        data_dir: data_path,
        target,
        password,
        progress,
        started: false,
    };
    with_sessions(|sessions| insert_session(sessions, session))
}

/// Add a session unless the table is full.
fn insert_session(
    sessions: &mut HashMap<u64, Session>,
    session: Session,
) -> Result<u64, MiasmaFfiError> {
    if sessions.len() >= MAX_SESSIONS {
        return Err(MiasmaFfiError::Other {
            msg: "too many receive sessions".into(),
        });
    }
    let session_id = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
    sessions.insert(session_id, session);
    Ok(session_id)
}

/// Run the session: fetch, verify and deliver the object to `sink`, blocking
/// until it ends. No file is written. A session runs once.
#[uniffi::export]
pub fn receive_stream(
    session_id: u64,
    sink: Arc<dyn PlaintextSink>,
) -> Result<StreamReceiveResultFfi, MiasmaFfiError> {
    let (data_dir, target, password, progress) = with_sessions(|sessions| {
        let s = sessions
            .get_mut(&session_id)
            .ok_or_else(|| MiasmaFfiError::Other {
                msg: "unknown receive session".into(),
            })?;
        if s.started {
            return Err(MiasmaFfiError::Other {
                msg: "this receive session was already used".into(),
            });
        }
        s.started = true;
        Ok((
            s.data_dir.clone(),
            s.target.clone(),
            s.password.take(),
            s.progress.clone(),
        ))
    })?;
    let host = host_for(&data_dir).ok_or_else(|| MiasmaFfiError::Other {
        msg: "the node is not running".into(),
    })?;
    let mut adapter = ForeignSink {
        inner: sink,
        progress: progress.clone(),
        delivered: 0,
    };
    let outcome = shared_runtime()
        .block_on(host.receive_stream_id(&target, password, &mut adapter, progress))
        .map_err(stream_error)?;
    Ok(match outcome {
        StreamOutcome::Complete { segments, bytes } => StreamReceiveResultFfi {
            end: StreamEndFfi::Complete,
            segments_delivered: segments,
            bytes_delivered: bytes,
        },
        StreamOutcome::Cancelled {
            segments_delivered,
            bytes_delivered,
        } => StreamReceiveResultFfi {
            end: StreamEndFfi::Cancelled,
            segments_delivered,
            bytes_delivered,
        },
        StreamOutcome::SinkClosed {
            segments_delivered,
            bytes_delivered,
        } => StreamReceiveResultFfi {
            end: StreamEndFfi::SinkStopped,
            segments_delivered,
            bytes_delivered,
        },
    })
}

/// Ask a session to stop at the next safe point. Returns whether the session
/// exists. Safe to call from any thread, before or during `receive_stream`.
#[uniffi::export]
pub fn cancel_receive(session_id: u64) -> bool {
    with_sessions(|sessions| match sessions.get(&session_id) {
        Some(s) => {
            s.progress.cancel();
            true
        }
        None => false,
    })
}

/// Current progress of a session, or `None` for an unknown one.
#[uniffi::export]
pub fn receive_progress(session_id: u64) -> Option<ReceiveProgressFfi> {
    with_sessions(|sessions| {
        sessions
            .get(&session_id)
            .map(|s| progress_to_ffi(&s.progress))
    })
}

/// Forget a session. If it is still running it is cancelled first.
#[uniffi::export]
pub fn release_receive_session(session_id: u64) {
    with_sessions(|sessions| {
        if let Some(s) = sessions.remove(&session_id) {
            s.progress.cancel();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::{
        dissolution::segment::dissolve_segment_with,
        network::types::{DhtRecord, ShardLocation},
        transfer::{
            receive_stream as core_receive_stream, register_host, unregister_host, PieceSource,
            Protection, SegmentEntry, StreamHost, StreamSpec, TransferManifest,
        },
        ContentId, DissolutionParams, MiasmaShare,
    };
    use std::collections::HashMap as Map;
    use std::sync::atomic::AtomicBool;

    const SEG: usize = 1024;
    const MARK: &[u8] = b"PLAINTEXT-MARKER-0123456789";

    struct World {
        mid: ContentId,
        record: DhtRecord,
        manifest: TransferManifest,
        shares: Map<(u32, u16), MiasmaShare>,
        data: Vec<u8>,
    }

    fn world(segments: usize) -> World {
        let mut data = Vec::new();
        for i in 0..segments * SEG {
            data.push(MARK[i % MARK.len()] ^ (i / MARK.len()) as u8);
        }
        let params = DissolutionParams {
            data_shards: 4,
            total_shards: 6,
        };
        let mid = ContentId::compute(&data, &params.to_param_bytes());
        let mut manifest = TransferManifest::new(
            &mid,
            [0x42; 32],
            params,
            SEG as u32,
            data.len() as u64,
            Protection::None,
        );
        let mut shares = Map::new();
        let mut locations = Vec::new();
        for (i, chunk) in data.chunks(SEG).enumerate() {
            let (_, seg_shares) =
                dissolve_segment_with(chunk, &mid, i as u32, 0, params, None).unwrap();
            manifest
                .push_segment(
                    SegmentEntry::from_dissolved(i as u32, &mid, chunk, &seg_shares).unwrap(),
                )
                .unwrap();
            for s in seg_shares {
                locations.push(ShardLocation {
                    peer_id_bytes: vec![s.slot_index as u8],
                    shard_index: s.slot_index,
                    segment_index: i as u32,
                    addrs: vec![],
                });
                shares.insert((i as u32, s.slot_index), s);
            }
        }
        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: 4,
            total_shards: 6,
            version: 1,
            locations,
            published_at: 1,
        };
        World {
            mid,
            record,
            manifest,
            shares,
            data,
        }
    }

    struct MemSource(Map<(u32, u16), MiasmaShare>);

    #[async_trait]
    impl PieceSource for MemSource {
        async fn fetch_piece(
            &self,
            _mid: &ContentId,
            segment: u32,
            slot: u16,
            _holder: &ShardLocation,
        ) -> Result<Option<MiasmaShare>, MiasmaError> {
            Ok(self.0.get(&(segment, slot)).cloned())
        }
    }

    struct MemHost {
        mid: ContentId,
        record: DhtRecord,
        manifest: TransferManifest,
        shares: Map<(u32, u16), MiasmaShare>,
    }

    #[async_trait]
    impl StreamHost for MemHost {
        async fn receive_stream_id(
            &self,
            target: &TransferId,
            _password: Option<Zeroizing<String>>,
            sink: &mut dyn SegmentSink,
            progress: Arc<TransferProgress>,
        ) -> Result<StreamOutcome, MiasmaError> {
            assert_eq!(target.mid(), self.mid);
            let spec = StreamSpec::new(
                self.mid.clone(),
                self.record.clone(),
                Some(self.manifest.clone()),
            );
            core_receive_stream(&MemSource(self.shares.clone()), spec, sink, progress).await
        }
    }

    #[derive(Default)]
    struct Collect {
        bytes: Mutex<Vec<u8>>,
        progress: Mutex<Vec<ReceiveProgressFfi>>,
        completed: Mutex<Option<u64>>,
        aborted: AtomicBool,
        stop_after_chunks: Mutex<Option<usize>>,
        chunks: AtomicU64,
    }

    impl PlaintextSink for Collect {
        fn on_chunk(&self, _segment: u32, data: Vec<u8>) -> bool {
            self.bytes.lock().unwrap().extend_from_slice(&data);
            let n = self.chunks.fetch_add(1, Ordering::SeqCst) + 1;
            match *self.stop_after_chunks.lock().unwrap() {
                Some(limit) => (n as usize) < limit,
                None => true,
            }
        }
        fn on_progress(&self, progress: ReceiveProgressFfi) {
            self.progress.lock().unwrap().push(progress);
        }
        fn on_complete(&self, total_bytes: u64) {
            *self.completed.lock().unwrap() = Some(total_bytes);
        }
        fn on_abort(&self) {
            self.aborted.store(true, Ordering::SeqCst);
        }
    }

    fn install(w: &World, name: &str) -> PathBuf {
        let dir = PathBuf::from(format!("/stream-ffi-test/{name}"));
        register_host(
            &dir,
            Arc::new(MemHost {
                mid: w.mid.clone(),
                record: w.record.clone(),
                manifest: w.manifest.clone(),
                shares: w.shares.clone(),
            }),
        );
        dir
    }

    #[test]
    fn a_session_streams_the_object_to_the_app_and_reports_progress() {
        let w = world(5);
        let dir = install(&w, "ok");
        let id = open_session(dir.clone(), &w.mid.to_string(), None).unwrap();
        let sink = Arc::new(Collect::default());
        let result = receive_stream(id, sink.clone()).unwrap();

        assert_eq!(result.end, StreamEndFfi::Complete);
        assert_eq!(result.segments_delivered, 5);
        assert_eq!(result.bytes_delivered, w.data.len() as u64);
        assert_eq!(*sink.bytes.lock().unwrap(), w.data);
        assert_eq!(*sink.completed.lock().unwrap(), Some(w.data.len() as u64));
        assert!(!sink.aborted.load(Ordering::SeqCst));
        let seen = sink.progress.lock().unwrap();
        assert_eq!(seen.len(), 5, "one progress callback per segment");
        assert_eq!(seen.last().unwrap().segments_done, 5);
        assert_eq!(seen.last().unwrap().segments_total, 5);
        drop(seen);
        let fin = receive_progress(id).unwrap();
        assert_eq!(
            (fin.state.as_str(), fin.phase.as_str()),
            ("complete", "done")
        );

        // A session runs once.
        assert!(receive_stream(id, sink).is_err());
        release_receive_session(id);
        assert!(receive_progress(id).is_none());
        unregister_host(&dir);
    }

    #[test]
    fn cancelling_before_the_start_ends_with_cancelled_and_aborts_the_sink() {
        let w = world(3);
        let dir = install(&w, "cancel");
        let id = open_session(dir.clone(), &w.mid.to_string(), None).unwrap();
        assert!(cancel_receive(id));
        let sink = Arc::new(Collect::default());
        let result = receive_stream(id, sink.clone()).unwrap();
        assert_eq!(result.end, StreamEndFfi::Cancelled);
        assert_eq!(result.segments_delivered, 0);
        assert!(sink.aborted.load(Ordering::SeqCst));
        assert!(sink.completed.lock().unwrap().is_none());
        assert!(!cancel_receive(u64::MAX), "an unknown session is reported");
        release_receive_session(id);
        unregister_host(&dir);
    }

    #[test]
    fn the_app_can_stop_the_stream_by_returning_false() {
        let w = world(4);
        let dir = install(&w, "stop");
        let id = open_session(dir.clone(), &w.mid.to_string(), None).unwrap();
        let sink = Arc::new(Collect::default());
        *sink.stop_after_chunks.lock().unwrap() = Some(2);
        let result = receive_stream(id, sink.clone()).unwrap();
        assert_eq!(result.end, StreamEndFfi::SinkStopped);
        assert_eq!(sink.chunks.load(Ordering::SeqCst), 2);
        assert!(sink.aborted.load(Ordering::SeqCst));
        release_receive_session(id);
        unregister_host(&dir);
    }

    #[test]
    fn bad_input_and_a_missing_node_are_refused_with_fixed_messages() {
        let w = world(1);
        let none = PathBuf::from("/stream-ffi-test/no-host");
        let err = open_session(none, &w.mid.to_string(), None).unwrap_err();
        assert!(
            matches!(err, MiasmaFfiError::Other { ref msg } if msg == "the node is not running")
        );

        let dir = install(&w, "bad");
        let err = open_session(dir.clone(), "not-an-identifier", None).unwrap_err();
        assert!(matches!(err, MiasmaFfiError::InvalidMid { .. }));
        unregister_host(&dir);
    }

    #[test]
    fn errors_never_carry_data_from_the_object() {
        let leaky = MiasmaError::Decryption("the plaintext was PLAINTEXT-MARKER".into());
        let shown = format!("{}", stream_error(leaky));
        assert!(!shown.contains("MARKER"), "{shown}");
        let leaky = MiasmaError::Storage("/data/user/0/app/files/secret-name.txt".into());
        match stream_error(leaky) {
            MiasmaFfiError::Other { msg } => assert_eq!(msg, "receive failed"),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn session_with_password(dir: &str, w: &World, password: &str) -> Session {
        Session {
            data_dir: PathBuf::from(dir),
            target: parse_transfer_id(&w.mid.to_string()).unwrap(),
            password: Some(Zeroizing::new(password.to_string())),
            progress: TransferProgress::new(w.mid.to_string()),
            started: false,
        }
    }

    #[test]
    fn scrubbing_a_session_overwrites_the_password_in_place() {
        let w = world(1);
        let mut s = session_with_password("/stream-ffi-test/scrub", &w, "pw-SECRET-0123456789");
        let (ptr, cap) = {
            let p = s.password.as_ref().unwrap();
            (p.as_ptr(), p.capacity())
        };
        assert!(cap >= "pw-SECRET-0123456789".len());
        s.scrub();
        // The buffer is still owned by `s`, so reading it here is sound.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, cap) };
        assert!(
            bytes.iter().all(|b| *b == 0),
            "the password bytes must be zero after a scrub"
        );
    }

    #[test]
    fn releasing_a_session_scrubs_and_drops_it() {
        let w = world(1);
        let dir = install(&w, "release-scrub");
        let before = SESSIONS_DROPPED.load(Ordering::SeqCst);
        let id = open_session(dir.clone(), &w.mid.to_string(), Some("pw-1-secret".into())).unwrap();
        release_receive_session(id);
        assert!(receive_progress(id).is_none());
        assert!(SESSIONS_DROPPED.load(Ordering::SeqCst) > before);
        unregister_host(&dir);
    }

    #[test]
    fn a_wipe_ends_every_session_of_that_node_and_only_that_node() {
        let w = world(1);
        let wiped = install(&w, "wipe-a");
        let other = install(&w, "wipe-b");
        let a1 = open_session(wiped.clone(), &w.mid.to_string(), Some("pw-1-a1".into())).unwrap();
        let a2 = open_session(wiped.clone(), &w.mid.to_string(), None).unwrap();
        let b1 = open_session(other.clone(), &w.mid.to_string(), Some("pw-1-b1".into())).unwrap();
        let progress_of = |id: u64| {
            with_sessions(|s| s.get(&id).map(|x| x.progress.clone())).expect("session present")
        };
        let (pa1, pa2, pb1) = (progress_of(a1), progress_of(a2), progress_of(b1));
        let before = SESSIONS_DROPPED.load(Ordering::SeqCst);

        assert_eq!(clear_sessions_for(&wiped), 2);

        // Wipe, then inspect: nothing of the wiped node's sessions is left.
        assert!(receive_progress(a1).is_none() && receive_progress(a2).is_none());
        assert!(!with_sessions(|s| s.values().any(|x| x.data_dir == wiped)));
        assert!(pa1.is_cancelled() && pa2.is_cancelled());
        assert!(SESSIONS_DROPPED.load(Ordering::SeqCst) >= before + 2);
        let sink = Arc::new(Collect::default());
        assert!(
            receive_stream(a1, sink).is_err(),
            "a wiped session cannot run"
        );
        // Another node's session is untouched.
        assert!(receive_progress(b1).is_some());
        assert!(!pb1.is_cancelled());
        assert_eq!(clear_sessions_for(&wiped), 0, "clearing is repeatable");

        release_receive_session(b1);
        unregister_host(&wiped);
        unregister_host(&other);
    }

    #[cfg(unix)]
    #[test]
    fn distress_wipe_ends_the_receive_sessions_of_its_data_dir() {
        let w = world(1);
        let dir = PathBuf::from(format!("/tmp/stream-ffi-wipe-{}", std::process::id()));
        register_host(
            &dir,
            Arc::new(MemHost {
                mid: w.mid.clone(),
                record: w.record.clone(),
                manifest: w.manifest.clone(),
                shares: w.shares.clone(),
            }),
        );
        let id = open_session(dir.clone(), &w.mid.to_string(), Some("pw-1-wipe".into())).unwrap();
        let progress = with_sessions(|s| s.get(&id).map(|x| x.progress.clone())).unwrap();
        // The wipe result depends on what is on disk; the sessions go either way.
        let _ = crate::distress_wipe(dir.to_string_lossy().into_owned());
        assert!(receive_progress(id).is_none());
        assert!(progress.is_cancelled());
        unregister_host(&dir);
    }

    #[test]
    fn the_session_table_is_bounded() {
        let w = world(1);
        let mut table: HashMap<u64, Session> = HashMap::new();
        for _ in 0..MAX_SESSIONS {
            let s = Session {
                data_dir: PathBuf::from("/stream-ffi-test/cap"),
                target: parse_transfer_id(&w.mid.to_string()).unwrap(),
                password: None,
                progress: TransferProgress::new(w.mid.to_string()),
                started: false,
            };
            insert_session(&mut table, s).unwrap();
        }
        let extra = Session {
            data_dir: PathBuf::from("/stream-ffi-test/cap"),
            target: parse_transfer_id(&w.mid.to_string()).unwrap(),
            password: None,
            progress: TransferProgress::new(w.mid.to_string()),
            started: false,
        };
        assert!(insert_session(&mut table, extra).is_err());
        assert_eq!(table.len(), MAX_SESSIONS);
    }
}
