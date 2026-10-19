//! The RAM-only receive (`receive_stream`) against real dissolved transfers:
//! delivery and ordering, cancellation (including while a fetch or the sink is
//! stuck), back-pressure, early returns, and that nothing from the plaintext
//! reaches an error message. Every plaintext buffer the engine creates is
//! counted; each test that stops early also requires that every buffer was wiped
//! and none is left alive.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use miasma_core::{
    dissolution::segment::dissolve_segment_with,
    network::types::{DhtRecord, ShardLocation},
    transfer::{
        receive_stream, PasswordProtection, PieceSource, Protection, RetryConfig, SegmentEntry,
        SegmentSink, SinkError, StreamOutcome, StreamSpec, StreamStats, TransferManifest,
        TransferProgress, TransferState,
    },
    ContentId, DissolutionParams, MiasmaError, MiasmaShare,
};
use tokio::sync::Semaphore;

const SEG: usize = 1024;
const MARK: &[u8] = b"SECRET-PLAINTEXT-MARKER:";

fn random_password() -> String {
    format!("pw-1{:032x}", rand::random::<u128>())
}

/// Plaintext in which the marker text recurs, so any leak into an error message
/// or a log line is easy to see.
fn content(len: usize) -> Vec<u8> {
    let salt: u8 = rand::random();
    (0..len)
        .map(|i| {
            if i % 64 < MARK.len() {
                MARK[i % 64]
            } else {
                (i as u8).wrapping_mul(31).wrapping_add(salt)
            }
        })
        .collect()
}

struct World {
    data: Vec<u8>,
    mid: ContentId,
    record: DhtRecord,
    manifest: Option<TransferManifest>,
    shares: HashMap<(u32, u16), MiasmaShare>,
    password: Option<String>,
}

fn build_world(segments: usize, with_manifest: bool, protected: bool) -> World {
    build_world_with(segments, with_manifest, protected, None)
}

fn build_world_with(
    segments: usize,
    with_manifest: bool,
    protected: bool,
    mid_override: Option<ContentId>,
) -> World {
    let data = content(segments * SEG);
    let params = DissolutionParams {
        data_shards: 4,
        total_shards: 6,
    };
    let mid = mid_override.unwrap_or_else(|| ContentId::compute(&data, &params.to_param_bytes()));
    let password = protected.then(random_password);
    let (protection, key) = match &password {
        Some(pw) => {
            let (p, key) = PasswordProtection::create_with_cost(pw, 64, 1, 1).unwrap();
            (Protection::Password(p), Some(key))
        }
        None => (Protection::None, None),
    };
    let mut manifest = TransferManifest::new(
        &mid,
        [0x5a; 32],
        params,
        SEG as u32,
        data.len() as u64,
        protection,
    );
    let mut shares = HashMap::new();
    let mut locations = Vec::new();
    for (i, chunk) in data.chunks(SEG).enumerate() {
        let (_, seg_shares) =
            dissolve_segment_with(chunk, &mid, i as u32, 0, params, key.as_ref()).unwrap();
        manifest
            .push_segment(SegmentEntry::from_dissolved(i as u32, &mid, chunk, &seg_shares).unwrap())
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
        data,
        mid,
        record,
        manifest: with_manifest.then_some(manifest),
        shares,
        password,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ev {
    Fetch(u32),
    SinkStart(u32),
    SinkEnd(u32),
}

type Log = Arc<Mutex<Vec<Ev>>>;

/// Serves a world's pieces, recording every fetch.
struct Src {
    shares: HashMap<(u32, u16), MiasmaShare>,
    log: Log,
    /// Return nothing for every slot of this segment.
    missing_segment: Option<u32>,
    /// Never answer for this segment (a holder that hangs).
    hang_on: Option<u32>,
    /// Cancel this transfer from inside the first fetch of this segment, then
    /// fail that fetch (return nothing).
    cancel_then_fail: Option<(u32, Arc<TransferProgress>)>,
    cancel_done: AtomicBool,
}

impl Src {
    fn new(w: &World, log: &Log) -> Self {
        Self {
            shares: w.shares.clone(),
            log: log.clone(),
            missing_segment: None,
            hang_on: None,
            cancel_then_fail: None,
            cancel_done: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl PieceSource for Src {
    async fn fetch_piece(
        &self,
        _mid: &ContentId,
        segment: u32,
        slot: u16,
        _holder: &ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        self.log.lock().unwrap().push(Ev::Fetch(segment));
        if self.hang_on == Some(segment) {
            std::future::pending::<()>().await;
        }
        if let Some((seg, progress)) = &self.cancel_then_fail {
            if *seg == segment && !self.cancel_done.swap(true, Ordering::SeqCst) {
                // Yield past the first cancel poll (it fires at once), then
                // cancel while this fetch is still in flight and fail it.
                tokio::time::sleep(Duration::from_millis(5)).await;
                progress.cancel();
                return Ok(None);
            }
        }
        if self.missing_segment == Some(segment) {
            return Ok(None);
        }
        Ok(self.shares.get(&(segment, slot)).cloned())
    }
}

/// A consumer that can be slow, blocked, stopping or failing on cue.
struct TestSink {
    log: Log,
    collected: Vec<u8>,
    delay: Duration,
    /// Segments that must wait for a permit before `accept` returns.
    gate: Option<(u32, Arc<Semaphore>)>,
    fail_at: Option<u32>,
    close_at: Option<u32>,
    /// Cancel the transfer from inside `accept` for this segment.
    cancel_at: Option<(u32, Arc<TransferProgress>)>,
    completed: Option<u64>,
    aborted: u32,
    completes: u32,
}

impl TestSink {
    fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            collected: Vec::new(),
            delay: Duration::ZERO,
            gate: None,
            fail_at: None,
            close_at: None,
            cancel_at: None,
            completed: None,
            aborted: 0,
            completes: 0,
        }
    }
}

#[async_trait]
impl SegmentSink for TestSink {
    async fn accept(&mut self, index: u32, data: &[u8]) -> Result<(), SinkError> {
        self.log.lock().unwrap().push(Ev::SinkStart(index));
        if let Some((seg, gate)) = &self.gate {
            if *seg == index {
                gate.acquire().await.unwrap().forget();
            }
        }
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        if self.fail_at == Some(index) {
            return Err(SinkError::Failed);
        }
        if self.close_at == Some(index) {
            return Err(SinkError::Closed);
        }
        self.collected.extend_from_slice(data);
        if let Some((seg, progress)) = &self.cancel_at {
            if *seg == index {
                progress.cancel();
            }
        }
        self.log.lock().unwrap().push(Ev::SinkEnd(index));
        Ok(())
    }
    fn complete(&mut self, total_bytes: u64) {
        self.completed = Some(total_bytes);
        self.completes += 1;
    }
    fn abort(&mut self) {
        self.aborted += 1;
    }
}

fn quick_retry() -> RetryConfig {
    RetryConfig {
        max_attempts_per_segment: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    }
}

fn spec(w: &World) -> StreamSpec {
    let mut s = StreamSpec::new(w.mid.clone(), w.record.clone(), w.manifest.clone());
    s.password = w
        .password
        .as_ref()
        .map(|p| zeroize::Zeroizing::new(p.clone()));
    s.retry = quick_retry();
    s
}

struct Run {
    result: Result<StreamOutcome, MiasmaError>,
    sink: TestSink,
    stats: Arc<StreamStats>,
    progress: Arc<TransferProgress>,
}

async fn run(w: &World, src: Src, mut sink: TestSink, progress: Arc<TransferProgress>) -> Run {
    let spec = spec(w);
    let stats = spec.stats.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        receive_stream(&src, spec, &mut sink, progress.clone()),
    )
    .await
    .expect("the stream must not hang");
    Run {
        result,
        sink,
        stats,
        progress,
    }
}

/// Every buffer made was wiped and none is alive.
fn assert_all_buffers_wiped(stats: &StreamStats) {
    let s = stats.snapshot();
    assert_eq!(s.live, 0, "a plaintext buffer is still alive: {s:?}");
    assert_eq!(s.created, s.wiped, "not every buffer was wiped: {s:?}");
    assert_eq!(s.wipe_failures, 0, "a buffer read back non-zero: {s:?}");
    assert!(s.peak_live <= 1, "more than one segment at once: {s:?}");
}

fn leftover_part_files() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(std::env::temp_dir())
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".part"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn fetched_segments(log: &Log) -> Vec<u32> {
    let mut v: Vec<u32> = log
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Fetch(s) => Some(*s),
            _ => None,
        })
        .collect();
    v.dedup();
    v
}

// ─── Delivery ────────────────────────────────────────────────────────────────

async fn delivers_everything(with_manifest: bool, protected: bool) {
    let w = build_world(6, with_manifest, protected);
    let log: Log = Arc::default();
    let progress = TransferProgress::new(w.mid.to_string());
    let r = run(&w, Src::new(&w, &log), TestSink::new(&log), progress).await;

    assert_eq!(
        r.result.unwrap(),
        StreamOutcome::Complete {
            segments: 6,
            bytes: w.data.len() as u64
        }
    );
    assert_eq!(r.sink.collected, w.data);
    assert_eq!(r.sink.completed, Some(w.data.len() as u64));
    assert_eq!((r.sink.completes, r.sink.aborted), (1, 0));
    let s = r.stats.snapshot();
    assert_eq!(s.created, 6);
    assert_eq!(s.largest_buffer, SEG);
    assert_all_buffers_wiped(&r.stats);
    let st = r.progress.snapshot();
    assert_eq!(st.state, TransferState::Complete);
    assert_eq!((st.segments_done, st.segments_total), (6, 6));
    assert_eq!(st.bytes_done, w.data.len() as u64);
}

#[tokio::test]
async fn a_plain_transfer_arrives_in_order_and_complete() {
    delivers_everything(true, false).await;
}

#[tokio::test]
async fn a_password_protected_transfer_arrives_complete() {
    delivers_everything(true, true).await;
}

#[tokio::test]
async fn a_record_without_a_manifest_still_streams_and_is_checked_at_the_end() {
    delivers_everything(false, false).await;
}

#[tokio::test]
async fn a_missing_password_is_refused_before_any_piece_is_fetched() {
    let w = build_world(3, true, true);
    let log: Log = Arc::default();
    let mut s = spec(&w);
    s.password = None;
    let mut sink = TestSink::new(&log);
    let err = receive_stream(
        &Src::new(&w, &log),
        s,
        &mut sink,
        TransferProgress::new(w.mid.to_string()),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, MiasmaError::PasswordRequired), "{err:?}");
    assert!(log.lock().unwrap().is_empty(), "nothing may be fetched");
    assert_eq!((sink.aborted, sink.completes), (1, 0));
}

// ─── Cancellation ────────────────────────────────────────────────────────────

#[tokio::test]
async fn cancelling_from_the_sink_stops_the_stream_and_wipes_every_buffer() {
    let parts_before = leftover_part_files();
    let w = build_world(8, true, false);
    let log: Log = Arc::default();
    let progress = TransferProgress::new(w.mid.to_string());
    let mut sink = TestSink::new(&log);
    sink.cancel_at = Some((2, progress.clone()));
    let r = run(&w, Src::new(&w, &log), sink, progress).await;

    assert_eq!(
        r.result.unwrap(),
        StreamOutcome::Cancelled {
            segments_delivered: 3,
            bytes_delivered: 3 * SEG as u64
        }
    );
    assert_eq!((r.sink.aborted, r.sink.completes), (1, 0));
    assert!(r.sink.completed.is_none());
    assert_eq!(r.sink.collected.len(), 3 * SEG);
    assert_eq!(
        fetched_segments(&log),
        vec![0, 1, 2],
        "nothing past the cancel point is fetched"
    );
    assert_all_buffers_wiped(&r.stats);
    assert_eq!(r.progress.snapshot().state, TransferState::Cancelled);
    assert_eq!(leftover_part_files(), parts_before, "no temp file left");
}

#[tokio::test]
async fn cancelling_while_a_fetch_hangs_returns_promptly() {
    let w = build_world(6, true, false);
    let log: Log = Arc::default();
    let progress = TransferProgress::new(w.mid.to_string());
    let mut src = Src::new(&w, &log);
    src.hang_on = Some(2);
    let p2 = progress.clone();
    let log2 = log.clone();
    tokio::spawn(async move {
        // Wait until the hanging fetch has started, then cancel.
        loop {
            if log2.lock().unwrap().contains(&Ev::Fetch(2)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        p2.cancel();
    });
    let r = run(&w, src, TestSink::new(&log), progress).await;
    assert_eq!(
        r.result.unwrap(),
        StreamOutcome::Cancelled {
            segments_delivered: 2,
            bytes_delivered: 2 * SEG as u64
        }
    );
    assert_eq!(r.sink.aborted, 1);
    assert_all_buffers_wiped(&r.stats);
}

#[tokio::test(start_paused = true)]
async fn a_fetch_that_fails_because_of_a_cancel_ends_as_cancelled_not_as_an_error() {
    // The cancel lands mid-fetch after the first cancel poll; the retries (1 ms
    // pauses) then run out well inside the 20 ms poll interval, so only the
    // explicit cancel check can report Cancelled. Fails on the unfixed code with
    // Err(InsufficientShares). The clock is paused so the 5 ms / 1 ms / 2 ms
    // virtual delays are exact (real Windows timers can stretch them past 20 ms).
    let w = build_world(6, true, false);
    let log: Log = Arc::default();
    let progress = TransferProgress::new(w.mid.to_string());
    let mut src = Src::new(&w, &log);
    src.cancel_then_fail = Some((2, progress.clone()));
    let parts_before = leftover_part_files();
    let r = run(&w, src, TestSink::new(&log), progress).await;
    assert_eq!(
        r.result.unwrap(),
        StreamOutcome::Cancelled {
            segments_delivered: 2,
            bytes_delivered: 2 * SEG as u64
        }
    );
    assert_eq!((r.sink.aborted, r.sink.completes), (1, 0));
    assert_all_buffers_wiped(&r.stats);
    assert_eq!(leftover_part_files(), parts_before, "no temp file left");
}

#[tokio::test]
async fn cancelling_while_the_sink_is_blocked_wipes_the_buffer_in_hand() {
    let w = build_world(6, true, false);
    let log: Log = Arc::default();
    let progress = TransferProgress::new(w.mid.to_string());
    let gate = Arc::new(Semaphore::new(0));
    let mut sink = TestSink::new(&log);
    sink.gate = Some((1, gate));
    let p2 = progress.clone();
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            if log2.lock().unwrap().contains(&Ev::SinkStart(1)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // The segment is in the sink's hands and the sink is stuck.
        tokio::time::sleep(Duration::from_millis(50)).await;
        p2.cancel();
    });
    let r = run(&w, Src::new(&w, &log), sink, progress).await;
    assert_eq!(
        r.result.unwrap(),
        StreamOutcome::Cancelled {
            segments_delivered: 1,
            bytes_delivered: SEG as u64
        }
    );
    assert_eq!(r.sink.aborted, 1);
    assert_eq!(r.stats.snapshot().created, 2, "segment 1 was in hand");
    assert_all_buffers_wiped(&r.stats);
}

// ─── Back-pressure ───────────────────────────────────────────────────────────

#[tokio::test]
async fn a_slow_sink_paces_the_fetching() {
    let w = build_world(5, true, false);
    let log: Log = Arc::default();
    let mut sink = TestSink::new(&log);
    sink.delay = Duration::from_millis(40);
    let r = run(
        &w,
        Src::new(&w, &log),
        sink,
        TransferProgress::new(w.mid.to_string()),
    )
    .await;
    r.result.unwrap();

    // No piece of segment n+1 is requested before the sink has finished n.
    let events = log.lock().unwrap().clone();
    for n in 1..5u32 {
        let end_prev = events
            .iter()
            .position(|e| *e == Ev::SinkEnd(n - 1))
            .unwrap();
        let first_fetch = events.iter().position(|e| *e == Ev::Fetch(n)).unwrap();
        assert!(
            first_fetch > end_prev,
            "segment {n} was fetched while the sink still held segment {}",
            n - 1
        );
    }
    assert_all_buffers_wiped(&r.stats);
}

#[tokio::test]
async fn a_blocked_sink_stops_the_fetching_until_it_is_released() {
    let w = Arc::new(build_world(6, true, false));
    let log: Log = Arc::default();
    let gate = Arc::new(Semaphore::new(0));
    let mut sink = TestSink::new(&log);
    sink.gate = Some((1, gate.clone()));
    let progress = TransferProgress::new(w.mid.to_string());

    let task = {
        let w = w.clone();
        let log = log.clone();
        tokio::spawn(async move { run(&w, Src::new(&w, &log), sink, progress).await })
    };

    // Let it run into the blocked sink, then give it time to misbehave.
    loop {
        if log.lock().unwrap().contains(&Ev::SinkStart(1)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fetched_segments(&log),
        vec![0, 1],
        "a sink that has not returned must not be outrun by the network"
    );
    assert!(!task.is_finished());

    gate.add_permits(1);
    let r = task.await.unwrap();
    r.result.unwrap();
    assert_eq!(r.sink.collected, w.data);
    assert_all_buffers_wiped(&r.stats);
}

// ─── Early returns and errors ────────────────────────────────────────────────

#[tokio::test]
async fn a_sink_that_fails_ends_the_stream_with_a_plain_error() {
    let w = build_world(6, true, false);
    let log: Log = Arc::default();
    let mut sink = TestSink::new(&log);
    sink.fail_at = Some(2);
    let r = run(
        &w,
        Src::new(&w, &log),
        sink,
        TransferProgress::new(w.mid.to_string()),
    )
    .await;
    let err = r.result.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("segment 2"), "{text}");
    assert!(!text.contains("SECRET"), "plaintext leaked: {text}");
    assert_eq!((r.sink.aborted, r.sink.completes), (1, 0));
    assert_eq!(fetched_segments(&log), vec![0, 1, 2]);
    assert_all_buffers_wiped(&r.stats);
    let st = r.progress.snapshot();
    assert_eq!(st.state, TransferState::Failed);
    assert!(!st.last_error.unwrap_or_default().contains("SECRET"));
}

#[tokio::test]
async fn a_sink_that_closes_is_not_an_error() {
    let w = build_world(6, true, false);
    let log: Log = Arc::default();
    let mut sink = TestSink::new(&log);
    sink.close_at = Some(1);
    let r = run(
        &w,
        Src::new(&w, &log),
        sink,
        TransferProgress::new(w.mid.to_string()),
    )
    .await;
    assert_eq!(
        r.result.unwrap(),
        StreamOutcome::SinkClosed {
            segments_delivered: 1,
            bytes_delivered: SEG as u64
        }
    );
    assert_eq!((r.sink.aborted, r.sink.completes), (1, 0));
    assert_all_buffers_wiped(&r.stats);
}

#[tokio::test]
async fn missing_pieces_end_the_stream_after_the_delivered_prefix() {
    let w = build_world(6, true, false);
    let log: Log = Arc::default();
    let mut src = Src::new(&w, &log);
    src.missing_segment = Some(3);
    let r = run(
        &w,
        src,
        TestSink::new(&log),
        TransferProgress::new(w.mid.to_string()),
    )
    .await;
    let err = r.result.unwrap_err();
    assert!(
        matches!(err, MiasmaError::InsufficientShares { need: 4, got: 0 }),
        "{err:?}"
    );
    assert!(!err.to_string().contains("SECRET"));
    assert_eq!(
        r.sink.collected.len(),
        3 * SEG,
        "segments 0..3 were delivered"
    );
    assert_eq!((r.sink.aborted, r.sink.completes), (1, 0));
    assert!(r.progress.snapshot().segment_retries >= 2);
    assert_all_buffers_wiped(&r.stats);
}

#[tokio::test]
async fn an_object_that_does_not_match_its_mid_is_reported_as_aborted() {
    // A legacy record (no manifest) whose publisher lied about the MID: every
    // segment authenticates, only the whole-object check can catch it.
    let wrong = ContentId::compute(b"some other object", b"params");
    let w = build_world_with(4, false, false, Some(wrong));
    let log: Log = Arc::default();
    let r = run(
        &w,
        Src::new(&w, &log),
        TestSink::new(&log),
        TransferProgress::new(w.mid.to_string()),
    )
    .await;
    let err = r.result.unwrap_err();
    assert!(matches!(err, MiasmaError::HashMismatch), "{err:?}");
    assert!(!err.to_string().contains("SECRET"));
    assert_eq!(
        (r.sink.aborted, r.sink.completes),
        (1, 0),
        "the sink must be told to discard what it kept"
    );
    assert!(r.sink.completed.is_none());
    assert_all_buffers_wiped(&r.stats);
}
