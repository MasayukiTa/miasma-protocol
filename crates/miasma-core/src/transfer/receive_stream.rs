//! RAM-only receive: verified plaintext goes segment by segment into a sink the
//! caller owns, and nothing is written to disk by this module.
//!
//! This is the counterpart of [`run_receive`](super::receive::run_receive) for a
//! consumer that views, analyses or forwards the content instead of saving it.
//! It uses the same record/manifest/password checks and the same verified piece
//! fetching and decoding, but it has no `.part` file and no journal, so there is
//! nothing to resume and nothing left behind when it stops.
//!
//! # Memory
//! At most one plaintext segment is alive at a time (the segment size the
//! publisher chose, 64 MiB by default; a mobile front end should publish smaller
//! segments). It lives in a [`SegmentBuf`], which wipes itself when it is
//! dropped, whatever the reason: delivered, cancelled, failed, or the future
//! being dropped. The next segment is not fetched until the sink has returned for
//! the current one, so a slow sink slows the network side down instead of
//! queueing data (back-pressure). No plaintext is alive across the fetching,
//! retry-sleep or piece-verification awaits: those hold only pieces, which are
//! ciphertext and secret-shares.
//!
//! # What it guarantees, and what it does not
//! * A segment is released to the sink only after its AEAD tag has verified and,
//!   when the record has a manifest, after it matched the manifest's hash for
//!   that segment.
//! * The whole-object MID is checked at the end. A sink therefore may have seen
//!   all of the plaintext before a failure of that last check; it is told through
//!   [`SegmentSink::abort`] and must discard what it kept. Only
//!   [`SegmentSink::complete`] means the object verified.
//! * Anything the sink keeps (a file, a bitmap, a network write) is outside this
//!   module and is not wiped by it. RAM-only is not "no trace": the operating
//!   system may page the process, and the copies the caller makes are the
//!   caller's.
//! * Error values and progress text never contain plaintext; they are built from
//!   fixed text, segment numbers and counts.

use std::{
    collections::HashSet,
    future::Future,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use zeroize::{Zeroize, Zeroizing};

use super::{
    manifest::TransferManifest,
    progress::{Phase, TransferProgress, TransferState},
    receive::{
        decode_with_fallback, fill_pool, prepare, PieceSource, PooledPiece, Prepared, RetryConfig,
        SegmentCtx,
    },
    share_id::ShareId,
};
use crate::{crypto::hash::ContentId, network::types::DhtRecord, MiasmaError};

/// How often a waiting stream looks at its cancel flag.
const CANCEL_POLL: Duration = Duration::from_millis(20);

// ─── The zeroizing segment buffer ────────────────────────────────────────────

/// Counters of the plaintext buffers one stream created. Cheap, lock-free, and
/// per stream so that tests (and a front end showing memory use) can read them
/// without a process-wide hook.
#[derive(Default)]
pub struct StreamStats {
    created: AtomicU64,
    wiped: AtomicU64,
    not_clean: AtomicU64,
    live: AtomicU64,
    peak_live: AtomicU64,
    largest: AtomicUsize,
}

/// A point-in-time copy of [`StreamStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamStatsSnapshot {
    /// Buffers created so far.
    pub created: u64,
    /// Buffers that were dropped and read back as all zero after wiping.
    pub wiped: u64,
    /// Buffers that did **not** read back as zero after wiping. Must stay 0.
    pub wipe_failures: u64,
    /// Buffers alive now.
    pub live: u64,
    /// The most buffers alive at the same moment.
    pub peak_live: u64,
    /// The size of the biggest buffer, in bytes.
    pub largest_buffer: usize,
}

impl StreamStats {
    pub fn snapshot(&self) -> StreamStatsSnapshot {
        StreamStatsSnapshot {
            created: self.created.load(Ordering::SeqCst),
            wiped: self.wiped.load(Ordering::SeqCst),
            wipe_failures: self.not_clean.load(Ordering::SeqCst),
            live: self.live.load(Ordering::SeqCst),
            peak_live: self.peak_live.load(Ordering::SeqCst),
            largest_buffer: self.largest.load(Ordering::SeqCst),
        }
    }
}

/// One decrypted segment. The bytes are wiped when this is dropped, and the wipe
/// is checked by reading them back, so a regression that stops wiping shows up in
/// [`StreamStatsSnapshot::wipe_failures`] rather than silently.
pub struct SegmentBuf {
    data: Zeroizing<Vec<u8>>,
    stats: Arc<StreamStats>,
}

impl SegmentBuf {
    /// Take over an already zeroizing buffer (no copy is made).
    pub fn adopt(data: Zeroizing<Vec<u8>>, stats: &Arc<StreamStats>) -> Self {
        stats.created.fetch_add(1, Ordering::SeqCst);
        let live = stats.live.fetch_add(1, Ordering::SeqCst) + 1;
        stats.peak_live.fetch_max(live, Ordering::SeqCst);
        stats.largest.fetch_max(data.len(), Ordering::SeqCst);
        Self {
            data,
            stats: stats.clone(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::fmt::Debug for SegmentBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the bytes.
        write!(f, "SegmentBuf({} bytes)", self.data.len())
    }
}

impl Drop for SegmentBuf {
    fn drop(&mut self) {
        self.data.as_mut_slice().zeroize();
        if self.data.iter().all(|b| *b == 0) {
            self.stats.wiped.fetch_add(1, Ordering::SeqCst);
        } else {
            self.stats.not_clean.fetch_add(1, Ordering::SeqCst);
        }
        self.stats.live.fetch_sub(1, Ordering::SeqCst);
        // The `Zeroizing` field wipes (and clears) once more as it drops.
    }
}

// ─── The sink ────────────────────────────────────────────────────────────────

/// Why a sink stopped a stream. Deliberately carries no text: whatever the sink
/// wants to say about it belongs to the sink, and nothing from the data may
/// travel in an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkError {
    /// The consumer is done or gone and wants the stream to stop. Not a failure:
    /// the stream ends with [`StreamOutcome::SinkClosed`].
    Closed,
    /// The consumer could not take the data. The stream ends with an error.
    Failed,
}

/// Where a RAM-only receive delivers plaintext.
///
/// The engine awaits `accept` before it fetches the next segment, so a sink that
/// is slower than the network paces the transfer.
#[async_trait]
pub trait SegmentSink: Send {
    /// One authenticated segment, in order, starting at 0. `data` is only valid
    /// for the duration of the call; keep a copy if you need it, and wipe that
    /// copy yourself.
    async fn accept(&mut self, index: u32, data: &[u8]) -> Result<(), SinkError>;

    /// The whole object arrived and its MID verified. Called at most once, and
    /// never together with [`abort`](Self::abort).
    fn complete(&mut self, _total_bytes: u64) {}

    /// The stream ended without a verified object (cancelled, failed, or the sink
    /// itself stopped it). Whatever was kept from earlier segments should be
    /// discarded. Called at most once.
    fn abort(&mut self) {}
}

// ─── Spec and outcome ────────────────────────────────────────────────────────

pub struct StreamSpec {
    pub mid: ContentId,
    pub record: DhtRecord,
    /// `None` for a record published before manifests existed: segments are then
    /// authenticated by their AEAD tag only, and the object by the final MID.
    pub manifest: Option<TransferManifest>,
    pub password: Option<Zeroizing<String>>,
    pub retry: RetryConfig,
    /// The share ID the person supplied, if any (see [`ReceiveSpec::expect`]).
    ///
    /// [`ReceiveSpec::expect`]: super::receive::ReceiveSpec::expect
    pub expect: Option<ShareId>,
    /// The key that verifiably signed the record envelope, when known.
    pub record_signer: Option<[u8; 32]>,
    /// Counters for this stream's plaintext buffers; keep a clone to read them.
    pub stats: Arc<StreamStats>,
}

impl StreamSpec {
    pub fn new(mid: ContentId, record: DhtRecord, manifest: Option<TransferManifest>) -> Self {
        Self {
            mid,
            record,
            manifest,
            password: None,
            retry: RetryConfig::default(),
            expect: None,
            record_signer: None,
            stats: Arc::new(StreamStats::default()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamOutcome {
    /// Every segment was delivered and the object's MID verified.
    Complete { segments: u32, bytes: u64 },
    /// Stopped by [`TransferProgress::cancel`]. Nothing is kept.
    Cancelled {
        segments_delivered: u32,
        bytes_delivered: u64,
    },
    /// The sink asked to stop ([`SinkError::Closed`]).
    SinkClosed {
        segments_delivered: u32,
        bytes_delivered: u64,
    },
}

// ─── The engine ──────────────────────────────────────────────────────────────

/// Receive an object into `sink`. Cancel with [`TransferProgress::cancel`] on
/// `progress`; read the live state from the same cell.
///
/// Exactly one of [`SegmentSink::complete`] and [`SegmentSink::abort`] is called
/// before this returns.
pub async fn receive_stream<S: PieceSource + ?Sized>(
    source: &S,
    spec: StreamSpec,
    sink: &mut dyn SegmentSink,
    progress: Arc<TransferProgress>,
) -> Result<StreamOutcome, MiasmaError> {
    let result = run_stream(source, spec, sink, &progress).await;
    match &result {
        Ok(StreamOutcome::Complete { bytes, .. }) => {
            progress.set_state(TransferState::Complete, None, false);
            sink.complete(*bytes);
        }
        Ok(StreamOutcome::Cancelled { .. }) | Ok(StreamOutcome::SinkClosed { .. }) => {
            progress.set_state(TransferState::Cancelled, None, false);
            sink.abort();
        }
        Err(e) => {
            progress.set_state(TransferState::Failed, Some(e.to_string()), false);
            sink.abort();
        }
    }
    result
}

/// Run `fut`, but give up (dropping it, and with it anything it holds) once the
/// transfer is cancelled. `None` means cancelled.
async fn with_cancel<F: Future>(fut: F, progress: &TransferProgress) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let mut tick = tokio::time::interval(CANCEL_POLL);
    loop {
        // Biased: a future that is already done wins over a cancel that arrived
        // at the same moment, so a delivered segment is counted as delivered.
        tokio::select! {
            biased;
            out = fut.as_mut() => return Some(out),
            _ = tick.tick() => {
                if progress.is_cancelled() {
                    return None;
                }
            }
        }
    }
}

async fn run_stream<S: PieceSource + ?Sized>(
    source: &S,
    spec: StreamSpec,
    sink: &mut dyn SegmentSink,
    progress: &Arc<TransferProgress>,
) -> Result<StreamOutcome, MiasmaError> {
    let StreamSpec {
        mid,
        record,
        manifest,
        password,
        retry,
        expect,
        record_signer,
        stats,
    } = spec;

    progress.set_phase(Phase::Preparing);
    let Prepared {
        params,
        k,
        key,
        segment_count,
        total_bytes,
        candidates,
        expect: _,
    } = prepare(
        &mid,
        &record,
        &manifest,
        password,
        expect,
        record_signer,
        progress,
    )
    .await?;
    progress.set_totals(segment_count, total_bytes);
    progress.set_resumed(0, 0);
    progress.set_phase(Phase::Transferring);

    let mut hasher = blake3::Hasher::new();
    // Pieces that verified but then failed to decode; never reused in this run.
    let mut suspects: HashSet<(u32, u16, Vec<u8>)> = HashSet::new();
    let mut bytes_done: u64 = 0;

    for seg in 0..segment_count {
        if progress.is_cancelled() {
            return Ok(StreamOutcome::Cancelled {
                segments_delivered: seg,
                bytes_delivered: bytes_done,
            });
        }
        let entry = manifest.as_ref().map(|m| &m.segments[seg as usize]);

        // Fetch k verified pieces (retrying with backoff) and decode. Only
        // pieces live across these awaits. The plaintext comes out already in a
        // zeroizing buffer, so dropping this future (cancel) wipes it too.
        let started = Instant::now();
        let produce = async {
            let mut attempt: u32 = 0;
            let mut pool: Vec<PooledPiece> = Vec::new();
            loop {
                match fill_pool(
                    source,
                    &mid,
                    seg,
                    &candidates[seg as usize],
                    k,
                    manifest.as_ref(),
                    progress,
                    &suspects,
                    &mut pool,
                )
                .await
                {
                    Ok(()) => break,
                    Err(MiasmaError::InsufficientShares { need, got }) => {
                        attempt += 1;
                        if attempt >= retry.max_attempts_per_segment {
                            return Err(MiasmaError::InsufficientShares { need, got });
                        }
                        progress.segment_retry();
                        tokio::time::sleep(retry.delay_for(attempt)).await;
                    }
                    Err(e) => return Err(e),
                }
            }
            let ctx = SegmentCtx {
                mid: &mid,
                seg,
                candidates: &candidates[seg as usize],
                k,
                params,
                key: key.as_ref(),
                entry,
                manifest: manifest.as_ref(),
            };
            decode_with_fallback(source, &ctx, progress, &mut suspects, &mut pool).await
        };
        let Some(produced) = with_cancel(produce, progress).await else {
            return Ok(StreamOutcome::Cancelled {
                segments_delivered: seg,
                bytes_delivered: bytes_done,
            });
        };
        let buf = SegmentBuf::adopt(produced?, &stats);
        let fetch_time = started.elapsed();

        hasher.update(buf.as_slice());
        let len = buf.len() as u64;

        // The one await that holds plaintext: the sink call. The next segment is
        // not requested until it returns.
        let handed_over = Instant::now();
        let delivered = with_cancel(sink.accept(seg, buf.as_slice()), progress).await;
        drop(buf); // wiped here, before anything else is awaited
        match delivered {
            None => {
                return Ok(StreamOutcome::Cancelled {
                    segments_delivered: seg,
                    bytes_delivered: bytes_done,
                })
            }
            Some(Err(SinkError::Closed)) => {
                return Ok(StreamOutcome::SinkClosed {
                    segments_delivered: seg,
                    bytes_delivered: bytes_done,
                })
            }
            Some(Err(SinkError::Failed)) => {
                return Err(MiasmaError::Storage(format!(
                    "the receiving sink could not take segment {seg}"
                )))
            }
            Some(Ok(())) => {}
        }
        bytes_done += len;
        progress.on_segment_done(len, fetch_time, Duration::ZERO, handed_over.elapsed());
    }

    // The whole object must be the one the MID names.
    progress.set_phase(Phase::Finalizing);
    hasher.update(&params.to_param_bytes());
    let actual = ContentId::from_digest(*hasher.finalize().as_bytes());
    if actual != mid {
        return Err(MiasmaError::HashMismatch);
    }
    Ok(StreamOutcome::Complete {
        segments: segment_count,
        bytes: bytes_done,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_buffer_is_wiped_and_counted() {
        let stats = Arc::new(StreamStats::default());
        let buf = SegmentBuf::adopt(Zeroizing::new(vec![0xAB; 4096]), &stats);
        assert_eq!(buf.len(), 4096);
        assert_eq!(stats.snapshot().live, 1);
        drop(buf);
        let s = stats.snapshot();
        assert_eq!((s.created, s.wiped, s.wipe_failures, s.live), (1, 1, 0, 0));
        assert_eq!((s.peak_live, s.largest_buffer), (1, 4096));
    }

    #[test]
    fn debug_never_prints_the_bytes() {
        let stats = Arc::new(StreamStats::default());
        let buf = SegmentBuf::adopt(Zeroizing::new(b"top-secret-marker".to_vec()), &stats);
        let shown = format!("{buf:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("17 bytes"), "{shown}");
    }

    #[tokio::test]
    async fn with_cancel_returns_none_once_cancelled_and_drops_the_future() {
        let progress = TransferProgress::new("miasma:x");
        let stats = Arc::new(StreamStats::default());
        let held = SegmentBuf::adopt(Zeroizing::new(vec![1; 64]), &stats);
        let p2 = progress.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            p2.cancel();
        });
        let out = with_cancel(
            async move {
                let _keep = held;
                std::future::pending::<()>().await
            },
            &progress,
        )
        .await;
        assert!(out.is_none());
        let s = stats.snapshot();
        assert_eq!((s.live, s.wiped), (0, 1), "the future's buffer was wiped");
    }

    #[tokio::test]
    async fn with_cancel_passes_the_result_through() {
        let progress = TransferProgress::new("miasma:x");
        assert_eq!(with_cancel(async { 7 }, &progress).await, Some(7));
    }
}
