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
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use zeroize::Zeroizing;

pub use super::plaintext_pool::{SegmentBuf, StreamStats, StreamStatsSnapshot};
use super::{
    manifest::TransferManifest,
    plaintext_pool::PlaintextPool,
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
                        // A cancelled receive does not retry; the error is
                        // turned into `Cancelled` by the caller below.
                        if progress.is_cancelled() || attempt >= retry.max_attempts_per_segment {
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
        // The decoder allocated this plaintext (inside `retrieve_segment_with`);
        // it is counted in the shared pool's live total and wiped on drop, but
        // not kept by the pool.
        // A fetch that failed because the transfer was cancelled is a cancel,
        // not a failure, whatever the cancel poll has seen so far.
        if produced.is_err() && progress.is_cancelled() {
            return Ok(StreamOutcome::Cancelled {
                segments_delivered: seg,
                bytes_delivered: bytes_done,
            });
        }
        let buf = SegmentBuf::adopt_in(produced?, &stats, PlaintextPool::shared());
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
