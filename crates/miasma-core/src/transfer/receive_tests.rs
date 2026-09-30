//! The receive engine against a source that misbehaves on purpose.
//!
//! Every test builds a real multi-segment transfer (real encryption, real
//! Reed-Solomon, real manifest) at a tiny segment size so there are many
//! segments, then serves it from an in-memory [`PieceSource`] that can drop
//! holders, return junk, die part-way, or record what was asked of it.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use zeroize::Zeroizing;

use super::{
    journal::{journal_path, part_path_for, ReceiveJournal},
    manifest::{SegmentEntry, TransferManifest},
    progress::{TransferProgress, TransferState},
    protection::{PasswordProtection, Protection},
    receive::{run_receive, PieceSource, ReceiveOutcome, ReceiveSpec, RetryConfig},
};
use crate::{
    crypto::hash::ContentId,
    dissolution::segment::dissolve_segment_with,
    network::types::{DhtRecord, ShardLocation},
    pipeline::DissolutionParams,
    share::MiasmaShare,
    MiasmaError,
};

const SEG: usize = 1024;

fn content(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

fn quick_retry() -> RetryConfig {
    RetryConfig {
        max_attempts_per_segment: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    }
}

/// A complete transfer, ready to serve.
struct World {
    data: Vec<u8>,
    mid: ContentId,
    record: DhtRecord,
    manifest: Option<TransferManifest>,
    shares: HashMap<(u32, u16), MiasmaShare>,
}

fn world(len: usize, k: usize, n: usize, password: Option<&str>) -> World {
    world_with(len, k, n, password, true, None)
}

/// `with_manifest = false` builds a legacy record. `mid_override` dissolves the
/// content under a MID that is *not* its real one (a lying publisher).
fn world_with(
    len: usize,
    k: usize,
    n: usize,
    password: Option<&str>,
    with_manifest: bool,
    mid_override: Option<ContentId>,
) -> World {
    let data = content(len);
    let params = DissolutionParams {
        data_shards: k,
        total_shards: n,
    };
    let real_mid = ContentId::compute(&data, &params.to_param_bytes());
    let mid = mid_override.unwrap_or(real_mid);

    let (protection, key) = match password {
        None => (Protection::None, None),
        Some(pw) => {
            // Unchecked on purpose: these fixtures are transfers published
            // before the password policy existed (weak passwords such as
            // "pw"). The receive side must never enforce the policy.
            let (p, key) = PasswordProtection::create_unchecked(pw, 64, 1, 1).unwrap();
            (Protection::Password(p), Some(key))
        }
    };

    let mut manifest = TransferManifest::new(&mid, params, SEG as u32, len as u64, protection);
    let mut shares = HashMap::new();
    let mut locations = Vec::new();

    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&data[..]]
    } else {
        data.chunks(SEG).collect()
    };
    for (i, chunk) in chunks.iter().enumerate() {
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
        data_shards: k as u8,
        total_shards: n as u8,
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
    }
}

/// An in-memory holder that can be told to misbehave.
struct MockSource {
    shares: HashMap<(u32, u16), MiasmaShare>,
    log: Mutex<Vec<(u32, u16)>>,
    /// Segments at or beyond this index return nothing (a holder that has died).
    dead_from: AtomicU32,
    /// Pieces returned as junk whose hash is self-consistent but wrong.
    junk_consistent: Mutex<HashSet<(u32, u16)>>,
    /// Pieces returned with a payload that no longer matches their own hash.
    junk_inconsistent: Mutex<HashSet<(u32, u16)>>,
    /// Ask the transfer to cancel after this many fetches.
    cancel_after: Mutex<Option<(usize, Arc<TransferProgress>)>>,
}

impl MockSource {
    fn new(w: &World) -> Self {
        Self {
            shares: w.shares.clone(),
            log: Mutex::new(Vec::new()),
            dead_from: AtomicU32::new(u32::MAX),
            junk_consistent: Mutex::new(HashSet::new()),
            junk_inconsistent: Mutex::new(HashSet::new()),
            cancel_after: Mutex::new(None),
        }
    }
    fn fetched_segments(&self) -> Vec<u32> {
        self.log.lock().unwrap().iter().map(|(s, _)| *s).collect()
    }
    fn fetch_count(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

#[async_trait]
impl PieceSource for MockSource {
    async fn fetch_piece(
        &self,
        _mid: &ContentId,
        segment: u32,
        slot: u16,
        _holder: &ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        let count = {
            let mut log = self.log.lock().unwrap();
            log.push((segment, slot));
            log.len()
        };
        if let Some((n, progress)) = self.cancel_after.lock().unwrap().as_ref() {
            if count >= *n {
                progress.cancel();
            }
        }
        if segment >= self.dead_from.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let Some(share) = self.shares.get(&(segment, slot)) else {
            return Ok(None);
        };
        let mut share = share.clone();
        if self
            .junk_consistent
            .lock()
            .unwrap()
            .contains(&(segment, slot))
        {
            share.shard_data[0] ^= 0xFF;
            share.shard_hash = *blake3::hash(&share.shard_data).as_bytes();
        } else if self
            .junk_inconsistent
            .lock()
            .unwrap()
            .contains(&(segment, slot))
        {
            share.shard_data[0] ^= 0xFF; // hash left stale
        }
        Ok(Some(share))
    }
}

struct Run {
    dir: tempfile::TempDir,
}

impl Run {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn out(&self) -> std::path::PathBuf {
        self.dir.path().join("out").join("file.bin")
    }
    fn journals(&self) -> std::path::PathBuf {
        self.dir.path().join("transfers")
    }
    fn spec(&self, w: &World, password: Option<&str>, restart: bool) -> ReceiveSpec {
        ReceiveSpec {
            mid: w.mid.clone(),
            record: w.record.clone(),
            manifest: w.manifest.clone(),
            password: password.map(|p| Zeroizing::new(p.to_owned())),
            output_path: self.out(),
            journal_dir: self.journals(),
            restart,
            retry: quick_retry(),
        }
    }
    fn journal(&self, w: &World) -> Option<ReceiveJournal> {
        ReceiveJournal::load(&journal_path(&self.journals(), &w.mid))
    }
}

fn progress(w: &World) -> Arc<TransferProgress> {
    TransferProgress::new(w.mid.to_string())
}

#[tokio::test]
async fn an_unprotected_multi_segment_transfer_completes_byte_for_byte() {
    let w = world(10_000, 4, 6, None);
    let src = MockSource::new(&w);
    let run = Run::new();
    let p = progress(&w);

    let outcome = run_receive(&src, run.spec(&w, None, false), p.clone())
        .await
        .unwrap();
    assert_eq!(outcome, ReceiveOutcome::Complete { bytes: 10_000 });
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);

    // Nothing is left lying around.
    assert!(!part_path_for(&run.out()).exists());
    assert!(run.journal(&w).is_none());

    let s = p.snapshot();
    assert_eq!(s.state, TransferState::Complete);
    assert_eq!(s.segments_total, 10);
    assert_eq!(s.segments_done, 10);
    assert_eq!(s.bytes_done, 10_000);
    assert_eq!(s.bytes_total, 10_000);
    assert_eq!(s.pieces_rejected, 0);
    assert_eq!(s.pieces_fetched, 10 * 4, "k pieces per segment, no more");
}

#[tokio::test]
async fn a_password_protected_transfer_completes_with_the_password() {
    let w = world(5_000, 4, 6, Some("pw-1"));
    let src = MockSource::new(&w);
    let run = Run::new();
    let outcome = run_receive(&src, run.spec(&w, Some("pw-1"), false), progress(&w))
        .await
        .unwrap();
    assert!(matches!(outcome, ReceiveOutcome::Complete { .. }));
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);
}

#[tokio::test]
async fn an_old_transfer_with_a_weak_password_is_still_receivable() {
    // Published before the password policy: one character, no digit or symbol.
    let weak_pw = super::password_policy::test_support::compose(1, 0, 0, &[]);
    let weak = weak_pw.as_str();
    assert!(super::password_policy::check(weak).is_err());
    assert!(PasswordProtection::create_with_cost(weak, 64, 1, 1).is_err());
    let w = world(5_000, 4, 6, Some(weak));
    let src = MockSource::new(&w);
    let run = Run::new();
    let outcome = run_receive(&src, run.spec(&w, Some(weak), false), progress(&w))
        .await
        .unwrap();
    assert!(matches!(outcome, ReceiveOutcome::Complete { .. }));
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);
}

#[tokio::test]
async fn a_wrong_password_is_refused_before_a_single_piece_is_fetched() {
    let w = world(5_000, 4, 6, Some("right"));
    let src = MockSource::new(&w);
    let run = Run::new();
    let err = run_receive(&src, run.spec(&w, Some("wrong"), false), progress(&w))
        .await
        .unwrap_err();
    assert!(matches!(err, MiasmaError::WrongPassword), "{err:?}");
    assert_eq!(
        src.fetch_count(),
        0,
        "no data may be fetched for a wrong password"
    );
    assert!(!run.out().exists());
    assert!(!part_path_for(&run.out()).exists());
}

#[tokio::test]
async fn a_missing_password_and_an_unneeded_password_are_both_refused() {
    let protected = world(3_000, 4, 6, Some("pw"));
    let src = MockSource::new(&protected);
    let run = Run::new();
    let err = run_receive(
        &src,
        run.spec(&protected, None, false),
        progress(&protected),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, MiasmaError::PasswordRequired), "{err:?}");
    assert_eq!(src.fetch_count(), 0);

    // A password given for content that is not protected is not silently ignored.
    let plain = world(3_000, 4, 6, None);
    let src = MockSource::new(&plain);
    let run = Run::new();
    let err = run_receive(&src, run.spec(&plain, Some("pw"), false), progress(&plain))
        .await
        .unwrap_err();
    assert!(matches!(err, MiasmaError::InvalidManifest(_)), "{err:?}");
    assert_eq!(src.fetch_count(), 0);
}

#[tokio::test]
async fn junk_pieces_are_rejected_by_id_and_the_next_holder_is_used() {
    // k=4, n=6: two spare pieces per segment.
    let w = world(6_000, 4, 6, None);
    let src = MockSource::new(&w);
    // A piece that lies consistently (its own hash matches its bytes) — only the
    // manifest can tell — and one whose bytes do not match its own hash.
    src.junk_consistent.lock().unwrap().insert((2, 0));
    src.junk_inconsistent.lock().unwrap().insert((4, 1));
    let run = Run::new();
    let p = progress(&w);

    let outcome = run_receive(&src, run.spec(&w, None, false), p.clone())
        .await
        .unwrap();
    assert!(matches!(outcome, ReceiveOutcome::Complete { .. }));
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);
    assert_eq!(p.snapshot().pieces_rejected, 2);
}

#[tokio::test]
async fn a_segment_with_too_few_good_pieces_pauses_and_keeps_what_it_has() {
    let w = world(6_000, 4, 6, None); // 6 segments
    let src = MockSource::new(&w);
    // n - k = 2 spares; poison three pieces of segment 3.
    for slot in 0..3u16 {
        src.junk_consistent.lock().unwrap().insert((3, slot));
    }
    let run = Run::new();
    let p = progress(&w);

    let outcome = run_receive(&src, run.spec(&w, None, false), p.clone())
        .await
        .unwrap();
    match outcome {
        ReceiveOutcome::Paused { next_segment, .. } => assert_eq!(next_segment, 3),
        other => panic!("expected Paused, got {other:?}"),
    }
    assert!(
        !run.out().exists(),
        "no output name until the file is whole"
    );
    assert!(
        part_path_for(&run.out()).exists(),
        "the partial file is kept"
    );
    let j = run.journal(&w).expect("journal is kept");
    assert_eq!(j.next_segment, 3);
    assert_eq!(j.bytes_done, 3 * SEG as u64);
    let s = p.snapshot();
    assert_eq!(s.state, TransferState::Paused);
    assert!(s.resumable);
    assert!(
        s.segment_retries >= 1,
        "the segment was retried before pausing"
    );
}

#[tokio::test]
async fn resuming_continues_from_the_last_good_segment_without_refetching() {
    let w = world(8_000, 4, 6, None); // 8 segments
    let run = Run::new();

    // First run: the holder dies from segment 5.
    let dying = MockSource::new(&w);
    dying.dead_from.store(5, Ordering::Relaxed);
    let outcome = run_receive(&dying, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        ReceiveOutcome::Paused {
            next_segment: 5,
            ..
        }
    ));

    // Second run: a healthy source that records what it is asked for.
    let healthy = MockSource::new(&w);
    let p = progress(&w);
    let outcome = run_receive(&healthy, run.spec(&w, None, false), p.clone())
        .await
        .unwrap();
    assert_eq!(outcome, ReceiveOutcome::Complete { bytes: 8_000 });
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);

    let asked = healthy.fetched_segments();
    assert!(
        asked.iter().all(|s| *s >= 5),
        "segments 0..5 were already on disk and must not be fetched again: {asked:?}"
    );
    let s = p.snapshot();
    assert_eq!(s.resumed_from_segment, 5);
    assert_eq!(s.segments_done, 8);
    assert_eq!(s.bytes_done, 8_000);
}

#[tokio::test]
async fn a_corrupted_part_file_is_detected_and_only_the_damaged_tail_is_redone() {
    let w = world(8_000, 4, 6, None);
    let run = Run::new();

    let dying = MockSource::new(&w);
    dying.dead_from.store(6, Ordering::Relaxed);
    let outcome = run_receive(&dying, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        ReceiveOutcome::Paused {
            next_segment: 6,
            ..
        }
    ));

    // Damage one byte inside segment 2 of the partial file.
    let part = part_path_for(&run.out());
    let mut bytes = std::fs::read(&part).unwrap();
    bytes[2 * SEG + 5] ^= 0x01;
    std::fs::write(&part, &bytes).unwrap();

    let healthy = MockSource::new(&w);
    let outcome = run_receive(&healthy, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();
    assert!(matches!(outcome, ReceiveOutcome::Complete { .. }));
    assert_eq!(
        std::fs::read(run.out()).unwrap(),
        w.data,
        "the damaged segment must have been fetched again, not trusted"
    );
    let asked = healthy.fetched_segments();
    assert_eq!(
        *asked.iter().min().unwrap(),
        2,
        "resume starts at the damaged segment"
    );
    assert!(
        !asked.contains(&0) && !asked.contains(&1),
        "segments before the damage are kept: {asked:?}"
    );
}

#[tokio::test]
async fn a_journal_for_a_different_manifest_is_not_applied() {
    let w = world(5_000, 4, 6, None);
    let run = Run::new();
    let dying = MockSource::new(&w);
    dying.dead_from.store(3, Ordering::Relaxed);
    run_receive(&dying, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();

    // Someone re-published: the journal now refers to a manifest that is not this one.
    let jp = journal_path(&run.journals(), &w.mid);
    let mut j = ReceiveJournal::load(&jp).unwrap();
    j.manifest_hash = Some("00".repeat(32));
    j.save(&jp).unwrap();

    let healthy = MockSource::new(&w);
    let outcome = run_receive(&healthy, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();
    assert!(matches!(outcome, ReceiveOutcome::Complete { .. }));
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);
    assert!(
        healthy.fetched_segments().contains(&0),
        "a stale journal must not skip segments"
    );
}

#[tokio::test]
async fn restart_discards_a_partial_transfer() {
    let w = world(5_000, 4, 6, None);
    let run = Run::new();
    let dying = MockSource::new(&w);
    dying.dead_from.store(3, Ordering::Relaxed);
    run_receive(&dying, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();

    let healthy = MockSource::new(&w);
    let outcome = run_receive(&healthy, run.spec(&w, None, true), progress(&w))
        .await
        .unwrap();
    assert!(matches!(outcome, ReceiveOutcome::Complete { .. }));
    assert!(healthy.fetched_segments().contains(&0));
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);
}

#[tokio::test]
async fn cancelling_stops_at_a_safe_point_and_the_transfer_can_be_resumed() {
    let w = world(8_000, 4, 6, None);
    let run = Run::new();
    let src = MockSource::new(&w);
    let p = progress(&w);
    *src.cancel_after.lock().unwrap() = Some((10, p.clone()));

    let outcome = run_receive(&src, run.spec(&w, None, false), p.clone())
        .await
        .unwrap();
    let next = match outcome {
        ReceiveOutcome::Cancelled { next_segment } => next_segment,
        other => panic!("expected Cancelled, got {other:?}"),
    };
    assert!(next > 0 && next < 8, "cancelled part-way, got {next}");
    assert!(!run.out().exists());
    assert_eq!(p.snapshot().state, TransferState::Cancelled);

    let healthy = MockSource::new(&w);
    let outcome = run_receive(&healthy, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();
    assert!(matches!(outcome, ReceiveOutcome::Complete { .. }));
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);
}

#[tokio::test]
async fn a_publisher_that_lies_about_the_mid_never_gets_an_output_file() {
    // The pieces and manifest are perfectly self-consistent, but they were made
    // under a MID that is not the real hash of the content. Every per-piece and
    // per-segment check passes; only the whole-file MID can catch it.
    let fake = ContentId::compute(b"some other file entirely", b"k=4,n=6,v=1");
    let w = world_with(4_000, 4, 6, None, true, Some(fake));
    let src = MockSource::new(&w);
    let run = Run::new();
    let p = progress(&w);

    let err = run_receive(&src, run.spec(&w, None, false), p.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, MiasmaError::HashMismatch), "{err:?}");
    assert!(
        !run.out().exists(),
        "a file that fails the MID check must not appear"
    );
    assert!(!part_path_for(&run.out()).exists());
    assert!(run.journal(&w).is_none(), "resume cannot fix a bad MID");
    assert_eq!(p.snapshot().state, TransferState::Failed);
}

#[tokio::test]
async fn a_record_without_a_manifest_still_transfers_and_resumes() {
    let w = world_with(6_000, 4, 6, None, false, None);
    let run = Run::new();

    let dying = MockSource::new(&w);
    dying.dead_from.store(4, Ordering::Relaxed);
    let outcome = run_receive(&dying, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        ReceiveOutcome::Paused {
            next_segment: 4,
            ..
        }
    ));

    let healthy = MockSource::new(&w);
    let outcome = run_receive(&healthy, run.spec(&w, None, false), progress(&w))
        .await
        .unwrap();
    assert_eq!(outcome, ReceiveOutcome::Complete { bytes: 6_000 });
    assert_eq!(std::fs::read(run.out()).unwrap(), w.data);
    assert!(
        healthy.fetched_segments().iter().all(|s| *s >= 4),
        "the legacy path resumes too"
    );

    // But it cannot be password-protected: there is nothing to protect it with.
    let run2 = Run::new();
    let err = run_receive(&healthy, run2.spec(&w, Some("pw"), false), progress(&w))
        .await
        .unwrap_err();
    assert!(matches!(err, MiasmaError::InvalidManifest(_)), "{err:?}");
}

#[tokio::test]
async fn edge_sizes_transfer_correctly() {
    // Empty, exactly one segment, exactly N segments, one byte over, and no parity.
    for (len, k, n) in [
        (0, 4, 6),
        (SEG, 4, 6),
        (4 * SEG, 4, 6),
        (4 * SEG + 1, 4, 6),
        (5 * SEG + 300, 4, 4), // n == k: no parity
    ] {
        let w = world(len, k, n, Some("edge"));
        let src = MockSource::new(&w);
        let run = Run::new();
        let outcome = run_receive(&src, run.spec(&w, Some("edge"), false), progress(&w))
            .await
            .unwrap_or_else(|e| panic!("len={len} k={k} n={n}: {e}"));
        assert_eq!(
            outcome,
            ReceiveOutcome::Complete { bytes: len as u64 },
            "len={len}"
        );
        assert_eq!(
            std::fs::read(run.out()).unwrap(),
            w.data,
            "len={len} k={k} n={n}"
        );
    }
}

#[tokio::test]
async fn a_record_for_a_different_mid_is_refused() {
    let w = world(2_000, 4, 6, None);
    let other = world(2_500, 4, 6, None);
    let src = MockSource::new(&w);
    let run = Run::new();
    let mut spec = run.spec(&w, None, false);
    spec.record = other.record.clone();
    let err = run_receive(&src, spec, progress(&w)).await.unwrap_err();
    assert!(matches!(err, MiasmaError::InvalidMid(_)), "{err:?}");
}
