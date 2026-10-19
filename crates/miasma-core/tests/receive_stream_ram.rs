//! Memory cost of the RAM-only receive: streaming a 32-segment object (8 MiB of
//! plaintext in 256 KiB segments) into a sink that keeps nothing must raise the
//! live heap by no more than twelve segments at its peak, however long the
//! object is. A receive that collected the object, or queued segments ahead of
//! the consumer, would show up as a peak of the object's size or more.
//!
//! How it is measured: a counting global allocator that tracks the bytes
//! currently allocated by this process and the highest value reached
//! (the same approach as `group_ram.rs`). The pieces being served are held by
//! the test source for the whole run, so they are part of the baseline; the
//! growth is what the receive itself keeps alive. The test is alone in this
//! file so no other test shares the process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use miasma_core::{
    dissolution::segment::dissolve_segment_with,
    network::types::{DhtRecord, ShardLocation},
    transfer::{
        receive_stream, PieceSource, Protection, SegmentEntry, SegmentSink, SinkError,
        StreamOutcome, StreamSpec, TransferManifest, TransferProgress,
    },
    ContentId, DissolutionParams, MiasmaError, MiasmaShare,
};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn bump(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: every call is forwarded unchanged to the system allocator; the
// counters are only updated from the size the caller passed or got back.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            bump(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            bump(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let q = System.realloc(p, l, new_size);
        if !q.is_null() {
            if new_size >= l.size() {
                bump(new_size - l.size());
            } else {
                LIVE.fetch_sub(l.size() - new_size, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const SEG: usize = 256 * 1024;
const SEGMENTS: usize = 32;
/// Peak growth allowed: a dozen segments. Fetched pieces, their copies for the
/// decoder, the reconstructed ciphertext and the plaintext are each about one
/// segment; the object is 32.
const LIMIT: usize = 12 * SEG;

struct MemSource(HashMap<(u32, u16), MiasmaShare>);

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

/// Keeps a digest and a count, nothing else.
struct DigestSink {
    hasher: blake3::Hasher,
    segments: u32,
    largest_call: usize,
}

#[async_trait]
impl SegmentSink for DigestSink {
    async fn accept(&mut self, _index: u32, data: &[u8]) -> Result<(), SinkError> {
        self.hasher.update(data);
        self.segments += 1;
        self.largest_call = self.largest_call.max(data.len());
        Ok(())
    }
}

#[test]
fn streaming_a_long_object_keeps_the_heap_near_one_segment() {
    // ── The object, dissolved once; only a digest of it is kept. ──
    let params = DissolutionParams {
        data_shards: 4,
        total_shards: 6,
    };
    let mut data = vec![0u8; SEG * SEGMENTS];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2654435761).to_le_bytes()[2];
    }
    let expected = blake3::hash(&data);
    let mid = ContentId::compute(&data, &params.to_param_bytes());
    let mut manifest = TransferManifest::new(
        &mid,
        [0x33; 32],
        params,
        SEG as u32,
        data.len() as u64,
        Protection::None,
    );
    let mut shares = HashMap::new();
    let mut locations = Vec::new();
    for (i, chunk) in data.chunks(SEG).enumerate() {
        let (_, seg_shares) =
            dissolve_segment_with(chunk, &mid, i as u32, 0, params, None).unwrap();
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
    drop(data);
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: 4,
        total_shards: 6,
        version: 1,
        locations,
        published_at: 1,
    };
    let source = MemSource(shares);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    // Warm up the runtime and its blocking pool so their one-off allocations are
    // part of the baseline.
    rt.block_on(async {
        tokio::task::spawn_blocking(|| vec![0u8; 1024])
            .await
            .unwrap();
    });

    let mut sink = DigestSink {
        hasher: blake3::Hasher::new(),
        segments: 0,
        largest_call: 0,
    };
    let spec = StreamSpec::new(mid.clone(), record, Some(manifest));
    let stats = spec.stats.clone();
    let progress = TransferProgress::new(mid.to_string());

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let outcome = rt
        .block_on(receive_stream(&source, spec, &mut sink, progress))
        .unwrap();
    let peak = PEAK.load(Ordering::Relaxed);
    let growth = peak.saturating_sub(baseline);
    let after = LIVE.load(Ordering::Relaxed).saturating_sub(baseline);

    println!(
        "object {} MiB in {} segments of {} KiB: peak growth {:.2} MiB, left behind {} KiB",
        SEG * SEGMENTS / (1024 * 1024),
        SEGMENTS,
        SEG / 1024,
        growth as f64 / 1048576.0,
        after / 1024
    );

    assert_eq!(
        outcome,
        StreamOutcome::Complete {
            segments: SEGMENTS as u32,
            bytes: (SEG * SEGMENTS) as u64
        }
    );
    assert_eq!(sink.segments, SEGMENTS as u32);
    assert_eq!(
        sink.largest_call, SEG,
        "the sink sees one segment at a time"
    );
    assert_eq!(sink.hasher.finalize(), expected, "the bytes are the object");
    let s = stats.snapshot();
    assert_eq!(
        (s.created, s.wiped, s.wipe_failures, s.live),
        (32, 32, 0, 0)
    );
    assert_eq!(s.peak_live, 1);
    assert!(
        growth <= LIMIT,
        "peak heap grew by {growth} bytes for a {} byte object; limit {LIMIT}",
        SEG * SEGMENTS
    );
    assert!(
        after <= 512 * 1024,
        "{after} bytes stayed allocated after the receive"
    );
}
