//! Memory cost of a file publish: the peak heap of publishing a long file must not
//! grow with the number of segments, the plaintext pool must stay within its cap,
//! and what the pool keeps must be freed when the pool is wiped.
//!
//! Two files are published in the same process, the first of 2 segments and the
//! second of 4. If a publish kept plaintext (or its by-products) per segment, the
//! second peak would be about two segments above the first.
//!
//! Counting global allocator, same approach as `receive_stream_ram.rs`. The test
//! is alone in this file so no other test shares the process. The two nodes
//! (loopback) run on the test's runtime; their one-off allocations are warmed up
//! with a small publish first so they are part of the baseline.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use miasma_core::{
    transfer::PlaintextPool, DissolutionParams, LocalShareStore, MiasmaCoordinator, MiasmaNode,
    NodeType, PublishOptions,
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

/// `max_segment_size_for(2)` in `network/coordinator.rs`:
/// `(SHARE_MSG_MAX - SHARE_WIRE_OVERHEAD_BYTES) * k` = `(8 MiB - 4096) * 2`.
const MAX_SEGMENT_K2: usize = (8 * 1024 * 1024 - 4096) * 2;
const TAIL: usize = 4 * 1024 * 1024;

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    }
}

/// Write a file of `len` bytes without holding it in memory.
fn write_file(len: usize) -> std::path::PathBuf {
    use std::io::Write;
    let path = tempfile::tempdir().unwrap().keep().join("payload.bin");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
    let mut block = vec![0u8; 1 << 20];
    let mut x: u32 = 0x9E37_79B9;
    let mut left = len;
    while left > 0 {
        let n = left.min(block.len());
        for b in &mut block[..n] {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x >> 24) as u8;
        }
        f.write_all(&block[..n]).unwrap();
        left -= n;
    }
    f.flush().unwrap();
    path
}

async fn spawn_node(key_byte: u8) -> (MiasmaCoordinator, Arc<LocalShareStore>) {
    let dir = tempfile::tempdir().unwrap().keep();
    miasma_core::state_crypto::provision_master_key(&dir).unwrap();
    let store = Arc::new(LocalShareStore::open(&dir, 1000).unwrap());
    let key = [key_byte; 32];
    let mut node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let addrs = node.collect_listen_addrs(400).await;
    let coord = MiasmaCoordinator::start(node, store.clone(), vec![addrs[0].to_string()]).await;
    (coord, store)
}

#[test]
fn publishing_a_long_file_keeps_plaintext_memory_bounded_and_wipeable() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let small = write_file(1024);
    let two = write_file(MAX_SEGMENT_K2 + TAIL);
    let four = write_file(3 * MAX_SEGMENT_K2 + TAIL);

    let (a, b) = rt.block_on(async {
        let (a, _sa) = spawn_node(0xA1).await;
        let (b, _sb) = spawn_node(0xB1).await;
        let addr_a: miasma_core::Multiaddr = a.listen_addrs()[0].parse().unwrap();
        b.add_bootstrap_peer(*a.peer_id(), addr_a).await.unwrap();
        b.bootstrap_dht().await.unwrap();
        b.wait_until_peer_connected(*a.peer_id(), Duration::from_secs(10))
            .await
            .unwrap();
        // Warm up the nodes and the pool with a tiny publish.
        a.dissolve_and_publish_file_with_options(&small, params(), PublishOptions::default())
            .await
            .unwrap();
        (a, b)
    });

    let publish = |path: &std::path::Path| {
        let baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(baseline, Ordering::Relaxed);
        let report = rt
            .block_on(a.dissolve_and_publish_file_with_options(
                path,
                params(),
                PublishOptions::default(),
            ))
            .unwrap();
        let growth = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        let after = LIVE.load(Ordering::Relaxed).saturating_sub(baseline);
        (report, growth, after)
    };

    let (r2, growth2, after2) = publish(&two);
    let (r4, growth4, after4) = publish(&four);
    println!(
        "2 segments: peak growth {:.2} MiB, left {} KiB; 4 segments: peak growth {:.2} MiB, left {} KiB",
        growth2 as f64 / 1048576.0,
        after2 / 1024,
        growth4 as f64 / 1048576.0,
        after4 / 1024
    );
    assert_eq!(r2.remote_distinct_shards_per_segment.len(), 2);
    assert_eq!(r4.remote_distinct_shards_per_segment.len(), 4);

    // The peak does not depend on how many segments there are.
    assert!(
        growth4 <= growth2 + 8 * 1024 * 1024,
        "4-segment publish peaked at {growth4} bytes over baseline, 2-segment at {growth2}: \
         memory grows with the number of segments"
    );
    // And it is a small multiple of one segment (plaintext, ciphertext and the
    // shards of the segment being stored), nowhere near the file.
    let file_len = 3 * MAX_SEGMENT_K2 + TAIL;
    assert!(
        growth4 <= 8 * MAX_SEGMENT_K2,
        "peak {growth4} bytes for a {file_len} byte file"
    );

    // Plaintext went through the shared pool, one buffer at a time, all wiped.
    let pool = PlaintextPool::shared();
    let st = pool.stats().snapshot();
    assert!(st.created >= 1 + 1 + 2 + 1 + 4, "stats: {st:?}");
    assert_eq!(st.wiped, st.created);
    assert_eq!(st.wipe_failures, 0);
    assert_eq!(st.live, 0);
    assert_eq!(st.peak_live, 1, "no two plaintext buffers alive together");
    let p = pool.snapshot();
    assert_eq!(p.live_bytes, 0);
    assert!(p.peak_live_bytes <= MAX_SEGMENT_K2, "pool snapshot: {p:?}");
    assert!(p.reuses > 0, "segments after the first reuse the buffer");
    assert!(
        p.idle_bytes <= pool.idle_cap(),
        "idle {} over cap {}",
        p.idle_bytes,
        pool.idle_cap()
    );
    // What stays allocated afterwards is what the pool keeps idle, not more.
    assert!(
        after4 <= p.idle_bytes + 8 * 1024 * 1024,
        "{after4} bytes stayed allocated; the pool holds {} idle",
        p.idle_bytes
    );

    // Wiping the pool frees the idle buffers.
    let live_before = LIVE.load(Ordering::Relaxed);
    assert!(pool.wipe() >= 1);
    let live_after = LIVE.load(Ordering::Relaxed);
    assert_eq!(pool.snapshot().idle_bytes, 0);
    assert!(
        live_before.saturating_sub(live_after) + 64 * 1024 >= p.idle_bytes,
        "wipe freed {} bytes, the pool held {}",
        live_before.saturating_sub(live_after),
        p.idle_bytes
    );

    rt.block_on(async {
        a.shutdown().await;
        b.shutdown().await;
    });
}
