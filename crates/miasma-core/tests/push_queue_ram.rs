//! Memory cost of the durable send queue: a thousand queued jobs may grow the
//! process by at most 4 MiB, and queueing, progressing and finishing jobs over
//! and over (the outbox) and filling then emptying the service's queue (500
//! waiting sends, again and again) must keep the curve flat.
//!
//! How it is measured: with a counting global allocator that tracks the bytes
//! currently allocated by this process. Process-level counters (resident or
//! private bytes) move in allocator-sized steps and with the page-touch
//! behaviour of the build (an instrumented coverage build touches pages at
//! other moments), so a bounded structure showed up as a rising curve on some
//! runs. Live heap bytes depend only on what the code keeps. A warm-up first
//! fills every capped structure so the baseline is taken at steady state. The
//! test is alone in this file so no other test shares the process.

#![cfg(feature = "iroh")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use miasma_core::{
    config::PushConfig,
    push::{
        link::{Dialer, Link},
        outbox::{OutJob, Outbox},
        service::{PushService, PushSettings},
        ContactCode, PushState,
    },
    transport::iroh_direct::IrohClientError,
};

/// Global allocator that keeps a running total of the bytes in use.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is forwarded unchanged to the system allocator; the
// counter is only updated from the size the caller passed or got back.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
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
                LIVE.fetch_add(new_size - l.size(), Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(l.size() - new_size, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live_bytes() -> u64 {
    LIVE.load(Ordering::Relaxed) as u64
}

fn job(i: usize) -> OutJob {
    OutJob {
        id: format!("{i:016x}"),
        contact_id: "c1".into(),
        path: format!("C:/Users/someone/Documents/folder/報告書の下書き_{i}.pdf"),
        name: format!("報告書の下書き_{i}.pdf"),
        size: 1_000_000 + i as u64,
        mtime_ms: 1_700_000_000_000,
        hash: Some("ab".repeat(32)),
        offset: 0,
        attempt: 0,
        created_at_ms: i as u64,
    }
}

struct Offline;

#[async_trait::async_trait]
impl Dialer for Offline {
    async fn dial(&self, _t: &[u8; 32]) -> Result<Arc<dyn Link>, IrohClientError> {
        Err(IrohClientError::Unreachable("offline".into()))
    }
}

fn check_flat(what: &str, base: u64, curve: &[(usize, u64)], max_growth: u64) {
    let peak = curve.iter().map(|c| c.1).max().unwrap_or(base);
    let growth = peak.saturating_sub(base);
    println!(
        "{what}: baseline {:.2} MiB, max {:.2} MiB, growth {:.2} MiB",
        base as f64 / 1048576.0,
        peak as f64 / 1048576.0,
        growth as f64 / 1048576.0
    );
    for (k, r) in curve {
        println!(
            "  {k:>7}: {:.2} MiB over baseline",
            r.saturating_sub(base) as f64 / 1048576.0
        );
    }
    assert!(growth <= max_growth, "{what}: grew by {growth} bytes");
    let first = curve.first().map(|c| c.1).unwrap_or(base);
    let last = curve.last().map(|c| c.1).unwrap_or(base);
    assert!(
        last.saturating_sub(first) <= 512 * 1024,
        "{what}: the curve keeps rising: {first} -> {last}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_thousand_queued_jobs_are_small_and_the_curve_is_flat() {
    // ── The stored queue: 1000 jobs resident, then churn ──
    let dir = tempfile::tempdir().unwrap();
    {
        // Warm-up of the same code paths.
        let w = Outbox::open(dir.path());
        for i in 0..200 {
            w.put(&job(i), false);
        }
        for i in 0..200 {
            w.update(&job(i).id, |j| j.offset = 5);
            w.remove(&job(i).id);
        }
    }
    let base = live_bytes();
    let ob = Outbox::open(dir.path());
    for i in 0..1000 {
        ob.put(&job(i), false);
    }
    assert_eq!(ob.len(), 1000);
    let mut curve = vec![(1000usize, live_bytes())];
    // 100 000 progress updates and 50 full replacements of the queue.
    for round in 0..50usize {
        for i in 0..1000 {
            ob.update(&job(i).id, |j| {
                j.offset = (round * 1000 + i) as u64;
                j.attempt = (round % 7) as u32;
            });
            ob.update(&job(i).id, |j| j.offset += 1);
        }
        if round % 10 == 9 {
            curve.push(((round + 1) * 2000, live_bytes()));
        }
    }
    for i in 0..1000 {
        ob.remove(&job(i).id);
    }
    assert!(ob.is_empty());
    check_flat("1000 queued jobs", base, &curve, 4 * 1024 * 1024);
    drop(ob);
    // The log was compacted on the way: it does not hold 100 000 records.
    let size = std::fs::metadata(miasma_core::paths::PUSH_OUTBOX.in_dir(dir.path()))
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(size < 4 * 1024 * 1024, "the queue log grew to {size} bytes");

    // ── The service: 500 sends waiting for an offline contact, again and again ──
    let sdir = tempfile::tempdir().unwrap();
    let mut settings = PushSettings::from_config(&PushConfig::default(), sdir.path());
    settings.retry.window = None;
    let svc =
        PushService::start_with_dialer(sdir.path(), rand::random(), Arc::new(Offline), settings);
    svc.add_contact(&ContactCode::new(rand::random()), Some("bob"))
        .unwrap();
    let file = sdir.path().join("tiny.bin");
    std::fs::write(&file, b"hello").unwrap();

    let cycle = |svc: &Arc<PushService>| {
        let ids: Vec<String> = (0..500)
            .map(|_| svc.queue_send("bob", &file).unwrap())
            .collect();
        ids
    };
    async fn drain(svc: &Arc<PushService>, ids: &[String]) {
        for id in ids {
            svc.board().cancel(id);
        }
        for _ in 0..600 {
            if svc.board().active_count() == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the queue did not drain");
    }
    // Warm-up: the history of finished sends (kept in memory up to a fixed size, trimmed at
    // 2000 entries) has to reach its ceiling first, or its one-time fill reads as a leak.
    for _ in 0..6 {
        let ids = cycle(&svc);
        drain(&svc, &ids).await;
    }
    let base = live_bytes();
    let mut curve = Vec::new();
    for round in 1..=20usize {
        let ids = cycle(&svc);
        // They all sit in the queue; the first one is waiting to retry.
        for _ in 0..200 {
            if svc.board().get(&ids[0]).map(|t| t.state) == Some(PushState::Waiting) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert_eq!(svc.queue_snapshot().len(), 500);
        if round == 1 {
            // 500 queued: the high-water mark.
            curve.push((round, live_bytes()));
        }
        drain(&svc, &ids).await;
        if round % 5 == 0 {
            curve.push((round, live_bytes()));
        }
    }
    check_flat(
        "500 waiting sends, 20 rounds",
        base,
        &curve,
        6 * 1024 * 1024,
    );
    svc.shutdown();
}
