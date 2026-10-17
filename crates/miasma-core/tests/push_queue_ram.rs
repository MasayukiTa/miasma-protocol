//! Memory cost of the durable send queue: a thousand queued jobs may grow the
//! process by at most 4 MiB, and queueing, progressing and finishing jobs over
//! and over (the outbox) and filling then emptying the service's queue (500
//! waiting sends, again and again) must keep the curve flat.
//!
//! How it is measured: the private (commit) bytes of this process (`VmRSS` on
//! Linux; `GetProcessMemoryInfo` private usage on Windows). A warm-up faults
//! in the code and allocator arenas first. The test is alone in this file so
//! no other test shares the process. On other systems it only checks the
//! data.

#![cfg(feature = "iroh")]

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

#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb: u64 = s
        .lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb * 1024)
}

#[cfg(windows)]
fn resident_bytes() -> Option<u64> {
    #[repr(C)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(p: isize, c: *mut Counters, cb: u32) -> i32;
    }
    // SAFETY: valid pointer to a correctly laid out struct of the stated size.
    unsafe {
        let mut c: Counters = std::mem::zeroed();
        c.cb = std::mem::size_of::<Counters>() as u32;
        if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) == 0 {
            return None;
        }
        Some(c.pagefile_usage as u64)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn resident_bytes() -> Option<u64> {
    None
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
    if resident_bytes().is_none() {
        println!("no memory probe on this platform; data checks only");
        return;
    }
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
    let base = resident_bytes().unwrap_or(0);
    let ob = Outbox::open(dir.path());
    for i in 0..1000 {
        ob.put(&job(i), false);
    }
    assert_eq!(ob.len(), 1000);
    let mut curve = vec![(1000usize, resident_bytes().unwrap_or(0))];
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
            curve.push(((round + 1) * 2000, resident_bytes().unwrap_or(0)));
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
    let base = resident_bytes().unwrap_or(0);
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
            curve.push((round, resident_bytes().unwrap_or(0)));
        }
        drain(&svc, &ids).await;
        if round % 5 == 0 {
            curve.push((round, resident_bytes().unwrap_or(0)));
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
