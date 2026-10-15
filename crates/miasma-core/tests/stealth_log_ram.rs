//! Memory cost of stealth logging: one million log lines may grow the
//! process's resident memory by at most 4 MiB.
//!
//! How it is measured: the subscriber (and with it the whole 2 MiB ring
//! buffer) is built first, then the resident size of this process is read
//! (`VmRSS` from `/proc/self/status` on Linux; the private (commit) bytes from
//! `GetProcessMemoryInfo` on Windows, because the working set is trimmed and
//! re-faulted by the system, which made the test depend on what else the
//! machine was doing). One million events then go through the
//! normal `tracing` macros, the size is sampled every 10 000 events, and the
//! test asserts that `max(samples) - baseline <= 4 MiB`. The ring is
//! allocated zeroed and untouched, so the ring's own pages count as growth
//! here: the budget covers them (up to 2 MiB) plus the per-thread scratch
//! buffers. The test is alone in this file so no other test shares the
//! process. On other systems it only checks that the buffer stays bounded.

use miasma_core::config::PrivacyConfig;
use miasma_core::logging::{build, Component, InitOptions};

const BUDGET: u64 = 4 * 1024 * 1024;

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

#[test]
fn one_million_lines_grow_resident_memory_by_at_most_4_mib() {
    let dir = tempfile::tempdir().unwrap();
    let privacy = PrivacyConfig::default();
    let (logger, sub) = build(
        &InitOptions {
            component: Component::Daemon,
            data_dir: dir.path(),
            filter_env: "MIASMA_TEST_UNSET_FILTER",
            default_filter: "info",
            process_hardening: false,
        },
        &privacy,
    );

    let mut baseline = None;
    let mut peak = 0;
    let mut curve: Vec<(u32, u64)> = Vec::new();
    tracing::subscriber::with_default(sub, || {
        // Warm-up: the first events fault in the code pages of the logging
        // path and register the call site. That one-off cost is program size,
        // not logging volume, so it is taken out of the baseline. Only 2 000
        // lines are written, so nearly all of the ring is still untouched.
        for i in 0..2_000u32 {
            tracing::info!(i, peer = "x", "log line number for the memory test");
        }
        baseline = resident_bytes();
        peak = baseline.unwrap_or(0);
        for i in 0..1_000_000u32 {
            tracing::info!(i, peer = "x", "log line number for the memory test");
            if i % 10_000 == 0 {
                if let Some(r) = resident_bytes() {
                    peak = peak.max(r);
                    if i % 100_000 == 0 {
                        curve.push((i, r));
                    }
                }
            }
        }
    });
    if let Some(r) = resident_bytes() {
        peak = peak.max(r);
    }

    assert_eq!(logger.read(None, 0, 0).next_seq, 1_002_000);
    assert!(logger.read(None, 10, 1 << 20).lines.len() == 10);
    match baseline {
        Some(b) => {
            let growth = peak.saturating_sub(b);
            println!(
                "resident growth after 1,000,000 lines: {:.2} MiB (baseline {:.1} MiB, peak {:.1} MiB, ring {} KiB)",
                growth as f64 / 1048576.0,
                b as f64 / 1048576.0,
                peak as f64 / 1048576.0,
                logger.ring_capacity() / 1024
            );
            // Growth must level off once the ring has been filled: no
            // per-line leak. From 300 000 lines on, at most 512 KiB more.
            for (i, r) in &curve {
                println!(
                    "  after {i:>7} lines: {:.2} MiB over baseline",
                    r.saturating_sub(b) as f64 / 1048576.0
                );
            }
            let at_300k = curve
                .iter()
                .find(|(i, _)| *i >= 300_000)
                .map(|(_, r)| *r)
                .unwrap();
            assert!(
                peak.saturating_sub(at_300k) <= 512 * 1024,
                "resident memory keeps growing after the ring is full"
            );
            assert!(
                growth <= BUDGET,
                "resident memory grew by {growth} bytes (> {BUDGET})"
            );
        }
        None => println!("no resident-size probe on this platform; bounded-buffer check only"),
    }
}
