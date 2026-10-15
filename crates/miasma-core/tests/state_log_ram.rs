//! Memory cost of the encrypted transfer history: appending and reading one
//! million records may grow the process's resident memory by at most 3 MiB.
//!
//! How it is measured: after a short warm-up (which faults in the code of the
//! append and read paths), the resident size of this process is read (`VmRSS`
//! on Linux; the working set from `GetProcessMemoryInfo` on Windows). One
//! million entries are then appended through `History::append`, streamed back
//! through `LogReader`, and finally the history is opened again, which counts
//! all entries and rewrites the newest 1 000 into a fresh file. The size is
//! sampled every 10 000 records and the test asserts `max(samples) - baseline
//! <= 3 MiB`, and that the curve is flat: the growth after 1 000 000 records is
//! within 512 KiB of the growth after 100 000. The test is alone in this file
//! so no other test shares the process. On other systems it only checks the
//! data.

use miasma_core::{
    paths,
    push::{
        state::{History, HistoryEntry},
        Direction, PushState,
    },
    state_crypto::{self, Label, LogReader, StateKeys},
};

const BUDGET: u64 = 3 * 1024 * 1024;

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
        Some(c.working_set_size as u64)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn resident_bytes() -> Option<u64> {
    None
}

fn entry(i: u64) -> HistoryEntry {
    HistoryEntry {
        id: format!("{i:08}"),
        direction: if i.is_multiple_of(2) {
            Direction::In
        } else {
            Direction::Out
        },
        contact_id: "0123456789abcdef".into(),
        contact_label: "A contact label".into(),
        name: format!("a-fairly-ordinary-file-name-{i}.bin"),
        size: i * 1000,
        state: PushState::Done,
        error: None,
        reject_reason: None,
        error_kind: None,
        source_path: Some(format!("C:/Users/someone/Documents/folder/file-{i}.bin")),
        saved_as: None,
        finished_at_ms: 1_700_000_000_000 + i,
    }
}

struct Probe {
    baseline: u64,
    peak: u64,
    curve: Vec<(&'static str, u64, u64)>,
}

impl Probe {
    fn sample(&mut self) {
        if let Some(r) = resident_bytes() {
            self.peak = self.peak.max(r);
        }
    }
    fn mark(&mut self, phase: &'static str, n: u64) {
        if let Some(r) = resident_bytes() {
            self.peak = self.peak.max(r);
            self.curve.push((phase, n, r.saturating_sub(self.baseline)));
        }
    }
}

/// 100 000 records: quick enough for every CI run (the encryption runs
/// unoptimised in debug builds).
#[test]
fn a_hundred_thousand_history_records_stay_flat_in_memory() {
    run(100_000, 10_000);
}

/// The full one-million-record measurement. About 14 minutes in a debug
/// build: `cargo test -p miasma-core --test state_log_ram -- --ignored --nocapture`.
#[test]
#[ignore]
fn one_million_history_records_grow_resident_memory_by_at_most_3_mib() {
    run(1_000_000, 100_000);
}

fn run(records: u64, step: u64) {
    let dir = tempfile::tempdir().unwrap();
    state_crypto::provision_master_key(dir.path()).unwrap();
    let history_path = dir.path().join(paths::PUSH_HISTORY.name);
    let history = History::open(dir.path());

    // Warm-up: first calls fault in code pages and allocator arenas. That is
    // program size, not history length, so it is taken out of the baseline.
    for i in 0..2_000 {
        history.append(&entry(i));
    }
    let keys = StateKeys::load(dir.path()).unwrap();
    {
        let mut r = LogReader::open(&keys, Label::PushHistory, &history_path)
            .unwrap()
            .unwrap();
        while r.next_record().unwrap().is_some() {}
    }
    let baseline = resident_bytes().unwrap_or(0);
    let mut probe = Probe {
        baseline,
        peak: baseline,
        curve: Vec::new(),
    };

    // Phase A: append.
    for i in 0..records {
        history.append(&entry(2_000 + i));
        if i.is_multiple_of(10_000) {
            probe.sample();
        }
        if (i + 1).is_multiple_of(step) {
            probe.mark("append", i + 1);
        }
    }

    // Phase B: stream everything back, one record at a time.
    let mut r = LogReader::open(&keys, Label::PushHistory, &history_path)
        .unwrap()
        .unwrap();
    let mut n = 0u64;
    let mut last_id = String::new();
    while let Some(rec) = r.next_record().unwrap() {
        n += 1;
        if n.is_multiple_of(10_000) {
            probe.sample();
            if n.is_multiple_of(step) {
                probe.mark("read", n);
            }
        }
        if n == records + 2_000 {
            let e: HistoryEntry = serde_json::from_slice(&rec).unwrap();
            last_id = e.id;
        }
    }
    assert_eq!(n, records + 2_000);
    assert!(r.torn_at().is_none());
    assert_eq!(last_id, format!("{:08}", 2_000 + records - 1));
    drop(r);
    let file_len = std::fs::metadata(&history_path).unwrap().len();

    // Phase C: opening the history counts every entry and trims it to the
    // newest 1 000, streaming from the old file into the new one.
    drop(history);
    let reopened = History::open(dir.path());
    probe.mark("open+trim", records + 2_000);
    let newest = reopened.list(5);
    assert_eq!(newest.len(), 5);
    assert_eq!(newest[0].id, format!("{:08}", 2_000 + records - 1));
    assert_eq!(reopened.list(100_000).len(), 1_000);
    assert!(std::fs::metadata(&history_path).unwrap().len() < file_len / 100);
    probe.mark("list", 1_000);

    match resident_bytes() {
        Some(_) => {
            let growth = probe.peak.saturating_sub(baseline);
            println!(
                "history of {} records ({:.1} MiB on disk): baseline {:.2} MiB, max {:.2} MiB, growth {:.2} MiB",
                records,
                file_len as f64 / 1048576.0,
                baseline as f64 / 1048576.0,
                probe.peak as f64 / 1048576.0,
                growth as f64 / 1048576.0
            );
            for (phase, n, over) in &probe.curve {
                println!(
                    "  {phase:>10} {n:>8} records: {:.2} MiB over baseline",
                    *over as f64 / 1048576.0
                );
            }
            let at = |phase: &str, n: u64| {
                probe
                    .curve
                    .iter()
                    .find(|(p, k, _)| *p == phase && *k == n)
                    .map(|(_, _, o)| *o)
                    .unwrap()
            };
            let a100 = at("append", step);
            let a1m = at("append", records);
            let r100 = at("read", step);
            let r1m = at("read", records);
            assert!(
                a1m.saturating_sub(a100) <= 512 * 1024,
                "append keeps growing: {a100} -> {a1m}"
            );
            assert!(
                r1m.saturating_sub(r100) <= 512 * 1024,
                "read keeps growing: {r100} -> {r1m}"
            );
            assert!(
                growth <= BUDGET,
                "resident memory grew by {growth} bytes (> {BUDGET})"
            );
        }
        None => println!("no resident-size probe on this platform; data checks only"),
    }
}
