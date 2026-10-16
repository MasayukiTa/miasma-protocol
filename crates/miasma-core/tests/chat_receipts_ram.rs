//! Memory cost of read receipts: 10 000 receipts, each carrying a message that
//! it reads, go through the cipher, the outbox and the session state between
//! two engines in this process. Memory must stay flat, the outbox must hold at
//! most one receipt per contact however many are asked for, and the event
//! queue must stay at its cap.
//!
//! Measured as in `chat_ram.rs`: private (commit) bytes of this process on
//! Windows, `VmRSS` on Linux; on other systems only the data is checked. The
//! test is alone in this file so no other test shares the process.

use std::sync::Arc;

use miasma_core::{
    chat::{
        crypto::Identity,
        engine::{ChatCore, MarkOutcome},
        outbox::Outbox,
        proto::AckStatus,
        store::{ChatStore, StoreSettings},
    },
    state_crypto::StateKeys,
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

fn open_core(dir: &std::path::Path, seed: &[u8; 32], keys: Arc<StateKeys>) -> ChatCore {
    let s = StoreSettings {
        defer_flush: true,
        ..StoreSettings::default()
    };
    let id = Identity::from_seed(seed);
    let chat = dir.join("chat");
    let store = ChatStore::open(&chat, keys.clone(), id.id(), s.clone()).unwrap();
    let (outbox, _) = Outbox::open(&miasma_core::paths::chat_outbox_file(&chat), keys, s, 1);
    let core = ChatCore::new(store, outbox, id, 4096);
    core.set_receipt_interval_ms(0);
    core
}

/// `a` sends one text to `b`, which reads it and sends a receipt to `a`.
fn round(a: &ChatCore, b: &ChatCore, i: u64) {
    let now = 1_700_000_000_000 + i;
    let id = a.enqueue(&b.own_id(), "read me", now).unwrap();
    let (wire, _) = a.prepare_wire(&id).unwrap();
    assert_eq!(
        b.accept(&a.own_id(), &wire, now).status,
        AckStatus::Stored,
        "text {i}"
    );
    a.mark_delivered(&id, now);
    let newest = i + 1;
    assert_eq!(
        b.mark_read(&a.own_id(), newest, now).unwrap(),
        MarkOutcome::Queued,
        "receipt {i}"
    );
    let r = b.outbox.first_for(&a.own_id()).expect("the receipt");
    let (rw, _) = b.prepare_wire(&r.id).unwrap();
    assert_eq!(
        a.accept(&b.own_id(), &rw, now).status,
        AckStatus::Stored,
        "receipt {i}"
    );
    b.mark_delivered(&r.id, now);
}

#[test]
fn ten_thousand_receipts_leave_memory_flat_and_the_queues_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let keys_a = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let keys_b = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let (seed_a, seed_b): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    let (da, db) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir_all(&da).unwrap();
    std::fs::create_dir_all(&db).unwrap();
    let a = open_core(&da, &seed_a, keys_a);
    let b = open_core(&db, &seed_b, keys_b);

    // Warm-up: the first rounds start the session and fault in the code.
    for i in 0..500 {
        round(&a, &b, i);
    }
    let baseline = resident_bytes().unwrap_or(0);
    let mut peak = baseline;
    let mut curve: Vec<(u64, u64)> = Vec::new();
    for k in 0..10_000u64 {
        round(&a, &b, 500 + k);
        if (k + 1) % 100 == 0 {
            a.store.flush_all().unwrap();
            b.store.flush_all().unwrap();
        }
        if (k + 1) % 1_000 == 0 {
            if let Some(r) = resident_bytes() {
                peak = peak.max(r);
                curve.push((k + 1, r.saturating_sub(baseline)));
            }
        }
    }
    // Nothing is left queued, and every text of `a` shows as read.
    assert!(a.outbox.is_empty() && b.outbox.is_empty());
    let page = a.history(&b.own_id(), None, 5);
    assert!(!page.is_empty());
    assert!(page
        .iter()
        .filter(|m| m.outgoing)
        .all(|m| m.state == miasma_core::chat::store::MsgState::Read));
    // The event queue holds its cap and no more.
    let (_, ev) = a.events_since(0);
    assert!(ev.len() <= 200, "{} events held", ev.len());

    match resident_bytes() {
        Some(_) => {
            let growth = peak.saturating_sub(baseline);
            println!(
                "10000 receipts: baseline {:.2} MiB, max {:.2} MiB, growth {:.2} MiB",
                baseline as f64 / 1048576.0,
                peak as f64 / 1048576.0,
                growth as f64 / 1048576.0
            );
            for (k, over) in &curve {
                println!(
                    "  {k:>7} receipts: {:.2} MiB over baseline",
                    *over as f64 / 1048576.0
                );
            }
            assert!(
                growth <= 3 * 1024 * 1024,
                "memory grew by {growth} bytes over 10000 receipts"
            );
            let first = curve.first().map(|c| c.1).unwrap_or(0);
            let last = curve.last().map(|c| c.1).unwrap_or(0);
            assert!(
                last.saturating_sub(first) <= 512 * 1024,
                "the curve keeps rising: {first} -> {last}"
            );
        }
        None => println!("no memory probe on this platform; data checks only"),
    }
    // Measured first, on its own; this part only checks the data.
    undelivered_receipts_do_not_pile_up();
}

fn undelivered_receipts_do_not_pile_up() {
    let dir = tempfile::tempdir().unwrap();
    let keys_a = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let keys_b = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let (seed_a, seed_b): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    let (da, db) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir_all(&da).unwrap();
    std::fs::create_dir_all(&db).unwrap();
    let a = open_core(&da, &seed_a, keys_a);
    let b = open_core(&db, &seed_b, keys_b);
    // `b` keeps reading but its receipts never get through.
    for i in 0..10_000u64 {
        let now = 1_700_000_000_000 + i;
        let id = a.enqueue(&b.own_id(), "read me", now).unwrap();
        let (wire, _) = a.prepare_wire(&id).unwrap();
        assert_eq!(b.accept(&a.own_id(), &wire, now).status, AckStatus::Stored);
        a.mark_delivered(&id, now);
        assert_eq!(
            b.mark_read(&a.own_id(), i + 1, now).unwrap(),
            MarkOutcome::Queued
        );
        assert_eq!(b.outbox.len(), 1, "after {i} receipts");
    }
    // The log that holds it was compacted along the way, not left to grow.
    b.store.flush_all().unwrap();
    let log = miasma_core::paths::chat_outbox_file(&db.join("chat"));
    let size = std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
    assert!(size < 1024 * 1024, "the outbox log grew to {size} bytes");
}
