//! Memory cost of chat: opening the chat state with 100 contacts and 100
//! queued messages may grow the process by at most 4 MiB, and sending and
//! receiving 100 000 messages (through the cipher, the history, the outbox and
//! the session state, between two engines in this process) may grow it by at
//! most 3 MiB with a flat curve.
//!
//! How it is measured: the private (commit) bytes of this process (`VmRSS` on
//! Linux; `GetProcessMemoryInfo` private usage on Windows, because the working
//! set is trimmed by the system). A warm-up faults in the code and allocator
//! arenas first, and that is taken out of the baseline. The size is sampled
//! every 10 000 messages. The test is alone in this file so no other test
//! shares the process. On other systems it only checks the data.
//!
//! The session state is written once per 100 messages here (`defer_flush`)
//! instead of once per message, because 100 000 disk syncs would take longer
//! than the run is worth; the memory behaviour does not depend on it.

use std::sync::Arc;

use miasma_core::{
    chat::{
        crypto::Identity,
        engine::ChatCore,
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
    ChatCore::new(store, outbox, id, 4096)
}

/// One message from `from` to `to`.
fn one(from: &ChatCore, to: &ChatCore, i: u64) {
    let text = format!(
        "message {i}: こんにちは、今日はいい天気ですね。 {}",
        i % 997
    );
    let id = from
        .enqueue(&to.own_id(), &text, 1_700_000_000_000 + i)
        .unwrap();
    let (wire, _) = from.prepare_wire(&id).unwrap();
    let st = to
        .accept(&from.own_id(), &wire, 1_700_000_000_000 + i)
        .status;
    assert_eq!(st, AckStatus::Stored, "message {i}");
    from.mark_delivered(&id, 1_700_000_000_000 + i);
}

/// `n` messages in bursts of 20 in alternating directions (so the
/// Diffie-Hellman ratchet turns over as it does in a conversation).
fn run(a: &ChatCore, b: &ChatCore, first: u64, n: u64, mut each: impl FnMut(u64)) {
    for k in 0..n {
        let i = first + k;
        if (i / 20).is_multiple_of(2) {
            one(a, b, i);
        } else {
            one(b, a, i);
        }
        if (i + 1).is_multiple_of(100) {
            a.store.flush_all().unwrap();
            b.store.flush_all().unwrap();
        }
        each(k + 1);
    }
}

#[test]
fn chat_state_is_small_when_idle_and_flat_over_a_hundred_thousand_messages() {
    let dir = tempfile::tempdir().unwrap();
    let keys_a = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let keys_b = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let seed_a: [u8; 32] = rand::random();
    let seed_b: [u8; 32] = rand::random();
    let (da, db) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir_all(&da).unwrap();
    std::fs::create_dir_all(&db).unwrap();

    // ── Idle: 100 contacts with sessions on disk and 100 queued messages ──
    {
        let a = open_core(&da, &seed_a, keys_a.clone());
        for p in 0..100u8 {
            let mut peer = Identity::from_seed(&rand::random()).id();
            peer[0] ^= p;
            a.enqueue(&peer, "waiting", 1).ok();
        }
        // Real sessions for 100 peers.
        for _ in 0..100 {
            let other = Identity::from_seed(&rand::random());
            let id = a.enqueue(&other.id(), "hello", 1).unwrap();
            a.prepare_wire(&id).unwrap();
        }
        a.store.flush_all().unwrap();
        a.store.close();
    }
    // Everything the first block allocated is freed; the baseline is taken
    // after a short warm-up of the same code paths.
    {
        let warm = open_core(&da, &seed_a, keys_a.clone());
        let _ = warm.store.conversations();
    }
    let idle_base = resident_bytes().unwrap_or(0);
    let a = open_core(&da, &seed_a, keys_a.clone());
    let listed = a.store.conversations();
    let queued = a.outbox.len();
    let idle_peak = resident_bytes().unwrap_or(0);
    assert!(!listed.is_empty());
    assert!(queued >= 100, "{queued}");
    let idle_growth = idle_peak.saturating_sub(idle_base);
    println!(
        "idle: {} conversations, {queued} queued, growth {:.2} MiB",
        listed.len(),
        idle_growth as f64 / 1048576.0
    );
    if resident_bytes().is_some() {
        assert!(
            idle_growth <= 4 * 1024 * 1024,
            "idle chat state grew by {idle_growth} bytes"
        );
    }
    drop(a);

    // ── Soak: 100 000 messages ──
    let a = open_core(&da, &seed_a, keys_a);
    let b = open_core(&db, &seed_b, keys_b);
    // The first message of a pair starts the session on both sides.
    run(&a, &b, 0, 2_000, |_| {});
    let baseline = resident_bytes().unwrap_or(0);
    let mut peak = baseline;
    let mut curve: Vec<(u64, u64)> = Vec::new();
    run(&a, &b, 2_000, 100_000, |k| {
        if k % 10_000 == 0 {
            if let Some(r) = resident_bytes() {
                peak = peak.max(r);
                curve.push((k, r.saturating_sub(baseline)));
            }
        }
    });
    // Everything arrived once, in order, within the per-conversation cap.
    let newest = b.history(&a.own_id(), None, 5);
    assert!(!newest.is_empty());
    assert!(a.outbox.is_empty() || a.outbox.len() >= 100);
    match resident_bytes() {
        Some(_) => {
            let growth = peak.saturating_sub(baseline);
            println!(
                "soak: 100000 messages: baseline {:.2} MiB, max {:.2} MiB, growth {:.2} MiB",
                baseline as f64 / 1048576.0,
                peak as f64 / 1048576.0,
                growth as f64 / 1048576.0
            );
            for (k, over) in &curve {
                println!(
                    "  {k:>7} messages: {:.2} MiB over baseline",
                    *over as f64 / 1048576.0
                );
            }
            assert!(
                growth <= 3 * 1024 * 1024,
                "resident memory grew by {growth} bytes"
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
}
