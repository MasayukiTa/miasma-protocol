//! Memory cost of the offline-delivery queues: 20 000 messages go through the
//! sealed-envelope store of the outbox, the in-memory custody store (with
//! items that expire and items that are never collected) and the catch-up
//! between two engines in this process. The process may grow by at most 3 MiB
//! over the run, with a flat curve, and the sizes of the queues themselves
//! stay within their stated bounds.
//!
//! Measured like `chat_ram.rs`: private (commit) bytes, sampled every 2 000
//! messages after a warm-up, alone in this file so no other test shares the
//! process. On other systems only the data checks run.

use std::sync::Arc;

use miasma_core::{
    chat::{
        crypto::Identity,
        engine::ChatCore,
        mailbox::{
            holder::{CustodyLimits, CustodyStore, MemoryCustody},
            ids::{ItemId, RecipientTag},
        },
        outbox::{Outbox, SEALED_BUDGET},
        store::{ChatStore, StoreSettings},
        sync,
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

const LIMITS_ITEMS: usize = 64;

/// One message from `from` to `to`: sealed and kept, put in custody, an
/// extra item nobody collects, collected and applied by the recipient, and
/// closed at the sender by the catch-up.
fn cycle(from: &ChatCore, to: &ChatCore, custody: &MemoryCustody, i: u64) {
    let now = 1_700_000_000_000 + i * 10;
    let (fid, tid) = (from.own_id(), to.own_id());
    let text = format!(
        "message {i}: こんにちは、今日はいい天気ですね。 {}",
        i % 997
    );
    let id = from.enqueue(&tid, &text, now).unwrap();
    let (wire, env_id) = from.prepare_wire(&id).unwrap();
    let tag = RecipientTag::for_recipient(&tid);
    let mut blob = fid.to_vec();
    blob.extend_from_slice(&wire);
    custody
        .deposit(&fid, tag, ItemId(env_id), &blob, now)
        .unwrap();
    if i % 5 == 0 {
        // Never collected: only the expiry removes it.
        let _ = custody.deposit(
            &fid,
            RecipientTag([9; 16]),
            ItemId(rand::random()),
            &[1u8; 300],
            now,
        );
    }
    for item in custody.list(&tid, tag, now).unwrap() {
        if let Some(b) = custody.fetch(&tid, tag, item, now).unwrap() {
            let (sender, w) = b.split_at(32);
            let sender: [u8; 32] = sender.try_into().unwrap();
            let st = to.accept(&sender, w, now).status;
            assert!(st.is_delivered(), "message {i}: {st:?}");
            custody.delete(&tid, tag, item).unwrap();
        }
    }
    let asked = sync::request_for(from, &tid);
    let have = sync::answer(to, &fid, &asked);
    assert_eq!(sync::apply_reply(from, &tid, &asked, &have, now), 1);
}

fn run(
    a: &ChatCore,
    b: &ChatCore,
    custody: &MemoryCustody,
    first: u64,
    n: u64,
    mut each: impl FnMut(u64),
) {
    for k in 0..n {
        let i = first + k;
        if (i / 20).is_multiple_of(2) {
            cycle(a, b, custody, i);
        } else {
            cycle(b, a, custody, i);
        }
        if (i + 1).is_multiple_of(100) {
            a.store.flush_all().unwrap();
            b.store.flush_all().unwrap();
        }
        each(k + 1);
    }
}

#[test]
fn the_offline_queues_are_bounded_and_flat_over_twenty_thousand_messages() {
    let dir = tempfile::tempdir().unwrap();
    let keys_a = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let keys_b = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let (seed_a, seed_b): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    let (da, db) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir_all(&da).unwrap();
    std::fs::create_dir_all(&db).unwrap();
    let a = open_core(&da, &seed_a, keys_a);
    let b = open_core(&db, &seed_b, keys_b);
    let custody = MemoryCustody::new(CustodyLimits {
        enabled: true,
        max_items_per_depositor: LIMITS_ITEMS,
        // 100 cycles of 10 ms: the never-collected items live ~20 cycles.
        ttl_ms: 1000,
        ..CustodyLimits::default()
    });
    custody.trust(a.own_id());
    custody.trust(b.own_id());

    run(&a, &b, &custody, 0, 1_000, |_| {});
    let baseline = resident_bytes().unwrap_or(0);
    let mut peak = baseline;
    let mut curve: Vec<(u64, u64)> = Vec::new();
    let mut max_sealed = 0usize;
    let mut max_held = 0usize;
    let mut max_held_bytes = 0usize;
    run(&a, &b, &custody, 1_000, 20_000, |k| {
        max_sealed = max_sealed.max(a.outbox.sealed_bytes().max(b.outbox.sealed_bytes()));
        let st = custody.stats();
        max_held = max_held.max(st.items);
        max_held_bytes = max_held_bytes.max(st.bytes);
        if k % 2_000 == 0 {
            if let Some(r) = resident_bytes() {
                peak = peak.max(r);
                curve.push((k, r.saturating_sub(baseline)));
            }
        }
    });
    // The queues themselves.
    assert!(a.outbox.is_empty() && b.outbox.is_empty());
    assert_eq!(a.outbox.sealed_bytes() + b.outbox.sealed_bytes(), 0);
    assert!(max_sealed <= 32 * 1024, "kept envelopes: {max_sealed}");
    assert!(max_sealed <= SEALED_BUDGET);
    assert!(max_held <= 64, "held items: {max_held}");
    assert!(max_held_bytes <= 64 * 1024, "held bytes: {max_held_bytes}");
    println!(
        "max kept envelope bytes {max_sealed}, max held items {max_held} ({max_held_bytes} bytes)"
    );
    match resident_bytes() {
        Some(_) => {
            let growth = peak.saturating_sub(baseline);
            println!(
                "offline queues: 20000 messages: baseline {:.2} MiB, growth {:.2} MiB",
                baseline as f64 / 1048576.0,
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
