//! Memory cost of group chat: opening the state of 32 groups of 32 members
//! (with messages waiting) may grow the process by at most 4 MiB, and a
//! 32-member group in which every member writes and everyone receives (the
//! cipher, the history, the vectors and the session state of 32 engines in this
//! process) may grow it by at most 3 MiB with a flat curve.
//!
//! How it is measured: as in `chat_ram.rs` (private bytes of this process,
//! sampled at fixed intervals after a warm-up that is taken out of the
//! baseline). The test is alone in this file so no other test shares the
//! process. On other systems it only checks the data.

use std::sync::Arc;

use miasma_core::{
    chat::{
        crypto::Identity,
        engine::ChatCore,
        group::{engine::GroupCore, store::GroupStore},
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

struct Node {
    chat: Arc<ChatCore>,
    core: GroupCore,
}

fn open(dir: &std::path::Path, seed: &[u8; 32], keys: Arc<StateKeys>) -> Node {
    let s = StoreSettings {
        defer_flush: true,
        ..StoreSettings::default()
    };
    let id = Identity::from_seed(seed);
    let chat_dir = dir.join("chat");
    let store = ChatStore::open(&chat_dir, keys.clone(), id.id(), s.clone()).unwrap();
    let (outbox, _) = Outbox::open(
        &miasma_core::paths::chat_outbox_file(&chat_dir),
        keys.clone(),
        s.clone(),
        1,
    );
    let chat = Arc::new(ChatCore::new(store, outbox, id, 4096));
    let gs = GroupStore::open(&chat_dir, keys, chat.own_id(), s).unwrap();
    let core = GroupCore::new(chat.clone(), gs, seed).unwrap();
    Node { chat, core }
}

#[test]
fn group_state_is_small_when_idle_and_flat_with_thirty_two_members() {
    let root = tempfile::tempdir().unwrap();

    // ── Idle: 32 groups of 32 members, messages waiting in each ──
    let keys0 = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let seed0: [u8; 32] = rand::random();
    let d0 = root.path().join("idle");
    std::fs::create_dir_all(&d0).unwrap();
    {
        let n = open(&d0, &seed0, keys0.clone());
        for g in 0..32 {
            let others: Vec<([u8; 32], String)> = (0..31)
                .map(|_| (Identity::from_seed(&rand::random()).id(), "member".to_owned()))
                .collect();
            let gid = n.core.create(&format!("group {g}"), &others, 1).unwrap();
            for k in 0..5 {
                n.core.send(&gid, &format!("waiting {k}"), 2 + k).unwrap();
            }
        }
        n.core.flush_all();
        n.core.close();
        n.chat.store.close();
    }
    {
        let warm = open(&d0, &seed0, keys0.clone());
        let _ = warm.core.list();
    }
    let idle_base = resident_bytes().unwrap_or(0);
    let n = open(&d0, &seed0, keys0);
    let listed = n.core.list();
    let idle_peak = resident_bytes().unwrap_or(0);
    assert_eq!(listed.len(), 32);
    assert!(listed.iter().all(|g| g.members == 32 && g.pending > 0));
    let idle_growth = idle_peak.saturating_sub(idle_base);
    println!(
        "idle: {} groups of 32, growth {:.2} MiB",
        listed.len(),
        idle_growth as f64 / 1048576.0
    );
    if resident_bytes().is_some() {
        assert!(
            idle_growth <= 4 * 1024 * 1024,
            "idle group state grew by {idle_growth} bytes"
        );
    }
    drop(n);

    // ── Soak: one group of 32, everybody writes, everybody receives ──
    let nodes: Vec<Node> = (0..32)
        .map(|i| {
            let d = root.path().join(format!("n{i}"));
            std::fs::create_dir_all(&d).unwrap();
            let keys = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
            open(&d, &rand::random(), keys)
        })
        .collect();
    let ids: Vec<[u8; 32]> = nodes.iter().map(|n| n.core.own_id()).collect();
    let members: Vec<([u8; 32], String)> = ids[1..].iter().map(|i| (*i, String::new())).collect();
    let gid = nodes[0].core.create("everyone", &members, 1).unwrap();
    let trust_all = |_: &[u8; 32]| true;

    // Deliver everything owed from `from` to the others.
    let pump = |from: usize| {
        for (j, to) in nodes.iter().enumerate() {
            if j == from {
                continue;
            }
            while let Some(out) = nodes[from].core.next_for(&ids[j]) {
                let (wire, _) = nodes[from].chat.seal_for(&ids[j], &out.plain).unwrap();
                let st = to.core.accept(&ids[from], &wire, 5, &trust_all).status;
                assert!(
                    matches!(st, AckStatus::Stored | AckStatus::Duplicate),
                    "{st:?}"
                );
                nodes[from].core.delivered(&ids[j], &out.work);
            }
        }
    };
    pump(0);
    for n in &nodes[1..] {
        n.core.accept_invite(&gid).unwrap();
    }
    // Everyone writes once so that every pair has its session.
    let mut round = 0u64;
    let mut step = |k: u64| {
        let from = (k % 32) as usize;
        round += 1;
        nodes[from]
            .core
            .send(&gid, &format!("message {k}: こんにちは、今日はいい天気ですね。"), 100 + round)
            .unwrap();
        pump(from);
    };
    for k in 0..64 {
        step(k);
    }
    let baseline = resident_bytes().unwrap_or(0);
    let mut peak = baseline;
    let mut curve: Vec<(u64, u64)> = Vec::new();
    let total = 960u64;
    for k in 0..total {
        step(64 + k);
        if (k + 1) % 160 == 0 {
            if let Some(r) = resident_bytes() {
                peak = peak.max(r);
                curve.push((k + 1, r.saturating_sub(baseline)));
            }
        }
    }
    // Everybody has everything, once.
    for n in &nodes {
        let h = n.core.history(&gid, None, 200).unwrap();
        assert!(!h.is_empty());
        assert_eq!(n.core.list()[0].pending, 0);
    }
    assert_eq!(nodes[5].core.vector_of(&gid, &ids[0]).unwrap().2, 0);
    match resident_bytes() {
        Some(_) => {
            let growth = peak.saturating_sub(baseline);
            println!(
                "soak: {total} messages to 32 members: baseline {:.2} MiB, growth {:.2} MiB",
                baseline as f64 / 1048576.0,
                growth as f64 / 1048576.0
            );
            for (k, over) in &curve {
                println!(
                    "  {k:>5} messages: {:.2} MiB over baseline",
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
