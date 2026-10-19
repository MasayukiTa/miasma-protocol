//! Memory cost of group chat: opening the state of 32 groups of 32 members
//! (with messages waiting) may grow the live heap by at most 4 MiB, and a
//! 32-member group in which every member writes and everyone receives (the
//! cipher, the history, the vectors and the session state of 32 engines in this
//! process) may grow it by at most 3 MiB with a flat curve.
//!
//! How it is measured: with a counting global allocator that tracks the bytes
//! currently allocated by this process. Process-level counters (resident or
//! private bytes) were used before, but they move in allocator-sized steps and
//! with the page-touch behaviour of the build (an instrumented coverage build
//! maps and touches pages at other moments), so a bounded structure showed up
//! as a rising curve by a few KiB on some runs. Live heap bytes depend only on
//! what the code keeps. The soak first runs long enough for every capped
//! per-peer structure to be full and rotating (before that the curve rises by
//! design), takes the baseline there and requires the curve to stay flat. The
//! test is alone in this file so no other test shares the process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
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
                .map(|_| {
                    (
                        Identity::from_seed(&rand::random()).id(),
                        "member".to_owned(),
                    )
                })
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
    let idle_base = live_bytes();
    let n = open(&d0, &seed0, keys0);
    let listed = n.core.list();
    let idle_peak = live_bytes();
    assert_eq!(listed.len(), 32);
    assert!(listed.iter().all(|g| g.members == 32 && g.pending > 0));
    let idle_growth = idle_peak.saturating_sub(idle_base);
    println!(
        "idle: {} groups of 32, growth {:.2} MiB",
        listed.len(),
        idle_growth as f64 / 1048576.0
    );
    assert!(
        idle_growth <= 4 * 1024 * 1024,
        "idle group state grew by {idle_growth} bytes"
    );
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
            .send(
                &gid,
                &format!("message {k}: こんにちは、今日はいい天気ですね。"),
                100 + round,
            )
            .unwrap();
        pump(from);
    };
    for k in 0..64 {
        step(k);
    }
    let early_base = live_bytes();
    // Warm-up: every per-peer structure that has a cap (the ring of recent
    // envelope ids of each pair holds 64 entries, the event and ledger logs
    // 200) must be full and rotating before the baseline is taken. In this
    // round-robin every pair exchanges one message per 32 messages, so the
    // 64-entry rings are full after 64 * 32 messages; the warm-up goes past
    // that. Before that point the curve rises by design, in steps (a ring
    // doubles its buffer when it passes 32 entries), and sampling it there
    // measures the filling, not the leak.
    const WARMUP: u64 = 72 * 32;
    let mut next = 64u64;
    while next < WARMUP {
        step(next);
        next += 1;
    }
    let baseline = live_bytes();
    let mut peak = baseline;
    let mut curve: Vec<(u64, i64)> = Vec::new();
    let total = 640u64;
    for k in 0..total {
        step(next);
        next += 1;
        if (k + 1) % 160 == 0 {
            let r = live_bytes();
            peak = peak.max(r);
            curve.push((k + 1, r as i64 - baseline as i64));
        }
    }
    // Everybody has everything, once.
    for n in &nodes {
        let h = n.core.history(&gid, None, 200).unwrap();
        assert!(!h.is_empty());
        assert_eq!(n.core.list()[0].pending, 0);
    }
    assert_eq!(nodes[5].core.vector_of(&gid, &ids[0]).unwrap().2, 0);

    let growth = peak.saturating_sub(baseline);
    let total_growth = peak.saturating_sub(early_base);
    println!(
        "soak: warm-up {} messages, baseline {:.2} MiB (early {:.2} MiB), growth after warm-up {:.2} MiB, since the start {:.2} MiB",
        WARMUP,
        baseline as f64 / 1048576.0,
        early_base as f64 / 1048576.0,
        growth as f64 / 1048576.0,
        total_growth as f64 / 1048576.0
    );
    for (k, over) in &curve {
        println!(
            "  {k:>5} messages: {:+.2} MiB over baseline",
            *over as f64 / 1048576.0
        );
    }
    assert!(
        total_growth <= 3 * 1024 * 1024,
        "live memory grew by {total_growth} bytes"
    );
    let worst = curve.iter().map(|c| c.1).max().unwrap_or(0);
    assert!(
        worst <= 512 * 1024,
        "the curve keeps rising after warm-up: {worst} bytes over the baseline"
    );
}
