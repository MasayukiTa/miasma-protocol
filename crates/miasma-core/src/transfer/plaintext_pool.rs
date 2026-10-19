//! Zeroizing plaintext buffers: one type ([`SegmentBuf`]) and one bounded pool
//! ([`PlaintextPool`]) for every bulk plaintext buffer of the publish and
//! receive paths.
//!
//! # Rules
//! * A plaintext buffer is always a [`SegmentBuf`]. It is wiped when it is
//!   dropped, whatever the reason: success, an error, an early `return`, a
//!   cancelled future (dropped at an `.await`), or a panic unwinding past it.
//!   The wipe is checked by reading the bytes back; a buffer that does not read
//!   back as zero is counted in [`StreamStatsSnapshot::wipe_failures`] and is
//!   never reused.
//! * [`PlaintextPool::take`] hands out a zero-filled buffer. A buffer that came
//!   from the pool goes back to it after it has been wiped, so a publish that
//!   reads many segments reuses one allocation instead of allocating (and
//!   freeing, unwiped, to the allocator) a segment-sized block per segment.
//! * What the pool keeps is bounded: idle buffers are only retained while their
//!   total capacity stays within the idle cap; anything beyond it is wiped and
//!   freed. Idle buffers hold only zeros. Buffers handed out are the callers'
//!   and are bounded by what the callers run at once, not by the pool.
//! * [`PlaintextPool::wipe`] frees every idle buffer and makes buffers that are
//!   out right now (they belong to work the wipe gate is cancelling) free
//!   themselves instead of returning to the pool. It is called from the wipe
//!   sequence, see [`crate::wipe::WipeGate`].
//!
//! The pool does not and cannot reach a buffer that is out: wiping those is the
//! job of the gate, which cancels the work holding them (dropping the future
//! drops the buffer) and waits for it.

use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock,
};

use zeroize::{Zeroize, Zeroizing};

use crate::dissolution::DEFAULT_SEGMENT_SIZE;

/// Default total capacity of the idle buffers a pool keeps: one default segment.
pub const DEFAULT_IDLE_CAP: usize = DEFAULT_SEGMENT_SIZE;

// ─── Counters ────────────────────────────────────────────────────────────────

/// Counters of the plaintext buffers one stream (or one pool) created. Cheap,
/// lock-free, and per owner so that tests (and a front end showing memory use)
/// can read them without a process-wide hook.
#[derive(Default)]
pub struct StreamStats {
    created: AtomicU64,
    wiped: AtomicU64,
    not_clean: AtomicU64,
    live: AtomicU64,
    peak_live: AtomicU64,
    largest: AtomicUsize,
}

/// A point-in-time copy of [`StreamStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamStatsSnapshot {
    /// Buffers created so far.
    pub created: u64,
    /// Buffers that were dropped and read back as all zero after wiping.
    pub wiped: u64,
    /// Buffers that did **not** read back as zero after wiping. Must stay 0.
    pub wipe_failures: u64,
    /// Buffers alive now.
    pub live: u64,
    /// The most buffers alive at the same moment.
    pub peak_live: u64,
    /// The size of the biggest buffer, in bytes.
    pub largest_buffer: usize,
}

impl StreamStats {
    pub fn snapshot(&self) -> StreamStatsSnapshot {
        StreamStatsSnapshot {
            created: self.created.load(Ordering::SeqCst),
            wiped: self.wiped.load(Ordering::SeqCst),
            wipe_failures: self.not_clean.load(Ordering::SeqCst),
            live: self.live.load(Ordering::SeqCst),
            peak_live: self.peak_live.load(Ordering::SeqCst),
            largest_buffer: self.largest.load(Ordering::SeqCst),
        }
    }

    fn note_created(&self, len: usize) {
        self.created.fetch_add(1, Ordering::SeqCst);
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_live.fetch_max(live, Ordering::SeqCst);
        self.largest.fetch_max(len, Ordering::SeqCst);
    }
}

/// A point-in-time view of a [`PlaintextPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSnapshot {
    /// Idle buffers being kept for reuse.
    pub idle_buffers: usize,
    /// Their total capacity in bytes (never above the idle cap).
    pub idle_bytes: usize,
    /// Capacity of the pool-linked buffers that are out right now.
    pub live_bytes: usize,
    /// The highest `live_bytes` seen.
    pub peak_live_bytes: usize,
    /// Times a buffer was served from the idle list instead of allocated.
    pub reuses: u64,
    /// Buffers that were wiped and freed instead of kept (over the cap, after a
    /// wipe, or not clean).
    pub discards: u64,
}

// ─── The pool ────────────────────────────────────────────────────────────────

/// Bounded pool of zeroed byte buffers. See the module documentation.
pub struct PlaintextPool {
    idle_cap: usize,
    /// Idle buffers. Invariant: every initialised byte of each is zero.
    idle: Mutex<Vec<Zeroizing<Vec<u8>>>>,
    live_bytes: AtomicUsize,
    peak_live_bytes: AtomicUsize,
    /// Bumped by [`wipe`](Self::wipe); a buffer from an older generation is not
    /// taken back.
    generation: AtomicU64,
    reuses: AtomicU64,
    discards: AtomicU64,
    stats: Arc<StreamStats>,
}

impl PlaintextPool {
    /// A pool that keeps at most `idle_cap` bytes of capacity idle.
    pub fn new(idle_cap: usize) -> Arc<Self> {
        Arc::new(Self {
            idle_cap,
            idle: Mutex::new(Vec::new()),
            live_bytes: AtomicUsize::new(0),
            peak_live_bytes: AtomicUsize::new(0),
            generation: AtomicU64::new(0),
            reuses: AtomicU64::new(0),
            discards: AtomicU64::new(0),
            stats: Arc::new(StreamStats::default()),
        })
    }

    /// The process-wide pool used by the publish and receive engines and wiped
    /// by the wipe sequence.
    pub fn shared() -> &'static Arc<PlaintextPool> {
        static SHARED: OnceLock<Arc<PlaintextPool>> = OnceLock::new();
        SHARED.get_or_init(|| PlaintextPool::new(DEFAULT_IDLE_CAP))
    }

    /// Counters of every buffer created through this pool.
    pub fn stats(&self) -> &Arc<StreamStats> {
        &self.stats
    }

    /// The idle cap this pool was built with.
    pub fn idle_cap(&self) -> usize {
        self.idle_cap
    }

    pub fn snapshot(&self) -> PoolSnapshot {
        let idle = self.lock_idle();
        PoolSnapshot {
            idle_buffers: idle.len(),
            idle_bytes: idle.iter().map(|b| b.capacity()).sum(),
            live_bytes: self.live_bytes.load(Ordering::SeqCst),
            peak_live_bytes: self.peak_live_bytes.load(Ordering::SeqCst),
            reuses: self.reuses.load(Ordering::SeqCst),
            discards: self.discards.load(Ordering::SeqCst),
        }
    }

    /// A zero-filled buffer of exactly `len` bytes, reusing an idle allocation
    /// when one is big enough (the smallest that fits).
    pub fn take(self: &Arc<Self>, len: usize) -> SegmentBuf {
        let reused = {
            let mut idle = self.lock_idle();
            let best = idle
                .iter()
                .enumerate()
                .filter(|(_, b)| b.capacity() >= len)
                .min_by_key(|(_, b)| b.capacity())
                .map(|(i, _)| i);
            best.map(|i| idle.swap_remove(i))
        };
        let data = match reused {
            Some(mut z) => {
                self.reuses.fetch_add(1, Ordering::SeqCst);
                let mut v = std::mem::take(&mut *z);
                // Every initialised byte of an idle buffer is zero, so cutting it
                // short needs no write and growing it (within its capacity)
                // writes zeros only.
                if len <= v.len() {
                    v.truncate(len);
                } else {
                    v.resize(len, 0);
                }
                v
            }
            None => vec![0u8; len],
        };
        let charged = data.capacity();
        let live = self.live_bytes.fetch_add(charged, Ordering::SeqCst) + charged;
        self.peak_live_bytes.fetch_max(live, Ordering::SeqCst);
        self.stats.note_created(len);
        SegmentBuf {
            data: Zeroizing::new(data),
            stats: self.stats.clone(),
            link: Some(PoolLink {
                pool: self.clone(),
                generation: self.generation.load(Ordering::SeqCst),
                charged,
                reusable: true,
            }),
        }
    }

    /// Free every idle buffer and stop buffers that are out right now from
    /// coming back. Returns how many idle buffers were freed. Safe to call at
    /// any time and as often as wanted.
    pub fn wipe(&self) -> usize {
        // Bump first: a release that runs after this sees the new generation
        // (checked under the same lock the drain below takes).
        self.generation.fetch_add(1, Ordering::SeqCst);
        let drained = std::mem::take(&mut *self.lock_idle());
        let freed = drained.len();
        drop(drained); // each `Zeroizing` wipes its buffer as it drops
        freed
    }

    fn lock_idle(&self) -> std::sync::MutexGuard<'_, Vec<Zeroizing<Vec<u8>>>> {
        self.idle.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take back a wiped buffer, or wipe and free it.
    fn release(&self, v: Vec<u8>, link: &PoolLink, clean: bool) {
        self.live_bytes.fetch_sub(link.charged, Ordering::SeqCst);
        let cap = v.capacity();
        if link.reusable && clean && cap > 0 {
            let mut idle = self.lock_idle();
            // Checked under the lock `wipe` drains under.
            if link.generation == self.generation.load(Ordering::SeqCst) {
                let held: usize = idle.iter().map(|b| b.capacity()).sum();
                if held.saturating_add(cap) <= self.idle_cap {
                    idle.push(Zeroizing::new(v));
                    return;
                }
            }
        }
        self.discards.fetch_add(1, Ordering::SeqCst);
        drop(Zeroizing::new(v)); // wiped once more, then freed
    }

    /// Test hook: every idle buffer reads back as zero over its whole length.
    #[cfg(test)]
    pub(crate) fn idle_all_zero(&self) -> bool {
        self.lock_idle()
            .iter()
            .all(|b| b.iter().all(|byte| *byte == 0))
    }
}

// ─── The buffer ──────────────────────────────────────────────────────────────

struct PoolLink {
    pool: Arc<PlaintextPool>,
    generation: u64,
    charged: usize,
    /// Only buffers the pool allocated or served may go back to its idle list.
    reusable: bool,
}

/// One buffer of plaintext. The bytes are wiped when this is dropped, and the
/// wipe is checked by reading them back, so a regression that stops wiping
/// shows up in [`StreamStatsSnapshot::wipe_failures`] rather than silently.
pub struct SegmentBuf {
    data: Zeroizing<Vec<u8>>,
    stats: Arc<StreamStats>,
    link: Option<PoolLink>,
}

impl SegmentBuf {
    /// Take over an already zeroizing buffer (no copy is made).
    pub fn adopt(data: Zeroizing<Vec<u8>>, stats: &Arc<StreamStats>) -> Self {
        stats.note_created(data.len());
        Self {
            data,
            stats: stats.clone(),
            link: None,
        }
    }

    /// As [`adopt`](Self::adopt), and count the buffer's bytes in `pool`'s live
    /// total while it exists. The allocation was made elsewhere, so it is wiped
    /// and freed when dropped, never kept by the pool.
    pub fn adopt_in(
        data: Zeroizing<Vec<u8>>,
        stats: &Arc<StreamStats>,
        pool: &Arc<PlaintextPool>,
    ) -> Self {
        stats.note_created(data.len());
        let charged = data.capacity();
        let live = pool.live_bytes.fetch_add(charged, Ordering::SeqCst) + charged;
        pool.peak_live_bytes.fetch_max(live, Ordering::SeqCst);
        Self {
            data,
            stats: stats.clone(),
            link: Some(PoolLink {
                pool: pool.clone(),
                generation: pool.generation.load(Ordering::SeqCst),
                charged,
                reusable: false,
            }),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::fmt::Debug for SegmentBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the bytes.
        write!(f, "SegmentBuf({} bytes)", self.data.len())
    }
}

impl Drop for SegmentBuf {
    fn drop(&mut self) {
        self.data.as_mut_slice().zeroize();
        let clean = self.data.iter().all(|b| *b == 0);
        if clean {
            self.stats.wiped.fetch_add(1, Ordering::SeqCst);
        } else {
            self.stats.not_clean.fetch_add(1, Ordering::SeqCst);
        }
        self.stats.live.fetch_sub(1, Ordering::SeqCst);
        match self.link.take() {
            Some(link) => {
                let v = std::mem::take(&mut *self.data);
                link.pool.release(v, &link, clean);
            }
            None => {
                // The `Zeroizing` field wipes (and clears) once more as it drops.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::time::Duration;

    fn pool() -> Arc<PlaintextPool> {
        PlaintextPool::new(4096)
    }

    fn counters(p: &PlaintextPool) -> (u64, u64, u64, u64) {
        let s = p.stats().snapshot();
        (s.created, s.wiped, s.wipe_failures, s.live)
    }

    #[test]
    fn a_dropped_buffer_is_wiped_and_counted() {
        let stats = Arc::new(StreamStats::default());
        let buf = SegmentBuf::adopt(Zeroizing::new(vec![0xAB; 4096]), &stats);
        assert_eq!(buf.len(), 4096);
        assert_eq!(stats.snapshot().live, 1);
        drop(buf);
        let s = stats.snapshot();
        assert_eq!((s.created, s.wiped, s.wipe_failures, s.live), (1, 1, 0, 0));
        assert_eq!((s.peak_live, s.largest_buffer), (1, 4096));
    }

    #[test]
    fn success_path_wipes_and_the_idle_copy_reads_back_zero() {
        let p = pool();
        let mut b = p.take(1024);
        b.as_mut_slice().fill(0xAB);
        assert!(b.as_slice().iter().all(|x| *x == 0xAB));
        drop(b);
        assert_eq!(counters(&p), (1, 1, 0, 0));
        let s = p.snapshot();
        assert_eq!((s.idle_buffers, s.live_bytes), (1, 0));
        assert!(p.idle_all_zero(), "the kept buffer must hold no plaintext");
    }

    #[test]
    fn an_error_return_wipes() {
        fn work(p: &Arc<PlaintextPool>) -> Result<(), &'static str> {
            let mut b = p.take(512);
            b.as_mut_slice().fill(0xCD);
            Err("boom")?;
            drop(b);
            Ok(())
        }
        let p = pool();
        assert!(work(&p).is_err());
        assert_eq!(counters(&p), (1, 1, 0, 0));
        assert!(p.idle_all_zero());
    }

    #[test]
    fn an_early_return_inside_a_loop_wipes_every_buffer() {
        fn work(p: &Arc<PlaintextPool>) -> usize {
            for i in 0..5 {
                let mut b = p.take(256);
                b.as_mut_slice().fill(0xEE);
                if i == 2 {
                    return i;
                }
            }
            99
        }
        let p = pool();
        assert_eq!(work(&p), 2);
        assert_eq!(counters(&p), (3, 3, 0, 0));
        assert!(p.idle_all_zero());
    }

    #[tokio::test]
    async fn a_cancelled_future_wipes_the_buffer_it_held() {
        let p = pool();
        let p2 = p.clone();
        let out = tokio::time::timeout(Duration::from_millis(30), async move {
            let mut b = p2.take(2048);
            b.as_mut_slice().fill(0x5A);
            std::future::pending::<()>().await; // an `.await` that never returns
            drop(b);
        })
        .await;
        assert!(out.is_err(), "the timeout cancelled the future");
        assert_eq!(counters(&p), (1, 1, 0, 0));
        assert!(p.idle_all_zero());
    }

    #[test]
    fn a_panic_unwinding_past_the_buffer_wipes_it() {
        let p = pool();
        let p2 = p.clone();
        let r = catch_unwind(AssertUnwindSafe(move || {
            let mut b = p2.take(768);
            b.as_mut_slice().fill(0x77);
            panic!("unwind through the buffer");
        }));
        assert!(r.is_err());
        assert_eq!(counters(&p), (1, 1, 0, 0));
        assert!(p.idle_all_zero());
    }

    #[test]
    fn a_reused_buffer_is_served_zeroed_and_counted() {
        let p = pool();
        let mut a = p.take(1000);
        a.as_mut_slice().fill(0xFF);
        drop(a);
        let b = p.take(600); // smaller: cut from the idle 1000
        assert_eq!(b.len(), 600);
        assert!(b.as_slice().iter().all(|x| *x == 0));
        drop(b);
        let c = p.take(1000); // bigger than the last cut, within capacity
        assert!(c.as_slice().iter().all(|x| *x == 0));
        assert_eq!(p.snapshot().reuses, 2);
    }

    #[test]
    fn idle_memory_is_capped_and_the_excess_is_freed() {
        let p = PlaintextPool::new(3 * 1024);
        let held: Vec<SegmentBuf> = (0..10).map(|_| p.take(1024)).collect();
        assert_eq!(p.snapshot().live_bytes, 10 * 1024);
        drop(held);
        let s = p.snapshot();
        assert_eq!(s.live_bytes, 0);
        assert_eq!(s.peak_live_bytes, 10 * 1024);
        assert!(s.idle_bytes <= 3 * 1024, "idle {} over cap", s.idle_bytes);
        assert_eq!(s.idle_buffers, 3);
        assert_eq!(s.discards, 7);
        assert_eq!(counters(&p), (10, 10, 0, 0));
        // A buffer bigger than the whole cap is never kept.
        drop(p.take(8 * 1024));
        assert!(p.snapshot().idle_bytes <= 3 * 1024);
    }

    #[test]
    fn wipe_frees_idle_buffers_and_refuses_the_ones_still_out() {
        let p = pool();
        let (a, b) = (p.take(1024), p.take(1024));
        drop(a);
        drop(b);
        assert_eq!(p.snapshot().idle_buffers, 2);
        let out = p.take(512); // served from idle; out while the wipe runs
        assert_eq!(p.snapshot().idle_buffers, 1);
        assert_eq!(p.wipe(), 1);
        assert_eq!(p.snapshot().idle_buffers, 0);
        drop(out); // belongs to the old generation: wiped and freed, not kept
        let s = p.snapshot();
        assert_eq!((s.idle_buffers, s.idle_bytes, s.live_bytes), (0, 0, 0));
        assert_eq!(p.stats().snapshot().wipe_failures, 0);
        // The pool works after a wipe.
        drop(p.take(256));
        assert_eq!(p.snapshot().idle_buffers, 1);
    }

    #[test]
    fn an_adopted_buffer_is_counted_wiped_and_never_kept() {
        let p = pool();
        let stats = Arc::new(StreamStats::default());
        let b = SegmentBuf::adopt_in(Zeroizing::new(vec![9u8; 640]), &stats, &p);
        assert_eq!(p.snapshot().live_bytes, 640);
        drop(b);
        let s = p.snapshot();
        assert_eq!((s.live_bytes, s.idle_buffers, s.discards), (0, 0, 1));
        let st = stats.snapshot();
        assert_eq!((st.created, st.wiped, st.wipe_failures), (1, 1, 0));
    }

    #[test]
    fn debug_never_prints_the_bytes() {
        let stats = Arc::new(StreamStats::default());
        let buf = SegmentBuf::adopt(Zeroizing::new(b"top-secret-marker".to_vec()), &stats);
        let shown = format!("{buf:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("17 bytes"), "{shown}");
    }

    #[test]
    fn a_zero_length_buffer_is_fine_and_not_kept() {
        let p = pool();
        let b = p.take(0);
        assert!(b.is_empty());
        drop(b);
        assert_eq!(p.snapshot().idle_buffers, 0);
    }
}
