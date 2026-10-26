//! Rate limiting for the push send loop.
//!
//! The push send loop writes file chunks as fast as QUIC allows. That can fill
//! the uplink and delay the small chat acknowledgements that share it. The
//! [`SendPacer`] decides how long to wait before the next chunk so the send
//! stays within a byte-per-second ceiling, and lowers that ceiling while a chat
//! send is in flight.
//!
//! The type is pure: the caller passes the current [`Instant`] into every
//! method, so a test can drive it with a clock it controls and never touches
//! the wall clock. It does no I/O; the caller does the waiting and the writing.
//!
//! Ceiling, per call to [`SendPacer::delay_before_send`]:
//!   * no chat in flight: the configured limit (`0` = unlimited, no wait);
//!   * chat in flight, configured limit non-zero: the configured limit;
//!   * chat in flight, configured limit zero (unlimited): 25% of the send rate
//!     measured over the last second, but never below [`YIELD_FLOOR_BPS`], so
//!     an unmetered send yields to chat yet still makes progress instead of
//!     being throttled toward a standstill.
//!
//! While a chat yield is in force the window it governs is marked throttled and
//! its byte count is not used to refresh the measured rate, so the yield ceiling
//! does not chase the send's own slowed pace downward window after window.
//!
//! When the ceiling is unlimited the pacer never waits and keeps no bucket, so
//! the default build (`max_send_kib_per_sec = 0`, no chat) behaves exactly as
//! before.

use std::time::{Duration, Instant};

/// One KiB in bytes.
const KIB: u64 = 1024;
/// The window the recent-rate estimate is measured over.
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// The fraction of the measured rate a send is held to while chat is in flight
/// and no fixed limit is configured, as a numerator over 100.
const YIELD_PERCENT: u64 = 25;
/// The lowest ceiling a chat yield may impose, in bytes per second. Without a
/// floor the yield ceiling is a fraction of the rate the send itself just
/// achieved; once the send is throttled that measured rate falls, which would
/// lower the next window's ceiling again, and so on until the send is starved.
/// This floor keeps a throttled send moving at a small but non-zero rate so a
/// file transfer still makes progress for the whole time chat is in flight.
const YIELD_FLOOR_BPS: u64 = 64 * KIB;
/// The largest bucket fill, in seconds of the ceiling, so a long idle stretch
/// cannot bank an unbounded burst.
const BUCKET_SECONDS: f64 = 1.0;

/// Paces the push send loop to a byte-per-second ceiling, tightened while chat
/// is sending. Pure: the caller supplies the clock.
pub struct SendPacer {
    /// Configured ceiling in bytes per second; `0` means unlimited.
    limit_bps: u64,
    /// Available tokens (bytes) in the leaky bucket. Only meaningful while a
    /// finite ceiling is in force.
    tokens: f64,
    /// The ceiling the bucket was last refilled against, in bytes per second.
    /// `0` means the bucket is idle (the last ceiling was unlimited).
    bucket_rate_bps: u64,
    /// When the bucket was last refilled.
    last_refill: Instant,
    /// Bytes sent inside the current rate window.
    window_bytes: u64,
    /// When the current rate window began.
    window_start: Instant,
    /// The send rate measured over the last full window, in bytes per second.
    measured_bps: u64,
    /// Whether a chat yield has driven the ceiling from the measured rate at any
    /// point inside the current window. While this is set the window is being
    /// throttled by the send's own slowed rate, so its byte count is not a
    /// faithful sample of the uplink; `record_sent` holds `measured_bps` at its
    /// last unthrottled value rather than letting the throttled window lower it
    /// and feed the ceiling further down. Reset when the window slides.
    window_throttled: bool,
}

impl SendPacer {
    /// A pacer with the configured ceiling in KiB per second (`0` = unlimited).
    pub fn new(limit_kib_per_sec: u32, now: Instant) -> Self {
        let limit_bps = u64::from(limit_kib_per_sec).saturating_mul(KIB);
        Self {
            limit_bps,
            tokens: 0.0,
            bucket_rate_bps: 0,
            last_refill: now,
            window_bytes: 0,
            window_start: now,
            measured_bps: 0,
            window_throttled: false,
        }
    }

    /// The send rate measured over the most recent full window, in bytes per
    /// second. Zero until the first window has elapsed.
    pub fn measured_bps(&self) -> u64 {
        self.measured_bps
    }

    /// The ceiling in force right now given whether chat is in flight, in bytes
    /// per second; `0` means unlimited (no pacing). Takes `&mut self` because a
    /// ceiling derived from the measured rate marks the current window as
    /// throttled (see `window_throttled`).
    fn ceiling_bps(&mut self, chat_active: bool) -> u64 {
        if !chat_active {
            return self.limit_bps;
        }
        if self.limit_bps != 0 {
            return self.limit_bps;
        }
        // Unlimited configured, but chat is sending: hold to a fraction of the
        // rate measured over the last second, but never below YIELD_FLOOR_BPS so
        // the send keeps moving instead of being throttled toward a standstill.
        // Saturating throughout; the multiply cannot overflow a u64 for any
        // realistic rate but is guarded anyway. A measured rate of zero yields a
        // ceiling of zero, which this module treats as "no fixed ceiling yet" so
        // the first window is not stalled before any rate is known; the floor is
        // not applied in that case for the same reason.
        if self.measured_bps == 0 {
            return 0;
        }
        // This ceiling comes from the measured rate, so the window it governs is
        // throttled: record_sent must not let that window lower measured_bps.
        self.window_throttled = true;
        let fraction = self.measured_bps.saturating_mul(YIELD_PERCENT) / 100;
        fraction.max(YIELD_FLOOR_BPS)
    }

    /// How long to wait before sending `want` bytes, given whether a chat send
    /// is in flight. `Duration::ZERO` means send now. The caller must call
    /// [`record_sent`](Self::record_sent) once the bytes are actually written.
    pub fn delay_before_send(&mut self, now: Instant, want: usize, chat_active: bool) -> Duration {
        let ceiling = self.ceiling_bps(chat_active);
        if ceiling == 0 {
            // No ceiling in force: let the bucket go idle so a later finite
            // ceiling starts fresh rather than honouring tokens banked under a
            // different rate.
            self.bucket_rate_bps = 0;
            self.last_refill = now;
            return Duration::ZERO;
        }
        self.refill(now, ceiling);
        let want = want as f64;
        if self.tokens >= want {
            return Duration::ZERO;
        }
        let deficit = want - self.tokens;
        // ceiling > 0 here, so the division is safe.
        let secs = deficit / ceiling as f64;
        duration_from_secs_f64(secs)
    }

    /// Refill the bucket for the time since the last refill at `ceiling` bytes
    /// per second, capping the fill at `BUCKET_SECONDS` of the ceiling.
    fn refill(&mut self, now: Instant, ceiling: u64) {
        if self.bucket_rate_bps != ceiling {
            // The ceiling changed (chat started or stopped, or the measured
            // rate moved): rebase the bucket on the new rate without carrying a
            // burst earned under the old one.
            self.bucket_rate_bps = ceiling;
            self.last_refill = now;
            let cap = ceiling as f64 * BUCKET_SECONDS;
            if self.tokens > cap {
                self.tokens = cap;
            }
            return;
        }
        let dt = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        self.tokens += dt * ceiling as f64;
        let cap = ceiling as f64 * BUCKET_SECONDS;
        if self.tokens > cap {
            self.tokens = cap;
        }
    }

    /// Record that `n` bytes were written at `now`: spend the tokens and feed
    /// the recent-rate estimate. Always call this after a write, whether or not
    /// [`delay_before_send`](Self::delay_before_send) asked for a wait.
    pub fn record_sent(&mut self, now: Instant, n: usize) {
        let n = n as u64;
        // Spend tokens only while a finite ceiling is in force; under an
        // unlimited ceiling the bucket is idle and its count is not read.
        if self.bucket_rate_bps != 0 {
            // Refill for the time waited before this write, then spend. Without
            // the refill here the tokens earned during the wait this method's
            // caller just honoured would instead be banked for the next refill,
            // letting the following chunk go free and the loop run at twice the
            // ceiling.
            self.refill(now, self.bucket_rate_bps);
            self.tokens -= n as f64;
            if self.tokens < 0.0 {
                self.tokens = 0.0;
            }
        }
        self.window_bytes = self.window_bytes.saturating_add(n);
        let elapsed = now.saturating_duration_since(self.window_start);
        if elapsed >= RATE_WINDOW {
            // Publish the rate only for a window that actually carried bytes and
            // was not throttled by a chat yield. An empty window would compute to
            // zero and erase the last real rate, which the chat yield relies on.
            // A throttled window carried only what the yield ceiling allowed, so
            // its rate reflects the send's own slowed pace rather than the
            // uplink; publishing it would feed the ceiling lower each window and
            // starve the send. In both cases keep the last rate and just slide
            // the window forward; the next unthrottled window refreshes it.
            if self.window_bytes > 0 && !self.window_throttled {
                let secs = elapsed.as_secs_f64();
                self.measured_bps = if secs > 0.0 {
                    (self.window_bytes as f64 / secs) as u64
                } else {
                    0
                };
            }
            self.window_bytes = 0;
            self.window_start = now;
            self.window_throttled = false;
        }
    }
}

/// Convert a non-negative number of seconds to a [`Duration`], clamping NaN,
/// infinities and out-of-range values to a bounded wait rather than panicking
/// as `Duration::from_secs_f64` would.
fn duration_from_secs_f64(secs: f64) -> Duration {
    if !secs.is_finite() || secs <= 0.0 {
        return Duration::ZERO;
    }
    // Cap the single wait so a pathological input cannot park the loop for an
    // unbounded time; the caller re-evaluates on the next iteration anyway.
    const MAX_WAIT: f64 = 60.0;
    let secs = if secs > MAX_WAIT { MAX_WAIT } else { secs };
    Duration::from_secs_f64(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHUNK: usize = 256 * 1024;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn unlimited_never_waits() {
        let t0 = Instant::now();
        let mut p = SendPacer::new(0, t0);
        // Many back-to-back chunks with no chat: never any wait.
        let mut now = t0;
        for _ in 0..1000 {
            assert_eq!(p.delay_before_send(now, CHUNK, false), Duration::ZERO);
            p.record_sent(now, CHUNK);
            now = at(t0, 0); // no time passes at all
        }
    }

    #[test]
    fn limited_holds_average_rate() {
        let t0 = Instant::now();
        // 1024 KiB/s = 1 MiB/s ceiling.
        let limit_kib = 1024u32;
        let mut p = SendPacer::new(limit_kib, t0);
        let ceiling = u64::from(limit_kib) * KIB; // bytes/s
                                                  // Send 4 MiB worth of 256 KiB chunks, obeying each requested wait, and
                                                  // check the elapsed virtual time is at least what the ceiling implies.
        let total_bytes: u64 = 4 * 1024 * 1024;
        let chunks = total_bytes / CHUNK as u64;
        let mut now = t0;
        let mut sent: u64 = 0;
        for _ in 0..chunks {
            let wait = p.delay_before_send(now, CHUNK, false);
            now += wait;
            p.record_sent(now, CHUNK);
            sent += CHUNK as u64;
        }
        let elapsed = now.saturating_duration_since(t0).as_secs_f64();
        // At the ceiling, sending `sent` bytes needs at least sent/ceiling
        // seconds (minus one bucket of slack).
        let lower = (sent as f64 - ceiling as f64 * BUCKET_SECONDS) / ceiling as f64;
        assert!(
            elapsed >= lower - 1e-6,
            "elapsed {elapsed} s below the floor {lower} s for the ceiling"
        );
        // And it must not be wildly slower than the ideal.
        let ideal = sent as f64 / ceiling as f64;
        assert!(
            elapsed <= ideal + BUCKET_SECONDS + 1e-6,
            "elapsed {elapsed} s above the ideal {ideal} s plus slack"
        );
    }

    #[test]
    fn chat_in_flight_slows_an_unlimited_send_then_restores() {
        let t0 = Instant::now();
        let mut p = SendPacer::new(0, t0);
        // Warm the measured rate: send 4 MiB over one second with no chat.
        let four_mib: u64 = 4 * 1024 * 1024;
        let chunks = four_mib / CHUNK as u64;
        let step = Duration::from_secs(1).as_nanos() as u64 / chunks;
        let mut now = t0;
        for _ in 0..chunks {
            assert_eq!(p.delay_before_send(now, CHUNK, false), Duration::ZERO);
            now += Duration::from_nanos(step);
            p.record_sent(now, CHUNK);
        }
        // One more tick past the window boundary to publish the measured rate.
        p.record_sent(now + RATE_WINDOW, 0);
        let measured = p.measured_bps();
        assert!(measured > 0, "a non-zero rate should have been measured");

        // Now chat is in flight: the next chunk must be asked to wait, because
        // the ceiling drops to 25% of the measured rate.
        let base = now + RATE_WINDOW;
        let wait = p.delay_before_send(base, CHUNK, true);
        assert!(
            wait > Duration::ZERO,
            "a yield was expected while chat is in flight"
        );

        // When chat stops, an unlimited ceiling returns and no wait is asked.
        let after = base + wait;
        assert_eq!(p.delay_before_send(after, CHUNK, false), Duration::ZERO);
    }

    #[test]
    fn chat_in_flight_honours_a_fixed_limit() {
        let t0 = Instant::now();
        // Fixed 512 KiB/s ceiling.
        let mut p = SendPacer::new(512, t0);
        // Drain the starting bucket, then the next chunk must wait.
        let first = p.delay_before_send(t0, CHUNK, true);
        // The very first call rebases the bucket to empty, so the first chunk
        // already has to wait for tokens.
        assert!(first > Duration::ZERO, "the first chunk should wait");
        p.record_sent(t0 + first, CHUNK);
        // The fixed ceiling does not change whether chat is in flight.
        let with_chat = p.delay_before_send(t0 + first, CHUNK, true);
        let without = {
            let mut q = SendPacer::new(512, t0);
            let f = q.delay_before_send(t0, CHUNK, false);
            q.record_sent(t0 + f, CHUNK);
            q.delay_before_send(t0 + f, CHUNK, false)
        };
        assert_eq!(
            with_chat, without,
            "a fixed limit is the same with or without chat"
        );
    }

    #[test]
    fn measured_rate_of_zero_does_not_divide_by_zero() {
        let t0 = Instant::now();
        let mut p = SendPacer::new(0, t0);
        // Chat in flight before any rate has been measured: the ceiling is
        // zero, which is treated as "no ceiling yet" and must not panic or
        // stall.
        assert_eq!(p.delay_before_send(t0, CHUNK, true), Duration::ZERO);
        p.record_sent(t0, CHUNK);
    }

    #[test]
    fn huge_chunk_does_not_overflow() {
        let t0 = Instant::now();
        let mut p = SendPacer::new(1, t0); // 1 KiB/s, tiny ceiling
                                           // A very large request against a tiny ceiling: the wait is capped, not
                                           // overflowed or infinite.
        let wait = p.delay_before_send(t0, usize::MAX, true);
        assert!(wait <= Duration::from_secs(60));
        // Recording a huge count must not overflow the window counter.
        p.record_sent(t0, usize::MAX);
        p.record_sent(t0 + RATE_WINDOW, usize::MAX);
        let _ = p.measured_bps();
    }

    #[test]
    fn duration_helper_clamps_bad_values() {
        assert_eq!(duration_from_secs_f64(f64::NAN), Duration::ZERO);
        assert_eq!(duration_from_secs_f64(f64::INFINITY), Duration::ZERO);
        assert_eq!(duration_from_secs_f64(-1.0), Duration::ZERO);
        assert_eq!(duration_from_secs_f64(0.0), Duration::ZERO);
        assert_eq!(duration_from_secs_f64(120.0), Duration::from_secs(60));
        assert_eq!(duration_from_secs_f64(0.5), Duration::from_millis(500));
    }

    #[test]
    fn record_sent_refill_keeps_send_at_ceiling() {
        let t0 = Instant::now();
        // 1024 KiB/s = 1 MiB/s ceiling.
        let limit_kib = 1024u32;
        let mut p = SendPacer::new(limit_kib, t0);
        let ceiling = u64::from(limit_kib) * KIB;
        // Send two chunks, honouring each requested wait. record_sent must
        // refill for the waited time and spend, so the second chunk cannot go
        // free: two 256 KiB chunks at 1 MiB/s take half a second, not a
        // quarter.
        let mut now = t0;
        for _ in 0..2 {
            let wait = p.delay_before_send(now, CHUNK, false);
            now += wait;
            p.record_sent(now, CHUNK);
        }
        let elapsed = now.saturating_duration_since(t0).as_secs_f64();
        let ideal = (2 * CHUNK as u64) as f64 / ceiling as f64;
        // Must not be faster than the ceiling allows. Before the refill fix the
        // elapsed time was half this and the send ran at twice the ceiling.
        assert!(
            elapsed >= ideal - 1e-6,
            "elapsed {elapsed} s is faster than the ceiling floor {ideal} s"
        );
    }

    #[test]
    fn empty_window_keeps_last_measured_rate() {
        let t0 = Instant::now();
        let mut p = SendPacer::new(0, t0);
        // Warm the measured rate: 4 MiB over one second with no chat.
        let four_mib: u64 = 4 * 1024 * 1024;
        let chunks = four_mib / CHUNK as u64;
        let step = Duration::from_secs(1).as_nanos() as u64 / chunks;
        let mut now = t0;
        for _ in 0..chunks {
            let _ = p.delay_before_send(now, CHUNK, false);
            now += Duration::from_nanos(step);
            p.record_sent(now, CHUNK);
        }
        let warmed = p.measured_bps();
        assert!(warmed > 0, "the first full window should publish a rate");
        // Cross an empty window boundary: no bytes were sent, so the last real
        // rate must survive rather than being overwritten with zero.
        p.record_sent(now + RATE_WINDOW, 0);
        assert_eq!(
            p.measured_bps(),
            warmed,
            "an empty window must not erase the last measured rate"
        );
    }

    /// Warm the measured rate to roughly `target_bps` by sending `target_bps`
    /// bytes over one second with no chat, then publishing the window. Returns
    /// the pacer and the virtual clock positioned just past the publish tick.
    fn warmed_pacer(target_bps: u64) -> (SendPacer, Instant, Instant) {
        let t0 = Instant::now();
        let mut p = SendPacer::new(0, t0);
        let chunk = 64 * 1024usize; // small chunk so low targets still carry bytes
        let chunks = (target_bps / chunk as u64).max(1);
        let step = Duration::from_secs(1).as_nanos() as u64 / chunks;
        let mut now = t0;
        for _ in 0..chunks {
            let _ = p.delay_before_send(now, chunk, false);
            now += Duration::from_nanos(step);
            p.record_sent(now, chunk);
        }
        // One tick past the window boundary to publish the measured rate.
        now += RATE_WINDOW;
        p.record_sent(now, 0);
        (p, t0, now)
    }

    #[test]
    fn chat_yield_holds_a_floor_and_keeps_sending_for_many_windows() {
        // Warm to a rate whose 25% yield fraction sits *below* the floor, so the
        // floor is what keeps the send alive: 128 KiB/s measured -> 32 KiB/s
        // fraction < 64 KiB/s floor.
        let (mut p, _t0, start) = warmed_pacer(128 * 1024);
        let warmed = p.measured_bps();
        assert!(warmed > 0, "a rate should have been measured");

        // Chat stays in flight for 20 one-second windows. Each window must carry
        // bytes (the send keeps progressing) and the ceiling must never fall
        // below the floor, which it would without the floor-and-no-decay fix.
        // A 16 KiB chunk against the 64 KiB/s floor needs a quarter second, so
        // several chunks land inside each one-second window; a chunk equal to
        // the floor would need the whole window and straddle its boundary.
        let mut now = start;
        let chunk = 16 * 1024usize;
        for w in 0..20u32 {
            let mut window_sent: u64 = 0;
            let window_end = now + RATE_WINDOW;
            // Send chunks honouring each requested wait until the window closes.
            while now < window_end {
                let wait = p.delay_before_send(now, chunk, true);
                assert!(
                    wait <= Duration::from_secs(60),
                    "window {w}: the wait must stay bounded"
                );
                let next = now + wait;
                if next >= window_end {
                    break;
                }
                now = next;
                p.record_sent(now, chunk);
                window_sent += chunk as u64;
            }
            // Close the window with a tick at its end.
            p.record_sent(window_end, 0);
            now = window_end;
            assert!(
                window_sent > 0,
                "window {w}: the send made no progress while chat was in flight"
            );
            // The measured rate must not have decayed: the throttled windows do
            // not refresh it, so it stays at the warmed value.
            assert_eq!(
                p.measured_bps(),
                warmed,
                "window {w}: a throttled window must not lower the measured rate"
            );
            // The ceiling in force must sit at or above the floor.
            assert!(
                p.ceiling_bps(true) >= YIELD_FLOOR_BPS,
                "window {w}: the yield ceiling fell below the floor"
            );
        }
    }

    #[test]
    fn ceiling_uses_fraction_when_it_exceeds_the_floor() {
        // Warm to 4 MiB/s: 25% is 1 MiB/s, well above the 64 KiB/s floor, so the
        // fraction wins and the floor does not clamp a fast link down.
        let (mut p, _t0, _now) = warmed_pacer(4 * 1024 * 1024);
        let warmed = p.measured_bps();
        let expected = (warmed.saturating_mul(YIELD_PERCENT) / 100).max(YIELD_FLOOR_BPS);
        assert_eq!(p.ceiling_bps(true), expected);
        assert!(
            p.ceiling_bps(true) > YIELD_FLOOR_BPS,
            "a fast link's yield ceiling should exceed the floor"
        );
    }

    #[test]
    fn measured_rate_recovers_after_chat_stops() {
        // Warm, then throttle under chat for several windows (the measured rate
        // is held), then let chat stop and a fast unthrottled window refresh it.
        let (mut p, _t0, start) = warmed_pacer(128 * 1024);
        let warmed = p.measured_bps();
        let chunk = 16 * 1024usize;
        let mut now = start;
        for _ in 0..5u32 {
            let window_end = now + RATE_WINDOW;
            while now < window_end {
                let wait = p.delay_before_send(now, chunk, true);
                let next = now + wait;
                if next >= window_end {
                    break;
                }
                now = next;
                p.record_sent(now, chunk);
            }
            p.record_sent(window_end, 0);
            now = window_end;
        }
        assert_eq!(
            p.measured_bps(),
            warmed,
            "the measured rate must be held while chat throttles the send"
        );

        // Chat stops. Send a full fast window with no chat: 4 MiB over one
        // second. The unthrottled window must refresh the measured rate upward.
        let four_mib: u64 = 4 * 1024 * 1024;
        let chunks = four_mib / CHUNK as u64;
        let step = Duration::from_secs(1).as_nanos() as u64 / chunks;
        for _ in 0..chunks {
            let _ = p.delay_before_send(now, CHUNK, false);
            now += Duration::from_nanos(step);
            p.record_sent(now, CHUNK);
        }
        p.record_sent(now + RATE_WINDOW, 0);
        let recovered = p.measured_bps();
        assert!(
            recovered > warmed,
            "after chat stopped an unthrottled window should refresh the rate upward: \
             recovered {recovered} vs held {warmed}"
        );
    }
}
