//! Protocol-time scheduling primitives for autonomous piece maintenance.
//!
//! Everything here is a pure function of an explicit `now` (whole seconds)
//! supplied by a [`MaintenanceClock`], never of the platform clock, so retry
//! backoff and bandwidth pacing are deterministic and testable. Production
//! code uses [`SystemClock`]; tests drive a [`ManualClock`].

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Identity of one stored piece: `(mid digest, segment index, slot index)`.
pub type PieceKey = ([u8; 32], u32, u16);

/// Source of protocol time in whole seconds since the Unix epoch.
pub trait MaintenanceClock: Send + Sync {
    fn now_secs(&self) -> u64;
}

/// Production clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl MaintenanceClock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Manually advanced clock for tests.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(start_secs: u64) -> Self {
        Self(AtomicU64::new(start_secs))
    }

    pub fn set(&self, secs: u64) {
        self.0.store(secs, Ordering::SeqCst);
    }

    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl MaintenanceClock for ManualClock {
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

// ─── Retry backoff ───────────────────────────────────────────────────────────

/// Exponential backoff with deterministic jitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// Delay after the first failed attempt.
    pub base_secs: u64,
    /// Upper bound for the delay, however many failures accumulate.
    pub max_secs: u64,
    /// Quiet period after a successful repair of a piece.
    pub success_cooldown_secs: u64,
    /// Jitter as a percentage of the delay, applied symmetrically (0..=50).
    pub jitter_percent: u8,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base_secs: 300,
            max_secs: 6 * 3600,
            success_cooldown_secs: 1800,
            jitter_percent: 20,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AttemptEntry {
    failures: u32,
    next_allowed: u64,
}

/// Per-piece record of repair attempts and when the next one may happen.
///
/// Failed attempts back off exponentially so an unreachable or hostile network
/// cannot turn repair into a tight retry loop; a success only starts a short
/// cooldown and resets the failure count.
#[derive(Debug, Default)]
pub struct AttemptLedger {
    policy: BackoffPolicy,
    entries: HashMap<PieceKey, AttemptEntry>,
}

impl AttemptLedger {
    pub fn new(policy: BackoffPolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
        }
    }

    pub fn policy(&self) -> BackoffPolicy {
        self.policy
    }

    /// May `key` be attempted at `now`?
    pub fn allowed(&self, key: &PieceKey, now: u64) -> bool {
        self.entries.get(key).is_none_or(|e| now >= e.next_allowed)
    }

    /// Earliest time `key` may be attempted again, if it is currently held back.
    pub fn next_allowed(&self, key: &PieceKey) -> Option<u64> {
        self.entries.get(key).map(|e| e.next_allowed)
    }

    pub fn failures(&self, key: &PieceKey) -> u32 {
        self.entries.get(key).map_or(0, |e| e.failures)
    }

    /// Record the outcome of an attempt made at `now`.
    pub fn record(&mut self, key: PieceKey, now: u64, success: bool) {
        if success {
            self.entries.insert(
                key,
                AttemptEntry {
                    failures: 0,
                    next_allowed: now.saturating_add(self.policy.success_cooldown_secs),
                },
            );
            return;
        }
        let failures = self.failures(&key).saturating_add(1);
        let delay = self.failure_delay(&key, failures);
        self.entries.insert(
            key,
            AttemptEntry {
                failures,
                next_allowed: now.saturating_add(delay),
            },
        );
    }

    /// Delay applied after the `failures`-th consecutive failure of `key`.
    pub fn failure_delay(&self, key: &PieceKey, failures: u32) -> u64 {
        let p = self.policy;
        let shift = failures.saturating_sub(1).min(32);
        let raw = p
            .base_secs
            .checked_shl(shift)
            .unwrap_or(u64::MAX)
            .min(p.max_secs);
        let jitter = u64::from(p.jitter_percent.min(50));
        if jitter == 0 || raw == 0 {
            return raw;
        }
        // Deterministic, per-piece spread so pieces that failed together do not
        // all retry on the same second.
        let mut h = blake3::Hasher::new();
        h.update(&key.0);
        h.update(&key.1.to_le_bytes());
        h.update(&key.2.to_le_bytes());
        h.update(&failures.to_le_bytes());
        let digest = h.finalize();
        let roll = u64::from(u16::from_le_bytes([
            digest.as_bytes()[0],
            digest.as_bytes()[1],
        ]));
        let span = 2 * jitter + 1;
        let offset_pct = (roll % span) as i64 - jitter as i64;
        let delta = (raw as i128 * offset_pct as i128) / 100;
        (raw as i128 + delta).clamp(0, u64::MAX as i128) as u64
    }

    /// Forget entries whose hold-back has expired and that carry no failure
    /// history, bounding memory on long-running nodes.
    pub fn prune(&mut self, now: u64) {
        self.entries
            .retain(|_, e| e.failures > 0 || now < e.next_allowed);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

// ─── Bandwidth pacing ────────────────────────────────────────────────────────

/// Token-bucket pacing plus a rolling daily cap for background traffic.
///
/// A transfer larger than the burst is allowed once the bucket is full and then
/// leaves the bucket in debt, so the long-run average never exceeds
/// `rate_bytes_per_sec` however large individual shares are.
#[derive(Debug, Clone)]
pub struct RateBudget {
    rate_bytes_per_sec: u64,
    burst_bytes: u64,
    daily_cap_bytes: u64,
    tokens: i64,
    last_refill: u64,
    day_start: u64,
    day_used: u64,
}

const DAY_SECS: u64 = 86_400;

impl RateBudget {
    /// `daily_cap_bytes == 0` disables the daily cap.
    pub fn new(
        rate_bytes_per_sec: u64,
        burst_bytes: u64,
        daily_cap_bytes: u64,
        start_secs: u64,
    ) -> Self {
        Self {
            rate_bytes_per_sec,
            burst_bytes,
            daily_cap_bytes,
            tokens: i64::try_from(burst_bytes).unwrap_or(i64::MAX),
            last_refill: start_secs,
            day_start: start_secs,
            day_used: 0,
        }
    }

    fn refill(&mut self, now: u64) {
        if now > self.last_refill {
            let add = (now - self.last_refill).saturating_mul(self.rate_bytes_per_sec);
            let burst = i64::try_from(self.burst_bytes).unwrap_or(i64::MAX);
            self.tokens = self
                .tokens
                .saturating_add(i64::try_from(add).unwrap_or(i64::MAX))
                .min(burst);
            self.last_refill = now;
        }
        if now >= self.day_start.saturating_add(DAY_SECS) {
            self.day_start = now;
            self.day_used = 0;
        }
    }

    /// Would a transfer of `bytes` be allowed right now? Does not spend.
    pub fn can_spend(&mut self, now: u64, bytes: u64) -> bool {
        self.refill(now);
        let need = i64::try_from(bytes.min(self.burst_bytes)).unwrap_or(i64::MAX);
        if self.tokens < need || (bytes > 0 && self.tokens <= 0) {
            return false;
        }
        self.daily_cap_bytes == 0 || self.day_used.saturating_add(bytes) <= self.daily_cap_bytes
    }

    /// Spend `bytes` if allowed; returns whether the transfer may proceed.
    pub fn try_spend(&mut self, now: u64, bytes: u64) -> bool {
        if !self.can_spend(now, bytes) {
            return false;
        }
        self.charge(now, bytes);
        true
    }

    /// Account for traffic that already happened (for example a probe whose
    /// size was only known afterwards). May leave the bucket in debt.
    pub fn charge(&mut self, now: u64, bytes: u64) {
        self.refill(now);
        self.tokens = self
            .tokens
            .saturating_sub(i64::try_from(bytes).unwrap_or(i64::MAX));
        self.day_used = self.day_used.saturating_add(bytes);
    }

    pub fn day_used(&self) -> u64 {
        self.day_used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(slot: u16) -> PieceKey {
        ([7u8; 32], 0, slot)
    }

    #[test]
    fn failures_back_off_exponentially_up_to_the_cap() {
        let policy = BackoffPolicy {
            base_secs: 100,
            max_secs: 1000,
            success_cooldown_secs: 50,
            jitter_percent: 0,
        };
        let mut ledger = AttemptLedger::new(policy);
        let k = key(0);
        let clock = ManualClock::new(1_000);

        assert!(ledger.allowed(&k, clock.now_secs()));
        ledger.record(k, clock.now_secs(), false);
        assert_eq!(ledger.next_allowed(&k), Some(1_100));
        assert!(!ledger.allowed(&k, 1_099));
        assert!(ledger.allowed(&k, 1_100));

        clock.set(1_100);
        ledger.record(k, clock.now_secs(), false);
        assert_eq!(ledger.next_allowed(&k), Some(1_300));
        clock.set(1_300);
        ledger.record(k, clock.now_secs(), false);
        assert_eq!(ledger.next_allowed(&k), Some(1_700));
        clock.set(1_700);
        ledger.record(k, clock.now_secs(), false);
        // 800 -> capped at 1000 from the next failure on.
        assert_eq!(ledger.next_allowed(&k), Some(2_500));
        clock.set(2_500);
        ledger.record(k, clock.now_secs(), false);
        assert_eq!(ledger.next_allowed(&k), Some(3_500));
        assert_eq!(ledger.failures(&k), 5);
    }

    #[test]
    fn success_resets_failures_and_starts_a_short_cooldown() {
        let policy = BackoffPolicy {
            jitter_percent: 0,
            ..BackoffPolicy::default()
        };
        let mut ledger = AttemptLedger::new(policy);
        let k = key(1);
        ledger.record(k, 0, false);
        ledger.record(k, 10_000, true);
        assert_eq!(ledger.failures(&k), 0);
        assert_eq!(ledger.next_allowed(&k), Some(10_000 + 1800));
    }

    #[test]
    fn jitter_is_deterministic_and_bounded() {
        let ledger = AttemptLedger::new(BackoffPolicy {
            base_secs: 1000,
            max_secs: 1_000_000,
            success_cooldown_secs: 0,
            jitter_percent: 20,
        });
        for slot in 0..32u16 {
            let d1 = ledger.failure_delay(&key(slot), 1);
            let d2 = ledger.failure_delay(&key(slot), 1);
            assert_eq!(d1, d2);
            assert!((800..=1200).contains(&d1), "delay {d1} out of bounds");
        }
        let distinct: std::collections::HashSet<_> = (0..32u16)
            .map(|s| ledger.failure_delay(&key(s), 1))
            .collect();
        assert!(distinct.len() > 1, "jitter should spread pieces apart");
    }

    #[test]
    fn prune_drops_only_expired_clean_entries() {
        let mut ledger = AttemptLedger::new(BackoffPolicy {
            jitter_percent: 0,
            ..BackoffPolicy::default()
        });
        ledger.record(key(0), 0, true);
        ledger.record(key(1), 0, false);
        ledger.prune(100_000);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.failures(&key(1)), 1);
    }

    #[test]
    fn rate_budget_paces_to_the_configured_rate() {
        let mut b = RateBudget::new(100, 1_000, 0, 0);
        assert!(b.try_spend(0, 1_000));
        // Bucket is empty: nothing more until it refills.
        assert!(!b.try_spend(0, 1));
        assert!(!b.try_spend(4, 500)); // only 400 tokens so far
        assert!(b.try_spend(5, 500)); // 500 tokens
        assert!(!b.try_spend(5, 1));
        // Refill never exceeds the burst.
        assert!(b.can_spend(1_000_000, 1_000));
        assert!(b.try_spend(1_000_000, 1_000));
        assert!(!b.can_spend(1_000_000, 1));
    }

    #[test]
    fn oversized_transfer_leaves_debt_that_must_be_repaid() {
        let mut b = RateBudget::new(100, 1_000, 0, 0);
        assert!(b.try_spend(0, 5_000)); // allowed once the bucket is full
        assert!(!b.can_spend(0, 1));
        // 5_000 bytes at 100 B/s: 4_000 of debt takes 40 s to clear, then
        // the bucket has to refill before the next transfer.
        assert!(!b.can_spend(40, 1));
        assert!(b.can_spend(41, 1));
    }

    #[test]
    fn daily_cap_is_rolling_and_resets_after_a_day() {
        let mut b = RateBudget::new(1_000_000, 1_000_000, 3_000, 0);
        assert!(b.try_spend(0, 2_000));
        assert!(!b.try_spend(1, 2_000), "would exceed the daily cap");
        assert!(b.try_spend(2, 1_000));
        assert_eq!(b.day_used(), 3_000);
        assert!(!b.try_spend(3, 1));
        assert!(b.try_spend(DAY_SECS + 1, 2_000));
        assert_eq!(b.day_used(), 2_000);
    }
}
