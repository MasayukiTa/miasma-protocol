//! When and how often a send tries again after the other side could not be
//! reached. Pure arithmetic: no clock, no randomness of its own, so the
//! schedule is easy to test.

use std::time::Duration;

use crate::config::PushConfig;

/// Waits between attempts: a short ladder first (a relay that flaps usually
/// comes back within a minute), then a steady gap.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryPolicy {
    /// Wait after the 1st, 2nd, ... failed attempt in a row.
    pub ladder: Vec<Duration>,
    /// Wait after the ladder is used up.
    pub then_every: Duration,
    /// Give up when no byte has moved for this long. `None` never gives up;
    /// `Some(Duration::ZERO)` does not retry at all.
    pub window: Option<Duration>,
    /// Each wait is stretched or shrunk by up to this fraction (0.2 = +-20%).
    pub jitter: f64,
    /// A wake-up (relay is back, the person pressed "Try now") never starts
    /// two attempts closer together than this.
    pub min_gap: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            ladder: vec![
                Duration::from_secs(5),
                Duration::from_secs(15),
                Duration::from_secs(45),
                Duration::from_secs(120),
                Duration::from_secs(300),
            ],
            then_every: Duration::from_secs(600),
            window: Some(Duration::from_secs(
                crate::config::DEFAULT_PUSH_RETRY_WINDOW_HOURS * 3600,
            )),
            jitter: 0.2,
            min_gap: Duration::from_secs(2),
        }
    }
}

impl RetryPolicy {
    pub fn from_config(cfg: &PushConfig) -> Self {
        Self {
            window: match cfg.retry_window_hours {
                0 => None,
                h => Some(Duration::from_secs(h.saturating_mul(3600))),
            },
            ..Self::default()
        }
    }

    /// No retries: the first failure is final.
    pub fn never() -> Self {
        Self {
            window: Some(Duration::ZERO),
            ..Self::default()
        }
    }

    /// The wait before the next attempt, after `failures` attempts in a row
    /// have failed (1 = the first one), before jitter.
    pub fn base_delay(&self, failures: u32) -> Duration {
        let i = failures.saturating_sub(1) as usize;
        self.ladder.get(i).copied().unwrap_or(self.then_every)
    }

    /// As [`base_delay`](Self::base_delay) with jitter. `unit` is a random
    /// number in `[0, 1)`; 0.5 gives the unchanged delay.
    pub fn delay(&self, failures: u32, unit: f64) -> Duration {
        let base = self.base_delay(failures).as_secs_f64();
        let j = self.jitter.clamp(0.0, 0.9);
        let factor = 1.0 + j * (2.0 * unit.clamp(0.0, 1.0) - 1.0);
        Duration::from_secs_f64((base * factor).max(0.0))
    }

    /// Whether a send that last moved a byte `idle` ago has used up its window.
    pub fn exhausted(&self, idle: Duration) -> bool {
        match self.window {
            None => false,
            Some(w) => idle >= w,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_then_steady_gap() {
        let p = RetryPolicy::default();
        let secs: Vec<u64> = (1..=8).map(|n| p.base_delay(n).as_secs()).collect();
        assert_eq!(secs, vec![5, 15, 45, 120, 300, 600, 600, 600]);
        assert_eq!(p.base_delay(0).as_secs(), 5);
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        let p = RetryPolicy::default();
        for n in 1..=8 {
            let base = p.base_delay(n).as_secs_f64();
            assert!((p.delay(n, 0.5).as_secs_f64() - base).abs() < 1e-6);
            assert!(p.delay(n, 0.0).as_secs_f64() >= base * 0.8 - 1e-6);
            assert!(p.delay(n, 0.999_999).as_secs_f64() <= base * 1.2 + 1e-6);
        }
    }

    #[test]
    fn window_comes_from_hours_and_zero_means_forever() {
        let mut c = PushConfig::default();
        assert_eq!(
            RetryPolicy::from_config(&c).window,
            Some(Duration::from_secs(24 * 3600))
        );
        c.retry_window_hours = 2;
        assert_eq!(
            RetryPolicy::from_config(&c).window,
            Some(Duration::from_secs(7200))
        );
        c.retry_window_hours = 0;
        let p = RetryPolicy::from_config(&c);
        assert_eq!(p.window, None);
        assert!(!p.exhausted(Duration::from_secs(10 * 365 * 86_400)));
    }

    #[test]
    fn exhaustion_and_no_retry() {
        let p = RetryPolicy::default();
        assert!(!p.exhausted(Duration::from_secs(24 * 3600 - 1)));
        assert!(p.exhausted(Duration::from_secs(24 * 3600)));
        assert!(RetryPolicy::never().exhausted(Duration::ZERO));
    }
}
