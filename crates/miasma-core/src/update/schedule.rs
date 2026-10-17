//! When the updater is allowed to talk to the network.
//!
//! * At most one automatic check per process start. There is no timer: the
//!   check is not repeated while the program keeps running.
//! * Not in the first 60 seconds after start, plus a random 0 to 60 seconds on
//!   top, so the connection to GitHub is not tied to the moment Miasma was
//!   opened.
//! * A person pressing "Check now" is answered at most once per 30 seconds; in
//!   between, the previous answer stands.

use std::time::{Duration, Instant};

/// No automatic check earlier than this after start.
pub const STARTUP_DELAY: Duration = Duration::from_secs(60);
/// Random extra delay, at most.
pub const STARTUP_JITTER: Duration = Duration::from_secs(60);
/// Shortest time between two manual checks.
pub const MANUAL_MIN_GAP: Duration = Duration::from_secs(30);

/// The delay before the automatic check, for a random number `unit` in `[0, 1]`.
pub fn startup_delay_for(unit: f64) -> Duration {
    let u = if unit.is_finite() {
        unit.clamp(0.0, 1.0)
    } else {
        0.0
    };
    STARTUP_DELAY + STARTUP_JITTER.mul_f64(u)
}

/// The delay before the automatic check, with a fresh random jitter.
pub fn startup_delay() -> Duration {
    startup_delay_for(rand::random::<f64>())
}

/// Decides whether a check may go out now.
#[derive(Debug)]
pub struct Throttle {
    started: Instant,
    auto_used: bool,
    last_manual: Option<Instant>,
    delay: Duration,
    gap: Duration,
}

impl Throttle {
    /// A throttle for a process that started at `now`, with the automatic check
    /// due after `delay`.
    pub fn new(now: Instant, delay: Duration) -> Self {
        Self {
            started: now,
            auto_used: false,
            last_manual: None,
            delay,
            gap: MANUAL_MIN_GAP,
        }
    }

    /// Time left until the automatic check is due (zero when it is).
    pub fn auto_wait(&self, now: Instant) -> Duration {
        self.delay
            .saturating_sub(now.saturating_duration_since(self.started))
    }

    /// Take the single automatic check: true once, when it is due. Never again.
    pub fn take_auto(&mut self, now: Instant) -> bool {
        if self.auto_used || !self.auto_wait(now).is_zero() {
            return false;
        }
        self.auto_used = true;
        true
    }

    /// Whether the automatic check was already used.
    pub fn auto_used(&self) -> bool {
        self.auto_used
    }

    /// A manual check: `Ok` and the moment is recorded, or `Err(wait)` with how
    /// long to wait.
    pub fn take_manual(&mut self, now: Instant) -> Result<(), Duration> {
        if let Some(last) = self.last_manual {
            let since = now.saturating_duration_since(last);
            if since < self.gap {
                return Err(self.gap - since);
            }
        }
        self.last_manual = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_startup_delay_is_between_60_and_120_seconds() {
        assert_eq!(startup_delay_for(0.0), Duration::from_secs(60));
        assert_eq!(startup_delay_for(1.0), Duration::from_secs(120));
        assert_eq!(startup_delay_for(0.5), Duration::from_secs(90));
        // Out-of-range and broken inputs stay inside the window.
        assert_eq!(startup_delay_for(-3.0), Duration::from_secs(60));
        assert_eq!(startup_delay_for(9.0), Duration::from_secs(120));
        assert_eq!(startup_delay_for(f64::NAN), Duration::from_secs(60));
        for _ in 0..200 {
            let d = startup_delay();
            assert!(
                d >= STARTUP_DELAY && d <= STARTUP_DELAY + STARTUP_JITTER,
                "{d:?}"
            );
        }
    }

    #[test]
    fn the_jitter_actually_varies() {
        let first = startup_delay();
        assert!((0..200).any(|_| startup_delay() != first));
    }

    #[test]
    fn the_automatic_check_waits_then_happens_exactly_once() {
        let t0 = Instant::now();
        let mut t = Throttle::new(t0, Duration::from_secs(75));
        assert!(!t.take_auto(t0));
        assert!(!t.take_auto(t0 + Duration::from_secs(59)));
        assert!(!t.take_auto(t0 + Duration::from_secs(74)));
        assert_eq!(
            t.auto_wait(t0 + Duration::from_secs(70)),
            Duration::from_secs(5)
        );
        assert!(!t.auto_used());
        assert!(t.take_auto(t0 + Duration::from_secs(75)));
        assert!(t.auto_used());
        // Never again, however long the program runs.
        assert!(!t.take_auto(t0 + Duration::from_secs(76)));
        assert!(!t.take_auto(t0 + Duration::from_secs(86_400)));
    }

    #[test]
    fn manual_checks_are_spaced_by_30_seconds() {
        let t0 = Instant::now();
        let mut t = Throttle::new(t0, Duration::from_secs(60));
        assert!(t.take_manual(t0).is_ok());
        assert_eq!(
            t.take_manual(t0 + Duration::from_secs(10)),
            Err(Duration::from_secs(20))
        );
        // A refused attempt does not push the window out.
        assert!(t.take_manual(t0 + Duration::from_secs(30)).is_ok());
        assert!(t.take_manual(t0 + Duration::from_secs(31)).is_err());
    }

    #[test]
    fn a_manual_check_does_not_use_up_the_automatic_one() {
        let t0 = Instant::now();
        let mut t = Throttle::new(t0, Duration::from_secs(60));
        t.take_manual(t0).unwrap();
        assert!(t.take_auto(t0 + Duration::from_secs(61)));
    }
}
