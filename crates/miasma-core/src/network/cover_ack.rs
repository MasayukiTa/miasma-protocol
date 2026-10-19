//! Timing of acknowledgements for one-hop cover cells.
//!
//! A relay that receives a real first-hop cell forwards it and answers only
//! when the next hop has answered. A relay that receives a cover cell has
//! nothing to forward. Answering the cover cell at once would let an observer of
//! the link tell the two apart by the delay alone.
//!
//! When shaping is enabled the relay keeps the delays it actually observed
//! between forwarding a cell and getting the answer (a small bounded window) and
//! holds each cover acknowledgement for a delay drawn from that window. With
//! shaping disabled, or before any delay has been observed, a cover cell is
//! acknowledged immediately, as before.
//!
//! This only matches the distribution of the relay's own forward delays. It does
//! not hide a difference in the size of the answer, and it does not hide timing
//! seen anywhere other than on this relay's link to the sender.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Number of observed forward delays kept.
pub(crate) const DELAY_WINDOW: usize = 64;

/// Longest delay ever applied to a cover acknowledgement.
pub(crate) const MAX_ACK_DELAY: Duration = Duration::from_secs(5);

/// Most acknowledgements held back at once. Beyond this a cover cell is
/// answered immediately, so the queue cannot grow with attacker traffic.
pub(crate) const MAX_HELD_ACKS: usize = 64;

/// Bounded window of observed forward delays.
#[derive(Debug, Default)]
pub(crate) struct ForwardDelayWindow {
    samples: VecDeque<Duration>,
}

impl ForwardDelayWindow {
    pub(crate) fn record(&mut self, delay: Duration) {
        if self.samples.len() == DELAY_WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(delay.min(MAX_ACK_DELAY));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.samples.len()
    }

    /// Pick one observed delay. `pick` is any random number; it is reduced
    /// modulo the window size. `None` while nothing has been observed.
    pub(crate) fn sample(&self, pick: u64) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        self.samples
            .get((pick % self.samples.len() as u64) as usize)
            .copied()
    }
}

/// Decides when a cover acknowledgement is sent and holds the ones that wait.
#[derive(Debug)]
pub(crate) struct CoverAckShaper<T> {
    enabled: bool,
    window: ForwardDelayWindow,
    held: Vec<(Instant, T)>,
}

impl<T> CoverAckShaper<T> {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            window: ForwardDelayWindow::default(),
            held: Vec::new(),
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    #[cfg(test)]
    pub(crate) fn held_len(&self) -> usize {
        self.held.len()
    }

    #[cfg(test)]
    pub(crate) fn observed_samples(&self) -> usize {
        self.window.len()
    }

    /// Record the time a forwarded real cell took to be answered.
    pub(crate) fn record_forward_delay(&mut self, delay: Duration) {
        if self.enabled {
            self.window.record(delay);
        }
    }

    /// Submit a cover acknowledgement. Returns the item when it is to be sent
    /// right now, or `None` when it has been held until its due time.
    pub(crate) fn submit(&mut self, now: Instant, pick: u64, item: T) -> Option<T> {
        if !self.enabled || self.held.len() >= MAX_HELD_ACKS {
            return Some(item);
        }
        match self.window.sample(pick) {
            Some(delay) if !delay.is_zero() => {
                self.held.push((now + delay, item));
                None
            }
            _ => Some(item),
        }
    }

    /// Earliest due time among held acknowledgements.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        self.held.iter().map(|(due, _)| *due).min()
    }

    /// Remove and return every acknowledgement whose time has come.
    pub(crate) fn drain_due(&mut self, now: Instant) -> Vec<T> {
        let mut due = Vec::new();
        let mut i = 0;
        while i < self.held.len() {
            if self.held[i].0 <= now {
                due.push(self.held.swap_remove(i).1);
            } else {
                i += 1;
            }
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_shaper_answers_immediately_and_records_nothing() {
        let mut s = CoverAckShaper::<u32>::new(false);
        s.record_forward_delay(Duration::from_millis(300));
        assert_eq!(s.observed_samples(), 0);
        assert_eq!(s.submit(Instant::now(), 7, 1), Some(1));
        assert_eq!(s.held_len(), 0);
    }

    #[test]
    fn enabled_without_samples_answers_immediately() {
        let mut s = CoverAckShaper::<u32>::new(true);
        assert_eq!(s.submit(Instant::now(), 0, 9), Some(9));
    }

    #[test]
    fn enabled_with_samples_holds_for_an_observed_delay() {
        let mut s = CoverAckShaper::<u32>::new(true);
        for ms in [100u64, 200, 300] {
            s.record_forward_delay(Duration::from_millis(ms));
        }
        let t0 = Instant::now();
        // pick 1 -> second sample (200 ms)
        assert_eq!(s.submit(t0, 1, 5), None);
        assert_eq!(s.next_due(), Some(t0 + Duration::from_millis(200)));
        assert!(s.drain_due(t0 + Duration::from_millis(199)).is_empty());
        assert_eq!(s.drain_due(t0 + Duration::from_millis(200)), vec![5]);
        assert_eq!(s.held_len(), 0);
        assert_eq!(s.next_due(), None);
    }

    #[test]
    fn every_held_delay_comes_from_the_observed_set() {
        let observed = [40u64, 90, 250];
        let t0 = Instant::now();
        for pick in 0..30u64 {
            let mut one = CoverAckShaper::<u64>::new(true);
            for ms in observed {
                one.record_forward_delay(Duration::from_millis(ms));
            }
            assert_eq!(one.submit(t0, pick, pick), None);
            let due = one.next_due().unwrap() - t0;
            assert!(
                observed.iter().any(|ms| due == Duration::from_millis(*ms)),
                "delay {due:?} was not observed"
            );
        }
    }

    #[test]
    fn window_is_bounded_and_delays_are_capped() {
        let mut w = ForwardDelayWindow::default();
        for i in 0..(DELAY_WINDOW * 3) {
            w.record(Duration::from_millis(i as u64));
        }
        assert_eq!(w.len(), DELAY_WINDOW);
        w.record(Duration::from_secs(3600));
        assert!((0..DELAY_WINDOW as u64)
            .filter_map(|p| w.sample(p))
            .all(|d| d <= MAX_ACK_DELAY));
    }

    #[test]
    fn held_queue_is_bounded() {
        let mut s = CoverAckShaper::<usize>::new(true);
        s.record_forward_delay(Duration::from_millis(50));
        let t0 = Instant::now();
        let mut immediate = 0;
        for i in 0..(MAX_HELD_ACKS + 10) {
            if s.submit(t0, 0, i).is_some() {
                immediate += 1;
            }
        }
        assert_eq!(s.held_len(), MAX_HELD_ACKS);
        assert_eq!(immediate, 10);
    }
}
