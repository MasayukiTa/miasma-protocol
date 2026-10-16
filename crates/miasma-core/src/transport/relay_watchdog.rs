//! Keeps the iroh endpoint's home relay connection alive.
//!
//! The endpoint's relay connection is retried by iroh forever, but the state the
//! retries run on is not: iroh 1.3.0 reads the system DNS servers once, on the
//! first lookup of the relay host (`n0-dns-resolver` 0.1.0, `resolver.rs`
//! `DnsResolver::state`, a `OnceLock`), and only throws that snapshot away from
//! `DnsResolver::reset`, whose one caller is the "major network change" branch of
//! the socket actor (`iroh` `socket.rs`, `handle_network_change`). A daemon that
//! started while the network was still coming up (a VPN adapter appearing after
//! the first lookup) can therefore keep asking name servers that no longer
//! answer, while a new process, which reads the configuration afresh, connects at
//! once. `Endpoint::network_change` does not help by itself: `netwatch` drops it
//! when the interface list is unchanged (`netmon/actor.rs`,
//! `handle_potential_change`).
//!
//! The watchdog is the mitigation that does not depend on iroh noticing:
//!
//! 1. Not connected for 20 s after start, or for 30 s after a drop: refresh the
//!    endpoint (reset and empty the DNS resolver, then `network_change`).
//! 2. Refresh again 20 s, then 60 s after that, then wait 180 s.
//! 3. Still down: rebuild the endpoint in place (same key, so the endpoint ID
//!    and the contact ID stay), then again every 5 minutes.
//!
//! The decision is a pure function of the clock and the observed link
//! ([`Watchdog::observe`]); [`step`] applies it to an endpoint behind the
//! [`RelayEndpoint`] trait, so the tests need no network.

use std::{sync::Arc, time::Duration};

use tokio::sync::watch;
use tracing::{info, warn};

/// How long the relay may stay down before the first refresh, counted from the
/// start of the endpoint (it never was connected).
pub const FIRST_CONNECT_GRACE: Duration = Duration::from_secs(20);
/// How long a relay that was connected may stay down before the first refresh.
pub const DROP_GRACE: Duration = Duration::from_secs(30);
/// Waits after the first, second and third refresh.
pub const REFRESH_GAPS: [Duration; 3] = [
    Duration::from_secs(20),
    Duration::from_secs(60),
    Duration::from_secs(180),
];
/// Wait between rebuilds once the refreshes have not helped.
pub const REBUILD_INTERVAL: Duration = Duration::from_secs(300);
/// How often the link is looked at.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// What the watchdog asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Reset the DNS state and tell the endpoint the network may have changed.
    /// The number is 1, 2 or 3.
    Refresh(u32),
    /// Build the endpoint again, same key. The number counts from 1.
    Rebuild(u32),
}

/// The relay decision, driven by a clock the caller supplies (any monotonic
/// `Duration`, a fake one in tests).
#[derive(Debug, Clone)]
pub struct Watchdog {
    ever_connected: bool,
    down_since: Option<Duration>,
    /// Actions taken in the current outage.
    taken: u32,
    next_at: Option<Duration>,
}

impl Watchdog {
    /// A watchdog for an endpoint that started at `now` and is not connected yet.
    pub fn new(now: Duration) -> Self {
        Self {
            ever_connected: false,
            down_since: Some(now),
            taken: 0,
            next_at: None,
        }
    }

    /// How long the link has been down at `now` (`None` while connected).
    pub fn down_for(&self, now: Duration) -> Option<Duration> {
        self.down_since.map(|d| now.saturating_sub(d))
    }

    /// Feed one observation; the answer is what to do now, if anything.
    ///
    /// At most one action per call, and the next one is due a full gap after
    /// `now` (not after the time it was due), so a stalled caller never gets a
    /// burst of actions.
    pub fn observe(&mut self, now: Duration, connected: bool) -> Option<Action> {
        if connected {
            self.ever_connected = true;
            self.down_since = None;
            self.taken = 0;
            self.next_at = None;
            return None;
        }
        let down_since = *self.down_since.get_or_insert(now);
        let due = *self.next_at.get_or_insert_with(|| {
            down_since
                + if self.ever_connected {
                    DROP_GRACE
                } else {
                    FIRST_CONNECT_GRACE
                }
        });
        if now < due {
            return None;
        }
        self.taken += 1;
        let n = self.taken;
        let gap = match n {
            1..=3 => REFRESH_GAPS[(n - 1) as usize],
            _ => REBUILD_INTERVAL,
        };
        self.next_at = Some(now + gap);
        Some(if n <= 3 {
            Action::Refresh(n)
        } else {
            Action::Rebuild(n - 3)
        })
    }
}

/// The part of the link the decision needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLink {
    pub connected: bool,
    pub last_error: Option<String>,
}

/// The cause of a relay failure in words a person can act on, from the debug
/// text of iroh's last error (which is for logs, not for matching, hence the
/// coarse classes and the `Other` fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCause {
    /// The relay's name could not be looked up.
    Dns,
    /// The relay did not answer in time.
    Timeout,
    /// The relay's certificate was not accepted.
    Tls,
    /// The relay refused this endpoint.
    Denied,
    Other,
}

impl RelayCause {
    pub fn classify(error: &str) -> Self {
        let e = error.to_ascii_lowercase();
        if e.contains("no response")
            || e.contains("resolve")
            || e.contains("dns")
            || e.contains("nxdomain")
        {
            Self::Dns
        } else if e.contains("certificate") || e.contains("tls") {
            Self::Tls
        } else if e.contains("denied") || e.contains("unauthorized") {
            Self::Denied
        } else if e.contains("timed out") || e.contains("timeout") {
            Self::Timeout
        } else {
            Self::Other
        }
    }
}

/// An endpoint the watchdog can look at and act on.
#[async_trait::async_trait]
pub trait RelayEndpoint: Send + Sync {
    fn link(&self) -> RelayLink;
    /// Reset the DNS state and signal a network change.
    async fn refresh(&self);
    /// Build the endpoint again with the same key.
    async fn rebuild(&self) -> Result<(), String>;
}

/// One poll: observe, act, log. Returns the action taken.
pub async fn step<E: RelayEndpoint + ?Sized>(
    wd: &mut Watchdog,
    ep: &E,
    now: Duration,
) -> Option<Action> {
    let link = ep.link();
    let action = wd.observe(now, link.connected)?;
    let down = wd.down_for(now).unwrap_or_default().as_secs();
    let why = link.last_error.as_deref().unwrap_or("no error reported");
    match action {
        Action::Refresh(n) => {
            info!("relay watchdog: home relay down for {down} s ({why}); refresh {n} of 3");
            ep.refresh().await;
        }
        Action::Rebuild(n) => {
            info!("relay watchdog: home relay down for {down} s ({why}); rebuilding the endpoint (rebuild {n})");
            match ep.rebuild().await {
                Ok(()) => info!("relay watchdog: endpoint rebuilt (same endpoint ID)"),
                Err(e) => warn!("relay watchdog: rebuilding the endpoint failed: {e}"),
            }
        }
    }
    Some(action)
}

/// Poll `ep` until `stop` fires or its sender is dropped.
pub async fn run<E: RelayEndpoint + ?Sized>(ep: Arc<E>, mut stop: watch::Receiver<bool>) {
    let t0 = tokio::time::Instant::now();
    let mut wd = Watchdog::new(Duration::ZERO);
    let mut tick = tokio::time::interval(POLL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                step(&mut wd, ep.as_ref(), t0.elapsed()).await;
            }
            r = stop.changed() => {
                if r.is_err() || *stop.borrow() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Poll every 5 s from `from` to `to` (inclusive) and collect the actions.
    fn drive(wd: &mut Watchdog, from: u64, to: u64, connected: bool) -> Vec<(u64, Action)> {
        (from..=to)
            .step_by(5)
            .filter_map(|t| wd.observe(s(t), connected).map(|a| (t, a)))
            .collect()
    }

    #[test]
    fn quiet_while_connected() {
        let mut wd = Watchdog::new(s(0));
        assert!(wd.observe(s(1), true).is_none());
        assert!(drive(&mut wd, 0, 10_000, true).is_empty());
        assert_eq!(wd.down_for(s(10_000)), None);
    }

    #[test]
    fn follows_the_backoff_and_rebuilds_once_per_interval() {
        let mut wd = Watchdog::new(s(0));
        let acts = drive(&mut wd, 0, 1_000, false);
        let at = |a: Action| acts.iter().find(|(_, x)| *x == a).map(|(t, _)| *t);
        // First refresh once the 20 s grace is over; then +20 s, +60 s; the
        // first rebuild 180 s after the third refresh; then every 300 s.
        assert_eq!(at(Action::Refresh(1)), Some(20));
        assert_eq!(at(Action::Refresh(2)), Some(40));
        assert_eq!(at(Action::Refresh(3)), Some(100));
        assert_eq!(at(Action::Rebuild(1)), Some(280));
        assert_eq!(at(Action::Rebuild(2)), Some(580));
        assert_eq!(at(Action::Rebuild(3)), Some(880));
        assert_eq!(acts.len(), 6);
    }

    #[test]
    fn a_dropped_link_gets_the_longer_grace() {
        let mut wd = Watchdog::new(s(0));
        assert!(wd.observe(s(2), true).is_none());
        assert!(wd.observe(s(100), false).is_none());
        assert!(wd.observe(s(129), false).is_none());
        assert_eq!(wd.observe(s(130), false), Some(Action::Refresh(1)));
        assert_eq!(wd.down_for(s(130)), Some(s(30)));
    }

    #[test]
    fn success_resets_the_schedule() {
        let mut wd = Watchdog::new(s(0));
        assert_eq!(drive(&mut wd, 0, 100, false).len(), 3);
        assert!(wd.observe(s(105), true).is_none());
        // A new outage starts from the first step again.
        assert!(wd.observe(s(110), false).is_none());
        assert_eq!(wd.observe(s(140), false), Some(Action::Refresh(1)));
    }

    #[test]
    fn a_stalled_caller_gets_one_action_not_a_burst() {
        let mut wd = Watchdog::new(s(0));
        assert_eq!(wd.observe(s(10_000), false), Some(Action::Refresh(1)));
        // Nothing more until the gap has passed, however often it is asked.
        for t in 10_000..10_020 {
            assert_eq!(wd.observe(s(t), false), None);
        }
        assert_eq!(wd.observe(s(10_020), false), Some(Action::Refresh(2)));
    }

    #[test]
    fn no_tight_loop_on_repeated_polls() {
        let mut wd = Watchdog::new(s(0));
        let mut n = 0;
        // 10 000 polls inside one hour of fake time.
        for i in 0..10_000u64 {
            if wd.observe(Duration::from_millis(i * 360), false).is_some() {
                n += 1;
            }
        }
        // 3 refreshes + rebuilds at 280 s, 580 s, ... (3600 s window).
        assert!(n <= 3 + 12, "too many actions: {n}");
    }

    struct Fake {
        state: Mutex<(bool, Vec<&'static str>, bool)>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                state: Mutex::new((false, Vec::new(), true)),
            }
        }
        fn calls(&self) -> Vec<&'static str> {
            self.state.lock().unwrap().1.clone()
        }
    }

    #[async_trait::async_trait]
    impl RelayEndpoint for Fake {
        fn link(&self) -> RelayLink {
            let g = self.state.lock().unwrap();
            RelayLink {
                connected: g.0,
                last_error: Some("unable to connect".into()),
            }
        }
        async fn refresh(&self) {
            self.state.lock().unwrap().1.push("refresh");
        }
        async fn rebuild(&self) -> Result<(), String> {
            let mut g = self.state.lock().unwrap();
            g.1.push("rebuild");
            if g.2 {
                Ok(())
            } else {
                Err("bind failed".into())
            }
        }
    }

    #[tokio::test]
    async fn step_drives_the_endpoint() {
        let ep = Fake::new();
        let mut wd = Watchdog::new(s(0));
        for t in (0..=300).step_by(5) {
            step(&mut wd, &ep, s(t)).await;
        }
        assert_eq!(ep.calls(), ["refresh", "refresh", "refresh", "rebuild"]);
        // The relay comes back: nothing more happens.
        ep.state.lock().unwrap().0 = true;
        for t in (305..=2_000).step_by(5) {
            assert_eq!(step(&mut wd, &ep, s(t)).await, None);
        }
        assert_eq!(ep.calls().len(), 4);
    }

    #[tokio::test]
    async fn a_failed_rebuild_is_retried_on_the_next_interval_only() {
        let ep = Fake::new();
        ep.state.lock().unwrap().2 = false;
        let mut wd = Watchdog::new(s(0));
        for t in (0..=900).step_by(5) {
            step(&mut wd, &ep, s(t)).await;
        }
        let rebuilds = ep.calls().iter().filter(|c| **c == "rebuild").count();
        assert_eq!(rebuilds, 3);
    }
}
