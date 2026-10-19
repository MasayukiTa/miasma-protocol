//! Live statistics of one transfer: smoothed rate, the network path in use,
//! round-trip time and stalls.
//!
//! The arithmetic is plain data (testable without a network); the only part
//! that touches iroh is [`path_samples`] and [`spawn_sampler`], which read the
//! connection's own path information (`Connection::paths`, one entry per open
//! path with its `is_relay` / `is_selected` flags and per-path statistics).
//! Nothing here guesses: a value that the connection did not report stays
//! `None` / [`PathKind::Unknown`].

use serde::{Deserialize, Serialize};

/// How often a transfer's statistics are refreshed.
pub const TICK_MS: u64 = 250;
/// Time constant of the rate smoothing: roughly the last two seconds count.
pub const RATE_TAU_MS: f64 = 2000.0;
/// No byte for this long counts as a stall (the time beyond it is added up).
const STALL_AFTER_MS: u64 = 1000;
/// A path kind needs this share (per mille) of the recent bytes to count as in use.
const MIXED_SHARE_PERMILLE: u64 = 50;
/// Recent window for the path kind, in ticks (about 1.25 s).
const RECENT_TICKS: usize = 5;

/// The network path a transfer runs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// Not known (no connection information yet, or an older daemon).
    #[default]
    Unknown,
    /// Straight to the other computer over UDP.
    Direct,
    /// Through the public relay server (slower).
    Relay,
    /// Both kinds carried a real share of the recent bytes.
    Mixed,
}

impl PathKind {
    /// Stable lower-case name (same as the JSON value).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Mixed => "mixed",
        }
    }
}

/// Why a direct path is unlikely, from this computer's own network report
/// (the same facts `miasma netcheck` prints). Never set without that evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// No UDP got out (IPv4 and IPv6 probes both failed).
    UdpBlocked,
    /// The public port differs per destination, so hole punching rarely works.
    NatVaries,
}

/// The reason, if the report says so. `varies`: `mapping_varies_by_dest`.
pub fn block_reason(udp_v4: bool, udp_v6: bool, varies: Option<bool>) -> Option<BlockReason> {
    if !udp_v4 && !udp_v6 {
        Some(BlockReason::UdpBlocked)
    } else if varies == Some(true) {
        Some(BlockReason::NatVaries)
    } else {
        None
    }
}

/// The optional live part of a transfer record. Every field has a default, so
/// JSON without it (an older daemon) parses and JSON with it parses on an
/// older client that ignores the field.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TransferStats {
    /// Smoothed rate (about 2 s), bits per second.
    pub rate_bits: u64,
    pub path: PathKind,
    /// Round trip of the selected path, milliseconds.
    pub rtt_ms: Option<u32>,
    /// Bytes this transfer put on / took from direct (UDP) paths.
    pub bytes_direct: Option<u64>,
    /// Bytes this transfer put on / took from relay paths.
    pub bytes_relay: Option<u64>,
    /// Time with no progress (beyond one second each time), milliseconds.
    pub stall_ms: u64,
    /// Time spent moving data, milliseconds.
    pub active_ms: u64,
    /// Bytes moved in this session divided by `active_ms`, bits per second
    /// (0 until the data phase ended).
    pub avg_bits: u64,
    /// Lost packets on the selected path, per mille of the datagrams sent.
    pub loss_permille: Option<u32>,
    /// Set only while the path is not direct and this computer's network
    /// report shows why a direct path is unlikely.
    pub direct_blocked: Option<BlockReason>,
}

// ─── Rate smoothing ──────────────────────────────────────────────────────────

/// Exponentially weighted moving average of a byte counter, with a time
/// constant (so uneven sampling does not change the smoothing).
#[derive(Debug, Clone)]
pub struct RateEwma {
    tau_ms: f64,
    value_bits: f64,
    last: Option<(u64, u64)>, // (time ms, bytes)
}

impl RateEwma {
    pub fn new(tau_ms: f64) -> Self {
        Self {
            tau_ms,
            value_bits: 0.0,
            last: None,
        }
    }

    /// Feed the byte total at `now_ms`; returns the smoothed rate in bits/s.
    pub fn update(&mut self, now_ms: u64, bytes: u64) -> u64 {
        match self.last {
            None => {
                self.last = Some((now_ms, bytes));
            }
            Some((t0, b0)) => {
                let dt = now_ms.saturating_sub(t0);
                if dt > 0 {
                    let inst = bytes.saturating_sub(b0) as f64 * 8000.0 / dt as f64;
                    if self.value_bits == 0.0 && bytes > b0 {
                        self.value_bits = inst;
                    } else {
                        let alpha = 1.0 - (-(dt as f64) / self.tau_ms).exp();
                        self.value_bits += alpha * (inst - self.value_bits);
                    }
                    self.last = Some((now_ms, bytes));
                }
            }
        }
        self.value()
    }

    pub fn value(&self) -> u64 {
        if self.value_bits < 1.0 {
            0
        } else {
            self.value_bits as u64
        }
    }
}

// ─── Stalls ──────────────────────────────────────────────────────────────────

/// Adds up the time during which the byte count did not move for longer than
/// [`STALL_AFTER_MS`].
#[derive(Debug, Clone, Default)]
pub struct StallMeter {
    last_bytes: u64,
    last_progress_ms: u64,
    last_tick_ms: u64,
    total_ms: u64,
    started: bool,
}

impl StallMeter {
    pub fn update(&mut self, now_ms: u64, bytes: u64) -> u64 {
        if !self.started {
            *self = Self {
                last_bytes: bytes,
                last_progress_ms: now_ms,
                last_tick_ms: now_ms,
                total_ms: 0,
                started: true,
            };
            return 0;
        }
        if bytes > self.last_bytes {
            self.last_bytes = bytes;
            self.last_progress_ms = now_ms;
        } else {
            let stalled_from = self.last_progress_ms + STALL_AFTER_MS;
            if now_ms > stalled_from {
                self.total_ms += now_ms - self.last_tick_ms.max(stalled_from);
            }
        }
        self.last_tick_ms = now_ms;
        self.total_ms
    }
}

// ─── Paths ───────────────────────────────────────────────────────────────────

/// One open path of a connection, as the connection reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSample {
    /// Stable within a connection (the path's remote address).
    pub key: String,
    pub relay: bool,
    pub selected: bool,
    /// Cumulative bytes on this path in the direction of the transfer.
    pub bytes: u64,
    pub rtt_ms: u32,
    pub lost_packets: u64,
    pub datagrams: u64,
}

/// Which kind the recent bytes say, falling back to the selected path.
pub fn classify(direct: u64, relay: u64, selected_relay: Option<bool>) -> PathKind {
    let total = direct + relay;
    if total == 0 {
        return match selected_relay {
            Some(true) => PathKind::Relay,
            Some(false) => PathKind::Direct,
            None => PathKind::Unknown,
        };
    }
    let d_share = direct * 1000 / total;
    let r_share = relay * 1000 / total;
    match (
        d_share >= MIXED_SHARE_PERMILLE,
        r_share >= MIXED_SHARE_PERMILLE,
    ) {
        (true, true) => PathKind::Mixed,
        (true, false) => PathKind::Direct,
        (false, true) => PathKind::Relay,
        (false, false) => PathKind::Unknown,
    }
}

/// Turns successive path snapshots into per-transfer byte counts per kind.
#[derive(Debug, Clone, Default)]
pub struct PathTracker {
    seen: Vec<(String, u64)>,
    first: bool,
    direct: u64,
    relay: u64,
    recent: [(u64, u64); RECENT_TICKS],
    recent_i: usize,
    any: bool,
}

/// What one snapshot adds up to.
#[derive(Debug, Clone, Default)]
pub struct PathView {
    pub kind: PathKind,
    pub rtt_ms: Option<u32>,
    pub bytes_direct: Option<u64>,
    pub bytes_relay: Option<u64>,
    pub loss_permille: Option<u32>,
}

impl PathTracker {
    pub fn new() -> Self {
        Self {
            first: true,
            ..Self::default()
        }
    }

    /// The first call fixes the starting point (the connection may have served
    /// earlier files); a path that appears later counts from zero.
    pub fn observe(&mut self, samples: &[PathSample]) -> PathView {
        let (mut d_new, mut r_new) = (0u64, 0u64);
        for s in samples {
            let base = match self.seen.iter_mut().find(|(k, _)| *k == s.key) {
                Some(e) => {
                    let b = e.1;
                    e.1 = s.bytes.max(b);
                    b
                }
                None => {
                    self.seen.push((s.key.clone(), s.bytes));
                    if self.first {
                        s.bytes
                    } else {
                        0
                    }
                }
            };
            let delta = s.bytes.saturating_sub(base);
            if s.relay {
                r_new += delta;
            } else {
                d_new += delta;
            }
        }
        self.first = false;
        self.any = true;
        self.direct += d_new;
        self.relay += r_new;
        self.recent[self.recent_i % RECENT_TICKS] = (d_new, r_new);
        self.recent_i += 1;
        let (rd, rr) = self
            .recent
            .iter()
            .fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
        let sel = samples.iter().find(|s| s.selected);
        let kind = if samples.is_empty() {
            PathKind::Unknown
        } else {
            classify(rd, rr, sel.map(|s| s.relay))
        };
        let rtt_ms = sel
            .map(|s| s.rtt_ms)
            .or_else(|| samples.iter().map(|s| s.rtt_ms).min());
        let loss_permille = sel.and_then(|s| {
            (s.datagrams > 0).then(|| (s.lost_packets * 1000 / s.datagrams).min(1000) as u32)
        });
        PathView {
            kind,
            rtt_ms,
            bytes_direct: Some(self.direct),
            bytes_relay: Some(self.relay),
            loss_permille,
        }
    }

    /// The kind over the whole transfer (for a finished row).
    pub fn overall_kind(&self) -> PathKind {
        if !self.any {
            return PathKind::Unknown;
        }
        classify(self.direct, self.relay, None)
    }
}

// ─── The per-transfer meter ──────────────────────────────────────────────────

/// Everything one transfer keeps to produce [`TransferStats`] (a few hundred
/// bytes; it lives only while the transfer runs).
#[derive(Debug, Clone)]
pub struct LiveStats {
    start_ms: u64,
    start_bytes: u64,
    rate: RateEwma,
    stall: StallMeter,
    paths: PathTracker,
    last: TransferStats,
    /// Set by `finish`: nothing may be published from this record any more.
    closed: bool,
}

impl LiveStats {
    pub fn new(now_ms: u64, start_bytes: u64) -> Self {
        Self {
            start_ms: now_ms,
            start_bytes,
            rate: RateEwma::new(RATE_TAU_MS),
            stall: StallMeter::default(),
            paths: PathTracker::new(),
            last: TransferStats::default(),
            closed: false,
        }
    }

    /// True once `finish` ran; a refresh that is still in flight must then
    /// drop its result instead of publishing a live rate over the final one.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// One refresh. `bytes` counts from byte 0 of the file (a resumed prefix
    /// included, like the board's `bytes`).
    pub fn tick(&mut self, now_ms: u64, bytes: u64, samples: &[PathSample]) -> TransferStats {
        let rate_bits = self.rate.update(now_ms, bytes);
        let stall_ms = self.stall.update(now_ms, bytes);
        let v = self.paths.observe(samples);
        self.last = TransferStats {
            rate_bits,
            path: v.kind,
            rtt_ms: v.rtt_ms,
            bytes_direct: v.bytes_direct,
            bytes_relay: v.bytes_relay,
            stall_ms,
            active_ms: now_ms.saturating_sub(self.start_ms),
            avg_bits: 0,
            loss_permille: v.loss_permille,
            direct_blocked: None,
        };
        self.last.clone()
    }

    /// The data phase ended with `bytes` moved: the rate drops to zero and the
    /// average of the whole phase is fixed.
    pub fn finish(&mut self, now_ms: u64, bytes: u64, samples: &[PathSample]) -> TransferStats {
        self.closed = true;
        let mut s = self.tick(now_ms, bytes, samples);
        let active = now_ms.saturating_sub(self.start_ms).max(1);
        let moved = bytes.saturating_sub(self.start_bytes);
        s.rate_bits = 0;
        s.active_ms = active;
        s.avg_bits = (moved as u128 * 8000 / active as u128) as u64;
        let kind = self.paths.overall_kind();
        if kind != PathKind::Unknown {
            s.path = kind;
        }
        self.last = s.clone();
        s
    }
}

/// Reads the open paths of one connection (`true`: count the bytes this side
/// sent, `false`: the bytes it received). Cheap to clone, so a sampling task
/// can hold it without holding the connection type.
pub type PathProbe = std::sync::Arc<dyn Fn(bool) -> Vec<PathSample> + Send + Sync>;

/// Why a direct path is unlikely, if this computer's network report says so.
pub type BlockProbe = std::sync::Arc<dyn Fn() -> Option<BlockReason> + Send + Sync>;

// ─── Reading a live connection ───────────────────────────────────────────────

/// The connection's open paths. `sending`: count the bytes this side sent
/// (otherwise the bytes it received).
#[cfg(feature = "iroh")]
pub fn path_samples(conn: &iroh::endpoint::Connection, sending: bool) -> Vec<PathSample> {
    conn.paths()
        .iter()
        .map(|p| {
            let st = p.stats();
            PathSample {
                key: format!("{:?}", p.remote_addr()),
                relay: p.is_relay(),
                selected: p.is_selected(),
                bytes: if sending {
                    st.udp_tx.bytes
                } else {
                    st.udp_rx.bytes
                },
                rtt_ms: st.rtt.as_millis().min(u32::MAX as u128) as u32,
                lost_packets: st.lost_packets,
                datagrams: st.udp_tx.datagrams,
            }
        })
        .collect()
}

/// Refreshes a transfer's statistics on the board every [`TICK_MS`] while it
/// lives. The transfer loop only stores its byte count in `progress`; reading
/// the connection happens here, off the data path.
#[cfg(feature = "iroh")]
pub struct Sampler {
    live: std::sync::Arc<std::sync::Mutex<LiveStats>>,
    task: tokio::task::JoinHandle<()>,
    probe: Option<PathProbe>,
    sending: bool,
    board: super::state::Board,
    id: String,
    finished: bool,
}

/// The network report's verdict, only when it holds one.
#[cfg(feature = "iroh")]
pub fn endpoint_block_reason(ep: &iroh::Endpoint) -> Option<BlockReason> {
    use iroh::Watcher;
    let r = ep.net_report().get()?;
    block_reason(r.udp_v4, r.udp_v6, r.mapping_varies_by_dest())
}

#[cfg(feature = "iroh")]
impl Sampler {
    pub fn spawn(
        board: super::state::Board,
        id: String,
        progress: std::sync::Arc<std::sync::atomic::AtomicU64>,
        probe: Option<PathProbe>,
        blocked: Option<BlockProbe>,
        sending: bool,
    ) -> Self {
        use std::sync::atomic::Ordering;
        let start = progress.load(Ordering::Relaxed);
        let live = std::sync::Arc::new(std::sync::Mutex::new(LiveStats::new(
            super::state::now_ms(),
            start,
        )));
        let task = {
            let (live, probe) = (live.clone(), probe.clone());
            let (board, id) = (board.clone(), id.clone());
            tokio::spawn(async move {
                let mut every = tokio::time::interval(std::time::Duration::from_millis(TICK_MS));
                every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    every.tick().await;
                    let samples = probe.as_ref().map(|p| p(sending)).unwrap_or_default();
                    // The board is written while the record is locked, and
                    // `finish` closes the record under the same lock: a tick
                    // that was already running when the sampler was stopped
                    // (`abort` only takes effect at the next await) can then
                    // no longer put a live rate on the board after the final
                    // statistics were published.
                    let mut g = live.lock().unwrap();
                    if g.is_closed() {
                        break;
                    }
                    let mut s = g.tick(
                        super::state::now_ms(),
                        progress.load(Ordering::Relaxed),
                        &samples,
                    );
                    if matches!(s.path, PathKind::Relay | PathKind::Mixed) {
                        s.direct_blocked = blocked.as_ref().and_then(|b| b());
                    }
                    board.update(&id, |i| i.stats = Some(s));
                    drop(g);
                }
            })
        };
        Self {
            live,
            task,
            probe,
            sending,
            board,
            id,
            finished: false,
        }
    }

    /// Stop sampling and return the final record (rate zero, average fixed).
    pub fn finish(mut self, bytes: u64) -> TransferStats {
        self.finished = true;
        self.task.abort();
        let samples = self
            .probe
            .as_ref()
            .map(|p| p(self.sending))
            .unwrap_or_default();
        self.live
            .lock()
            .unwrap()
            .finish(super::state::now_ms(), bytes, &samples)
    }
}

#[cfg(feature = "iroh")]
impl Drop for Sampler {
    fn drop(&mut self) {
        self.task.abort();
        if !self.finished {
            // The attempt ended before the data phase did (dropped connection,
            // cancel, error): the row must not keep showing the last speed
            // while it waits to retry.
            self.board.update(&self.id, |i| {
                if let Some(s) = i.stats.as_mut() {
                    s.rate_bits = 0;
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(key: &str, relay: bool, selected: bool, bytes: u64) -> PathSample {
        PathSample {
            key: key.into(),
            relay,
            selected,
            bytes,
            rtt_ms: if relay { 90 } else { 12 },
            lost_packets: 5,
            datagrams: 1000,
        }
    }

    #[test]
    fn ewma_converges_and_follows_a_drop() {
        let mut e = RateEwma::new(2000.0);
        assert_eq!(e.update(0, 0), 0);
        // 1 MB/s = 8 Mbps, sampled every 250 ms.
        let mut b = 0;
        let mut v = 0;
        for i in 1..=40 {
            b += 250_000;
            v = e.update(i * 250, b);
        }
        assert!((7_900_000..=8_100_000).contains(&v), "{v}");
        // The line stops: the value decays by the time constant, not instantly.
        let v1 = e.update(10_250, b);
        assert!(v1 < v && v1 > v / 2, "{v1}");
        let mut v2 = v1;
        for i in 1..=40 {
            v2 = e.update(10_250 + i * 250, b);
        }
        assert!(v2 < 100_000, "{v2}");
    }

    #[test]
    fn ewma_first_sample_is_not_averaged_with_zero() {
        let mut e = RateEwma::new(2000.0);
        e.update(0, 0);
        assert_eq!(e.update(1000, 125_000), 1_000_000);
    }

    #[test]
    fn ewma_ignores_repeated_timestamps_and_counter_resets() {
        let mut e = RateEwma::new(2000.0);
        e.update(100, 10);
        let a = e.update(100, 10);
        assert_eq!(a, 0);
        assert_eq!(e.update(200, 5), 0);
    }

    #[test]
    fn stall_counts_only_time_beyond_one_second() {
        let mut s = StallMeter::default();
        assert_eq!(s.update(0, 0), 0);
        assert_eq!(s.update(500, 100), 0);
        assert_eq!(s.update(1250, 100), 0); // 750 ms without a byte
        assert_eq!(s.update(1750, 100), 250); // beyond 1 s since 500
        assert_eq!(s.update(2250, 100), 750);
        assert_eq!(s.update(2500, 200), 750); // moving again
        assert_eq!(s.update(2750, 200), 750);
    }

    #[test]
    fn path_kind_mapping() {
        assert_eq!(classify(0, 0, None), PathKind::Unknown);
        assert_eq!(classify(0, 0, Some(true)), PathKind::Relay);
        assert_eq!(classify(0, 0, Some(false)), PathKind::Direct);
        assert_eq!(classify(1000, 0, Some(true)), PathKind::Direct);
        assert_eq!(classify(0, 1000, Some(false)), PathKind::Relay);
        assert_eq!(classify(500, 500, None), PathKind::Mixed);
        // 4% on the other kind is noise, 5% is a real share.
        assert_eq!(classify(960, 40, None), PathKind::Direct);
        assert_eq!(classify(950, 50, None), PathKind::Mixed);
        for (k, s) in [
            (PathKind::Unknown, "unknown"),
            (PathKind::Direct, "direct"),
            (PathKind::Relay, "relay"),
            (PathKind::Mixed, "mixed"),
        ] {
            assert_eq!(serde_json::to_string(&k).unwrap(), format!("\"{s}\""));
            assert_eq!(k.as_str(), s);
        }
    }

    #[test]
    fn tracker_counts_from_the_first_snapshot_and_follows_an_upgrade() {
        let mut t = PathTracker::new();
        // The connection served earlier files: 10 MB are already on the relay path.
        let v = t.observe(&[sample("relay", true, true, 10_000_000)]);
        assert_eq!(v.kind, PathKind::Relay);
        assert_eq!(v.bytes_relay, Some(0));
        assert_eq!(v.rtt_ms, Some(90));
        assert_eq!(v.loss_permille, Some(5));
        let v = t.observe(&[sample("relay", true, true, 11_000_000)]);
        assert_eq!(v.bytes_relay, Some(1_000_000));
        // A direct path opens and takes over.
        for i in 1..=6u64 {
            let v = t.observe(&[
                sample("relay", true, false, 11_000_000),
                sample("ip", false, true, i * 2_000_000),
            ]);
            if i == 6 {
                assert_eq!(v.kind, PathKind::Direct, "recent bytes are all direct");
                assert_eq!(v.bytes_direct, Some(12_000_000));
                assert_eq!(v.bytes_relay, Some(1_000_000));
                assert_eq!(v.rtt_ms, Some(12));
            }
        }
        // Over the whole transfer: 1 of 13 MB went through the relay (7.7%).
        assert_eq!(t.overall_kind(), PathKind::Mixed);
    }

    #[test]
    fn tracker_with_no_paths_is_unknown() {
        let mut t = PathTracker::new();
        let v = t.observe(&[]);
        assert_eq!(v.kind, PathKind::Unknown);
        assert_eq!(v.rtt_ms, None);
        assert_eq!(t.overall_kind(), PathKind::Unknown);
    }

    #[test]
    fn live_stats_average_covers_the_data_phase_only() {
        let mut l = LiveStats::new(1_000, 4_000_000);
        let p = [sample("ip", false, true, 0)];
        l.tick(1_000, 4_000_000, &p);
        // 25 MB in 20 s = 10 Mbps.
        let end = l.finish(21_000, 4_000_000 + 25_000_000, &p);
        assert_eq!(end.rate_bits, 0);
        assert_eq!(end.active_ms, 20_000);
        assert_eq!(end.avg_bits, 10_000_000);
    }

    #[test]
    fn block_reason_needs_evidence() {
        assert_eq!(
            block_reason(false, false, None),
            Some(BlockReason::UdpBlocked)
        );
        assert_eq!(
            block_reason(true, false, Some(true)),
            Some(BlockReason::NatVaries)
        );
        assert_eq!(block_reason(true, true, Some(false)), None);
        // Nothing known about the NAT: no claim.
        assert_eq!(block_reason(true, true, None), None);
    }

    #[test]
    fn transfer_record_of_an_older_daemon_parses_and_new_fields_do_not_break_old_readers() {
        use super::super::state::PushTransferInfo;
        // Exactly the fields a daemon wrote before `stats` existed.
        let old = r#"{"id":"ab","direction":"out","contact_id":"c","contact_label":"L",
            "name":"f.bin","size":10,"bytes":5,"rate_bps":123,"state":"sending",
            "created_at_ms":1,"updated_at_ms":2}"#;
        let t: PushTransferInfo = serde_json::from_str(old).unwrap();
        assert_eq!(t.stats, None);
        assert_eq!(t.rate_bps, 123);
        // A new record carries the field; a reader that predates it would ignore
        // it (serde skips unknown keys here), which this checks by dropping the key.
        let mut with = t.clone();
        with.stats = Some(TransferStats {
            rate_bits: 1_000_000,
            path: PathKind::Direct,
            ..Default::default()
        });
        let mut v: serde_json::Value = serde_json::to_value(&with).unwrap();
        let back: PushTransferInfo = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(back, with);
        v.as_object_mut().unwrap().remove("stats");
        let without: PushTransferInfo = serde_json::from_value(v).unwrap();
        assert_eq!(without.stats, None);
    }

    #[test]
    fn json_without_the_field_parses_and_with_it_round_trips() {
        let s: TransferStats = serde_json::from_str("{}").unwrap();
        assert_eq!(s, TransferStats::default());
        assert_eq!(s.path, PathKind::Unknown);
        let s = TransferStats {
            rate_bits: 42_000_000,
            path: PathKind::Relay,
            rtt_ms: Some(180),
            bytes_direct: Some(0),
            bytes_relay: Some(9),
            stall_ms: 3,
            active_ms: 5,
            avg_bits: 7,
            loss_permille: Some(12),
            direct_blocked: Some(BlockReason::NatVaries),
        };
        let back: TransferStats =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }
}
