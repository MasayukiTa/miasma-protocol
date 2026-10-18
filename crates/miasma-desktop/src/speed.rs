//! Live speed in the transfer rows: text in the user's units, the path badge,
//! the reason a relay is in use (only with evidence), a 60-second sparkline
//! and the total of all running transfers.
//!
//! Everything but the painter is plain data and tested without a window.

use std::collections::HashMap;

use miasma_core::push::{
    speed_fmt::{format_narrow, format_speed, SpeedShown, SpeedUnit},
    stats::{BlockReason, PathKind, TransferStats},
};

use crate::{contacts::Row, locale::Locale, transfers::fill};

/// Seconds the sparkline covers (one sample per second).
pub const SPARK_SECS: usize = 60;
/// Below this width the text drops to the narrow form.
pub const NARROW_PX: f32 = 420.0;

/// `ui.speed_unit` and `ui.speed_units_shown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpeedPrefs {
    pub unit: SpeedUnit,
    pub shown: SpeedShown,
}

impl SpeedPrefs {
    pub fn text(&self, bits: u64) -> String {
        format_speed(bits, self.unit, self.shown)
    }

    pub fn narrow(&self, bits: u64) -> String {
        format_narrow(bits, self.unit, self.shown)
    }

    /// Full text when there is room, otherwise the one-line form.
    pub fn fit(&self, bits: u64, width_px: f32) -> String {
        if width_px < NARROW_PX {
            self.narrow(bits)
        } else {
            self.text(bits)
        }
    }
}

// ─── Sparkline data ──────────────────────────────────────────────────────────

/// The last 60 seconds of one transfer's rate, in Kbps (u32 reaches 4 Tbps).
/// A fixed 244 bytes: no allocation, nothing that grows.
#[derive(Debug, Clone, Copy)]
pub struct Spark {
    kbps: [u32; SPARK_SECS],
    head: u8,
    len: u8,
}

impl Default for Spark {
    fn default() -> Self {
        Self {
            kbps: [0; SPARK_SECS],
            head: 0,
            len: 0,
        }
    }
}

impl Spark {
    pub fn push(&mut self, bits_per_s: u64) {
        let k = (bits_per_s / 1000).min(u32::MAX as u64) as u32;
        self.kbps[self.head as usize] = k;
        self.head = ((self.head as usize + 1) % SPARK_SECS) as u8;
        self.len = (self.len + 1).min(SPARK_SECS as u8);
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Oldest first.
    pub fn values(&self) -> impl Iterator<Item = u32> + '_ {
        let n = self.len as usize;
        let start = (self.head as usize + SPARK_SECS - n) % SPARK_SECS;
        (0..n).map(move |i| self.kbps[(start + i) % SPARK_SECS])
    }

    pub fn max(&self) -> u32 {
        self.values().max().unwrap_or(0)
    }
}

/// One [`Spark`] per running transfer, dropped when the transfer ends.
#[derive(Debug, Default)]
pub struct SparkStore {
    map: HashMap<String, Spark>,
    last_sample_ms: u64,
}

impl SparkStore {
    /// Take at most one sample per second of every running row's rate and
    /// forget every transfer that is no longer running.
    pub fn observe(&mut self, now_ms: u64, rows: &[Row]) {
        let running: std::collections::HashSet<&str> = rows
            .iter()
            .filter(|r| !r.finished())
            .map(|r| r.id.as_str())
            .collect();
        self.map.retain(|id, _| running.contains(id.as_str()));
        if now_ms.saturating_sub(self.last_sample_ms) < 1000 {
            return;
        }
        self.last_sample_ms = now_ms;
        for r in rows.iter().filter(|r| !r.finished()) {
            self.map
                .entry(r.id.clone())
                .or_default()
                .push(row_rate_bits(r));
        }
    }

    pub fn get(&self, id: &str) -> Option<&Spark> {
        self.map.get(id)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ─── Numbers of a row ────────────────────────────────────────────────────────

/// Bits per second of a row: the daemon's smoothed value, or (older daemons)
/// its byte rate times eight.
pub fn row_rate_bits(r: &Row) -> u64 {
    match &r.stats {
        Some(s) => s.rate_bits,
        None => r.rate_bps.saturating_mul(8),
    }
}

/// Total of all running transfers.
pub fn total_rate_bits(rows: &[Row]) -> u64 {
    rows.iter()
        .filter(|r| !r.finished())
        .map(row_rate_bits)
        .fold(0u64, |a, b| a.saturating_add(b))
}

/// How many running transfers are moving data.
pub fn moving_count(rows: &[Row]) -> usize {
    rows.iter()
        .filter(|r| !r.finished() && row_rate_bits(r) > 0)
        .count()
}

// ─── Words ───────────────────────────────────────────────────────────────────

pub use crate::locale::{speed_strings, SpeedStrings};

/// The badge text of a path, or `None` when the path is not known (nothing is
/// shown rather than a guess).
pub fn path_badge(s: &SpeedStrings, kind: PathKind) -> Option<&'static str> {
    match kind {
        PathKind::Direct => Some(s.path_direct),
        PathKind::Relay => Some(s.path_relay),
        PathKind::Mixed => Some(s.path_mixed),
        PathKind::Unknown => None,
    }
}

/// Why a relay is in use: only when the daemon reported evidence from this
/// computer's network report (`direct_blocked`) and the path is the relay.
pub fn relay_reason(s: &SpeedStrings, st: &TransferStats) -> Option<&'static str> {
    if st.path != PathKind::Relay {
        return None;
    }
    match st.direct_blocked? {
        BlockReason::UdpBlocked => Some(s.reason_udp),
        BlockReason::NatVaries => Some(s.reason_nat),
    }
}

/// `avg 45 Mbps (5.6 MB/s / 5.4 MiB/s), 20 s` for a finished row, if it moved data.
pub fn avg_text(
    s: &SpeedStrings,
    st: &TransferStats,
    p: SpeedPrefs,
    width_px: f32,
) -> Option<String> {
    if st.avg_bits == 0 {
        return None;
    }
    let secs = ((st.active_ms + 500) / 1000).to_string();
    Some(fill(
        s.avg,
        &[("speed", &p.fit(st.avg_bits, width_px)), ("secs", &secs)],
    ))
}

/// Header total, `None` when nothing is moving.
pub fn total_text(s: &SpeedStrings, rows: &[Row], p: SpeedPrefs, width_px: f32) -> Option<String> {
    let bits = total_rate_bits(rows);
    if bits == 0 {
        return None;
    }
    Some(fill(
        s.total,
        &[
            ("speed", &p.fit(bits, width_px)),
            ("n", &moving_count(rows).to_string()),
        ],
    ))
}

/// `RTT 12 ms`, `stalled 3 s` of a running row.
pub fn detail_text(s: &SpeedStrings, st: &TransferStats) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(ms) = st.rtt_ms {
        parts.push(fill(s.rtt, &[("ms", &ms.to_string())]));
    }
    if st.stall_ms >= 1000 {
        parts.push(fill(
            s.stalled,
            &[("secs", &(st.stall_ms / 1000).to_string())],
        ));
    }
    (!parts.is_empty()).then(|| parts.join("  ·  "))
}

// ─── State the contacts screen holds ─────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SpeedUi {
    pub prefs: SpeedPrefs,
    pub locale: Locale,
    pub sparks: SparkStore,
}

impl SpeedUi {
    /// Speed text for the progress bar of a running row.
    pub fn rate_text(&self, r: &Row, width_px: f32) -> Option<String> {
        let bits = row_rate_bits(r);
        (bits > 0).then(|| self.prefs.fit(bits, width_px))
    }

    /// The header total of the transfer list.
    pub fn header_total(&self, rows: &[Row], width_px: f32) -> Option<String> {
        total_text(speed_strings(self.locale), rows, self.prefs, width_px)
    }

    /// Under a row: the path badge, round trip, stall, the sparkline, and for a
    /// finished row the average. Nothing for a row whose daemon sent no stats.
    pub fn row_extras(&self, ui: &mut egui::Ui, r: &Row) {
        let Some(st) = &r.stats else { return };
        let s = speed_strings(self.locale);
        let pal = crate::ui_kit::pal();
        let width = ui.available_width();
        let badge = path_badge(s, st.path);
        let line = if r.finished() {
            if r.state != miasma_core::push::PushState::Done {
                return;
            }
            avg_text(s, st, self.prefs, width)
        } else {
            detail_text(s, st)
        };
        if badge.is_none() && line.is_none() {
            return;
        }
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            if let Some(b) = badge {
                let color = match st.path {
                    PathKind::Direct => pal.success,
                    _ => pal.warning,
                };
                crate::transfers::draw_chip(ui, color, b);
            }
            if let Some(l) = line {
                ui.label(egui::RichText::new(l).color(pal.muted));
            }
            if !r.finished() {
                if let Some(sp) = self.sparks.get(&r.id).filter(|sp| sp.len() >= 2) {
                    paint_spark(ui, sp, pal.info, pal.surface);
                }
            }
        });
        if !r.finished() {
            if let Some(why) = relay_reason(s, st) {
                ui.add(egui::Label::new(egui::RichText::new(why).color(pal.warning)).wrap(true));
            }
        }
    }
}

/// The sparkline: a thin polyline scaled to the busiest second shown.
pub fn paint_spark(ui: &mut egui::Ui, spark: &Spark, color: egui::Color32, track: egui::Color32) {
    let size = egui::vec2(120.0, 22.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 3.0, track);
    let max = spark.max().max(1) as f32;
    let n = spark.len();
    if n < 2 {
        return;
    }
    let pad = 2.0;
    let w = rect.width() - 2.0 * pad;
    let h = rect.height() - 2.0 * pad;
    let pts: Vec<egui::Pos2> = spark
        .values()
        .enumerate()
        .map(|(i, v)| {
            // The newest sample sits at the right edge; a short history starts mid-way.
            let x = rect.right() - pad - w * ((n - 1 - i) as f32 / (SPARK_SECS - 1) as f32);
            let y = rect.bottom() - pad - h * (v as f32 / max);
            egui::pos2(x, y)
        })
        .collect();
    p.add(egui::Shape::line(pts, egui::Stroke::new(1.5, color)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::push::PushState;

    fn row(id: &str, state: PushState, stats: Option<TransferStats>, rate_bps: u64) -> Row {
        Row {
            id: id.into(),
            outbound: true,
            contact_id: "c".into(),
            contact_label: "L".into(),
            name: "n".into(),
            size: 100,
            bytes: 0,
            rate_bps,
            state,
            error: None,
            reject_reason: None,
            error_kind: None,
            source_path: None,
            saved_as: None,
            at_ms: 0,
            next_attempt_at_ms: None,
            attempt: None,
            stats,
        }
    }

    fn st(path: PathKind, bits: u64) -> TransferStats {
        TransferStats {
            rate_bits: bits,
            path,
            ..Default::default()
        }
    }

    #[test]
    fn path_badge_mapping() {
        let s = speed_strings(Locale::En);
        assert_eq!(path_badge(s, PathKind::Direct), Some("Direct"));
        assert_eq!(path_badge(s, PathKind::Relay), Some("Via relay (slower)"));
        assert_eq!(path_badge(s, PathKind::Mixed), Some("Direct + relay"));
        assert_eq!(path_badge(s, PathKind::Unknown), None);
        for l in Locale::ALL {
            let s = speed_strings(l);
            assert!(!s.path_relay.is_empty() && !s.path_direct.is_empty());
        }
    }

    #[test]
    fn relay_reason_needs_evidence_and_the_relay_path() {
        let s = speed_strings(Locale::En);
        let mut t = st(PathKind::Relay, 1);
        assert_eq!(relay_reason(s, &t), None, "no evidence, no claim");
        t.direct_blocked = Some(BlockReason::UdpBlocked);
        assert_eq!(relay_reason(s, &t), Some(s.reason_udp));
        t.direct_blocked = Some(BlockReason::NatVaries);
        assert_eq!(relay_reason(s, &t), Some(s.reason_nat));
        t.path = PathKind::Direct;
        assert_eq!(relay_reason(s, &t), None);
    }

    #[test]
    fn totals_use_running_rows_and_the_old_daemons_byte_rate() {
        let rows = vec![
            row(
                "a",
                PushState::Sending,
                Some(st(PathKind::Direct, 40_000_000)),
                0,
            ),
            row("b", PushState::Sending, None, 1_000_000), // 8 Mbps from bytes
            row(
                "c",
                PushState::Done,
                Some(st(PathKind::Direct, 99_000_000)),
                0,
            ),
            row("d", PushState::Queued, None, 0),
        ];
        assert_eq!(total_rate_bits(&rows), 48_000_000);
        assert_eq!(moving_count(&rows), 2);
        let s = speed_strings(Locale::En);
        let p = SpeedPrefs::default();
        assert_eq!(
            total_text(s, &rows, p, 800.0).unwrap(),
            "Now: 48 Mbps (6.0 MB/s / 5.7 MiB/s) (2)"
        );
        assert_eq!(total_text(s, &rows[2..], p, 800.0), None);
        // A narrow header keeps one line with one byte unit.
        assert_eq!(
            total_text(s, &rows, p, 300.0).unwrap(),
            "Now: 48 Mbps (5.7 MiB/s) (2)"
        );
    }

    #[test]
    fn avg_text_on_finished_rows() {
        let s = speed_strings(Locale::En);
        let t = TransferStats {
            avg_bits: 45_000_000,
            active_ms: 20_200,
            ..Default::default()
        };
        assert_eq!(
            avg_text(s, &t, SpeedPrefs::default(), 800.0).unwrap(),
            "avg 45 Mbps (5.6 MB/s / 5.4 MiB/s), 20 s"
        );
        let p = SpeedPrefs {
            unit: SpeedUnit::Bytes,
            shown: SpeedShown::BitsOnly,
        };
        assert_eq!(avg_text(s, &t, p, 800.0).unwrap(), "avg 45 Mbps, 20 s");
        assert_eq!(avg_text(s, &TransferStats::default(), p, 800.0), None);
    }

    #[test]
    fn detail_text_shows_rtt_and_long_stalls_only() {
        let s = speed_strings(Locale::En);
        let mut t = TransferStats::default();
        assert_eq!(detail_text(s, &t), None);
        t.rtt_ms = Some(12);
        assert_eq!(detail_text(s, &t).unwrap(), "RTT 12 ms");
        t.stall_ms = 999;
        assert_eq!(detail_text(s, &t).unwrap(), "RTT 12 ms");
        t.stall_ms = 2999;
        assert_eq!(detail_text(s, &t).unwrap(), "RTT 12 ms  ·  stalled 2 s");
        t.stall_ms = 3500;
        assert_eq!(detail_text(s, &t).unwrap(), "RTT 12 ms  ·  stalled 3 s");
    }

    #[test]
    fn spark_keeps_the_last_sixty_in_order() {
        let mut sp = Spark::default();
        assert!(sp.is_empty());
        for i in 1..=75u64 {
            sp.push(i * 1000);
        }
        assert_eq!(sp.len(), 60);
        let v: Vec<u32> = sp.values().collect();
        assert_eq!(v.first(), Some(&16));
        assert_eq!(v.last(), Some(&75));
        assert!(v.windows(2).all(|w| w[0] + 1 == w[1]));
        assert_eq!(sp.max(), 75);
        assert!(std::mem::size_of::<Spark>() <= 1024);
    }

    #[test]
    fn sparks_are_sampled_once_a_second_and_dropped_with_the_row() {
        let mut store = SparkStore::default();
        let mut rows = vec![row(
            "a",
            PushState::Sending,
            Some(st(PathKind::Direct, 8_000_000)),
            0,
        )];
        store.observe(10_000, &rows);
        store.observe(10_400, &rows); // too soon
        store.observe(11_000, &rows);
        assert_eq!(store.get("a").unwrap().len(), 2);
        rows[0].state = PushState::Done;
        store.observe(12_000, &rows);
        assert!(store.is_empty());
    }

    #[test]
    fn memory_stays_flat_for_a_thousand_rows() {
        let mut store = SparkStore::default();
        let rows: Vec<Row> = (0..1000)
            .map(|i| {
                row(
                    &format!("t{i}"),
                    PushState::Sending,
                    Some(st(PathKind::Direct, 9_000_000)),
                    0,
                )
            })
            .collect();
        for step in 0..500u64 {
            store.observe(1_000 * (step + 1), &rows);
        }
        assert_eq!(store.len(), 1000);
        let per_row = std::mem::size_of::<Spark>();
        assert!(per_row <= 1024, "{per_row} bytes per row");
        // Nothing grew with time: every row holds exactly the 60 samples.
        assert!(rows
            .iter()
            .all(|r| store.get(&r.id).unwrap().len() == SPARK_SECS));
        // All rows end: everything is released.
        let done: Vec<Row> = rows
            .into_iter()
            .map(|mut r| {
                r.state = PushState::Done;
                r
            })
            .collect();
        store.observe(10_000_000, &done);
        assert!(store.is_empty());
    }
}
