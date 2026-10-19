/// Cover traffic engine — Phase 2 (Task 17).
///
/// Generates dummy traffic at a configurable rate to normalise the
/// traffic pattern of a Miasma node. Without cover traffic, a passive
/// network observer can distinguish "node transferring shares" (bursts)
/// from "idle node" (silence). Cover traffic ensures the node always
/// emits a background stream of indistinguishable traffic.
///
/// # Design
/// - A background `tokio` task sends random-length packets (512–2048 bytes)
///   over the node's swarm at the configured rate.
/// - Jitter (±`pattern_jitter_pct`%) is applied to inter-packet gaps so that
///   the packet cadence is not metronomic.
/// - Cover packets use a reserved Miasma protocol tag (0xFF) that relay nodes
///   discard after a single hop — they never reach the DHT or data plane.
///
/// # Integration
/// Call `CoverTrafficEngine::start()` after building `MiasmaNode`.
/// The engine runs until `CoverTrafficEngine::stop()` is called or the
/// returned `JoinHandle` is dropped.
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
// rand 0.8 requires the `small_rng` feature for SmallRng.
// Instead use StdRng which is always available and is Send.
use rand::rngs::StdRng;
use std::time::Duration;
use tokio::{sync::watch, task::JoinHandle, time::sleep};
use tracing::{debug, trace};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for cover traffic generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverTrafficConfig {
    /// Enable / disable cover traffic entirely.
    pub enabled: bool,

    /// Target average throughput in bytes/second.
    /// Range: 512 – 2_048 (Phase 2 default: 1_024).
    pub rate_bytes_per_sec: u64,

    /// Jitter applied to inter-packet intervals as a percentage (0–50).
    /// A value of 20 means each interval is varied by ±20% of the nominal gap.
    pub pattern_jitter_pct: u8,

    /// Approximate maximum encrypted cover-envelope bytes emitted per rolling
    /// 24-hour window. Transport framing overhead is not included. A value of
    /// zero disables cover emission even when `enabled` is true.
    pub daily_budget_bytes: u64,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            // Production cover traffic is opt-in because idle bandwidth and
            // battery costs matter on mobile and metered networks.
            enabled: false,
            rate_bytes_per_sec: 1_024,
            pattern_jitter_pct: 20,
            daily_budget_bytes: 96 * 1024 * 1024,
        }
    }
}

// ─── Cover packet ─────────────────────────────────────────────────────────────

/// Minimum and maximum cover payload sizes (bytes).
pub(crate) const COVER_MIN_BYTES: usize = 512;
pub(crate) const COVER_MAX_BYTES: usize = 2_048;

/// Estimated encrypted onion request bytes used for rate/budget accounting.
/// The real outer layer pads its data field to 8 KiB and adds X25519/nonce/AEAD
/// metadata plus request framing. This estimate intentionally rounds upward.
pub(crate) const COVER_ENVELOPE_ESTIMATE: u64 = crate::onion::packet::ONION_PAD_TARGET as u64 + 512;

/// Protocol tag for cover packets (relay nodes discard after 1 hop).
pub const COVER_TAG: u8 = 0xFF;

/// Build a random cover payload: [COVER_TAG, random bytes…].
fn make_cover_packet(rng: &mut impl Rng) -> Vec<u8> {
    let len = rng.gen_range(COVER_MIN_BYTES..=COVER_MAX_BYTES);
    let mut buf = Vec::with_capacity(1 + len);
    buf.push(COVER_TAG);
    let padding: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    buf.extend_from_slice(&padding);
    buf
}

/// Cover payload validation performed only after the surrounding onion layer has
/// authenticated and decrypted. The marker is therefore not visible on the wire.
pub(crate) fn is_cover_payload(payload: &[u8]) -> bool {
    (COVER_MIN_BYTES + 1..=COVER_MAX_BYTES + 1).contains(&payload.len())
        && payload.first() == Some(&COVER_TAG)
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// Handle to the background cover traffic task.
pub struct CoverTrafficEngine {
    stop_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl CoverTrafficEngine {
    /// Start the cover traffic engine with the given config.
    ///
    /// Returns a handle to stop it later. If `config.enabled` is false the
    /// engine is started in a no-op mode (no actual packets sent) so callers
    /// do not need to branch.
    ///
    /// `send_fn` is called for each cover packet. In production this wraps
    /// `swarm.send_to_random_peer`; in tests it can be any closure.
    pub fn start<F>(config: CoverTrafficConfig, mut send_fn: F) -> Self
    where
        F: FnMut(Vec<u8>) + Send + Sync + 'static,
    {
        let (stop_tx, mut stop_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            if !config.enabled || config.rate_bytes_per_sec == 0 || config.daily_budget_bytes == 0 {
                // Parked until stop signal. A zero rate/budget is an explicit
                // no-traffic setting rather than "send one then sleep forever".
                let _ = stop_rx.changed().await;
                return;
            }

            let mut rng = StdRng::from_entropy();

            // Rate is budgeted on the encrypted onion envelope, not the small
            // random marker payload hidden inside it. This prevents a nominal
            // 1 KiB/s setting from accidentally becoming ~8 KiB/s on wire.
            let nom_gap_us: u64 = COVER_ENVELOPE_ESTIMATE
                .saturating_mul(1_000_000)
                .checked_div(config.rate_bytes_per_sec)
                .unwrap_or(u64::MAX / 4)
                .max(1);
            let mut budget_window_started = tokio::time::Instant::now();
            let mut budget_used = 0u64;

            loop {
                // Check stop signal without blocking.
                if *stop_rx.borrow() {
                    break;
                }

                let now = tokio::time::Instant::now();
                if now.duration_since(budget_window_started) >= Duration::from_secs(86_400) {
                    budget_window_started = now;
                    budget_used = 0;
                }
                if budget_used.saturating_add(COVER_ENVELOPE_ESTIMATE) > config.daily_budget_bytes {
                    let until_reset = Duration::from_secs(86_400)
                        .saturating_sub(now.duration_since(budget_window_started));
                    tokio::select! {
                        _ = sleep(until_reset) => {
                            budget_window_started = tokio::time::Instant::now();
                            budget_used = 0;
                            continue;
                        }
                        _ = stop_rx.changed() => { break; }
                    }
                }

                let packet = make_cover_packet(&mut rng);
                trace!(payload_bytes = packet.len(), "cover packet queued");
                send_fn(packet);
                budget_used = budget_used.saturating_add(COVER_ENVELOPE_ESTIMATE);

                // Apply jitter to the gap.
                let jitter_range = (nom_gap_us * config.pattern_jitter_pct as u64) / 100;
                let gap_us = if jitter_range == 0 {
                    nom_gap_us
                } else {
                    nom_gap_us + rng.gen_range(0..=(2 * jitter_range)) - jitter_range
                };

                tokio::select! {
                    _ = sleep(Duration::from_micros(gap_us)) => {}
                    _ = stop_rx.changed() => { break; }
                }
            }
            debug!("Cover traffic engine stopped");
        });

        Self { stop_tx, handle }
    }

    /// Stop the cover traffic engine.  Returns when the background task exits.
    pub async fn stop(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.handle.await;
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::time::Duration;

    #[tokio::test]
    async fn cover_engine_sends_packets() {
        let packets: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let pkts_clone = packets.clone();

        let engine = CoverTrafficEngine::start(
            CoverTrafficConfig {
                enabled: true,
                rate_bytes_per_sec: 100_000,
                ..Default::default()
            },
            move |pkt| pkts_clone.lock().unwrap().push(pkt),
        );

        // Allow some packets to accumulate.
        tokio::time::sleep(Duration::from_millis(100)).await;
        engine.stop().await;

        let count = packets.lock().unwrap().len();
        assert!(count > 0, "expected at least one cover packet, got 0");
    }

    #[tokio::test]
    async fn cover_engine_disabled_sends_nothing() {
        let packets: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let pkts_clone = packets.clone();

        let config = CoverTrafficConfig {
            enabled: false,
            ..Default::default()
        };
        let engine = CoverTrafficEngine::start(config, move |pkt| {
            pkts_clone.lock().unwrap().push(pkt);
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        engine.stop().await;

        assert_eq!(packets.lock().unwrap().len(), 0);
    }

    #[test]
    fn cover_packet_starts_with_tag() {
        let mut rng = rand::thread_rng();
        let pkt = make_cover_packet(&mut rng);
        assert_eq!(pkt[0], COVER_TAG);
        assert!(pkt.len() > COVER_MIN_BYTES);
        assert!(pkt.len() <= COVER_MAX_BYTES + 1);
    }

    #[test]
    fn cover_payload_validator_is_bounded() {
        let mut rng = rand::thread_rng();
        let pkt = make_cover_packet(&mut rng);
        assert!(is_cover_payload(&pkt));
        assert!(!is_cover_payload(&[]));
        assert!(!is_cover_payload(&vec![COVER_TAG; COVER_MAX_BYTES + 2]));
        let mut wrong_tag = pkt;
        wrong_tag[0] = 0;
        assert!(!is_cover_payload(&wrong_tag));
    }

    #[test]
    fn production_default_is_opt_in_and_budgeted() {
        let cfg = CoverTrafficConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.daily_budget_bytes >= 24 * 60 * 60 * cfg.rate_bytes_per_sec);
    }
}
