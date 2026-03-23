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
// rand 0.8 requires the `small_rng` feature for SmallRng.
// Instead use StdRng which is always available and is Send.
use rand::rngs::StdRng;
use std::time::Duration;
use tokio::{sync::watch, task::JoinHandle, time::sleep};
use tracing::{debug, trace};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for cover traffic generation.
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    /// Enable / disable cover traffic entirely.
    pub enabled: bool,

    /// Target average throughput in bytes/second.
    /// Range: 512 – 2_048 (Phase 2 default: 1_024).
    pub rate_bytes_per_sec: u64,

    /// Jitter applied to inter-packet intervals as a percentage (0–50).
    /// A value of 20 means each interval is varied by ±20% of the nominal gap.
    pub pattern_jitter_pct: u8,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_bytes_per_sec: 1_024,
            pattern_jitter_pct: 20,
        }
    }
}

// ─── Cover packet ─────────────────────────────────────────────────────────────

/// Minimum and maximum cover payload sizes (bytes).
const COVER_MIN_BYTES: usize = 512;
const COVER_MAX_BYTES: usize = 2_048;

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
            if !config.enabled {
                // Parked until stop signal.
                let _ = stop_rx.changed().await;
                return;
            }

            let mut rng = StdRng::from_entropy();

            // Nominal inter-packet gap derived from rate and average packet size.
            let avg_packet = (COVER_MIN_BYTES + COVER_MAX_BYTES) / 2;
            let nom_gap_us: u64 = if config.rate_bytes_per_sec == 0 {
                1_000_000 // 1 packet/s safety fallback
            } else {
                (avg_packet as u64 * 1_000_000) / config.rate_bytes_per_sec
            };

            loop {
                // Check stop signal without blocking.
                if *stop_rx.borrow() {
                    break;
                }

                let packet = make_cover_packet(&mut rng);
                trace!(bytes = packet.len(), "cover packet");
                send_fn(packet);

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
}
