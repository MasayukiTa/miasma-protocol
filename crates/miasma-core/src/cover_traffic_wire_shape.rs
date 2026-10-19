//! Wire-shape measurement harness for the traffic-shaping policies (test only).
//!
//! The harness builds first-hop onion cells with the production builders, runs
//! them through the production relay codec and relay peeling code, and drives
//! the production cover engine on a paused clock. It records what a passive
//! observer of the transport envelope can see (frame length, enum tag, send
//! times) and asserts the properties the shaping layer claims:
//!
//! - a cover cell and a real cell have the same frame length and framing;
//! - only `CoverBasic` adds sends; the other supported policies add none;
//! - cover sends follow the configured mean rate with bounded jitter;
//! - the daily budget caps emission and resets after 24 hours;
//! - stopping the engine leaves no task (and no captured state) alive.
//!
//! Size and timing histograms are printed with `--nocapture`.

use super::*;
use crate::{
    network::onion_relay::{
        process_onion_layer, OnionRelayAction, OnionRelayCodec, OnionRelayRequest,
    },
    onion::packet::{OnionPacket, OnionPacketBuilder, FIRST_HOP_FRAME_BYTES},
};
use libp2p::request_response::Codec;
use std::{collections::BTreeMap, sync::Mutex};
use tokio::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};

struct Node {
    secret: [u8; 32],
    public: [u8; 32],
    peer_id: Vec<u8>,
}

fn node(seed: u8) -> Node {
    let secret = StaticSecret::from([seed; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    let peer_id = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32])
        .unwrap()
        .public()
        .to_peer_id()
        .to_bytes();
    Node {
        secret: secret.to_bytes(),
        public,
        peer_id,
    }
}

fn request(packet: OnionPacket) -> OnionRelayRequest {
    OnionRelayRequest::Packet {
        circuit_id: packet.circuit_id,
        layer: packet.layer,
    }
}

/// Length-prefixed frame exactly as `OnionRelayCodec` writes it.
fn frame_bytes(req: &OnionRelayRequest) -> Vec<u8> {
    let body = bincode::serialize(req).unwrap();
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn real_cell(r1: &Node, r2: &Node, target: &Node, addr_len: usize, body_len: usize) -> OnionPacket {
    OnionPacketBuilder::build_e2e(
        &r1.public,
        &r2.public,
        &target.public,
        r2.peer_id.clone(),
        target.peer_id.clone(),
        vec![0x11; addr_len],
        vec![0xAB; body_len],
    )
    .unwrap()
    .0
}

fn cover_cell(relay: &Node, rng: &mut impl Rng) -> OnionPacket {
    OnionPacketBuilder::build_cover(&relay.public, make_cover_packet(rng)).unwrap()
}

fn histogram(label: &str, sizes: impl IntoIterator<Item = usize>) -> BTreeMap<usize, usize> {
    let mut h = BTreeMap::new();
    for s in sizes {
        *h.entry(s).or_insert(0usize) += 1;
    }
    eprintln!("wire-size histogram [{label}]: {h:?}");
    h
}

#[test]
fn cover_peer_id_length_matches_the_padding_assumption() {
    // The cover padding compensates for the first-hop `next_hop` field, which
    // holds an Ed25519 peer id. If libp2p ever changes the encoding, the
    // lengths below stop matching and this fails before the wire does.
    assert_eq!(
        node(1).peer_id.len(),
        crate::onion::packet::FIRST_HOP_PEER_ID_LEN
    );
}

#[tokio::test]
async fn cover_cells_and_real_cells_share_length_and_framing() {
    let r1 = node(1);
    let r2 = node(2);
    let target = node(3);
    let mut rng = StdRng::seed_from_u64(7);

    // Real cells across body sizes and relay address lengths.
    let mut real_sizes = Vec::new();
    let mut real_frames = Vec::new();
    for body_len in [0usize, 64, 1_000, 4_000] {
        for addr_len in [0usize, 24, 120, 300] {
            let frame = frame_bytes(&request(real_cell(&r1, &r2, &target, addr_len, body_len)));
            real_sizes.push(frame.len());
            real_frames.push(frame);
        }
    }
    // Cover cells across the whole payload length range.
    let mut cover_sizes = Vec::new();
    let mut cover_frames = Vec::new();
    for _ in 0..96 {
        let frame = frame_bytes(&request(cover_cell(&r1, &mut rng)));
        cover_sizes.push(frame.len());
        cover_frames.push(frame);
    }

    let real_hist = histogram("real first-hop cell", real_sizes);
    let cover_hist = histogram("cover cell", cover_sizes);
    assert_eq!(
        real_hist.keys().copied().collect::<Vec<_>>(),
        vec![FIRST_HOP_FRAME_BYTES],
        "every real first-hop cell must have one length"
    );
    assert_eq!(
        cover_hist.keys().copied().collect::<Vec<_>>(),
        vec![FIRST_HOP_FRAME_BYTES],
        "every cover cell must have the real first-hop length"
    );
    assert_eq!(COVER_ENVELOPE_ESTIMATE, FIRST_HOP_FRAME_BYTES as u64);

    // Framing: 4-byte length prefix, then the same enum tag (the `Packet`
    // variant), for both kinds; nothing but ciphertext differs.
    for frame in real_frames.iter().chain(cover_frames.iter()) {
        let declared = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(declared, frame.len() - 4);
        assert_eq!(u32::from_le_bytes(frame[4..8].try_into().unwrap()), 0);
    }

    // The production codec writes exactly the bytes measured above and reads
    // both kinds back as the same request variant.
    let proto = libp2p::StreamProtocol::new("/miasma/onion/1.1.0");
    for packet in [
        real_cell(&r1, &r2, &target, 40, 100),
        cover_cell(&r1, &mut rng),
    ] {
        let req = request(packet);
        let expected = frame_bytes(&req);
        let mut codec = OnionRelayCodec;
        let mut written: Vec<u8> = Vec::new();
        codec
            .write_request(&proto, &mut written, req)
            .await
            .unwrap();
        assert_eq!(written, expected);
        let decoded = codec.read_request(&proto, &mut &written[..]).await.unwrap();
        assert!(matches!(decoded, OnionRelayRequest::Packet { .. }));
    }

    // Only after authentication does a relay tell them apart.
    let real = real_cell(&r1, &r2, &target, 40, 100);
    match process_onion_layer(&r1.secret, real.circuit_id, &real.layer) {
        Ok(OnionRelayAction::ForwardToNext { .. }) => {}
        _ => panic!("real first-hop cell must be forwarded"),
    }
    let cover = cover_cell(&r1, &mut rng);
    assert!(matches!(
        process_onion_layer(&r1.secret, cover.circuit_id, &cover.layer),
        Ok(OnionRelayAction::DiscardCover)
    ));
}

struct Run {
    sends: Vec<(Instant, usize)>,
    metrics: CoverTrafficMetricsSnapshot,
}

async fn run_policy(policy: TrafficShapePolicy, seconds: u64, relay: &Node) -> Run {
    let base = CoverTrafficConfig {
        enabled: false,
        rate_bytes_per_sec: 10_000,
        pattern_jitter_pct: 20,
        daily_budget_bytes: 96 * 1024 * 1024,
    };
    let cfg = effective_cover_config(policy, &base);
    let sends: Arc<Mutex<Vec<(Instant, usize)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = sends.clone();
    let relay_public = relay.public;
    let engine = CoverTrafficEngine::start(cfg, move |payload| {
        let cell = OnionPacketBuilder::build_cover(&relay_public, payload).unwrap();
        let len = frame_bytes(&request(cell)).len();
        recorded.lock().unwrap().push((Instant::now(), len));
    });
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    let metrics = engine.metrics();
    engine.stop().await;
    let sends = sends.lock().unwrap().clone();
    Run { sends, metrics }
}

#[tokio::test(start_paused = true)]
async fn cover_policies_wire_size_and_timing_histograms() {
    let relay = node(9);
    let seconds = 600;

    // Policies that add no cover send nothing on top of the real traffic.
    for policy in [
        TrafficShapePolicy::Off,
        TrafficShapePolicy::FixedPadding,
        TrafficShapePolicy::Bucketed,
    ] {
        let run = run_policy(policy, seconds, &relay).await;
        eprintln!("policy {policy}: {} cover sends", run.sends.len());
        assert!(run.sends.is_empty(), "{policy} must not emit cover");
        assert_eq!(run.metrics, CoverTrafficMetricsSnapshot::default());
    }

    let run = run_policy(TrafficShapePolicy::CoverBasic, seconds, &relay).await;
    let n = run.sends.len();
    assert!(n > 100, "cover_basic produced only {n} sends");

    // Wire sizes: one bucket, equal to the real first-hop frame.
    let sizes = histogram("cover_basic sends", run.sends.iter().map(|s| s.1));
    assert_eq!(sizes.len(), 1);
    assert_eq!(sizes.get(&FIRST_HOP_FRAME_BYTES), Some(&n));

    // Timing: gaps stay inside the jitter band and average to the nominal gap.
    // The clock is paused, so only the 1 ms timer granularity adds error.
    let nominal_us = COVER_ENVELOPE_ESTIMATE * 1_000_000 / 10_000;
    let lo = Duration::from_micros(nominal_us * 80 / 100).saturating_sub(Duration::from_millis(2));
    let hi = Duration::from_micros(nominal_us * 120 / 100) + Duration::from_millis(2);
    let gaps: Vec<Duration> = run
        .sends
        .windows(2)
        .map(|w| w[1].0.duration_since(w[0].0))
        .collect();
    for gap in &gaps {
        assert!(
            *gap >= lo && *gap <= hi,
            "gap {gap:?} outside {lo:?}..{hi:?}"
        );
    }
    let mut gap_hist: BTreeMap<u64, usize> = BTreeMap::new();
    for gap in &gaps {
        *gap_hist
            .entry(gap.as_millis() as u64 / 50 * 50)
            .or_insert(0) += 1;
    }
    eprintln!("cover_basic inter-send gap histogram (50 ms bins): {gap_hist:?}");
    assert!(gap_hist.len() > 3, "gaps must not be metronomic");
    let mean_us = gaps.iter().map(|g| g.as_micros() as u64).sum::<u64>() / gaps.len() as u64;
    let error = mean_us.abs_diff(nominal_us) * 100 / nominal_us;
    assert!(
        error <= 5,
        "mean gap {mean_us} us vs nominal {nominal_us} us"
    );

    // Accounting matches the observed sends.
    assert_eq!(run.metrics.generated_packets as usize, n);
    assert_eq!(run.metrics.enqueued_packets as usize, n);
    assert_eq!(
        run.metrics.estimated_enqueued_bytes,
        n as u64 * COVER_ENVELOPE_ESTIMATE
    );
}

#[tokio::test(start_paused = true)]
async fn cover_idle_emission_respects_the_daily_budget() {
    let metrics = Arc::new(CoverTrafficMetrics::default());
    let cells_per_day = 10u64;
    let engine = CoverTrafficEngine::start_with_metrics(
        CoverTrafficConfig {
            enabled: true,
            rate_bytes_per_sec: 1_000_000,
            pattern_jitter_pct: 20,
            daily_budget_bytes: cells_per_day * COVER_ENVELOPE_ESTIMATE,
        },
        metrics.clone(),
        |_| true,
    );

    // Far more time than the budget needs at this rate: it must stop at the cap.
    tokio::time::sleep(Duration::from_secs(3_600)).await;
    let first = metrics.snapshot();
    assert_eq!(first.enqueued_packets, cells_per_day);
    assert_eq!(
        first.estimated_enqueued_bytes,
        cells_per_day * COVER_ENVELOPE_ESTIMATE
    );
    assert_eq!(first.budget_pauses, 1);

    // The window rolls over after 24 hours and allows one more day's budget.
    tokio::time::sleep(Duration::from_secs(86_400)).await;
    let second = metrics.snapshot();
    assert_eq!(second.enqueued_packets, 2 * cells_per_day);
    assert_eq!(second.budget_pauses, 2);

    engine.stop().await;
}

#[tokio::test(start_paused = true)]
async fn cover_engine_stop_leaves_no_task_or_captured_state() {
    // Running, budget-paused and disabled engines must all release the send
    // closure (the task owns it) once `stop` returns.
    for (enabled, budget) in [
        (true, u64::MAX),
        (true, COVER_ENVELOPE_ESTIMATE),
        (false, 1),
    ] {
        let guard = Arc::new(());
        let held = guard.clone();
        let engine = CoverTrafficEngine::start(
            CoverTrafficConfig {
                enabled,
                rate_bytes_per_sec: 1_000_000,
                pattern_jitter_pct: 20,
                daily_budget_bytes: budget,
            },
            move |_| {
                let _keep = &held;
            },
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            Arc::strong_count(&guard) >= 2,
            "engine should hold the closure"
        );
        engine.stop().await;
        assert_eq!(
            Arc::strong_count(&guard),
            1,
            "task still holds state after stop (enabled={enabled}, budget={budget})"
        );
    }
}

#[test]
fn cover_policy_support_and_effective_config() {
    for policy in TrafficShapePolicy::supported() {
        assert!(policy.is_implemented());
        assert!(policy.unsupported_reason().is_none());
    }
    for policy in [
        TrafficShapePolicy::Adaptive,
        TrafficShapePolicy::ConstantRate,
    ] {
        assert!(!policy.is_implemented());
        assert!(policy.unsupported_reason().is_some());
        assert!(!TrafficShapePolicy::supported().contains(&policy));
    }

    let base = CoverTrafficConfig::default();
    assert!(!base.enabled);
    for policy in [
        TrafficShapePolicy::Off,
        TrafficShapePolicy::FixedPadding,
        TrafficShapePolicy::Bucketed,
    ] {
        assert!(!effective_cover_config(policy, &base).enabled);
    }
    assert!(effective_cover_config(TrafficShapePolicy::CoverBasic, &base).enabled);

    // Selecting the unsupported policy from a config file parses, so the
    // daemon can refuse it with a clear message instead of a parse error.
    let parsed: TrafficShapePolicy = serde_json::from_str("\"adaptive\"").unwrap();
    assert_eq!(parsed, TrafficShapePolicy::Adaptive);
}
