//! The r18 gate: the new paths exercised together under faults.
//!
//! Wipe and the key vault, piece maintenance, cover traffic and the 9 KiB
//! onion cell, the RAM-only receive, capability negotiation with handshake
//! fragmentation, and transport selection under an anonymity policy are driven
//! against a bad network, a failing process and an older peer.
//!
//! Every scenario is reproducible. Randomness comes from `gate::rng(seed, ..)`;
//! a failure message names its seed, and `R18_GATE_SEEDS=<n>` (or `a..b`) reruns
//! exactly that seed. Time is the paused tokio clock or a value passed in by the
//! test, never the wall clock. The scenarios:
//!
//! 1. Handshake fragments, capability encodings and onion cells under loss,
//!    duplication, reordering, truncation and bit flips: nothing panics, the
//!    heap stays within a stated bound, every error is a typed value.
//! 2. A streamed receive over slow holders, holder churn and relay-only
//!    transports: it finishes or stops cleanly, never falls back to a transport
//!    the policy forbids, wipes its buffers and leaves no temp file.
//! 3. A crash at every single backend call of a maintenance repair: the next
//!    start resumes, k/n/MID stay as published and no piece is stored twice.
//! 4. A wipe at a seeded moment while a receive, a publish, maintenance and
//!    cover traffic run: afterwards no key operation succeeds, no plaintext or
//!    temp file remains and every task has stopped.
//! 5. A peer limited to the protocol set of the beta.2 / beta.3 releases keeps
//!    working with a current node that has the new features switched on, and a
//!    downgrade is visible.

#[path = "support/r18_gate.rs"]
mod gate;

use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use miasma_core::{
    cover_traffic::COVER_TAG,
    dissolution::segment::dissolve_segment_with,
    network::AnonymityPolicy,
    onion::{
        derive_onion_static_key,
        packet::{LayerPayload, ONION_OUTER_PAD_TARGET, ONION_PAD_TARGET},
        OnionLayer, OnionLayerProcessor, OnionPacket, OnionPacketBuilder, OnionRelayHandler,
    },
    protocol::{
        capability::{
            negotiate, transcript_binding, Capabilities, CapabilityError, DowngradeReason,
            NegotiationError, Requirements, CAPABILITY_VERSION, FEATURE_FRAGMENTATION,
            SUITE_CLASSICAL, SUITE_HYBRID_X25519_MLKEM768,
        },
        fragment::{
            self, FragmentError, HandshakeFragment, PushOutcome, Reassembler, ReassemblyLimits,
            HEADER_LEN,
        },
    },
    repair::{
        check_record_update, spawn_executor, MaintenanceBackend, MaintenanceCore, ManualClock,
        ProbeResult,
    },
    transfer::{receive_stream, StreamOutcome, StreamStats, TransferProgress, TransferState},
    ContentId, CoverTrafficConfig, CoverTrafficEngine, CoverTrafficMetrics, DissolutionParams,
    LocalShareStore, MiasmaError, MiasmaShare, PayloadTransportKind, PayloadTransportSelector,
};
use rand::{rngs::OsRng, Rng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[global_allocator]
static METER: gate::Meter = gate::Meter;

// ═════════════════════════════════════════════════════════════════════════════
// 1. Loss / reorder / duplicate / truncate
// ═════════════════════════════════════════════════════════════════════════════

fn frag_limits() -> ReassemblyLimits {
    ReassemblyLimits {
        max_total_len: 16 * 1024,
        max_fragments: 32,
        max_concurrent: 4,
        timeout_ms: 10_000,
    }
}

fn random_message(seed: u64, purpose: u64) -> (rand::rngs::StdRng, Vec<u8>, usize, u64) {
    let mut r = gate::rng(seed, purpose);
    let len = r.gen_range(1..=frag_limits().max_total_len as usize);
    let msg: Vec<u8> = (0..len).map(|_| r.gen()).collect();
    let lo = len.div_ceil(30).max(1);
    let max_payload = r.gen_range(lo..=lo.max(1500));
    let hid: u64 = r.gen();
    (r, msg, max_payload, hid)
}

#[test]
fn fragments_lost_duplicated_and_reordered_assemble_exactly_or_not_at_all() {
    let (mut complete_runs, mut incomplete_runs) = (0, 0);
    for seed in gate::seeds(96) {
        let (mut r, msg, max_payload, hid) = random_message(seed, 11);
        let frags = fragment::fragment(hid, 1, &msg, max_payload).unwrap();
        let count = frags.len();
        let wire: Vec<Vec<u8>> = frags.iter().map(|f| f.encode()).collect();
        let delivered = gate::hostile(wire, gate::Hostility::delivery_only(), &mut r);

        let mut seen = BTreeSet::new();
        let mut re = Reassembler::new(frag_limits());
        let mut completions = 0;
        for (t, bytes) in delivered.iter().enumerate() {
            let f = HandshakeFragment::decode(bytes)
                .unwrap_or_else(|e| panic!("seed {seed}: an undamaged fragment was refused: {e}"));
            seen.insert(f.fragment_index);
            match re.push(f, t as u64 * 5) {
                Ok(PushOutcome::Complete {
                    handshake_id, data, ..
                }) => {
                    assert_eq!(handshake_id, hid, "seed {seed}");
                    assert_eq!(data, msg, "seed {seed}: a completed message differs");
                    completions += 1;
                }
                Ok(_) => {}
                Err(e) => panic!("seed {seed}: delivery faults alone caused {e}"),
            }
            assert!(
                re.in_progress() <= 1,
                "seed {seed}: one handshake, one entry"
            );
        }
        assert_eq!(
            seen.len() == count,
            completions > 0,
            "seed {seed}: completed iff every fragment arrived at least once"
        );
        if completions > 0 {
            complete_runs += 1;
        } else {
            incomplete_runs += 1;
        }
        // A replayed fragment may have opened a new entry; it ages out.
        re.expire(10_000_000);
        assert_eq!(re.in_progress(), 0, "seed {seed}: state is released");
    }
    if std::env::var("R18_GATE_SEEDS").is_err() {
        assert!(
            complete_runs > 0 && incomplete_runs > 0,
            "the schedule must cover both outcomes ({complete_runs} / {incomplete_runs})"
        );
    }
}

#[test]
fn damaged_fragments_never_panic_never_pile_up_and_errors_are_typed() {
    let mut refused = 0usize;
    for seed in gate::seeds(96) {
        let (mut r, msg, max_payload, hid) = random_message(seed, 12);
        let frags = fragment::fragment(hid, 1, &msg, max_payload).unwrap();
        let mut wire: Vec<Vec<u8>> = frags.iter().map(|f| f.encode()).collect();
        // Fragments of unrelated handshakes mixed in, as another sender would.
        for _ in 0..8 {
            let other = fragment::fragment(r.gen(), 1, &msg, max_payload).unwrap();
            wire.extend(other.iter().map(|f| f.encode()));
        }
        let delivered = gate::hostile(wire, gate::Hostility::damaging(), &mut r);

        let mut re = Reassembler::new(frag_limits());
        for (t, bytes) in delivered.iter().enumerate() {
            match HandshakeFragment::decode(bytes) {
                Err(e) => {
                    refused += 1;
                    let _: FragmentError = e.clone();
                    assert!(!e.to_string().is_empty());
                }
                Ok(f) => match re.push(f, t as u64) {
                    Ok(_) => {}
                    Err(e) => {
                        refused += 1;
                        assert!(!e.to_string().is_empty());
                    }
                },
            }
            assert!(
                re.in_progress() <= frag_limits().max_concurrent,
                "seed {seed}: more entries than the limit"
            );
        }
        re.expire(10_000_000);
        assert_eq!(re.in_progress(), 0, "seed {seed}");
    }
    assert!(
        refused > 0,
        "the damage schedule must reach the error paths"
    );
}

#[test]
fn a_flood_of_fragments_and_length_bombs_stays_inside_the_memory_bound() {
    let limits = frag_limits();
    // Pre-build the traffic so only the receiver's own allocations are metered.
    let mut r = gate::rng(0, 13);
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for i in 0..20_000u64 {
        let f = HandshakeFragment {
            version: fragment::FRAGMENT_VERSION,
            handshake_id: i,
            suite: 1,
            fragment_index: r.gen_range(0..32),
            fragment_count: 32,
            total_len: limits.max_total_len,
            payload: vec![r.gen(); 512],
        };
        frames.push(f.encode());
    }
    // Headers that promise far more than they carry.
    for _ in 0..2_000 {
        let mut b = vec![0u8; HEADER_LEN + 8];
        b[0] = fragment::FRAGMENT_VERSION;
        b[13..15].copy_from_slice(&1u16.to_be_bytes());
        b[15..19].copy_from_slice(&u32::MAX.to_be_bytes());
        b[19..23].copy_from_slice(&u32::MAX.to_be_bytes());
        frames.push(b);
    }

    let ((rejected, accepted, max_entries), growth) = gate::peak_heap_growth(|| {
        let mut re = Reassembler::new(limits);
        let (mut rejected, mut accepted, mut max_entries) = (0usize, 0usize, 0usize);
        for (t, bytes) in frames.iter().enumerate() {
            match HandshakeFragment::decode(bytes) {
                Err(_) => rejected += 1,
                Ok(f) => match re.push(f, t as u64) {
                    Ok(_) => accepted += 1,
                    Err(_) => rejected += 1,
                },
            }
            max_entries = max_entries.max(re.in_progress());
        }
        (rejected, accepted, max_entries)
    });
    assert!(rejected > 2_000, "the flood is refused ({rejected})");
    assert!(accepted > 0);
    assert!(max_entries <= limits.max_concurrent, "{max_entries}");
    let bound = limits.max_concurrent as i64 * (limits.max_total_len as i64 + 4096) + 64 * 1024;
    assert!(
        growth < bound,
        "heap grew by {growth} bytes, bound {bound} (concurrent {} x total {})",
        limits.max_concurrent,
        limits.max_total_len
    );
}

#[test]
fn a_forged_fragment_cannot_overwrite_or_derail_an_assembly() {
    let msg: Vec<u8> = (0..6000u32).map(|i| (i % 253) as u8).collect();
    let hid = 0x5EED_u64;
    let frags = fragment::fragment(hid, 1, &msg, 2000).unwrap();
    assert_eq!(frags.len(), 3);
    let mut re = Reassembler::new(frag_limits());
    assert_eq!(re.push(frags[0].clone(), 0), Ok(PushOutcome::Pending));

    // Same slot, other bytes.
    let mut forged = frags[0].clone();
    forged.payload[0] ^= 0xFF;
    assert_eq!(re.push(forged, 1), Err(FragmentError::Conflict));
    // Same handshake id, other shape.
    let mut reshaped = frags[1].clone();
    reshaped.total_len += 1;
    assert_eq!(re.push(reshaped, 2), Err(FragmentError::Conflict));
    let mut other_suite = frags[1].clone();
    other_suite.suite = 2;
    assert_eq!(re.push(other_suite, 3), Err(FragmentError::Conflict));
    // A newer version byte is a clean refusal, not a parse of unknown bytes.
    let mut newer = frags[1].encode();
    newer[0] = fragment::FRAGMENT_VERSION + 1;
    assert_eq!(
        HandshakeFragment::decode(&newer),
        Err(FragmentError::UnsupportedVersion(
            fragment::FRAGMENT_VERSION + 1
        ))
    );

    // The honest rest still completes the original message.
    let mut done = None;
    for (i, f) in frags.iter().enumerate().skip(1) {
        if let Ok(PushOutcome::Complete { data, .. }) = re.push(f.clone(), 10 + i as u64) {
            done = Some(data);
        }
    }
    assert_eq!(done.as_deref(), Some(msg.as_slice()));
}

#[test]
fn capability_encodings_cut_short_or_garbled_are_clean_errors() {
    let caps = Capabilities::current().with_unknown(vec![9u8; 40]).unwrap();
    let enc = caps.encode();
    for cut in 0..enc.len() {
        assert_eq!(
            Capabilities::decode(&enc[..cut]),
            Err(CapabilityError::Truncated),
            "prefix of {cut} bytes"
        );
    }
    assert_eq!(Capabilities::decode(&enc), Ok(caps));

    for seed in gate::seeds(200) {
        let mut r = gate::rng(seed, 15);
        let len = r.gen_range(0..400usize);
        let buf: Vec<u8> = (0..len).map(|_| r.gen()).collect();
        if let Ok(c) = Capabilities::decode(&buf) {
            if c.version <= CAPABILITY_VERSION {
                assert_eq!(
                    c.encode(),
                    buf,
                    "seed {seed}: an accepted encoding is canonical"
                );
            }
        }
    }
}

fn random_caps(r: &mut rand::rngs::StdRng) -> Capabilities {
    let ext_len = r.gen_range(0..20usize);
    Capabilities {
        version: r.gen_range(0..4),
        suites: r.gen(),
        features: r.gen(),
        unknown: (0..ext_len).map(|_| r.gen()).collect(),
    }
}

#[test]
fn negotiation_is_symmetric_keeps_the_baseline_and_a_stripped_offer_is_caught() {
    for seed in gate::seeds(300) {
        let mut r = gate::rng(seed, 16);
        let (a, b) = (random_caps(&mut r), random_caps(&mut r));
        let none = Requirements::default();
        let ab = negotiate(&a, &b, &none).unwrap();
        let ba = negotiate(&b, &a, &none).unwrap();
        assert_eq!(
            (ab.version, ab.suites, ab.features),
            (ba.version, ba.suites, ba.features),
            "seed {seed}"
        );
        assert_ne!(ab.suites & SUITE_CLASSICAL, 0, "seed {seed}: baseline");
        assert_eq!(ab.downgraded, !ab.reasons.is_empty(), "seed {seed}");
        let lost = (a.suites | SUITE_CLASSICAL) & !(b.suites | SUITE_CLASSICAL);
        assert_eq!(
            ab.reasons
                .contains(&DowngradeReason::SuitesUnavailable { bits: lost }),
            lost != 0,
            "seed {seed}: a lost suite is reported"
        );

        // A demand that is not met is an error, never a silent downgrade.
        let missing = (a.suites | b.suites) & !(a.suites & b.suites) & !SUITE_CLASSICAL;
        if missing != 0 {
            let bit = missing & missing.wrapping_neg();
            assert_eq!(
                negotiate(
                    &a,
                    &b,
                    &Requirements {
                        suites: bit,
                        features: 0
                    }
                ),
                Err(NegotiationError::RequirementUnmet {
                    missing_suites: bit,
                    missing_features: 0
                }),
                "seed {seed}"
            );
        }

        // An on-path party that rewrites one offer is visible in the binding.
        let honest = transcript_binding(&a, &b, &ab);
        let mut stripped = b.clone();
        stripped.suites ^= SUITE_HYBRID_X25519_MLKEM768;
        assert_ne!(
            honest,
            transcript_binding(&a, &stripped, &ab),
            "seed {seed}"
        );
        let mut other = a.clone();
        other.features ^= FEATURE_FRAGMENTATION;
        assert_ne!(honest, transcript_binding(&other, &b, &ab), "seed {seed}");
    }
}

// ─── Onion cells ─────────────────────────────────────────────────────────────

struct Relays {
    r1_secret: [u8; 32],
    r1_pub: [u8; 32],
    r2_secret: [u8; 32],
    r2_pub: [u8; 32],
}

fn relays() -> Relays {
    let r1_secret: [u8; 32] = *derive_onion_static_key(&[1u8; 32]).unwrap();
    let r2_secret: [u8; 32] = *derive_onion_static_key(&[2u8; 32]).unwrap();
    let public = |s: &[u8; 32]| PublicKey::from(&StaticSecret::from(*s)).to_bytes();
    Relays {
        r1_pub: public(&r1_secret),
        r2_pub: public(&r2_secret),
        r1_secret,
        r2_secret,
    }
}

fn peer_id(b: u8) -> Vec<u8> {
    vec![b; 38]
}

fn onion_packet(r: &Relays, addr_len: usize, body: &[u8]) -> OnionPacket {
    OnionPacketBuilder::build(
        &r.r1_pub,
        &r.r2_pub,
        peer_id(2),
        peer_id(3),
        vec![4; addr_len],
        body.to_vec(),
    )
    .unwrap()
    .0
}

/// What the two relays make of a packet: the target and the body it carries.
fn through_relays(r: &Relays, pkt: &OnionPacket) -> Result<(Vec<u8>, Vec<u8>), MiasmaError> {
    let (_next, cell) = OnionRelayHandler::new(r.r1_secret).handle_packet(pkt)?;
    let (target, inner) = OnionRelayHandler::new(r.r2_secret).handle_forward_cell(&cell)?;
    Ok((target, inner.body))
}

#[test]
fn every_first_hop_cell_has_one_length_whatever_it_carries() {
    let r = relays();
    let mut sizes = BTreeSet::new();
    for body_len in [0usize, 1, 64, 512, 2048, 4096] {
        for addr_len in [0usize, 20, 100] {
            let body = vec![0xA5; body_len];
            let pkt = onion_packet(&r, addr_len, &body);
            sizes.insert(bincode::serialize(&pkt).unwrap().len());
            let (target, got) = through_relays(&r, &pkt).unwrap();
            assert_eq!((target, got), (peer_id(3), body));
        }
    }
    assert_eq!(sizes.len(), 1, "cells of different lengths: {sizes:?}");
    let size = *sizes.iter().next().unwrap();
    assert!(
        size > ONION_OUTER_PAD_TARGET && size < ONION_OUTER_PAD_TARGET + 1024,
        "a 9 KiB cell plus its header, got {size}"
    );
    // A body past the padded size is carried, only larger: never cut.
    let big = vec![7u8; ONION_PAD_TARGET * 2];
    let pkt = onion_packet(&r, 20, &big);
    assert!(bincode::serialize(&pkt).unwrap().len() > size);
    assert_eq!(through_relays(&r, &pkt).unwrap().1, big);
}

#[test]
fn onion_cells_under_loss_reorder_duplication_truncation_and_flips() {
    let r = relays();
    let bodies: Vec<Vec<u8>> = (0..6u8).map(|i| vec![i; 100 + 300 * i as usize]).collect();
    let (mut delivered_ok, mut refused) = (0usize, 0usize);
    let mut worst_growth = 0i64;
    for seed in gate::seeds(40) {
        let mut rr = gate::rng(seed, 17);
        let wire: Vec<Vec<u8>> = bodies
            .iter()
            .map(|b| bincode::serialize(&onion_packet(&r, 30, b)).unwrap())
            .collect();
        let delivered = gate::hostile(wire, gate::Hostility::damaging(), &mut rr);

        let (counts, growth) = gate::peak_heap_growth(|| {
            let (mut ok, mut bad) = (0usize, 0usize);
            for bytes in &delivered {
                let outcome = bincode::deserialize::<OnionPacket>(bytes)
                    .map_err(|e| MiasmaError::Serialization(e.to_string()))
                    .and_then(|p| through_relays(&r, &p));
                match outcome {
                    Ok((target, body)) => {
                        assert_eq!(target, peer_id(3), "seed {seed}");
                        assert!(
                            bodies.contains(&body),
                            "seed {seed}: a damaged cell opened to a body nobody sent"
                        );
                        ok += 1;
                    }
                    Err(e) => {
                        assert!(!e.to_string().is_empty());
                        bad += 1;
                    }
                }
            }
            (ok, bad)
        });
        delivered_ok += counts.0;
        refused += counts.1;
        worst_growth = worst_growth.max(growth);
    }
    assert!(
        delivered_ok > 0 && refused > 0,
        "{delivered_ok} / {refused}"
    );
    // A handful of 10 KiB cells at a time, never a queue of them.
    assert!(worst_growth < 1024 * 1024, "heap grew by {worst_growth}");

    // A cell whose length field promises the moon.
    let mut bomb = vec![0u8; 16 + 32 + 24];
    bomb.extend_from_slice(&u64::MAX.to_le_bytes());
    bomb.extend_from_slice(&[1u8; 10]);
    let (res, growth) = gate::peak_heap_growth(|| bincode::deserialize::<OnionPacket>(&bomb));
    assert!(res.is_err());
    assert!(growth < 4 * 1024 * 1024, "heap grew by {growth}");
}

// ─── Cover traffic ───────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn cover_cells_keep_their_shape_stay_in_budget_and_stop_cleanly() {
    let metrics = Arc::new(CoverTrafficMetrics::default());
    let sent: Arc<Mutex<Vec<(usize, u8)>>> = Arc::default();
    let n = Arc::new(AtomicUsize::new(0));
    let engine = {
        let (sent, n) = (sent.clone(), n.clone());
        CoverTrafficEngine::start_with_metrics(
            CoverTrafficConfig {
                enabled: true,
                rate_bytes_per_sec: 200_000,
                pattern_jitter_pct: 50,
                daily_budget_bytes: 1_000_000,
            },
            metrics.clone(),
            move |packet| {
                sent.lock().unwrap().push((packet.len(), packet[0]));
                // The command queue refuses every third cell.
                n.fetch_add(1, Ordering::SeqCst) % 3 != 2
            },
        )
    };
    tokio::time::sleep(Duration::from_secs(20)).await;
    let m = engine.metrics();
    assert!(m.generated_packets > 10, "{m:?}");
    assert_eq!(m.generated_packets, m.enqueued_packets + m.dropped_packets);
    assert!(m.dropped_packets > 0, "a full queue is counted: {m:?}");
    assert!(
        m.estimated_enqueued_bytes <= 1_000_000,
        "inside the daily budget: {m:?}"
    );
    assert!(m.budget_pauses >= 1, "the budget stopped the engine: {m:?}");
    for (len, tag) in sent.lock().unwrap().iter() {
        assert_eq!(*tag, COVER_TAG);
        assert!((513..=2049).contains(len), "payload of {len} bytes");
    }

    tokio::time::timeout(Duration::from_secs(5), engine.stop())
        .await
        .expect("the engine stops promptly");
    let after_stop = sent.lock().unwrap().len();
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(sent.lock().unwrap().len(), after_stop, "nothing after stop");

    // Disabled, and enabled with a zero budget: parked, silent, stoppable.
    for cfg in [
        CoverTrafficConfig {
            enabled: false,
            ..CoverTrafficConfig::default()
        },
        CoverTrafficConfig {
            enabled: true,
            daily_budget_bytes: 0,
            ..CoverTrafficConfig::default()
        },
    ] {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let e = CoverTrafficEngine::start(cfg, move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_secs(30)).await;
        tokio::time::timeout(Duration::from_secs(5), e.stop())
            .await
            .expect("a parked engine stops");
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Slow holders, relay-only transports, churn, during a streamed receive
// ═════════════════════════════════════════════════════════════════════════════

struct Stage {
    world: gate::World,
    script: Arc<gate::Script>,
    src: gate::SelectorSource,
    direct_attempts: Arc<AtomicUsize>,
    relay_attempts: Arc<AtomicUsize>,
}

/// Configured order is `order`; the world has `segments` segments of k=4, n=6.
fn stage(seed: u64, policy: AnonymityPolicy, order: &[PayloadTransportKind]) -> Stage {
    let mut r = gate::rng(seed, 20);
    let world = gate::build_world(8, 4, 6, false, &mut r);
    let shares = Arc::new(world.shares.clone());
    let script = gate::Script::new();
    let (mut transports, mut direct_attempts, mut relay_attempts) = (
        Vec::<Box<dyn miasma_core::PayloadTransport>>::new(),
        None,
        None,
    );
    for kind in order {
        let (t, attempts) = gate::ScriptedTransport::new(*kind, shares.clone(), script.clone());
        match kind {
            PayloadTransportKind::DirectLibp2p => direct_attempts = Some(attempts),
            PayloadTransportKind::RelayHop => relay_attempts = Some(attempts),
            _ => {}
        }
        transports.push(Box::new(t));
    }
    Stage {
        world,
        script,
        src: gate::SelectorSource {
            selector: PayloadTransportSelector::new(transports),
            policy,
        },
        direct_attempts: direct_attempts.unwrap_or_default(),
        relay_attempts: relay_attempts.unwrap_or_default(),
    }
}

struct Ran {
    result: Result<StreamOutcome, MiasmaError>,
    sink: gate::VaultSink,
    stats: Arc<StreamStats>,
    progress: Arc<TransferProgress>,
}

async fn run_stream(st: &Stage, sink_delay: Duration, cancel_at: Option<Duration>) -> Ran {
    let spec = gate::stream_spec(&st.world);
    let stats = spec.stats.clone();
    let progress = TransferProgress::new(st.world.mid.to_string());
    if let Some(at) = cancel_at {
        let p = progress.clone();
        tokio::spawn(async move {
            tokio::time::sleep(at).await;
            p.cancel();
        });
    }
    let mut sink = gate::VaultSink::new(sink_delay);
    let result = tokio::time::timeout(
        Duration::from_secs(3_600),
        receive_stream(&st.src, spec, &mut sink, progress.clone()),
    )
    .await
    .expect("the stream must end (virtual hour)");
    Ran {
        result,
        sink,
        stats,
        progress,
    }
}

fn assert_clean_buffers(stats: &StreamStats, what: &str) {
    let s = stats.snapshot();
    assert_eq!(s.live, 0, "{what}: a plaintext buffer is alive: {s:?}");
    assert_eq!(s.created, s.wiped, "{what}: not every buffer wiped: {s:?}");
    assert_eq!(s.wipe_failures, 0, "{what}: a buffer was not zero: {s:?}");
    assert!(s.peak_live <= 1, "{what}: more than one segment: {s:?}");
}

fn assert_no_plaintext_in(text: &str, what: &str) {
    assert!(
        !text.contains("R18-GATE"),
        "{what}: plaintext reached a message: {text}"
    );
}

const RELAY_ONLY: AnonymityPolicy = AnonymityPolicy::Required { min_hops: 2 };

#[tokio::test(start_paused = true)]
async fn a_relay_only_stream_over_slow_and_leaving_holders_completes_without_a_direct_hop() {
    let parts_before = gate::part_files_in_temp();
    for seed in gate::seeds(24) {
        let mut r = gate::rng(seed, 21);
        let st = stage(
            seed,
            RELAY_ONLY,
            &[
                PayloadTransportKind::DirectLibp2p,
                PayloadTransportKind::RelayHop,
            ],
        );
        // Every holder answers slowly; up to n-k holders leave at random moments.
        for slot in 0..6u16 {
            st.script.set_holder(
                slot,
                gate::HolderScript {
                    slow: Duration::from_millis(r.gen_range(0..40)),
                    gone_after: None,
                },
            );
        }
        let leaving = r.gen_range(0..=2usize);
        let mut slots: Vec<u16> = (0..6).collect();
        for _ in 0..leaving {
            let slot = slots.swap_remove(r.gen_range(0..slots.len()));
            st.script.set_holder(
                slot,
                gate::HolderScript {
                    slow: Duration::from_millis(r.gen_range(0..40)),
                    gone_after: Some(Duration::from_millis(r.gen_range(0..300))),
                },
            );
        }
        let ran = run_stream(&st, Duration::from_millis(r.gen_range(0..10)), None).await;

        let outcome = ran.result.unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        assert_eq!(
            outcome,
            StreamOutcome::Complete {
                segments: 8,
                bytes: st.world.data.len() as u64
            },
            "seed {seed}"
        );
        assert_eq!(ran.sink.collected.as_slice(), st.world.data.as_slice());
        assert_eq!((ran.sink.completes, ran.sink.aborted), (1, 0));
        assert_eq!(
            st.direct_attempts.load(Ordering::SeqCst),
            0,
            "seed {seed}: the policy forbids a direct hop and none was tried"
        );
        assert!(st.relay_attempts.load(Ordering::SeqCst) > 0);
        assert!(
            st.src
                .selector
                .stats()
                .kind_stats(PayloadTransportKind::RelayHop)
                .0
                > 0
        );
        assert_clean_buffers(&ran.stats, &format!("seed {seed}"));
        assert_eq!(ran.progress.snapshot().state, TransferState::Complete);
    }
    assert_eq!(
        gate::part_files_in_temp(),
        parts_before,
        "no temp file left"
    );
}

#[tokio::test(start_paused = true)]
async fn more_holders_leaving_than_the_code_can_spare_ends_the_stream_cleanly() {
    let parts_before = gate::part_files_in_temp();
    let (mut failed, mut finished) = (0, 0);
    for seed in gate::seeds(24) {
        let mut r = gate::rng(seed, 22);
        let st = stage(
            seed,
            RELAY_ONLY,
            &[
                PayloadTransportKind::RelayHop,
                PayloadTransportKind::DirectLibp2p,
            ],
        );
        // Three of six holders (one more than n-k) leave while the stream runs.
        let mut slots: Vec<u16> = (0..6).collect();
        for _ in 0..3 {
            let slot = slots.swap_remove(r.gen_range(0..slots.len()));
            st.script.set_holder(
                slot,
                gate::HolderScript {
                    slow: Duration::from_millis(r.gen_range(0..20)),
                    gone_after: Some(Duration::from_millis(r.gen_range(10..120))),
                },
            );
        }
        let ran = run_stream(&st, Duration::from_millis(20), None).await;

        assert_eq!(
            st.direct_attempts.load(Ordering::SeqCst),
            0,
            "seed {seed}: no way out through a forbidden transport"
        );
        assert_clean_buffers(&ran.stats, &format!("seed {seed}"));
        let seen: Vec<u32> = ran.sink.seen.clone();
        assert_eq!(
            seen,
            (0..seen.len() as u32).collect::<Vec<_>>(),
            "seed {seed}: segments arrive in order, with no gap"
        );
        match ran.result {
            Ok(StreamOutcome::Complete { .. }) => {
                finished += 1;
                assert_eq!(ran.sink.completes, 1);
            }
            Ok(other) => panic!("seed {seed}: unexpected outcome {other:?}"),
            Err(e) => {
                failed += 1;
                assert_no_plaintext_in(&e.to_string(), &format!("seed {seed}"));
                assert_eq!(
                    (ran.sink.completes, ran.sink.aborted),
                    (0, 1),
                    "seed {seed}"
                );
                assert!(ran.sink.collected.is_empty(), "the sink discarded its copy");
                assert!(seen.len() < 8, "seed {seed}: a failed stream is a prefix");
                let snap = ran.progress.snapshot();
                assert_eq!(snap.state, TransferState::Failed, "seed {seed}");
                assert_no_plaintext_in(&snap.last_error.unwrap_or_default(), "progress");
            }
        }
    }
    if std::env::var("R18_GATE_SEEDS").is_err() {
        assert!(failed > 0, "the schedule must make some streams fail");
    }
    let _ = finished;
    assert_eq!(
        gate::part_files_in_temp(),
        parts_before,
        "no temp file left"
    );
}

#[tokio::test(start_paused = true)]
async fn when_the_relay_is_down_the_policy_decides_and_a_downgrade_is_visible() {
    // Required: no relay, no stream. The direct transport is never touched.
    let st = stage(
        1,
        RELAY_ONLY,
        &[
            PayloadTransportKind::RelayHop,
            PayloadTransportKind::DirectLibp2p,
        ],
    );
    st.script.set_down(PayloadTransportKind::RelayHop, true);
    let ran = run_stream(&st, Duration::ZERO, None).await;
    let err = ran.result.expect_err("no relay under a relay-only policy");
    assert_no_plaintext_in(&err.to_string(), "required, relay down");
    assert_eq!(st.direct_attempts.load(Ordering::SeqCst), 0);
    assert_eq!((ran.sink.completes, ran.sink.aborted), (0, 1));
    assert_clean_buffers(&ran.stats, "required, relay down");

    // Required, but only direct transports are configured: refused up front.
    let st = stage(2, RELAY_ONLY, &[PayloadTransportKind::DirectLibp2p]);
    let ran = run_stream(&st, Duration::ZERO, None).await;
    assert!(ran.result.is_err());
    assert_eq!(
        st.direct_attempts.load(Ordering::SeqCst),
        0,
        "nothing went on the wire"
    );
    assert_clean_buffers(&ran.stats, "required, direct only");

    // Opportunistic: the direct hop is the fallback, and it shows.
    let st = stage(
        3,
        AnonymityPolicy::Opportunistic,
        &[
            PayloadTransportKind::RelayHop,
            PayloadTransportKind::DirectLibp2p,
        ],
    );
    st.script.set_down(PayloadTransportKind::RelayHop, true);
    let ran = run_stream(&st, Duration::ZERO, None).await;
    assert!(matches!(ran.result, Ok(StreamOutcome::Complete { .. })));
    assert_eq!(ran.sink.collected.as_slice(), st.world.data.as_slice());
    let stats = st.src.selector.stats();
    assert!(
        stats.kind_stats(PayloadTransportKind::RelayHop).1 > 0,
        "relay failures are counted"
    );
    assert!(stats.kind_stats(PayloadTransportKind::DirectLibp2p).0 > 0);
    assert_eq!(
        stats.last_selected(),
        Some(PayloadTransportKind::DirectLibp2p),
        "the transport that carried the data is the visible fallback"
    );
    assert_clean_buffers(&ran.stats, "opportunistic");
}

#[tokio::test(start_paused = true)]
async fn cancelling_a_slow_relay_stream_at_any_moment_leaves_nothing_behind() {
    let parts_before = gate::part_files_in_temp();
    let (mut cancelled, mut completed) = (0, 0);
    for seed in gate::seeds(24) {
        let mut r = gate::rng(seed, 23);
        let st = stage(
            seed,
            RELAY_ONLY,
            &[
                PayloadTransportKind::DirectLibp2p,
                PayloadTransportKind::RelayHop,
            ],
        );
        for slot in 0..6u16 {
            st.script.set_holder(
                slot,
                gate::HolderScript {
                    slow: Duration::from_millis(r.gen_range(5..60)),
                    gone_after: None,
                },
            );
        }
        let at = Duration::from_millis(r.gen_range(1..600));
        let ran = run_stream(&st, Duration::from_millis(r.gen_range(0..15)), Some(at)).await;
        assert_clean_buffers(&ran.stats, &format!("seed {seed}"));
        assert_eq!(st.direct_attempts.load(Ordering::SeqCst), 0);
        match ran.result {
            Ok(StreamOutcome::Cancelled {
                segments_delivered, ..
            }) => {
                cancelled += 1;
                assert!(segments_delivered < 8, "seed {seed}");
                assert_eq!((ran.sink.completes, ran.sink.aborted), (0, 1));
                assert_eq!(ran.progress.snapshot().state, TransferState::Cancelled);
            }
            Ok(StreamOutcome::Complete { .. }) => {
                completed += 1;
                assert_eq!(ran.sink.collected.as_slice(), st.world.data.as_slice());
            }
            other => panic!("seed {seed}: {other:?}"),
        }
    }
    if std::env::var("R18_GATE_SEEDS").is_err() {
        assert!(cancelled > 0 && completed > 0, "{cancelled} / {completed}");
    }
    assert_eq!(
        gate::part_files_in_temp(),
        parts_before,
        "no temp file left"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. A crash in the middle of a maintenance repair
// ═════════════════════════════════════════════════════════════════════════════

struct RepairWorld {
    durable: Arc<gate::Durable>,
    original: miasma_core::network::types::DhtRecord,
    pieces: usize,
}

fn repair_world(seed: u64) -> RepairWorld {
    let mut r = gate::rng(seed, 30);
    let (k, n) = [(2u8, 3u8), (2, 4), (3, 6)][r.gen_range(0..3)];
    let segments = 1 + r.gen_range(0..2u32);
    let mid: [u8; 32] = r.gen();
    let mut locations = Vec::new();
    for g in 0..segments {
        for s in 0..n as u16 {
            locations.push(gate::location(g, s, &format!("h{g}_{s}")));
        }
    }
    let original = miasma_core::network::types::DhtRecord {
        mid_digest: mid,
        data_shards: k,
        total_shards: n,
        version: 1,
        locations,
        published_at: 1_000,
    };
    let spare = r.gen_range(3..6usize);
    let candidates = (0..spare)
        .map(|i| gate::candidate(&format!("c{i}")))
        .collect();
    let durable = gate::Durable::new(original.clone(), candidates);
    let dead = r.gen_range(1..=3usize);
    let mut all: Vec<(u32, u16)> = (0..segments)
        .flat_map(|g| (0..n as u16).map(move |s| (g, s)))
        .collect();
    for _ in 0..dead {
        let (g, s) = all.swap_remove(r.gen_range(0..all.len()));
        durable.kill(&format!("h{g}_{s}"));
    }
    RepairWorld {
        durable,
        pieces: (segments as usize) * n as usize,
        original,
    }
}

/// One start of the node: a fresh core (memory is gone), one pass. Returns
/// `true` when the process died inside the pass.
async fn one_start(
    durable: &gate::Durable,
    now: u64,
    crash: Option<(usize, gate::CrashPhase)>,
) -> bool {
    match crash {
        Some((n, phase)) => durable.arm_crash(n, phase),
        None => durable.disarm(),
    }
    let mut core = MaintenanceCore::new(gate::maintenance_cfg(), now);
    let pass = core.tick(durable as &dyn MaintenanceBackend, now);
    tokio::pin!(pass);
    tokio::select! {
        _ = &mut pass => false,
        _ = durable.crashed.notified() => true,
    }
}

fn assert_repair_invariants(w: &RepairWorld, ctx: &str) {
    let s = w.durable.state.lock().unwrap();
    // Every record anyone could have read is a legal rewrite of the original.
    for (i, rec) in s.history.iter().enumerate() {
        check_record_update(&w.original, rec)
            .unwrap_or_else(|e| panic!("{ctx}: record #{i} is not a legal rewrite: {e}"));
        assert_eq!(rec.mid_digest, w.original.mid_digest, "{ctx}: MID");
        assert_eq!(
            (rec.data_shards, rec.total_shards),
            (w.original.data_shards, w.original.total_shards),
            "{ctx}: k/n"
        );
        assert!(rec.published_at >= w.original.published_at, "{ctx}");
    }
    // A location in the record is never one that was not written.
    for l in &s.record.locations {
        let holder = miasma_core::repair::holder_id_of(l);
        assert!(
            s.dead.contains(&holder)
                || s.stored
                    .get(&holder)
                    .is_some_and(|p| p.contains(&(l.segment_index, l.shard_index))),
            "{ctx}: the record names a holder that does not have the piece: {l:?}"
        );
    }
}

fn assert_repaired(w: &RepairWorld, ctx: &str) {
    assert_repair_invariants(w, ctx);
    let s = w.durable.state.lock().unwrap();
    assert_eq!(
        s.record.locations.len(),
        w.pieces,
        "{ctx}: one location per piece"
    );
    let mut seen = BTreeSet::new();
    for l in &s.record.locations {
        assert!(
            seen.insert((l.segment_index, l.shard_index)),
            "{ctx}: two locations for one piece"
        );
        let holder = miasma_core::repair::holder_id_of(l);
        assert!(
            !s.dead.contains(&holder),
            "{ctx}: still points at a dead holder: {l:?}"
        );
    }
    assert_eq!(seen.len(), w.pieces);
    // No second copy anywhere: every piece a live holder stores is in the record.
    for (holder, pieces) in &s.stored {
        if s.dead.contains(holder) {
            continue;
        }
        for (g, slot) in pieces {
            assert!(
                s.record.locations.iter().any(|l| {
                    miasma_core::repair::holder_id_of(l) == *holder
                        && (l.segment_index, l.shard_index) == (*g, *slot)
                }),
                "{ctx}: {holder} stores piece ({g},{slot}) that the record does not list (a duplicate)"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_crash_at_every_step_of_a_repair_is_resumed_without_a_duplicate() {
    let mut crash_points = 0usize;
    for seed in gate::seeds(12) {
        // The reference run: how many backend calls does a clean repair make?
        let reference = repair_world(seed);
        assert!(!one_start(&reference.durable, 10_000, None).await);
        let calls = reference.durable.calls();
        assert_repaired(&reference, &format!("seed {seed}, clean run"));
        assert!(calls >= 4, "seed {seed}: {calls} calls");
        let clean_pushes = reference.durable.state.lock().unwrap().pushes.len();
        assert!(clean_pushes >= 1, "seed {seed}: something was repaired");

        for phase in [gate::CrashPhase::Before, gate::CrashPhase::After] {
            for n in 1..=calls {
                let ctx = format!("seed {seed}, crash {phase:?} call {n}/{calls}");
                let w = repair_world(seed);
                let died = one_start(&w.durable, 10_000, Some((n, phase))).await;
                assert!(died, "{ctx}: the doomed call was reached");
                crash_points += 1;
                assert_repair_invariants(&w, &format!("{ctx}, after the crash"));

                // The next start resumes (one pass is enough on a quiet network)...
                assert!(!one_start(&w.durable, 20_000, None).await, "{ctx}");
                assert_repaired(&w, &format!("{ctx}, after one restart"));
                // ...and a further start has nothing left to do.
                let (pushes, commits) = {
                    let s = w.durable.state.lock().unwrap();
                    (s.pushes.len(), s.commits)
                };
                assert!(!one_start(&w.durable, 30_000, None).await);
                let s = w.durable.state.lock().unwrap();
                assert_eq!(
                    (s.pushes.len(), s.commits),
                    (pushes, commits),
                    "{ctx}: idle"
                );
            }
        }
    }
    assert!(crash_points > 100, "{crash_points} crash points exercised");
}

#[tokio::test(start_paused = true)]
async fn a_refused_record_commit_is_retried_without_pushing_again_and_survives_a_restart() {
    for seed in gate::seeds(12) {
        // Same process: the retry commits the held update and sends nothing.
        let w = repair_world(seed);
        w.durable.state.lock().unwrap().fail_commit = 1;
        let mut core = MaintenanceCore::new(gate::maintenance_cfg(), 10_000);
        let backend = &*w.durable as &dyn MaintenanceBackend;
        let first = core.tick(backend, 10_000).await;
        assert!(
            first.repaired >= 1 && first.commit_failures == 1,
            "seed {seed}: {first:?}"
        );
        let pushes = w.durable.state.lock().unwrap().pushes.len();
        let retry = core.tick(backend, 10_001).await;
        assert_eq!(retry.records_committed, 1, "seed {seed}: {retry:?}");
        assert_eq!(
            w.durable.state.lock().unwrap().pushes.len(),
            pushes,
            "seed {seed}: the held update is committed, not re-pushed"
        );
        assert_repaired(&w, &format!("seed {seed}, same process"));

        // The process dies before the retry: the next start re-plans. The same
        // holder gets the same piece again, so there is still one copy.
        let w = repair_world(seed);
        w.durable.state.lock().unwrap().fail_commit = 1;
        let mut core = MaintenanceCore::new(gate::maintenance_cfg(), 10_000);
        let first = core
            .tick(&*w.durable as &dyn MaintenanceBackend, 10_000)
            .await;
        assert_eq!(first.commit_failures, 1, "seed {seed}");
        drop(core);
        assert_repair_invariants(&w, &format!("seed {seed}, before the restart"));
        assert!(!one_start(&w.durable, 20_000, None).await);
        assert_repaired(&w, &format!("seed {seed}, after the restart"));
    }
}

// ─── The same on a real five-node network ────────────────────────────────────

mod real_repair {
    use super::*;
    use miasma_core::{
        daemon::maintenance_exec::{CoordinatorBackend, MemoryRecordSource, RecordSource},
        network::coordinator::PublishOptions,
        repair::{
            EvidenceConfig, MaintenanceClock, MaintenanceConfig, PieceMaintenanceConfig,
            SystemClock,
        },
        MiasmaCoordinator, MiasmaNode, Multiaddr, NodeType,
    };

    async fn spawn_node(
        key_byte: u8,
        hosted_quota_mb: u64,
    ) -> (MiasmaCoordinator, Arc<LocalShareStore>) {
        let dir = tempfile::tempdir().unwrap().keep();
        let store = Arc::new(
            LocalShareStore::open(&dir, 100)
                .unwrap()
                .with_hosted_quota_mb(hosted_quota_mb),
        );
        let key = [key_byte; 32];
        let mut node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let addrs = node.collect_listen_addrs(400).await;
        let coord = MiasmaCoordinator::start(node, store.clone(), vec![addrs[0].to_string()]).await;
        (coord, store)
    }

    async fn join(joiner: &MiasmaCoordinator, seed: &MiasmaCoordinator) {
        let seed_addr: Multiaddr = seed.listen_addrs()[0].parse().unwrap();
        let seed_id = *seed.peer_id();
        let joiner_id = *joiner.peer_id();
        joiner.add_bootstrap_peer(seed_id, seed_addr).await.unwrap();
        joiner.bootstrap_dht().await.unwrap();
        joiner
            .wait_until_peer_connected(seed_id, Duration::from_secs(10))
            .await
            .unwrap();
        seed.wait_until_peer_connected(joiner_id, Duration::from_secs(10))
            .await
            .unwrap();
    }

    fn holder_of(record: &miasma_core::network::types::DhtRecord, slot: u16) -> Vec<u8> {
        let held: Vec<_> = record
            .locations
            .iter()
            .filter(|l| l.shard_index == slot)
            .collect();
        assert_eq!(held.len(), 1, "slot {slot} must have exactly one location");
        held[0].peer_id_bytes.clone()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pass_cut_off_at_a_seeded_moment_is_resumed_by_the_next_start() {
        let seed = gate::seeds(1)[0];
        let cut = Duration::from_millis(gate::rng(seed, 31).gen_range(0..400));
        let result = tokio::time::timeout(Duration::from_secs(150), async {
            let (coord_a, store_a) = spawn_node(0xA8, 0).await;
            let (coord_b, store_b) = spawn_node(0xB8, 50).await;
            let (coord_c, store_c) = spawn_node(0xC8, 50).await;
            let (coord_d, store_d) = spawn_node(0xD8, 50).await;
            let (coord_e, store_e) = spawn_node(0xE8, 50).await;
            for host in [&coord_b, &coord_c, &coord_d, &coord_e] {
                join(host, &coord_a).await;
            }
            tokio::time::sleep(Duration::from_millis(1000)).await;

            let params = DissolutionParams {
                data_shards: 2,
                total_shards: 3,
            };
            let content = b"crash mid repair: the next start finishes it, k/n and MID untouched";
            let report = coord_a
                .dissolve_and_publish_with_options(content, params, PublishOptions::strict(params))
                .await
                .expect("publish");
            let mid = report.mid;
            let before = coord_a
                .dht_handle()
                .get_record(*mid.as_bytes())
                .await
                .unwrap()
                .expect("record published");
            assert_eq!(before.locations.len(), 3);

            let all = [&coord_b, &coord_c, &coord_d, &coord_e];
            let stores = [&store_b, &store_c, &store_d, &store_e];
            let owner_of = |slot: u16| -> usize {
                let bytes = holder_of(&before, slot);
                all.iter()
                    .position(|c| c.peer_id().to_bytes() == bytes)
                    .expect("holder is one of the four hosts")
            };
            let (dead_idx, second_idx, survivor_idx) = (owner_of(0), owner_of(1), owner_of(2));
            let spare_idx = (0..all.len())
                .find(|i| ![dead_idx, second_idx, survivor_idx].contains(i))
                .expect("one host holds no slot");
            let spare = all[spare_idx];
            assert_eq!(stores[spare_idx].used_hosted_bytes(), 0);

            all[dead_idx].shutdown().await;

            let coord_a = Arc::new(coord_a);
            let source = Arc::new(MemoryRecordSource::new(vec![before.clone()]));
            let backend = CoordinatorBackend::new(
                coord_a.clone(),
                store_a.clone(),
                source.clone() as Arc<dyn RecordSource>,
            );
            let cfg = MaintenanceConfig {
                planner: PieceMaintenanceConfig {
                    target_replicas_per_slot: 1,
                    prefer_distinct_failure_domains: false,
                    ..PieceMaintenanceConfig::default()
                },
                evidence: EvidenceConfig {
                    max_failures: 1,
                    ..EvidenceConfig::default()
                },
                ..MaintenanceConfig::default()
            };
            let clock = SystemClock;

            // First start: the process dies `cut` into the pass (it may also
            // have finished by then; both are legal).
            let mut core = MaintenanceCore::new(cfg.clone(), clock.now_secs());
            let _ = tokio::time::timeout(cut, core.tick(&backend, clock.now_secs())).await;
            drop(core);

            // Next starts: a fresh core each time, until the record is whole.
            let mut starts = 0;
            loop {
                let now_rec = source.records().pop().expect("record kept");
                if !now_rec
                    .locations
                    .iter()
                    .any(|l| l.peer_id_bytes == all[dead_idx].peer_id().to_bytes())
                {
                    break;
                }
                starts += 1;
                assert!(
                    starts <= 5,
                    "the repair never completed after {starts} restarts"
                );
                let mut core = MaintenanceCore::new(cfg.clone(), clock.now_secs());
                let t = core.tick(&backend, clock.now_secs()).await;
                assert_eq!(t.invariant_violations, 0, "{t:?}");
            }

            let after = source.records().pop().expect("record kept");
            check_record_update(&before, &after).expect("legal maintenance rewrite");
            assert_eq!(after.mid_digest, *mid.as_bytes(), "MID unchanged");
            assert_eq!(
                (after.data_shards, after.total_shards),
                (2, 3),
                "k/n unchanged"
            );
            assert_eq!(after.locations.len(), 3);
            assert_eq!(holder_of(&after, 0), spare.peer_id().to_bytes());
            assert_eq!(holder_of(&after, 1), holder_of(&before, 1));
            assert_eq!(holder_of(&after, 2), holder_of(&before, 2));

            // No second copy: the spare holds exactly as much as a host with one piece.
            let survivor_used = stores[survivor_idx].used_hosted_bytes();
            assert!(survivor_used > 0);
            assert_eq!(
                stores[spare_idx].used_hosted_bytes(),
                survivor_used,
                "the spare holds one copy of one piece, however often the push was retried"
            );
            assert_eq!(ContentId::from_digest(after.mid_digest), mid);

            coord_a.shutdown().await;
            for (i, c) in all.iter().enumerate() {
                if i != dead_idx {
                    c.shutdown().await;
                }
            }
        })
        .await;
        result.expect("real repair crash test timed out (150s)");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Wipe at a seeded moment
// ═════════════════════════════════════════════════════════════════════════════

/// Maintenance over a real store: probes and pushes are simulated, but the
/// replica source is the node's own (encrypted) store, as in the daemon.
struct StoreBackedMaintenance {
    inner: Arc<gate::Durable>,
    store: Arc<LocalShareStore>,
    mid: ContentId,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl MaintenanceBackend for StoreBackedMaintenance {
    async fn tracked_records(&self) -> Vec<miasma_core::network::types::DhtRecord> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.tracked_records().await
    }
    async fn probe(
        &self,
        location: &miasma_core::network::types::ShardLocation,
        mid: &[u8; 32],
    ) -> ProbeResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.probe(location, mid).await
    }
    async fn source_share(
        &self,
        _record: &miasma_core::network::types::DhtRecord,
        segment: u32,
        slot: u16,
        _live: &[miasma_core::network::types::ShardLocation],
    ) -> Option<MiasmaShare> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let address = self.store.find_piece(&self.mid.prefix(), segment, slot)?;
        self.store.get_untouched(&address).ok()
    }
    async fn candidates(&self, exclude: &[String]) -> Vec<miasma_core::repair::Candidate> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.candidates(exclude).await
    }
    async fn push(
        &self,
        c: &miasma_core::repair::Candidate,
        share: &MiasmaShare,
    ) -> Result<miasma_core::network::types::ShardLocation, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.push(c, share).await
    }
    async fn commit_record(
        &self,
        updated: miasma_core::network::types::DhtRecord,
    ) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.commit_record(updated).await
    }
}

#[tokio::test(start_paused = true)]
async fn a_wipe_at_a_seeded_moment_stops_every_task_and_leaves_nothing_readable() {
    let parts_before = gate::part_files_in_temp();
    let (mut recv_cut, mut recv_done, mut pub_cut, mut pub_done) = (0, 0, 0, 0);
    for seed in gate::seeds(48) {
        let (rc, rd, pc, pd) = wipe_run(seed).await;
        recv_cut += rc;
        recv_done += rd;
        pub_cut += pc;
        pub_done += pd;
    }
    if std::env::var("R18_GATE_SEEDS").is_err() {
        assert!(
            recv_cut > 0 && recv_done > 0,
            "receive: cut {recv_cut}, done {recv_done}"
        );
        assert!(
            pub_cut > 0 && pub_done > 0,
            "publish: cut {pub_cut}, done {pub_done}"
        );
    }
    assert_eq!(
        gate::part_files_in_temp(),
        parts_before,
        "no temp file left"
    );
}

/// Returns (receive cut by the wipe, receive finished first, publish cut,
/// publish finished first) as 0/1 counters.
async fn wipe_run(seed: u64) -> (u32, u32, u32, u32) {
    let ctx = format!("seed {seed}");
    let mut r = gate::rng(seed, 40);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
    let key_path = dir.path().join("master.key");
    assert!(key_path.exists(), "{ctx}");

    // Content the node maintains: three pieces in its own store.
    let params = DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    };
    let kept = gate::content(2 * gate::SEG, &mut r);
    let (kept_mid, kept_shares) = miasma_core::dissolve(&kept, params).unwrap();
    for s in &kept_shares {
        store.put(s).unwrap();
    }
    let record = miasma_core::network::types::DhtRecord {
        mid_digest: *kept_mid.as_bytes(),
        data_shards: 2,
        total_shards: 3,
        version: 1,
        locations: (0..3u16)
            .map(|s| gate::location(0, s, &format!("h{s}")))
            .collect(),
        published_at: 1_000,
    };
    let durable = gate::Durable::new(record, vec![gate::candidate("c0"), gate::candidate("c1")]);
    durable.kill("h1");
    let maint_calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(StoreBackedMaintenance {
        inner: durable.clone(),
        store: store.clone(),
        mid: kept_mid.clone(),
        calls: maint_calls.clone(),
    });
    let exec = spawn_executor(
        backend,
        gate::maintenance_cfg(),
        Arc::new(ManualClock::new(50_000)),
    );

    // Cover traffic.
    let cover_sent = Arc::new(AtomicUsize::new(0));
    let cover = {
        let c = cover_sent.clone();
        CoverTrafficEngine::start(
            CoverTrafficConfig {
                enabled: true,
                rate_bytes_per_sec: 100_000,
                ..CoverTrafficConfig::default()
            },
            move |_| {
                c.fetch_add(1, Ordering::SeqCst);
            },
        )
    };

    // The streamed receive, saved to a file at the end through the gated write.
    let st = stage(
        seed,
        RELAY_ONLY,
        &[
            PayloadTransportKind::DirectLibp2p,
            PayloadTransportKind::RelayHop,
        ],
    );
    for slot in 0..6u16 {
        st.script.set_holder(
            slot,
            gate::HolderScript {
                slow: Duration::from_millis(r.gen_range(2..16)),
                gone_after: None,
            },
        );
    }
    let out_dir = tempfile::tempdir().unwrap();
    let out_path = out_dir.path().join("received.bin");
    let recv_stats;
    let recv = {
        let spec = gate::stream_spec(&st.world);
        recv_stats = spec.stats.clone();
        let progress = TransferProgress::new(st.world.mid.to_string());
        let store = store.clone();
        let out_path = out_path.clone();
        let sink_delay = Duration::from_millis(r.gen_range(0..5));
        tokio::spawn(async move {
            let mut sink = gate::VaultSink::new(sink_delay);
            let res = store
                .wipe_gate()
                .run_result(async {
                    let outcome = receive_stream(&st.src, spec, &mut sink, progress).await?;
                    if matches!(outcome, StreamOutcome::Complete { .. }) {
                        store
                            .wipe_gate()
                            .write_output(&out_path, &sink.collected)
                            .await?;
                    }
                    Ok(outcome)
                })
                .await;
            (res, st.world.data.clone())
        })
    };

    // The publish: segments dissolved and put into the store, one per step.
    let pub_data = gate::content(6 * gate::SEG, &mut r);
    let pub_mid = ContentId::compute(&pub_data, &params.to_param_bytes());
    let step = Duration::from_millis(r.gen_range(3..12));
    let publish = {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .wipe_gate()
                .run_result(async {
                    for (i, chunk) in pub_data.chunks(gate::SEG).enumerate() {
                        let (_, shares) =
                            dissolve_segment_with(chunk, &pub_mid, i as u32, 0, params, None)?;
                        for s in &shares {
                            store.put(s)?;
                        }
                        tokio::time::sleep(step).await;
                    }
                    Ok(())
                })
                .await
        })
    };

    // The wipe, in the daemon's order.
    tokio::time::sleep(Duration::from_millis(r.gen_range(0..200))).await;
    let addrs_before = store.list();
    store.begin_wipe();
    exec.cancel();
    let drained = store.wipe_gate().drained(Duration::from_secs(5)).await;
    let wiped = store.distress_wipe();
    assert!(drained, "{ctx}: operations did not stop in time");
    wiped.unwrap_or_else(|e| panic!("{ctx}: wipe failed: {e}"));

    // Every task has ended, one way or the other.
    let (recv_res, data) = tokio::time::timeout(Duration::from_secs(30), recv)
        .await
        .unwrap_or_else(|_| panic!("{ctx}: the receive did not end"))
        .unwrap();
    let pub_res = tokio::time::timeout(Duration::from_secs(30), publish)
        .await
        .unwrap_or_else(|_| panic!("{ctx}: the publish did not end"))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), exec.stop())
        .await
        .unwrap_or_else(|_| panic!("{ctx}: maintenance did not stop"));
    tokio::time::timeout(Duration::from_secs(30), cover.stop())
        .await
        .unwrap_or_else(|_| panic!("{ctx}: cover traffic did not stop"));
    assert_eq!(store.wipe_gate().in_flight(), 0, "{ctx}");

    let (calls, cover_count) = (
        maint_calls.load(Ordering::SeqCst),
        cover_sent.load(Ordering::SeqCst),
    );
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        maint_calls.load(Ordering::SeqCst),
        calls,
        "{ctx}: maintenance still runs"
    );
    assert_eq!(
        cover_sent.load(Ordering::SeqCst),
        cover_count,
        "{ctx}: cover still runs"
    );

    // The receive: finished before the wipe, or cut with a clean error; and
    // then it left no output.
    let recv_cut = match recv_res {
        Ok(StreamOutcome::Complete { .. }) => {
            assert_eq!(
                std::fs::read(&out_path).unwrap(),
                data,
                "{ctx}: finished output"
            );
            0
        }
        Ok(other) => panic!("{ctx}: unexpected outcome {other:?}"),
        Err(e) => {
            assert!(e.to_string().contains("wipe in progress"), "{ctx}: {e}");
            assert!(!out_path.exists(), "{ctx}: a cut receive left a file");
            1
        }
    };
    let pub_cut = match pub_res {
        Ok(()) => 0,
        Err(e) => {
            assert!(e.to_string().contains("wipe in progress"), "{ctx}: {e}");
            1
        }
    };
    {
        let s = recv_stats.snapshot();
        assert_eq!(s.live, 0, "{ctx}: {s:?}");
        assert_eq!(s.created, s.wiped, "{ctx}: {s:?}");
        assert_eq!(s.wipe_failures, 0, "{ctx}: {s:?}");
    }

    // No key operation succeeds any more.
    assert!(!key_path.exists(), "{ctx}: master.key is gone");
    assert!(store.key_memory_status().is_none(), "{ctx}");
    assert!(store.wipe_gate().enter().is_err(), "{ctx}");
    assert!(!addrs_before.is_empty(), "{ctx}");
    for a in &addrs_before {
        assert!(store.get(a).is_err(), "{ctx}: a share is still readable");
        assert!(store.get_untouched(a).is_err(), "{ctx}");
    }
    assert!(store.put(&kept_shares[0]).is_err(), "{ctx}: put after wipe");
    assert!(
        store.put_hosted(&kept_shares[0]).is_err(),
        "{ctx}: put_hosted after wipe"
    );
    assert!(
        store.find_piece(&kept_mid.prefix(), 0, 0).is_none()
            || store
                .get_untouched(&store.find_piece(&kept_mid.prefix(), 0, 0).unwrap())
                .is_err(),
        "{ctx}"
    );
    assert!(!key_path.exists(), "{ctx}: nothing recreated the key");

    // No plaintext, no temp file.
    assert!(
        gate::temp_like_files(dir.path()).is_empty(),
        "{ctx}: {:?}",
        gate::temp_like_files(dir.path())
    );
    assert!(
        gate::files_containing(dir.path(), gate::MARK).is_empty(),
        "{ctx}"
    );
    assert!(gate::temp_like_files(out_dir.path()).is_empty(), "{ctx}");

    (recv_cut, 1 - recv_cut, pub_cut, 1 - pub_cut)
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. Compatibility with the beta.2 / beta.3 protocol set
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn a_peer_without_the_new_features_is_served_in_the_classical_way_and_it_shows() {
    let current = Capabilities::current();
    for old in [
        Capabilities::legacy(),
        // A peer that sends a capability message but offers nothing new.
        Capabilities {
            version: CAPABILITY_VERSION,
            suites: SUITE_CLASSICAL,
            features: 0,
            unknown: Vec::new(),
        },
    ] {
        let agreed = negotiate(&current, &old, &Requirements::default()).unwrap();
        assert_eq!(agreed.best_suite(), SUITE_CLASSICAL);
        assert!(!agreed.has_suite(SUITE_HYBRID_X25519_MLKEM768));
        assert!(!agreed.has_feature(FEATURE_FRAGMENTATION));
        assert!(agreed.downgraded);
        assert!(agreed
            .reasons
            .contains(&DowngradeReason::SuitesUnavailable {
                bits: SUITE_HYBRID_X25519_MLKEM768
            }));
        assert!(agreed
            .reasons
            .iter()
            .any(|r| matches!(r, DowngradeReason::FeaturesUnavailable { .. })));

        // A local policy that demands the hybrid suite refuses, it does not downgrade.
        assert_eq!(
            negotiate(
                &current,
                &old,
                &Requirements {
                    suites: SUITE_HYBRID_X25519_MLKEM768,
                    features: 0
                }
            ),
            Err(NegotiationError::RequirementUnmet {
                missing_suites: SUITE_HYBRID_X25519_MLKEM768,
                missing_features: 0
            })
        );
        // Both ends compute the same binding: an honest downgrade authenticates.
        assert_eq!(
            transcript_binding(&current, &old, &agreed),
            transcript_binding(&current, &old, &agreed)
        );
    }
}

/// What a sender puts on the wire for one handshake message.
fn send_handshake(
    agreed: &miasma_core::protocol::capability::Agreed,
    hid: u64,
    msg: &[u8],
    mtu: usize,
) -> Vec<Vec<u8>> {
    if agreed.has_feature(FEATURE_FRAGMENTATION) {
        fragment::fragment(hid, agreed.best_suite() as u16, msg, mtu)
            .unwrap()
            .iter()
            .map(|f| f.encode())
            .collect()
    } else {
        vec![msg.to_vec()]
    }
}

#[test]
fn fragmentation_is_used_only_where_it_was_agreed_and_survives_a_bad_link_there() {
    let current = Capabilities::current();
    let old = Capabilities::legacy();
    let msg: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();

    // To the old peer: the message goes whole, exactly as before.
    let to_old = negotiate(&current, &old, &Requirements::default()).unwrap();
    assert_eq!(send_handshake(&to_old, 1, &msg, 1200), vec![msg.clone()]);

    // Between two current nodes: fragments, resent until the message is whole,
    // over a link that loses, duplicates, reorders and cuts fragments short.
    let both = negotiate(&current, &current, &Requirements::default()).unwrap();
    assert!(both.has_feature(FEATURE_FRAGMENTATION));
    assert_eq!(
        transcript_binding(&current, &current, &both),
        transcript_binding(&current, &current, &both)
    );
    for seed in gate::seeds(40) {
        let mut r = gate::rng(seed, 50);
        let mut re = Reassembler::new(ReassemblyLimits::default());
        let mut done = None;
        for round in 0..40u64 {
            let wire = send_handshake(&both, 77, &msg, 1200);
            let delivered = gate::hostile(wire, gate::Hostility::damaging(), &mut r);
            for bytes in delivered {
                if let Ok(f) = HandshakeFragment::decode(&bytes) {
                    if let Ok(PushOutcome::Complete { data, .. }) = re.push(f, round * 100) {
                        if data == msg {
                            done = Some(round);
                        }
                    }
                }
                assert!(re.in_progress() <= ReassemblyLimits::default().max_concurrent);
            }
            if done.is_some() {
                break;
            }
        }
        assert!(done.is_some(), "seed {seed}: the handshake never completed");
    }
}

// ─── Onion cells across the 8 KiB / 9 KiB change ─────────────────────────────

fn legacy_pad(data: &[u8], target: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    if out.len() < target {
        let mut pad = vec![0u8; target - out.len()];
        OsRng.fill_bytes(&mut pad);
        out.extend_from_slice(&pad);
    }
    out
}

fn onion_key(shared: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared)
        .expand(b"miasma-onion-enc-v1", &mut key)
        .unwrap();
    key
}

/// A layer as a build from before the 9 KiB outer cell wrote it: the outer
/// `data` field padded only to the 8 KiB target.
fn legacy_layer(recipient: &[u8; 32], mut payload: LayerPayload) -> OnionLayer {
    payload.data = legacy_pad(&payload.data, ONION_PAD_TARGET);
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient));
    let key = onion_key(shared.as_bytes());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let plain = bincode::serialize(&payload).unwrap();
    let ciphertext = XChaCha20Poly1305::new((&key).into())
        .encrypt(XNonce::from_slice(&nonce), plain.as_slice())
        .unwrap();
    OnionLayer {
        ephemeral_pubkey: eph_pub.to_bytes(),
        nonce,
        ciphertext,
    }
}

/// The receiving side of an old build, written from the documented format.
fn legacy_peel(secret: &[u8; 32], layer: &OnionLayer) -> LayerPayload {
    let shared =
        StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(layer.ephemeral_pubkey));
    let key = onion_key(shared.as_bytes());
    let plain = XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(&layer.nonce),
            layer.ciphertext.as_slice(),
        )
        .expect("the layer authenticates");
    let mut payload: LayerPayload = bincode::deserialize(&plain).unwrap();
    let len = u32::from_le_bytes(payload.data[..4].try_into().unwrap()) as usize;
    payload.data = payload.data[4..4 + len].to_vec();
    payload
}

#[test]
fn a_9_kib_cell_opens_on_an_older_relay_and_an_older_cell_opens_on_this_one() {
    let r = relays();
    let body = b"carried across the cell size change".to_vec();

    // New cell, old relay: the old receiver strips padding by the length prefix.
    let pkt = onion_packet(&r, 30, &body);
    let outer = legacy_peel(&r.r1_secret, &pkt.layer);
    assert_eq!(outer.next_hop.as_deref(), Some(peer_id(2).as_slice()));
    let inner_layer: OnionLayer = bincode::deserialize(&outer.data).unwrap();
    let inner = legacy_peel(&r.r2_secret, &inner_layer);
    assert_eq!(inner.next_hop.as_deref(), Some(peer_id(3).as_slice()));

    // Old cell, this relay: both layers written the old way.
    let inner_payload = miasma_core::onion::InnerPayload {
        return_path: miasma_core::onion::ReturnPath {
            circuit_id: miasma_core::CircuitId::random(),
            r2_addr: vec![4; 30],
            r2_r1_key: [5; 32],
            r1_init_key: [6; 32],
        },
        body: body.clone(),
    };
    let layer2 = legacy_layer(
        &r.r2_pub,
        LayerPayload {
            next_hop: Some(peer_id(3)),
            data: bincode::serialize(&inner_payload).unwrap(),
            return_key: Some([5; 32]),
        },
    );
    let layer1 = legacy_layer(
        &r.r1_pub,
        LayerPayload {
            next_hop: Some(peer_id(2)),
            data: bincode::serialize(&layer2).unwrap(),
            return_key: Some([6; 32]),
        },
    );
    let old_cell = OnionPacket {
        circuit_id: miasma_core::CircuitId::random(),
        layer: layer1,
    };
    let (target, got) = through_relays(&r, &old_cell).unwrap();
    assert_eq!((target, got), (peer_id(3), body));
    let _ = OnionLayerProcessor::peel(&r.r1_secret, &old_cell.layer).unwrap();
}

// ─── A current node and a beta.2 / beta.3 peer, features on ──────────────────

#[cfg(feature = "iroh")]
mod old_peer {
    use super::*;
    use iroh::{endpoint::Connection, tls::CaTlsConfig};
    use miasma_core::{
        chat::{
            crypto::Identity,
            engine::ChatCore,
            ipc::handle_with,
            outbox::Outbox,
            proto::{self, Ack, Frame},
            service::{ChatService, ChatSettings},
            store::{ChatStore, MsgState, StoreSettings},
            ChatRequest, ChatResponse,
        },
        config::IrohMode,
        push::{ContactCode, ContactStore},
        state_crypto::StateKeys,
        transport::iroh_direct::{
            endpoint_builder, ChatConnectionHandler, IrohNode, IrohServerLimits, IrohSettings,
            CHAT_ALPN, IROH_ALPN, PUSH_ALPN,
        },
    };

    struct Relay {
        _server: iroh_relay::server::Server,
        url: String,
    }

    async fn relay() -> Relay {
        let mut cfg = iroh_relay::server::testing::server_config();
        cfg.quic = None;
        let server = iroh_relay::server::Server::spawn(cfg).await.unwrap();
        let url = format!("https://{}", server.https_addr().unwrap());
        Relay {
            _server: server,
            url,
        }
    }

    async fn start_node(
        relay: &Relay,
        seed: &[u8; 32],
        alpns: Option<Vec<&'static [u8]>>,
    ) -> Arc<IrohNode> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(store_dir.path(), 10).unwrap());
        let s = IrohSettings {
            mode: IrohMode::Custom,
            relay_urls: vec![relay.url.clone()],
            discovery: false,
            lan_discovery: false,
            connect_timeout: Duration::from_secs(4),
            ca_pem: None,
            proxy_from_env: false,
        };
        let mut builder = endpoint_builder(Some(seed), &s, false)
            .unwrap()
            .ca_tls_config(CaTlsConfig::insecure_skip_verify());
        if let Some(list) = alpns {
            builder = builder.alpns(list.into_iter().map(|a| a.to_vec()).collect());
        }
        let node =
            IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
                .await
                .unwrap();
        assert!(node.wait_online(Duration::from_secs(20)).await);
        std::mem::forget(store_dir);
        node
    }

    fn fast() -> ChatSettings {
        ChatSettings {
            retry_delays: vec![Duration::from_millis(200)],
            retry_every: Duration::from_millis(300),
            retry_jitter: 0.0,
            idle_timeout: Duration::from_secs(20),
            ..ChatSettings::default()
        }
    }

    /// A hand-written receiver standing in for a beta.2 / beta.3 build:
    /// bidirectional streams only, no group protocol.
    struct Hand {
        core: Arc<ChatCore>,
        delivers: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ChatConnectionHandler for Hand {
        async fn handle(&self, conn: Connection) {
            let remote = *conn.remote_id().as_bytes();
            while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
                let Ok(Frame::Deliver(wire)) = proto::read_frame(&mut rx).await else {
                    return;
                };
                self.delivers.fetch_add(1, Ordering::SeqCst);
                let env_id: [u8; 16] = wire[3..19].try_into().unwrap();
                let status = self.core.accept(&remote, &wire, 1).status;
                let _ = proto::write_frame(
                    &mut tx,
                    &Frame::Ack(Ack {
                        status,
                        envelope_id: env_id,
                    }),
                )
                .await;
                let _ = tx.finish();
            }
        }
    }

    fn hand(seed: &[u8; 32]) -> Arc<Hand> {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(StateKeys::open_or_init(dir.path()).unwrap());
        let id = Identity::from_seed(seed);
        let chat = dir.path().join("chat");
        let store =
            ChatStore::open(&chat, keys.clone(), id.id(), StoreSettings::default()).unwrap();
        let (outbox, _) = Outbox::open(
            &miasma_core::paths::chat_outbox_file(&chat),
            keys,
            StoreSettings::default(),
            1,
        );
        std::mem::forget(dir);
        Arc::new(Hand {
            core: Arc::new(ChatCore::new(store, outbox, id, 4096)),
            delivers: AtomicUsize::new(0),
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_beta_3_peer_keeps_receiving_while_cover_traffic_and_9_kib_cells_run() {
        let result = tokio::time::timeout(Duration::from_secs(90), async {
            let r = relay().await;

            // The current node, chat on.
            let a_seed: [u8; 32] = rand::random();
            let a_dir = tempfile::tempdir().unwrap();
            let a_node = start_node(&r, &a_seed, None).await;
            let a_contacts = Arc::new(ContactStore::open(a_dir.path()));
            let a_keys = Arc::new(StateKeys::open_or_init(a_dir.path()).unwrap());
            let a = ChatService::start(
                &a_dir.path().join("chat"),
                a_node.clone(),
                &a_seed,
                a_keys,
                a_contacts.clone(),
                StoreSettings::default(),
                fast(),
            )
            .expect("chat starts");

            // The old peer lists only the protocols of its release.
            let b_seed: [u8; 32] = rand::random();
            let b_node = start_node(&r, &b_seed, Some(vec![IROH_ALPN, PUSH_ALPN, CHAT_ALPN])).await;
            let b = hand(&b_seed);
            b_node.set_chat_handler(b.clone());
            a_contacts
                .add(&ContactCode::new(b_node.endpoint_id()), Some("bob"), None)
                .unwrap();

            // New features switched on beside it: cover cells at a high rate and
            // a stream of 9 KiB onion cells through the relay handlers.
            let covered = Arc::new(AtomicUsize::new(0));
            let cover = {
                let c = covered.clone();
                CoverTrafficEngine::start(
                    CoverTrafficConfig {
                        enabled: true,
                        rate_bytes_per_sec: 512 * 1024,
                        ..CoverTrafficConfig::default()
                    },
                    move |_| {
                        c.fetch_add(1, Ordering::SeqCst);
                    },
                )
            };
            let cells = tokio::spawn(async move {
                let relays = relays();
                let mut opened = 0usize;
                for i in 0..200usize {
                    let body = vec![i as u8; 64 + i];
                    let pkt = onion_packet(&relays, 30, &body);
                    assert_eq!(through_relays(&relays, &pkt).unwrap().1, body);
                    opened += 1;
                    tokio::task::yield_now().await;
                }
                opened
            });

            for text in ["one", "two", "three"] {
                assert!(matches!(
                    handle_with(
                        &a,
                        ChatRequest::Send {
                            contact: "bob".into(),
                            text: text.into(),
                        },
                    ),
                    ChatResponse::Queued { .. }
                ));
            }
            let end = std::time::Instant::now() + Duration::from_secs(40);
            while !a.core().outbox.is_empty() {
                assert!(
                    std::time::Instant::now() < end,
                    "the messages never arrived"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(b.delivers.load(Ordering::SeqCst) >= 3);
            let peer = b_node.endpoint_id();
            assert!(a
                .core()
                .history(&peer, None, 20)
                .iter()
                .all(|m| m.state != MsgState::Failed));

            assert_eq!(cells.await.unwrap(), 200);
            assert!(
                covered.load(Ordering::SeqCst) > 0,
                "cover cells were produced"
            );
            cover.stop().await;
        })
        .await;
        result.expect("old-peer compatibility test timed out (90s)");
    }
}
