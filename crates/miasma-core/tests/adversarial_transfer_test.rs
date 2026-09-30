//! Regression tests for the transfer-layer findings of the 2026-09 adversarial
//! review (unbounded record counts; piece commitment not covering the key
//! material; Argon2 ceiling). Each test drives the real dissolve -> manifest ->
//! `run_receive` path with a hostile source and asserts that the attack now
//! FAILS: the transfer completes from a spare holder, or the input is refused
//! quickly with a typed error.
//!
//! No test carries a fixed secret: passwords and nonces are generated at run time.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use miasma_core::{
    dissolution::segment::dissolve_segment_with,
    network::types::{DhtRecord, ShardLocation, MAX_RECORD_LOCATIONS, MAX_SEGMENTS},
    transfer::{
        decode_record_value, encode_record_value,
        manifest::{MANIFEST_VERSION, MAX_SEGMENT_SIZE},
        protection::{MAX_M_KIB, MAX_P_COST, MAX_T_COST},
        run_receive, PasswordProtection, PieceSource, Protection, ReceiveOutcome, ReceiveSpec,
        RetryConfig, SegmentEntry, TransferManifest, TransferProgress,
    },
    ContentId, DissolutionParams, MiasmaError, MiasmaShare, ShareVerification,
};

const SEG: usize = 1024;

fn random_password() -> String {
    format!("pw-{:032x}", rand::random::<u128>())
}

fn content(len: usize) -> Vec<u8> {
    let mut x: u32 = rand::random::<u32>() | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

struct World {
    data: Vec<u8>,
    mid: ContentId,
    record: DhtRecord,
    manifest: TransferManifest,
    shares: HashMap<(u32, u16), MiasmaShare>,
}

fn build_world(len: usize, k: usize, n: usize, password: Option<&str>) -> World {
    let data = content(len);
    let params = DissolutionParams {
        data_shards: k,
        total_shards: n,
    };
    let mid = ContentId::compute(&data, &params.to_param_bytes());
    let (protection, key) = match password {
        Some(pw) => {
            let (p, key) = PasswordProtection::create_with_cost(pw, 64, 1, 1).unwrap();
            (Protection::Password(p), Some(key))
        }
        None => (Protection::None, None),
    };
    let mut manifest = TransferManifest::new(&mid, params, SEG as u32, len as u64, protection);
    let mut shares = HashMap::new();
    let mut locations = Vec::new();
    for (i, chunk) in data.chunks(SEG).enumerate() {
        let (_, seg_shares) =
            dissolve_segment_with(chunk, &mid, i as u32, 0, params, key.as_ref()).unwrap();
        manifest
            .push_segment(SegmentEntry::from_dissolved(i as u32, &mid, chunk, &seg_shares).unwrap())
            .unwrap();
        for s in seg_shares {
            locations.push(ShardLocation {
                peer_id_bytes: vec![s.slot_index as u8],
                shard_index: s.slot_index,
                segment_index: i as u32,
                addrs: vec![],
            });
            shares.insert((i as u32, s.slot_index), s);
        }
    }
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: k as u8,
        total_shards: n as u8,
        version: 1,
        locations,
        published_at: 1,
    };
    World {
        data,
        mid,
        record,
        manifest,
        shares,
    }
}

/// Serves honest shares except for one designated `(segment, slot)`, altered by
/// `tamper`. Records every fetch.
struct Hostile {
    shares: HashMap<(u32, u16), MiasmaShare>,
    target: (u32, u16),
    tamper: fn(&mut MiasmaShare),
    log: Mutex<Vec<(u32, u16)>>,
}

impl Hostile {
    fn new(w: &World, target: (u32, u16), tamper: fn(&mut MiasmaShare)) -> Self {
        Self {
            shares: w.shares.clone(),
            target,
            tamper,
            log: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl PieceSource for Hostile {
    async fn fetch_piece(
        &self,
        _mid: &ContentId,
        segment: u32,
        slot: u16,
        _holder: &ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        self.log.lock().unwrap().push((segment, slot));
        let Some(share) = self.shares.get(&(segment, slot)) else {
            return Ok(None);
        };
        let mut share = share.clone();
        if (segment, slot) == self.target {
            (self.tamper)(&mut share);
        }
        Ok(Some(share))
    }
}

fn spec(w: &World, dir: &tempfile::TempDir, with_manifest: bool, pw: Option<&str>) -> ReceiveSpec {
    ReceiveSpec {
        mid: w.mid.clone(),
        record: w.record.clone(),
        manifest: with_manifest.then(|| w.manifest.clone()),
        password: pw.map(|p| zeroize::Zeroizing::new(p.to_string())),
        output_path: dir.path().join("out").join("file.bin"),
        journal_dir: dir.path().join("transfers"),
        restart: false,
        retry: RetryConfig {
            max_attempts_per_segment: 2,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
        },
    }
}

fn flip_key_share(s: &mut MiasmaShare) {
    s.key_share[0] ^= 0xFF;
}
fn flip_nonce(s: &mut MiasmaShare) {
    s.nonce[0] ^= 0xFF;
}
fn flip_original_len(s: &mut MiasmaShare) {
    s.original_len ^= 1;
}

/// The attack of C-07: a holder alters key material but leaves the ciphertext
/// (and so `shard_hash`) intact. It must now be refused at piece verification and
/// the transfer must finish from a spare slot.
async fn poisoned_piece_is_refused_and_a_spare_is_used(
    tamper: fn(&mut MiasmaShare),
    password: Option<&str>,
) {
    let w = build_world(4 * SEG, 4, 6, password);
    let attacker = Hostile::new(&w, (2, 0), tamper);
    let dir = tempfile::tempdir().unwrap();
    let progress = TransferProgress::new(w.mid.to_string());
    let outcome = run_receive(&attacker, spec(&w, &dir, true, password), progress.clone())
        .await
        .expect("one hostile holder per segment must not kill the transfer");
    assert!(
        matches!(outcome, ReceiveOutcome::Complete { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("out").join("file.bin")).unwrap(),
        w.data
    );
    assert!(
        progress.snapshot().pieces_rejected >= 1,
        "the tampered piece must have been rejected on arrival"
    );
    let log = attacker.log.lock().unwrap();
    assert!(log.contains(&(2, 0)), "the poisoned piece was served");
    assert!(
        log.contains(&(2, 4)),
        "the spare slot must have been fetched instead: {log:?}"
    );
}

#[tokio::test]
async fn tampered_key_share_is_rejected_and_a_spare_holder_completes_the_transfer() {
    poisoned_piece_is_refused_and_a_spare_is_used(flip_key_share, None).await;
}

#[tokio::test]
async fn tampered_nonce_is_rejected_and_a_spare_holder_completes_a_protected_transfer() {
    let pw = random_password();
    poisoned_piece_is_refused_and_a_spare_is_used(flip_nonce, Some(&pw)).await;
}

#[tokio::test]
async fn tampered_original_len_is_rejected_and_a_spare_holder_completes_the_transfer() {
    poisoned_piece_is_refused_and_a_spare_is_used(flip_original_len, None).await;
}

#[test]
fn piece_commitment_covers_every_security_relevant_field() {
    let w = build_world(SEG, 4, 6, None);
    let good = w.shares[&(0, 1)].clone();
    let expected = *w.manifest.expected_piece(0, 1).unwrap();
    assert!(ShareVerification::verify_piece(&good, &w.mid, &expected));

    let mut cases: Vec<(&str, MiasmaShare)> = Vec::new();
    let mut s = good.clone();
    s.key_share[0] ^= 1;
    cases.push(("key_share", s));
    let mut s = good.clone();
    s.nonce[3] ^= 1;
    cases.push(("nonce", s));
    let mut s = good.clone();
    s.original_len += 1;
    cases.push(("original_len", s));
    let mut s = good.clone();
    s.shard_data[0] ^= 1;
    s.shard_hash = *blake3::hash(&s.shard_data).as_bytes(); // hash kept consistent
    cases.push(("shard_data", s));
    let mut s = good.clone();
    s.slot_index += 1;
    cases.push(("slot_index", s));
    let mut s = good.clone();
    s.segment_index += 1;
    cases.push(("segment_index", s));
    let mut s = good.clone();
    s.version = s.version.wrapping_add(1);
    cases.push(("version", s));
    for (field, s) in cases {
        assert!(
            !ShareVerification::verify_piece(&s, &w.mid, &expected),
            "a change in {field} must break the commitment"
        );
    }
    // Same share, other MID: also a different commitment.
    let other = ContentId::compute(b"another file", b"k=4,n=6,v=1");
    assert_ne!(good.piece_commitment(&w.mid), good.piece_commitment(&other));
}

/// Resilience (part b): without a manifest there is nothing to check pieces
/// against, so a poisoned key share is *accepted*; the decode then fails and the
/// receiver must try other pieces instead of giving up.
#[tokio::test]
async fn legacy_record_with_a_poisoned_key_share_recovers_from_spare_pieces() {
    let w = build_world(3 * SEG, 4, 6, None);
    let attacker = Hostile::new(&w, (1, 0), flip_key_share);
    let dir = tempfile::tempdir().unwrap();
    let outcome = run_receive(
        &attacker,
        spec(&w, &dir, false, None),
        TransferProgress::new(w.mid.to_string()),
    )
    .await
    .expect("a bad piece among the first k must not fail the transfer");
    assert!(
        matches!(outcome, ReceiveOutcome::Complete { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("out").join("file.bin")).unwrap(),
        w.data
    );
}

#[tokio::test]
async fn recovery_is_bounded_when_too_many_pieces_are_bad() {
    // k = n: there is no spare, so the decode error is reported, not looped on.
    let w = build_world(SEG, 3, 3, None);
    let attacker = Hostile::new(&w, (0, 0), flip_key_share);
    let dir = tempfile::tempdir().unwrap();
    let r = run_receive(
        &attacker,
        spec(&w, &dir, false, None),
        TransferProgress::new(w.mid.to_string()),
    )
    .await;
    assert!(r.is_err(), "no spare exists: {r:?}");
    assert!(!dir.path().join("out").join("file.bin").exists());
}

// ── C-02: a record must not size an allocation ─────────────────────────────

struct Nothing;
#[async_trait]
impl PieceSource for Nothing {
    async fn fetch_piece(
        &self,
        _m: &ContentId,
        _s: u32,
        _slot: u16,
        _h: &ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        Ok(None)
    }
}

fn hostile_record(mid: &ContentId, seg: u32) -> DhtRecord {
    DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: 1,
        total_shards: 1,
        version: 1,
        locations: vec![ShardLocation {
            peer_id_bytes: vec![1],
            shard_index: 0,
            segment_index: seg,
            addrs: vec![],
        }],
        published_at: 1,
    }
}

async fn receive_record(
    record: DhtRecord,
    mid: ContentId,
) -> (Result<ReceiveOutcome, MiasmaError>, Duration) {
    let tmp = tempfile::tempdir().unwrap();
    let t = Instant::now();
    let r = run_receive(
        &Nothing,
        ReceiveSpec {
            mid: mid.clone(),
            record,
            manifest: None,
            password: None,
            output_path: tmp.path().join("out.bin"),
            journal_dir: tmp.path().join("j"),
            restart: false,
            retry: RetryConfig {
                max_attempts_per_segment: 1,
                base_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
        },
        TransferProgress::new(mid.to_string()),
    )
    .await;
    (r, t.elapsed())
}

#[tokio::test]
async fn hostile_segment_indexes_are_rejected_quickly_without_a_huge_allocation() {
    let params = DissolutionParams {
        data_shards: 1,
        total_shards: 1,
    };
    let mid = ContentId::compute(b"x", &params.to_param_bytes());
    // u32::MAX-1 used to request ~103 GB and abort the process; u32::MAX used to
    // overflow; 10_000_000 used to build a table of hundreds of MB.
    for seg in [u32::MAX - 1, u32::MAX, 10_000_000, MAX_SEGMENTS] {
        let (r, dt) = receive_record(hostile_record(&mid, seg), mid.clone()).await;
        assert!(
            matches!(r, Err(MiasmaError::InvalidManifest(_))),
            "segment {seg}: {r:?}"
        );
        assert!(dt < Duration::from_secs(2), "segment {seg} took {dt:?}");
    }
}

#[tokio::test]
async fn the_highest_legal_segment_index_is_still_accepted_as_a_record() {
    let record = hostile_record(&ContentId::compute(b"x", b"p"), MAX_SEGMENTS - 1);
    record.validate().unwrap();
}

#[test]
fn malformed_records_are_rejected_by_validation() {
    let mid = ContentId::compute(b"x", b"p");
    let ok = hostile_record(&mid, 0);
    ok.validate().unwrap();

    let mut r = ok.clone();
    r.data_shards = 0;
    assert!(r.validate().is_err(), "k = 0");

    let mut r = ok.clone();
    r.data_shards = 3;
    r.total_shards = 2;
    assert!(r.validate().is_err(), "k > n");

    let mut r = ok.clone();
    r.locations[0].shard_index = 1; // n = 1, so slot 1 does not exist
    assert!(r.validate().is_err(), "slot >= n");

    let mut r = ok.clone();
    r.locations[0].addrs = vec!["a".into(); 1000];
    assert!(r.validate().is_err(), "too many addrs");

    let mut r = ok.clone();
    r.locations[0].addrs = vec!["x".repeat(100_000)];
    assert!(r.validate().is_err(), "oversized addr");

    let mut r = ok.clone();
    r.locations = vec![r.locations[0].clone(); MAX_RECORD_LOCATIONS + 1];
    assert!(r.validate().is_err(), "too many locations");
    // Never publish what receivers refuse.
    assert!(encode_record_value(&r, None).is_err());
}

// ── manifest versioning ────────────────────────────────────────────────────

#[test]
fn a_version_1_manifest_is_refused_with_a_clear_error() {
    let w = build_world(2 * SEG, 4, 6, None);
    assert_eq!(w.manifest.version, MANIFEST_VERSION);
    let mut value = encode_record_value(&w.record, Some(&w.manifest)).unwrap();
    let pos = value
        .windows(4)
        .position(|b| b == b"MNFT")
        .expect("trailer present");
    assert_eq!(value[pos + 4], MANIFEST_VERSION);
    value[pos + 4] = 1; // what an old publisher wrote
    match decode_record_value(&value) {
        Err(MiasmaError::InvalidManifest(m)) => {
            assert!(m.contains("no longer supported"), "message: {m}");
            assert!(m.contains("publish the file again"), "message: {m}");
        }
        other => panic!("a v1 manifest must be refused, got {other:?}"),
    }

    let mut m = w.manifest.clone();
    m.version = 1;
    assert!(matches!(m.validate(), Err(MiasmaError::InvalidManifest(_))));
}

#[test]
fn manifest_segment_size_and_count_are_bounded() {
    let w = build_world(2 * SEG, 4, 6, None);
    let mut m = w.manifest.clone();
    m.segment_size = MAX_SEGMENT_SIZE + 1;
    assert!(m.validate().is_err(), "segment_size above the limit");
    m.segment_size = u32::MAX;
    assert!(m.validate().is_err(), "segment_size = u32::MAX");
}

#[tokio::test]
async fn an_unchecked_original_len_cannot_size_the_decode_buffer() {
    // No manifest: every piece claims a 4 GiB segment. The pieces are refused
    // (transfer pauses) instead of a 4 GiB buffer being allocated.
    let w = build_world(SEG, 4, 6, None);
    struct Liar(HashMap<(u32, u16), MiasmaShare>);
    #[async_trait]
    impl PieceSource for Liar {
        async fn fetch_piece(
            &self,
            _m: &ContentId,
            s: u32,
            slot: u16,
            _h: &ShardLocation,
        ) -> Result<Option<MiasmaShare>, MiasmaError> {
            Ok(self.0.get(&(s, slot)).map(|sh| {
                let mut sh = sh.clone();
                sh.original_len = u32::MAX;
                sh
            }))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let t = Instant::now();
    let outcome = run_receive(
        &Liar(w.shares.clone()),
        spec(&w, &dir, false, None),
        TransferProgress::new(w.mid.to_string()),
    )
    .await
    .unwrap();
    assert!(
        matches!(outcome, ReceiveOutcome::Paused { .. }),
        "{outcome:?}"
    );
    assert!(t.elapsed() < Duration::from_secs(5));
}

// ── S-a: Argon2 ceiling ────────────────────────────────────────────────────

#[test]
fn argon2_cost_above_the_cap_is_rejected_before_any_kdf_work() {
    let pw = random_password();
    let (prot, _) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();

    // Each of these would take seconds and up to 256 MiB in a debug build if
    // the KDF ran; validation must answer at once.
    let cases: [(u32, u32, u32); 4] = [
        (MAX_M_KIB + 1, 1, 1),
        (256 * 1024, 10, 4), // the previous ceiling
        (64, MAX_T_COST + 1, 1),
        (64, 1, MAX_P_COST + 1),
    ];
    for (m, t, p) in cases {
        let mut hostile = prot.clone();
        hostile.m_kib = m;
        hostile.t_cost = t;
        hostile.p_cost = p;
        let start = Instant::now();
        assert!(
            matches!(hostile.unlock(&pw), Err(MiasmaError::InvalidManifest(_))),
            "m={m} t={t} p={p} must be refused"
        );
        assert!(
            start.elapsed() < Duration::from_millis(250),
            "m={m} t={t} p={p}: refusal must precede KDF work ({:?})",
            start.elapsed()
        );
    }

    // And through a whole manifest.
    let w = build_world(SEG, 4, 6, Some(&pw));
    let mut m = w.manifest.clone();
    if let Protection::Password(p) = &mut m.protection {
        p.m_kib = 256 * 1024;
    }
    assert!(m.validate().is_err());
}

// The ceiling must not exceed 128 MiB and must stay above what `create` produces
// (compile-time guards).
const _: () = {
    use miasma_core::transfer::protection::{DEFAULT_M_KIB, DEFAULT_P_COST, DEFAULT_T_COST};
    assert!(MAX_M_KIB <= 128 * 1024);
    assert!(DEFAULT_M_KIB <= MAX_M_KIB);
    assert!(DEFAULT_T_COST <= MAX_T_COST);
    assert!(DEFAULT_P_COST <= MAX_P_COST);
};
