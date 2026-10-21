//! The version-like numbers and labels of the formats, pinned on purpose.
//!
//! Ten values decide which bytes a build writes and which it accepts. Some are
//! `pub const`, some are a field set in one place, some are a private label.
//! A change to any of them is a format change; it must be deliberate and come
//! with a new fixture, not slip in with a refactor. This file lists them and
//! asserts the value in force today. The ten, by the name used in the design of
//! the next suite:
//!
//! 1. `MiasmaShare.version` (set by `MiasmaShare::new`): 1.
//! 2. The transfer manifest version and trailer: `MANIFEST_VERSION` 3, `TRAILER_MAGIC` "MNFT".
//! 3. `DirectedEnvelope.version` (set by `create_envelope`): 1.
//! 4. The `v=1` inside the MID: `DissolutionParams::to_param_bytes`.
//! 5. `DhtRecord.version`: a plain field with no constant; see the note on [`dht_record_version`].
//! 6. The share ID: `SHARE_ID_VERSION` 2, `FLAG_PROTECTED`, the prefix, the checksum context.
//! 7. `PIECE_COMMITMENT_DOMAIN` ("miasma-piece-commitment-v2"), and the formula that uses it.
//! 8. The key labels: `miasma-seg-key-v1`, `miasma-pw-check-v1`, `miasma-name-key-v1`
//!    (pinned by the known answers in `aead_known_answer_test.rs`), the sealed-name
//!    prefix, and the two directed labels (private constants in `directed/envelope.rs`;
//!    pinned by the real v1 envelope in `wire_compat_directed_test.rs`).
//! 9. `DissolutionManifest.version` (set by `dissolve_file`): 1.
//! 10. The journals: `JOURNAL_VERSION` 1 (receive) and `PUBLISH_JOURNAL_VERSION` 2.
//!
//! The Argon2id bounds and the handshake suite bits are added because they are
//! read the same way (a number a peer or an old build relies on).

use miasma_core::directed::{create_envelope, RetentionPeriod};
use miasma_core::dissolution::dissolve_file;
use miasma_core::network::types::DhtRecord;
use miasma_core::protocol::capability::{
    CAPABILITY_VERSION, KNOWN_SUITES, SUITE_CLASSICAL, SUITE_HYBRID_X25519_MLKEM768,
};
use miasma_core::share::PIECE_COMMITMENT_DOMAIN;
use miasma_core::transfer::journal::JOURNAL_VERSION;
use miasma_core::transfer::manifest::{MANIFEST_VERSION, SEALED_NAME_PREFIX, TRAILER_MAGIC};
use miasma_core::transfer::protection::{
    DEFAULT_M_KIB, DEFAULT_P_COST, DEFAULT_T_COST, KEY_CHECK_LEN, MAX_M_KIB, MAX_P_COST,
    MAX_T_COST, MIN_M_KIB, SALT_LEN,
};
use miasma_core::transfer::publish_journal::PUBLISH_JOURNAL_VERSION;
use miasma_core::transfer::share_id::{
    ShareId, ShareIdError, FLAG_PROTECTED, SHARE_ID_BYTES, SHARE_ID_PREFIX, SHARE_ID_VERSION,
};
use miasma_core::{ContentId, DissolutionParams, MiasmaShare};

const FIXTURES: &str = include_str!("fixtures/format_constants_v1/frozen.hex");

/// Deterministic test-only bytes: BLAKE3 in key-derivation mode over a label.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key("miasma format constants v1 (test-only)");
    h.update(label.as_bytes());
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

fn frozen(name: &str) -> Vec<u8> {
    for line in FIXTURES.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some((n, h)) = line.split_once(' ') {
            if n == name {
                return hex::decode(h.trim()).expect("fixture is hex");
            }
        }
    }
    panic!("no fixture {name}");
}

fn sample_mid() -> ContentId {
    ContentId::compute(
        &fill::<40>("sample"),
        &DissolutionParams::default().to_param_bytes(),
    )
}

fn sample_share() -> MiasmaShare {
    MiasmaShare::new(
        &sample_mid(),
        7,
        3,
        fill::<48>("shard").to_vec(),
        fill::<33>("key share").to_vec(),
        fill::<12>("nonce"),
        1234,
        1_700_000_000,
    )
}

#[test]
fn share_version_is_1() {
    assert_eq!(sample_share().version, 1);
}

#[test]
fn manifest_version_and_trailer_magic() {
    assert_eq!(MANIFEST_VERSION, 3);
    assert_eq!(TRAILER_MAGIC, b"MNFT");
    assert_eq!(SEALED_NAME_PREFIX, "miasma-sealed-name-v1:");
}

#[test]
fn directed_envelope_version_is_1() {
    let (envelope, _data, _key) = create_envelope(
        &fill::<32>("sender"),
        &fill::<32>("recipient"),
        &format!("Fx-{}-#9", hex::encode(fill::<12>("password"))),
        RetentionPeriod::OneDay,
        b"constants",
        None,
    )
    .unwrap();
    assert_eq!(envelope.version, 1);
}

#[test]
fn the_mid_parameter_string_carries_v1() {
    assert_eq!(
        DissolutionParams::default().to_param_bytes(),
        b"k=10,n=20,v=1"
    );
    assert_eq!(
        DissolutionParams {
            data_shards: 4,
            total_shards: 6
        }
        .to_param_bytes(),
        b"k=4,n=6,v=1"
    );
}

/// `DhtRecord.version` has no constant: each producer writes the literal `1`
/// (`network/coordinator.rs`, `daemon/replication.rs`, `daemon/mod.rs`) and no
/// reader checks it. Making a record needs a running node, so the value
/// written by a producer cannot be observed from here. What is pinned is the
/// place of the field in the bytes, so that a reader that starts to look at it
/// finds it where released builds put it: after the digest and the two shard
/// counts.
#[test]
fn dht_record_version() {
    let rec = DhtRecord {
        mid_digest: fill::<32>("digest"),
        data_shards: 4,
        total_shards: 6,
        version: 1,
        locations: vec![],
        published_at: 9,
    };
    let b = bincode::serialize(&rec).unwrap();
    assert_eq!(&b[..32], &rec.mid_digest);
    assert_eq!((b[32], b[33], b[34]), (4, 6, 1));
}

#[test]
fn share_id_version_flags_and_checksum() {
    assert_eq!(SHARE_ID_VERSION, 2);
    assert_eq!(FLAG_PROTECTED, 1);
    assert_eq!(SHARE_ID_PREFIX, "miasma-share:");
    assert_eq!(SHARE_ID_BYTES, 1 + 1 + 32 + 32 + 4);
    let mid = sample_mid();
    let publisher = fill::<32>("publisher");
    for (name, protected) in [("share_id_plain", false), ("share_id_protected", true)] {
        let id = ShareId::new(&mid, publisher, protected);
        // The bytes, with the checksum (BLAKE3 derive-key over the first 66 bytes).
        assert!(id.to_bytes().to_vec() == frozen(name), "{name}");
        let text = id.to_string();
        assert_eq!(
            text,
            format!(
                "{SHARE_ID_PREFIX}{}",
                bs58::encode(id.to_bytes()).into_string()
            )
        );
        let back = ShareId::parse(&text).unwrap();
        assert_eq!(back.protected(), protected);
        assert_eq!(back.mid_bytes(), mid.as_bytes());
    }
    // The checksum context, spelled out: the first four bytes of
    // BLAKE3_derive_key("miasma-share-id-v2 checksum")(first 66 bytes).
    let seal = |body: &[u8]| -> Vec<u8> {
        let mut h = blake3::Hasher::new_derive_key("miasma-share-id-v2 checksum");
        h.update(body);
        let mut out = body.to_vec();
        out.extend_from_slice(&h.finalize().as_bytes()[..4]);
        out
    };
    let plain = frozen("share_id_plain");
    assert_eq!(seal(&plain[..66]), plain);
    // A flipped version byte breaks the checksum, which covers it.
    let mut bytes = plain.clone();
    bytes[0] = 3;
    let text = format!("{SHARE_ID_PREFIX}{}", bs58::encode(&bytes).into_string());
    assert!(matches!(
        ShareId::parse(&text),
        Err(ShareIdError::BadChecksum)
    ));
    // A version or a flag this build does not know, with a valid checksum, is
    // refused by name ("update Miasma").
    let mut body = plain[..66].to_vec();
    body[0] = 3;
    let text = format!(
        "{SHARE_ID_PREFIX}{}",
        bs58::encode(seal(&body)).into_string()
    );
    assert!(matches!(
        ShareId::parse(&text),
        Err(ShareIdError::UnsupportedVersion(3))
    ));
    let mut body = plain[..66].to_vec();
    body[1] = 0b10;
    let text = format!(
        "{SHARE_ID_PREFIX}{}",
        bs58::encode(seal(&body)).into_string()
    );
    assert!(matches!(
        ShareId::parse(&text),
        Err(ShareIdError::UnknownFlags(0b10))
    ));
}

#[test]
fn piece_commitment_domain_and_formula() {
    assert_eq!(PIECE_COMMITMENT_DOMAIN, "miasma-piece-commitment-v2");
    // The formula, written out from the primitives:
    // BLAKE3_derive_key(domain)(version || mid || segment_le || slot_le ||
    //   original_len_le || len(shard)_le64 || shard || len(key)_le64 || key || nonce)
    let (share, mid) = (sample_share(), sample_mid());
    let mut h = blake3::Hasher::new_derive_key("miasma-piece-commitment-v2");
    h.update(&[1u8]);
    h.update(mid.as_bytes());
    h.update(&7u32.to_le_bytes());
    h.update(&3u16.to_le_bytes());
    h.update(&1234u32.to_le_bytes());
    h.update(&(share.shard_data.len() as u64).to_le_bytes());
    h.update(&share.shard_data);
    h.update(&(share.key_share.len() as u64).to_le_bytes());
    h.update(&share.key_share);
    h.update(&share.nonce);
    assert_eq!(share.piece_commitment(&mid), *h.finalize().as_bytes());
    // The share's version is part of it: a share that claims another version
    // gets another commitment.
    let mut other = share.clone();
    other.version = 2;
    assert_ne!(other.piece_commitment(&mid), share.piece_commitment(&mid));
}

#[test]
fn dissolution_manifest_version_is_1() {
    let (manifest, _shares) = dissolve_file(
        &fill::<50>("file"),
        DissolutionParams {
            data_shards: 2,
            total_shards: 3,
        },
        32,
    )
    .unwrap();
    assert_eq!(manifest.version, 1);
}

#[test]
fn journal_versions() {
    assert_eq!(JOURNAL_VERSION, 1);
    assert_eq!(PUBLISH_JOURNAL_VERSION, 2);
}

#[test]
fn argon2_bounds_and_lengths() {
    assert_eq!(
        (DEFAULT_M_KIB, DEFAULT_T_COST, DEFAULT_P_COST),
        (65536, 3, 1)
    );
    assert_eq!((MAX_M_KIB, MAX_T_COST, MAX_P_COST), (131072, 6, 2));
    assert_eq!(MIN_M_KIB, 8);
    assert_eq!((SALT_LEN, KEY_CHECK_LEN), (16, 16));
}

#[test]
fn handshake_suite_bits_are_not_object_suites() {
    // A different namespace from the object formats above: bits of the chat
    // handshake negotiation. Pinned so the two are not confused.
    assert_eq!(CAPABILITY_VERSION, 1);
    assert_eq!(SUITE_CLASSICAL, 1);
    assert_eq!(SUITE_HYBRID_X25519_MLKEM768, 2);
    assert_eq!(KNOWN_SUITES, 3);
}

/// Prints `frozen.hex`. Run with
/// `cargo test --test format_constants_test print_fixtures -- --ignored --nocapture`.
#[test]
#[ignore = "prints the fixture file; run by hand, once"]
fn print_fixtures() {
    let (mid, publisher) = (sample_mid(), fill::<32>("publisher"));
    for (name, protected) in [("share_id_plain", false), ("share_id_protected", true)] {
        println!(
            "FIXTURE {name} {}",
            hex::encode(ShareId::new(&mid, publisher, protected).to_bytes())
        );
    }
}
