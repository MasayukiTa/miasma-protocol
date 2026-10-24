//! WP-A4 reader: the manifest-version split.
//!
//! WP-A3 froze the Suite2 segment format (`core::format`). WP-A4 is the reader
//! that accepts it at the manifest layer without disturbing the v3 bytes a
//! shipped build writes and reads. These tests pin that reader:
//!
//! * a v3 trailer still decodes exactly as before, through both the unchanged
//!   `decode_record_value` and the new `decode_record_value_any`;
//! * a v4 trailer is accepted by `decode_record_value_any` and reports its
//!   suite, while the unchanged `decode_record_value` -- the stand-in for a
//!   build or a copied decoder that predates v4 -- refuses it with the
//!   "update Miasma" message, never a silent downgrade;
//! * a record with no trailer is a legacy record on both readers;
//! * the manifest version and the share version agree: a v4 manifest names the
//!   Suite2 share version, a v3 manifest the Suite1 one;
//! * a v4 manifest that is internally inconsistent, over-long in its extension
//!   area, or names an unknown suite is refused.
//!
//! No key, nonce or plaintext is a literal: each is derived with BLAKE3 in
//! key-derivation mode from a label, as the other suite tests do. This is a
//! behaviour test against live code, not a frozen-byte fixture: a new frozen
//! file (manifest v4 bytes) belongs with the v4 *writer*, which is out of
//! scope here.

use ed25519_dalek::SigningKey;
use miasma_core::dissolution::segment::dissolve_segment_at;
use miasma_core::format::ObjectSuite;
use miasma_core::network::sybil::SignedDhtRecord;
use miasma_core::network::types::DhtRecord;
use miasma_core::transfer::manifest::{
    decode_record_value, decode_record_value_any, encode_record_value, DecodedManifest, ManifestV4,
    SegmentEntry, TransferManifest, MANIFEST_VERSION_V4,
};
use miasma_core::transfer::protection::Protection;
use miasma_core::{ContentId, DissolutionParams, MiasmaError, MiasmaShare};

const TS: u64 = 1_700_000_000;
const SEG_SIZE: u32 = 64;
const TOTAL_BYTES: usize = 100;

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 4,
        total_shards: 6,
    }
}

/// Deterministic test-only bytes: BLAKE3 in key-derivation mode over a label.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key("miasma wp-a4 manifest reader (test-only)");
    h.update(label.as_bytes());
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

fn plaintext() -> [u8; TOTAL_BYTES] {
    fill("reader plaintext")
}

fn mid() -> ContentId {
    ContentId::compute(&plaintext(), &params().to_param_bytes())
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&fill::<32>("publisher seed"))
}

fn publisher() -> [u8; 32] {
    signing_key().verifying_key().to_bytes()
}

fn segment_bounds(s: usize) -> (usize, usize) {
    if s == 0 {
        (0, SEG_SIZE as usize)
    } else {
        (SEG_SIZE as usize, TOTAL_BYTES)
    }
}

/// Two segments of real shares for the test plaintext.
fn segments() -> Vec<Vec<MiasmaShare>> {
    let m = mid();
    let plain = plaintext();
    (0..2u32)
        .map(|s| {
            let (a, b) = segment_bounds(s as usize);
            let (_, shares) =
                dissolve_segment_at(&plain[a..b], &m, s, a as u64, params(), TS).unwrap();
            shares
        })
        .collect()
}

/// A valid v3 manifest over those shares.
fn v3_manifest(segs: &[Vec<MiasmaShare>]) -> TransferManifest {
    let m = mid();
    let plain = plaintext();
    let mut man = TransferManifest::new(
        &m,
        publisher(),
        params(),
        SEG_SIZE,
        TOTAL_BYTES as u64,
        Protection::None,
    );
    for (i, shares) in segs.iter().enumerate() {
        let (a, b) = segment_bounds(i);
        man.push_segment(SegmentEntry::from_dissolved(i as u32, &m, &plain[a..b], shares).unwrap())
            .unwrap();
    }
    man
}

/// A valid v4 manifest with the same structure, naming Suite2.
fn v4_manifest(segs: &[Vec<MiasmaShare>]) -> ManifestV4 {
    let v3 = v3_manifest(segs);
    ManifestV4 {
        version: MANIFEST_VERSION_V4,
        mid: *mid().as_bytes(),
        publisher: publisher(),
        name: Some("report.txt".into()),
        data_shards: v3.data_shards,
        total_shards: v3.total_shards,
        segment_size: v3.segment_size,
        total_bytes: v3.total_bytes,
        protection: Protection::None,
        segments: v3.segments.clone(),
        suite: ObjectSuite::Suite2.id(),
        ext: Vec::new(),
    }
}

fn record() -> DhtRecord {
    DhtRecord {
        mid_digest: *mid().as_bytes(),
        data_shards: 4,
        total_shards: 6,
        version: 1,
        locations: vec![],
        published_at: TS,
    }
}

/// A record value carrying a v4 trailer: the record bytes then the v4 trailer.
fn v4_record_value() -> Vec<u8> {
    let rec = record();
    let mut value = bincode::serialize(&rec).unwrap();
    value.extend_from_slice(&v4_manifest(&segments()).encode_trailer().unwrap());
    value
}

// ── v3 still decodes, through both readers ───────────────────────────────────

#[test]
fn a_v3_trailer_decodes_the_same_on_both_readers() {
    let segs = segments();
    let m = v3_manifest(&segs);
    let value = encode_record_value(&record(), Some(&m)).unwrap();

    // The unchanged v3 reader.
    let (r1, m1) = decode_record_value(&value).unwrap();
    assert_eq!(r1.mid_digest, *mid().as_bytes());
    assert_eq!(m1.unwrap().to_bytes().unwrap(), m.to_bytes().unwrap());

    // The version-accepting reader returns the same manifest, tagged V3.
    let (r2, m2) = decode_record_value_any(&value).unwrap();
    assert_eq!(r2.mid_digest, *mid().as_bytes());
    match m2 {
        Some(DecodedManifest::V3(back)) => {
            assert_eq!(back.to_bytes().unwrap(), m.to_bytes().unwrap());
        }
        other => panic!("expected a V3 manifest, got {other:?}"),
    }
}

#[test]
fn a_v3_manifest_names_the_suite1_share_version() {
    let segs = segments();
    let value = encode_record_value(&record(), Some(&v3_manifest(&segs))).unwrap();
    let (_, m) = decode_record_value_any(&value).unwrap();
    let m = m.unwrap();
    assert_eq!(m.object_suite().unwrap(), ObjectSuite::Suite1);
    assert_eq!(m.expected_share_version(), 1);
    // Every real share of a v3 transfer is version 1.
    for shares in &segs {
        for s in shares {
            assert_eq!(s.version, m.expected_share_version());
        }
    }
}

// ── v4 is accepted by the new reader, refused by the old one ─────────────────

#[test]
fn a_v4_trailer_is_accepted_by_the_version_accepting_reader() {
    let value = v4_record_value();
    let (rec, m) = decode_record_value_any(&value).unwrap();
    assert_eq!(rec.mid_digest, *mid().as_bytes());
    match m {
        Some(DecodedManifest::V4(v4)) => {
            assert_eq!(v4.version, MANIFEST_VERSION_V4);
            assert_eq!(v4.object_suite().unwrap(), ObjectSuite::Suite2);
            assert_eq!(v4.publisher, publisher());
            assert_eq!(v4.name.as_deref(), Some("report.txt"));
        }
        other => panic!("expected a V4 manifest, got {other:?}"),
    }
}

#[test]
fn a_v4_manifest_names_the_suite2_share_version() {
    let value = v4_record_value();
    let (_, m) = decode_record_value_any(&value).unwrap();
    let m = m.unwrap();
    assert_eq!(m.object_suite().unwrap(), ObjectSuite::Suite2);
    assert_eq!(m.expected_share_version(), 2);
    assert_eq!(
        m.expected_share_version(),
        ObjectSuite::Suite2.spec().share_version
    );
}

#[test]
fn a_v4_record_through_the_old_decoder_is_the_update_miasma_error() {
    // `decode_record_value` is the stand-in for a build (or a copied decoder)
    // that predates v4: it must refuse a v4 trailer with the "update Miasma"
    // message, not read it and not silently drop the trailer.
    let value = v4_record_value();
    match decode_record_value(&value) {
        Err(MiasmaError::InvalidManifest(msg)) => {
            assert!(msg.contains("update Miasma"), "{msg}");
            assert!(msg.contains("newer than this build supports"), "{msg}");
        }
        other => panic!("expected an update-Miasma error, got {other:?}"),
    }
}

#[test]
fn the_signed_v4_envelope_is_not_a_silent_downgrade_on_the_old_reader() {
    // Signing the value and opening it does not change the outcome: the old
    // reader still refuses the v4 trailer rather than treating it as a legacy
    // record with no manifest.
    let value = v4_record_value();
    let signed = SignedDhtRecord::sign(record().dht_key(), value.clone(), &signing_key());
    let bytes = bincode::serialize(&signed).unwrap();
    let signed_back: SignedDhtRecord = bincode::deserialize(&bytes).unwrap();
    assert!(decode_record_value(&signed_back.value).is_err());
    // But the v4-accepting reader reads it.
    assert!(decode_record_value_any(&signed_back.value).is_ok());
}

// ── the no-trailer (legacy) path splits by version correctly ─────────────────

#[test]
fn a_record_with_no_trailer_is_a_legacy_record_on_both_readers() {
    let value = bincode::serialize(&record()).unwrap();
    let (r1, m1) = decode_record_value(&value).unwrap();
    assert_eq!(r1.mid_digest, *mid().as_bytes());
    assert!(m1.is_none());
    let (r2, m2) = decode_record_value_any(&value).unwrap();
    assert_eq!(r2.mid_digest, *mid().as_bytes());
    assert!(m2.is_none());
}

// ── a malformed or inconsistent v4 manifest is refused ───────────────────────

#[test]
fn an_unknown_trailer_version_is_refused_by_the_new_reader_too() {
    let mut value = v4_record_value();
    let rec_len = bincode::serialize(&record()).unwrap().len();
    value[rec_len + 4] = 9; // neither 3 nor 4
    match decode_record_value_any(&value) {
        Err(MiasmaError::InvalidManifest(msg)) => {
            assert!(msg.contains("update Miasma"), "{msg}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_v4_manifest_for_a_different_mid_is_refused() {
    let mut other = record();
    other.mid_digest = [0xEE; 32];
    let mut value = bincode::serialize(&other).unwrap();
    value.extend_from_slice(&v4_manifest(&segments()).encode_trailer().unwrap());
    assert!(decode_record_value_any(&value).is_err());
}

#[test]
fn an_inconsistent_v4_manifest_fails_validation() {
    let segs = segments();

    let mut m = v4_manifest(&segs);
    m.total_bytes += 1;
    assert!(m.validate().is_err(), "total_bytes must match the segments");

    let mut m = v4_manifest(&segs);
    m.version = 3;
    assert!(m.validate().is_err(), "a v4 value must carry version 4");

    let mut m = v4_manifest(&segs);
    m.suite = ObjectSuite::Suite1.id();
    assert!(
        m.validate().is_err(),
        "a v4 manifest may not name the Suite1 object format"
    );

    let mut m = v4_manifest(&segs);
    m.suite = 9;
    assert!(m.validate().is_err(), "an unknown suite is refused");

    let mut m = v4_manifest(&segs);
    m.ext = vec![0u8; 10_000];
    assert!(m.validate().is_err(), "an over-long ext area is refused");
}

#[test]
fn a_v4_manifest_round_trips_through_its_own_bytes() {
    let m = v4_manifest(&segments());
    let bytes = m.to_bytes().unwrap();
    assert_eq!(ManifestV4::from_bytes(&bytes).unwrap(), m);
    assert_eq!(bytes[0], MANIFEST_VERSION_V4, "a v4 manifest starts with 4");
    // The trailer frames it with a version-4 byte.
    let trailer = m.encode_trailer().unwrap();
    assert_eq!(&trailer[..4], b"MNFT");
    assert_eq!(trailer[4], MANIFEST_VERSION_V4);
}

// ── a version-2 share carries the Suite2 version its manifest expects ─────────

#[test]
fn a_version_2_share_matches_the_v4_manifest_share_version() {
    // `new_v2` is the only way a version-2 share is built in R1 (the writer is
    // unchanged). Its version is what a v4 manifest expects.
    let m = mid();
    let s = MiasmaShare::new_v2(
        &m,
        0,
        0,
        vec![1, 2, 3],
        vec![4, 5, 6],
        fill::<12>("nonce"),
        3,
        TS,
    );
    assert_eq!(s.version, 2);
    let value = v4_record_value();
    let (_, man) = decode_record_value_any(&value).unwrap();
    assert_eq!(s.version, man.unwrap().expected_share_version());
}
