//! Receive-side acceptance of version-4 transfer records.
//!
//! WP-A4 taught the manifest layer to decode a v4 trailer
//! (`decode_record_value_any`) without disturbing the v3 bytes. This file pins
//! the next step: the production receive entry point, `open_signed_record`, now
//! calls the v4-accepting decoder, so a signed envelope carrying a v4 trailer is
//! taken apart and returned rather than refused. It checks that:
//!
//! * a v4 record round-trips through `open_signed_record` (with and without a
//!   required signer), the decoded manifest is tagged V4 and reports Suite2,
//!   and the v3-only `manifest` view is `None` for it;
//! * a v3 record is unchanged: `open_signed_record` still returns it with the
//!   same `TransferManifest` in the `manifest` field, byte for byte;
//! * a hostile v4 record is refused without a panic -- a v4 trailer whose MID
//!   does not match its record, and one whose manifest names a different
//!   publisher than the key that signed the envelope;
//! * a truncated v4 trailer is refused without a panic;
//! * the record size limit still applies: a value whose record header declares a
//!   length far larger than the bytes present is refused, not buffered.
//!
//! No key, nonce or plaintext is a literal: each is derived with BLAKE3 in
//! key-derivation mode from a label, as the other suite tests do. This is a
//! behaviour test against live code, not a frozen-byte fixture.

use ed25519_dalek::SigningKey;
use miasma_core::dissolution::segment::dissolve_segment_at;
use miasma_core::format::ObjectSuite;
use miasma_core::network::sybil::SignedDhtRecord;
use miasma_core::network::types::DhtRecord;
use miasma_core::transfer::manifest::{
    encode_record_value, DecodedManifest, ManifestV4, SegmentEntry, TransferManifest,
    MANIFEST_VERSION_V4,
};
use miasma_core::transfer::protection::Protection;
use miasma_core::transfer::{open_signed_record, SignedRecordError};
use miasma_core::{ContentId, DissolutionParams, MiasmaShare};

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
    let mut h = blake3::Hasher::new_derive_key("miasma receive-v4 records (test-only)");
    h.update(label.as_bytes());
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

fn plaintext() -> [u8; TOTAL_BYTES] {
    fill("receive plaintext")
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

/// A valid v4 manifest with the same structure, naming Suite2, published by
/// `pubkey`.
fn v4_manifest_by(segs: &[Vec<MiasmaShare>], pubkey: [u8; 32]) -> ManifestV4 {
    let v3 = v3_manifest(segs);
    ManifestV4 {
        version: MANIFEST_VERSION_V4,
        mid: *mid().as_bytes(),
        publisher: pubkey,
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

/// A record value carrying a v4 trailer whose manifest is published by `pubkey`.
fn v4_record_value_by(pubkey: [u8; 32]) -> Vec<u8> {
    let mut value = bincode::serialize(&record()).unwrap();
    value.extend_from_slice(
        &v4_manifest_by(&segments(), pubkey)
            .encode_trailer()
            .unwrap(),
    );
    value
}

/// A v4 record value whose manifest names the signing key as its publisher.
fn v4_record_value() -> Vec<u8> {
    v4_record_value_by(publisher())
}

/// Sign `value` under the publisher key, keyed to the record's own DHT key, and
/// serialize the envelope exactly as a node stores and serves it.
fn signed_envelope(value: &[u8]) -> Vec<u8> {
    let signed = SignedDhtRecord::sign(record().dht_key(), value.to_vec(), &signing_key());
    bincode::serialize(&signed).unwrap()
}

// ── a v4 record round-trips through the receive entry point ──────────────────

#[test]
fn a_v4_record_opens_through_open_signed_record() {
    let key = record().dht_key();
    let envelope = signed_envelope(&v4_record_value());

    // With the signer required (the DHT and direct paths both pass it).
    let opened = open_signed_record(&key, &envelope, Some(&publisher())).unwrap();
    assert_eq!(opened.signer, publisher());
    assert_eq!(opened.record.mid_digest, *mid().as_bytes());
    // The v3-only view is None for a v4 manifest; the decoded manifest carries it.
    assert!(opened.manifest.is_none());
    match opened.decoded {
        Some(DecodedManifest::V4(v4)) => {
            assert_eq!(v4.version, MANIFEST_VERSION_V4);
            assert_eq!(v4.object_suite().unwrap(), ObjectSuite::Suite2);
            assert_eq!(v4.object_suite().unwrap().spec().share_version, 2);
        }
        other => panic!("expected a V4 manifest, got {other:?}"),
    }

    // Without a required signer: still opens, still V4.
    let opened = open_signed_record(&key, &envelope, None).unwrap();
    assert!(opened.manifest.is_none());
    assert!(matches!(opened.decoded, Some(DecodedManifest::V4(_))));
}

// ── a v3 record is unchanged by the switch ───────────────────────────────────

#[test]
fn a_v3_record_opens_exactly_as_before() {
    let key = record().dht_key();
    let segs = segments();
    let man = v3_manifest(&segs);
    let value = encode_record_value(&record(), Some(&man)).unwrap();
    let envelope = signed_envelope(&value);

    let opened = open_signed_record(&key, &envelope, Some(&publisher())).unwrap();
    assert_eq!(opened.signer, publisher());
    // The v3 manifest is returned in the unchanged `manifest` field, byte for byte.
    assert_eq!(
        opened.manifest.as_ref().unwrap().to_bytes().unwrap(),
        man.to_bytes().unwrap()
    );
    // And it is also visible as the decoded V3 manifest.
    match opened.decoded {
        Some(DecodedManifest::V3(back)) => {
            assert_eq!(back.to_bytes().unwrap(), man.to_bytes().unwrap());
        }
        other => panic!("expected a V3 manifest, got {other:?}"),
    }
}

// ── a legacy record with no trailer still opens with no manifest ─────────────

#[test]
fn a_record_with_no_trailer_opens_with_no_manifest() {
    let key = record().dht_key();
    let value = bincode::serialize(&record()).unwrap();
    let envelope = signed_envelope(&value);
    let opened = open_signed_record(&key, &envelope, Some(&publisher())).unwrap();
    assert!(opened.manifest.is_none());
    assert!(opened.decoded.is_none());
}

// ── a hostile v4 record is refused without a panic ───────────────────────────

#[test]
fn a_v4_record_for_a_different_mid_is_refused() {
    // The record's MID digest is changed so it no longer matches the key it is
    // fetched under. open_signed_record must refuse it, not panic.
    let mut rec = record();
    rec.mid_digest = [0xEE; 32];
    let mut value = bincode::serialize(&rec).unwrap();
    value.extend_from_slice(
        &v4_manifest_by(&segments(), publisher())
            .encode_trailer()
            .unwrap(),
    );
    // Sign it keyed to the real key, so the signature check passes and the inner
    // MID mismatch is what refuses it.
    let signed = SignedDhtRecord::sign(record().dht_key(), value, &signing_key());
    let envelope = bincode::serialize(&signed).unwrap();

    // The trailer's MID does not match the record's altered MID: the decoder
    // refuses it before the key check is even reached.
    match open_signed_record(&record().dht_key(), &envelope, Some(&publisher())) {
        Err(SignedRecordError::InvalidInner(_)) | Err(SignedRecordError::InnerMidMismatch) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_v4_record_whose_manifest_names_another_publisher_is_refused() {
    // The envelope is signed by `signing_key`, but the v4 manifest names a
    // different publisher. A manifest must name the signer, so this is refused
    // as a publisher mismatch -- without a panic.
    let key = record().dht_key();
    let other_pub: [u8; 32] = fill("a different publisher");
    let envelope = signed_envelope(&v4_record_value_by(other_pub));
    match open_signed_record(&key, &envelope, Some(&publisher())) {
        Err(SignedRecordError::ManifestPublisher) => {}
        other => panic!("expected ManifestPublisher, got {other:?}"),
    }
}

#[test]
fn a_truncated_v4_trailer_is_refused_without_a_panic() {
    // Drop the last byte of the v4 trailer: the declared length no longer
    // matches the bytes that follow, so the decoder refuses it.
    let full = v4_record_value();
    let truncated = &full[..full.len() - 1];
    let envelope = signed_envelope(truncated);
    match open_signed_record(&record().dht_key(), &envelope, Some(&publisher())) {
        Err(SignedRecordError::InvalidInner(_)) => {}
        other => panic!("expected InvalidInner, got {other:?}"),
    }
}

// ── the record size limit still applies ──────────────────────────────────────

#[test]
fn an_oversized_record_declaration_is_refused_not_buffered() {
    // A record value whose leading `locations` vector declares an enormous
    // length (far more bytes than are present) must be refused by the bounded
    // decoder rather than attempting to allocate for the declared length. The
    // value is built by hand so bincode meets a huge length prefix with no data
    // behind it; the decoder's limit refuses it without a panic.
    //
    // DhtRecord fields in declaration order: mid_digest [u8; 32], data_shards
    // u8, total_shards u8, version u32, locations Vec<..> (len-prefixed), ...
    let mut value = Vec::new();
    value.extend_from_slice(mid().as_bytes()); // mid_digest
    value.push(4); // data_shards
    value.push(6); // total_shards
    value.extend_from_slice(&1u32.to_le_bytes()); // version
                                                  // locations length prefix: a huge count with nothing behind it.
    value.extend_from_slice(&u64::MAX.to_le_bytes());
    let envelope = signed_envelope(&value);
    // Must return an error (malformed / invalid inner), never panic or hang.
    let out = open_signed_record(&record().dht_key(), &envelope, Some(&publisher()));
    assert!(out.is_err(), "an oversized declaration must be refused");
}
