//! The production receive entry point, `open_signed_record`, accepts a v4
//! record.
//!
//! `decode_record_value_any` was already proven to read a v4 trailer
//! (`aead_v2_manifest_reader_test.rs`, `wire_compat_transfer_v4_test.rs`), but
//! those are decoder-unit tests. This file pins the integration: the one place a
//! network record is taken apart -- `open_signed_record`, the function the DHT
//! fetch check, the direct (`--via`) receive and upkeep all go through -- now
//! takes a v4 record instead of refusing it, without disturbing the v3 path.
//!
//! What is pinned here:
//!   * a signed v4 record round-trips through `open_signed_record`: it is
//!     accepted, the record and signer come back, and no panic happens;
//!   * a v3 record keeps coming back with its manifest, byte for byte, so the
//!     v3 receive path is unchanged;
//!   * a hostile or truncated v4 record is refused through `open_signed_record`
//!     without a panic, and a size-exceeding record is rejected;
//!   * an older program (the v3-only `decode_record_value`) still refuses a v4
//!     record with the existing "update Miasma" message, so versions stay
//!     interoperable.
//!
//! No key, nonce or plaintext is a literal: each is derived with BLAKE3 in
//! key-derivation mode from a label, as the other suite tests do.

use ed25519_dalek::SigningKey;
use miasma_core::dissolution::segment::dissolve_segment_at;
use miasma_core::format::ObjectSuite;
use miasma_core::network::sybil::SignedDhtRecord;
use miasma_core::network::types::DhtRecord;
use miasma_core::transfer::manifest::{
    decode_record_value, encode_record_value, ManifestV4, SegmentEntry, TransferManifest,
    MANIFEST_VERSION_V4,
};
use miasma_core::transfer::protection::Protection;
use miasma_core::transfer::{open_signed_record, SignedRecordError};
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
    let mut h = blake3::Hasher::new_derive_key("miasma open_signed_record v4 (test-only)");
    h.update(label.as_bytes());
    let mut out = vec![0u8; N];
    h.finalize_xof().fill(&mut out);
    out.try_into().unwrap()
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

/// A valid v3 manifest over those shares, naming the test publisher.
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

/// A valid v4 manifest with the same structure, naming Suite2 and the publisher.
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
    let mut value = bincode::serialize(&record()).unwrap();
    value.extend_from_slice(&v4_manifest(&segments()).encode_trailer().unwrap());
    value
}

/// Sign `value` under the test key and serialize the envelope exactly as the
/// network stores and serves it.
fn signed_envelope(value: Vec<u8>) -> Vec<u8> {
    let signed = SignedDhtRecord::sign(record().dht_key(), value, &signing_key());
    bincode::serialize(&signed).unwrap()
}

fn expected_key() -> Vec<u8> {
    record().dht_key()
}

// ── (1) a v4 record round-trips through open_signed_record ───────────────────

#[test]
fn a_v4_record_is_accepted_by_open_signed_record() {
    let envelope = signed_envelope(v4_record_value());
    let found = open_signed_record(&expected_key(), &envelope, Some(&publisher()))
        .expect("a signed v4 record opens on the receive path");
    assert_eq!(found.record.mid_digest, *mid().as_bytes());
    assert_eq!(found.signer, publisher());
    // The receive engine downstream of `FetchedRecord` takes a v3 manifest; a v4
    // record is accepted (not refused, no panic) but its manifest is not yet
    // threaded through the engine, so it rides as `None`. This is the documented
    // follow-up, pinned here so the behaviour does not change silently.
    assert!(
        found.manifest.is_none(),
        "a v4 record carries no v3 manifest through the engine yet"
    );
}

#[test]
fn a_v4_record_opens_without_an_expected_signer_too() {
    // The `--via`/DHT path may open a record without naming the signer up front.
    let envelope = signed_envelope(v4_record_value());
    let found = open_signed_record(&expected_key(), &envelope, None)
        .expect("a signed v4 record opens without a named signer");
    assert_eq!(found.signer, publisher());
    assert!(found.manifest.is_none());
}

// ── the v3 path is unchanged ─────────────────────────────────────────────────

#[test]
fn a_v3_record_still_opens_with_its_manifest() {
    let segs = segments();
    let man = v3_manifest(&segs);
    let value = encode_record_value(&record(), Some(&man)).unwrap();
    let envelope = signed_envelope(value);
    let found = open_signed_record(&expected_key(), &envelope, Some(&publisher()))
        .expect("a signed v3 record opens as before");
    assert_eq!(found.signer, publisher());
    // The v3 manifest comes back byte for byte: the v3 receive path is untouched.
    let back = found.manifest.expect("a v3 record carries its manifest");
    assert_eq!(back.to_bytes().unwrap(), man.to_bytes().unwrap());
}

#[test]
fn an_older_program_still_refuses_a_v4_record_with_update_miasma() {
    // The v3-only `decode_record_value` stands in for a pre-v4 build: it must go
    // on refusing the v4 record this build now accepts, so versions interoperate.
    let value = v4_record_value();
    match decode_record_value(&value) {
        Err(MiasmaError::InvalidManifest(msg)) => {
            assert!(msg.contains("update Miasma"), "{msg}");
            assert!(msg.contains("newer than this build supports"), "{msg}");
        }
        other => panic!("expected an update-Miasma error, got {other:?}"),
    }
}

// ── (2) a hostile or truncated v4 record is refused without a panic ──────────

#[test]
fn a_truncated_v4_record_is_refused_without_panic() {
    let full = v4_record_value();
    // Cut the trailer short at every length from the record end to one byte
    // before the full value. None may panic; each must be refused once signed.
    let rec_len = bincode::serialize(&record()).unwrap().len();
    for cut in rec_len + 1..full.len() {
        let envelope = signed_envelope(full[..cut].to_vec());
        let outcome = open_signed_record(&expected_key(), &envelope, Some(&publisher()));
        assert!(
            outcome.is_err(),
            "a v4 record truncated to {cut} bytes must be refused"
        );
    }
}

#[test]
fn a_v4_record_with_a_corrupt_trailer_version_is_refused() {
    let mut value = v4_record_value();
    let rec_len = bincode::serialize(&record()).unwrap().len();
    value[rec_len + 4] = 9; // a trailer version that is neither 3 nor 4
    let envelope = signed_envelope(value);
    match open_signed_record(&expected_key(), &envelope, Some(&publisher())) {
        Err(SignedRecordError::InvalidInner(msg)) => {
            assert!(msg.contains("update Miasma"), "{msg}");
        }
        other => panic!("expected an InvalidInner refusal, got {other:?}"),
    }
}

#[test]
fn a_v4_record_with_flipped_trailer_bytes_is_refused_without_panic() {
    // Flip a byte deep inside the v4 payload: the manifest no longer parses or no
    // longer matches the record. Either way it is refused, never a panic.
    let mut value = v4_record_value();
    let last = value.len() - 1;
    value[last] ^= 0xFF;
    let envelope = signed_envelope(value);
    assert!(open_signed_record(&expected_key(), &envelope, Some(&publisher())).is_err());
}

#[test]
fn a_v4_manifest_naming_another_publisher_is_refused() {
    // The manifest's publisher must be the signer. Build a v4 manifest whose
    // publisher is a different key, sign the record with the real key, and the
    // receive path refuses it as a publisher mismatch -- not a panic.
    let segs = segments();
    let mut man = v4_manifest(&segs);
    man.publisher = [0xAB; 32];
    let mut value = bincode::serialize(&record()).unwrap();
    value.extend_from_slice(&man.encode_trailer().unwrap());
    let envelope = signed_envelope(value);
    match open_signed_record(&expected_key(), &envelope, Some(&publisher())) {
        Err(SignedRecordError::InvalidInner(_)) | Err(SignedRecordError::ManifestPublisher) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_v4_record_for_a_different_key_is_refused() {
    // Open the v4 envelope under a key other than the one it was signed for: the
    // signature check fails first, before any trailer is read.
    let envelope = signed_envelope(v4_record_value());
    let wrong_key = [0x11u8; 32];
    assert!(open_signed_record(&wrong_key, &envelope, Some(&publisher())).is_err());
}

// ── (3) the size limit still applies ─────────────────────────────────────────

#[test]
fn a_v4_trailer_declaring_a_huge_length_is_refused_without_allocating() {
    // The trailer length field is a u32. Rewrite a real v4 trailer to declare the
    // largest possible payload while carrying only a few real bytes. The decoder
    // must refuse it on the length-mismatch check -- bounded, no panic, and
    // without sizing an allocation from the attacker-declared length (the
    // separate `decode_limits_test` pins the no-allocation property directly).
    let mut value = v4_record_value();
    let rec_len = bincode::serialize(&record()).unwrap().len();
    // Overwrite the 4-byte little-endian length that follows the magic+version.
    value[rec_len + 5..rec_len + 9].copy_from_slice(&u32::MAX.to_le_bytes());
    let envelope = signed_envelope(value);
    let outcome = open_signed_record(&expected_key(), &envelope, Some(&publisher()));
    assert!(
        outcome.is_err(),
        "a v4 trailer declaring {} bytes must be refused",
        u32::MAX
    );
}

#[test]
fn a_v4_record_padded_past_its_trailer_is_refused_without_panic() {
    // Appending bytes after a well-formed v4 trailer makes the declared trailer
    // length no longer match what follows. The receive path refuses it rather
    // than reading past the trailer or panicking.
    let mut value = v4_record_value();
    value.extend(std::iter::repeat(0u8).take(4096));
    let envelope = signed_envelope(value);
    assert!(open_signed_record(&expected_key(), &envelope, Some(&publisher())).is_err());
}
