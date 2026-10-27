//! The production receive entry point, `open_signed_record`, accepts a version-4
//! record instead of refusing it, while a version-3 record keeps opening exactly
//! as before and a hostile or truncated value is refused without a panic.
//!
//! `open_signed_record` is the one place a signed DHT envelope is taken apart for
//! both the DHT and the direct (`--via`) path. Before this change it called the
//! v3-only `decode_record_value`, so a v4 record was rejected with "update
//! Miasma" even on a build that understands v4. These tests pin the new
//! behaviour: a v4 record opens (its envelope passes every signature and bounds
//! check), a v3 record opens and still carries its `TransferManifest`, and a
//! damaged v4 value is a clean error.

use ed25519_dalek::SigningKey;

use miasma_core::format::ObjectSuite;
use miasma_core::network::sybil::SignedDhtRecord;
use miasma_core::network::types::DhtRecord;
use miasma_core::transfer::manifest::{
    encode_record_value, ManifestV4, SegmentEntry, TransferManifest, MANIFEST_MAX_BYTES,
    MANIFEST_VERSION_V4,
};
use miasma_core::transfer::protection::Protection;
use miasma_core::transfer::{open_signed_record, SignedRecordError};
use miasma_core::{ContentId, DissolutionParams};

const K: u8 = 4;
const N: u8 = 6;
const SEG_SIZE: u32 = 64;
const TOTAL_BYTES: u64 = 100;
const TS: u64 = 1_700_000_000;

/// Two segments (index, plaintext_len): a full 64-byte one and a 36-byte tail,
/// summing to TOTAL_BYTES, exactly what the manifest validator expects.
const SEG_LENS: [(u32, u32); 2] = [(0, 64), (1, 36)];

fn mid() -> ContentId {
    ContentId::from_digest([0x4d; 32])
}

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: K as usize,
        total_shards: N as usize,
    }
}

/// A deterministic signing key; its public key is the publisher a valid manifest
/// must name, and the signer `open_signed_record` reports.
fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn record() -> DhtRecord {
    DhtRecord {
        mid_digest: *mid().as_bytes(),
        data_shards: K,
        total_shards: N,
        version: 1,
        locations: vec![],
        published_at: TS,
    }
}

/// `n` distinct per-slot piece IDs for one segment. They are not real share
/// commitments -- the reader's version split and the structural validator do not
/// check them against shares -- but each is distinct so the manifest is
/// internally well formed.
fn piece_ids(seg_index: u32) -> Vec<[u8; 32]> {
    (0..N as u16)
        .map(|slot| {
            let mut h = blake3::Hasher::new();
            h.update(b"piece");
            h.update(&seg_index.to_le_bytes());
            h.update(&slot.to_le_bytes());
            *h.finalize().as_bytes()
        })
        .collect()
}

fn segments() -> Vec<SegmentEntry> {
    SEG_LENS
        .iter()
        .map(|&(index, plaintext_len)| SegmentEntry {
            index,
            plaintext_len,
            plain_hash: *blake3::hash(&vec![index as u8 + 1; plaintext_len as usize]).as_bytes(),
            piece_ids: piece_ids(index),
        })
        .collect()
}

/// A valid v4 manifest whose publisher is the signing key's public key, so
/// `open_signed_record`'s publisher check passes.
fn v4_manifest(publisher: [u8; 32]) -> ManifestV4 {
    ManifestV4 {
        version: MANIFEST_VERSION_V4,
        mid: *mid().as_bytes(),
        publisher,
        name: Some("report.txt".into()),
        data_shards: K,
        total_shards: N,
        segment_size: SEG_SIZE,
        total_bytes: TOTAL_BYTES,
        protection: Protection::None,
        segments: segments(),
        suite: ObjectSuite::Suite2.id(),
        ext: Vec::new(),
    }
}

/// A valid v3 manifest whose publisher is the signing key's public key.
fn v3_manifest(publisher: [u8; 32]) -> TransferManifest {
    let mut m = TransferManifest::new(
        &mid(),
        publisher,
        params(),
        SEG_SIZE,
        TOTAL_BYTES,
        Protection::None,
    );
    m.name = Some("report.txt".into());
    m.segments = segments();
    m
}

/// Serialize the record, append a v4 trailer, and wrap the whole value in a
/// SignedDhtRecord signed under `key`.
fn v4_envelope(key: &SigningKey) -> (Vec<u8>, [u8; 32]) {
    let pubkey = key.verifying_key().to_bytes();
    let mut value = bincode::serialize(&record()).unwrap();
    value.extend_from_slice(&v4_manifest(pubkey).encode_trailer().unwrap());
    let signed = SignedDhtRecord::sign(record().dht_key(), value, key);
    (bincode::serialize(&signed).unwrap(), pubkey)
}

#[test]
fn a_v4_record_opens_through_open_signed_record() {
    let key = signing_key();
    let (envelope, pubkey) = v4_envelope(&key);
    let mid = mid();

    // Accepted without a signer hint ...
    let fetched = open_signed_record(mid.as_bytes(), &envelope, None)
        .expect("a v4 record must open, not be refused");
    assert_eq!(fetched.record.mid_digest, *mid.as_bytes());
    assert_eq!(fetched.signer, pubkey);
    // The receive engine downstream takes a v3 manifest; a v4 record is accepted
    // here but its manifest is not yet threaded through, so it rides as None.
    assert!(
        fetched.manifest.is_none(),
        "a v4 manifest is not surfaced as a v3 TransferManifest"
    );

    // ... and with the exact signer required.
    let fetched = open_signed_record(mid.as_bytes(), &envelope, Some(&pubkey))
        .expect("a v4 record from the expected signer must open");
    assert_eq!(fetched.signer, pubkey);
}

#[test]
fn a_v3_record_still_opens_with_its_manifest_unchanged() {
    let key = signing_key();
    let pubkey = key.verifying_key().to_bytes();
    let manifest = v3_manifest(pubkey);
    let value = encode_record_value(&record(), Some(&manifest)).unwrap();
    let signed = SignedDhtRecord::sign(record().dht_key(), value, &key);
    let envelope = bincode::serialize(&signed).unwrap();

    let fetched = open_signed_record(mid().as_bytes(), &envelope, Some(&pubkey))
        .expect("a v3 record must open exactly as before");
    assert_eq!(fetched.signer, pubkey);
    assert_eq!(
        fetched.manifest.as_ref(),
        Some(&manifest),
        "the v3 manifest is returned byte for byte"
    );
}

#[test]
fn a_truncated_v4_record_is_refused_without_panic() {
    let key = signing_key();
    let (envelope, pubkey) = v4_envelope(&key);

    // Decode the envelope, cut the signed value short inside the v4 trailer, and
    // re-sign so the signature still matches: the failure is then the decode, not
    // the signature, which is the path under test.
    let mut signed: SignedDhtRecord = bincode::deserialize(&envelope).unwrap();
    let cut = signed.value.len() - 8;
    signed.value.truncate(cut);
    let resigned = SignedDhtRecord::sign(signed.key.clone(), signed.value.clone(), &key);
    let bad = bincode::serialize(&resigned).unwrap();

    match open_signed_record(mid().as_bytes(), &bad, Some(&pubkey)) {
        Err(SignedRecordError::InvalidInner(_)) => {}
        other => panic!("expected InvalidInner for a truncated v4 trailer, got {other:?}"),
    }
}

#[test]
fn a_hostile_v4_trailer_version_is_refused_without_panic() {
    let key = signing_key();
    let pubkey = key.verifying_key().to_bytes();
    let mut value = bincode::serialize(&record()).unwrap();
    let mut trailer = v4_manifest(pubkey).encode_trailer().unwrap();
    // Bump the trailer version byte (offset 4, just after the "MNFT" magic) to an
    // unknown version: neither 3 nor 4. It must be rejected, never decoded.
    trailer[4] = 9;
    value.extend_from_slice(&trailer);
    let signed = SignedDhtRecord::sign(record().dht_key(), value, &key);
    let envelope = bincode::serialize(&signed).unwrap();

    match open_signed_record(mid().as_bytes(), &envelope, Some(&pubkey)) {
        Err(SignedRecordError::InvalidInner(msg)) => {
            assert!(msg.contains("update Miasma"), "{msg}");
        }
        other => panic!("expected InvalidInner for an unknown trailer version, got {other:?}"),
    }
}

#[test]
fn the_size_limit_still_applies_to_a_v4_record() {
    // An oversized manifest cannot even be encoded: `to_bytes` enforces
    // MANIFEST_MAX_BYTES, so an attacker cannot smuggle an unbounded manifest
    // through the v4 trailer the receive path now reads.
    let key = signing_key();
    let pubkey = key.verifying_key().to_bytes();
    let mut manifest = v4_manifest(pubkey);
    // An ext area far past the manifest cap; serialization must refuse it.
    manifest.ext = vec![0u8; MANIFEST_MAX_BYTES + 1];
    assert!(
        manifest.to_bytes().is_err(),
        "a manifest past MANIFEST_MAX_BYTES must not serialize"
    );

    // And a trailer whose declared length does not match its payload is refused
    // by the reader rather than over-read.
    let mut value = bincode::serialize(&record()).unwrap();
    let mut trailer = v4_manifest(pubkey).encode_trailer().unwrap();
    // Claim one more payload byte than is present.
    let declared = u32::from_le_bytes(trailer[5..9].try_into().unwrap());
    trailer[5..9].copy_from_slice(&(declared + 1).to_le_bytes());
    value.extend_from_slice(&trailer);
    let signed = SignedDhtRecord::sign(record().dht_key(), value, &key);
    let envelope = bincode::serialize(&signed).unwrap();

    match open_signed_record(mid().as_bytes(), &envelope, Some(&pubkey)) {
        Err(SignedRecordError::InvalidInner(_)) => {}
        other => panic!("expected InvalidInner for a length-mismatched trailer, got {other:?}"),
    }
}
