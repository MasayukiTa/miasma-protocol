//! Suite2 (manifest v4, share v2) reader fixtures, frozen byte for byte.
//!
//! WP-A4 taught the reader to accept a version-4 manifest trailer and a
//! version-2 share without touching the v3/v1 bytes a shipped build reads and
//! writes. The behaviour of that reader against live values is pinned in
//! `aead_v2_manifest_reader_test.rs`. This file pins it against *frozen* bytes,
//! as the acceptance for WP-A4 asks: a Suite2 fixture that a later build must go
//! on reading unchanged.
//!
//! Two frozen files hold values computed independently of this library, by
//! `tools/gen_transfer_v4_fixtures.py`, from the design's definitions alone
//! (the 49-byte AAD of design 1.2, the v2 key schedule of 1.3, the piece
//! commitment of 1.8) -- not by copying the library's output:
//!
//! * `tests/fixtures/transfer_v4/frozen.hex` -- a two-segment transfer's
//!   version-2 shares (their decided inputs), the transfer-context AAD of each
//!   segment, and the per-slot piece commitment.
//! * `tests/fixtures/wholefile_v2/frozen.hex` -- a manifest-less version-2 share
//!   set, and the AES-256-GCM known answers of the v2 key schedule in the
//!   whole-file (context 2) and directed-body (context 3) shapes.
//!
//! The tests meet those bytes from two sides: (a) the library's `encode_aad`,
//! `piece_commitment`, `seal_segment` and `open_segment` reproduce them, and
//! (b) a v4 trailer built from the frozen shares is read by
//! `decode_record_value_any` as a Suite2 manifest while the unchanged
//! `decode_record_value` -- the stand-in for a pre-v4 build -- refuses it with
//! "update Miasma". No key, nonce, salt or plaintext is a literal: each is
//! derived with BLAKE3 in key-derivation mode from a label and the same context
//! string the generator uses, so both sides agree without a shared secret. A
//! new format gets a new file; the v1/v3 fixtures are never read or written
//! here.

use zeroize::Zeroizing;

use miasma_core::format::{
    encode_aad, open_segment, seal_segment, AadContext, ObjectSuite, SegmentAad, AAD_LEN,
};
use miasma_core::network::types::DhtRecord;
use miasma_core::transfer::manifest::{
    decode_record_value, decode_record_value_any, DecodedManifest, ManifestV4, SegmentEntry,
    TransferManifest, MANIFEST_VERSION_V4,
};
use miasma_core::transfer::protection::Protection;
use miasma_core::{ContentId, MiasmaError, MiasmaShare};

/// Must match CTX in `tools/gen_transfer_v4_fixtures.py`.
const CTX: &str = "miasma transfer v4 reader fixtures (test-only)";

const TRANSFER_FIXTURES: &str = include_str!("fixtures/transfer_v4/frozen.hex");
const WHOLEFILE_FIXTURES: &str = include_str!("fixtures/wholefile_v2/frozen.hex");

const K: u8 = 4;
const N: u8 = 6;
const SEG_SIZE: u32 = 64;
const TOTAL_BYTES: u64 = 100;
const TS: u64 = 1_700_000_000;

/// Segment (index, start, end), matching the generator's SEGMENTS table.
const SEGMENTS: [(u32, usize, usize); 2] = [(0, 0, 64), (1, 64, 100)];

// ── Deterministic inputs, identical to the generator's `fill` ────────────────

fn fill_vec(label: &str, len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key(CTX);
    h.update(label.as_bytes());
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

fn fill<const M: usize>(label: &str) -> [u8; M] {
    fill_vec(label, M).try_into().unwrap()
}

fn mid() -> ContentId {
    ContentId::from_digest(fill::<32>("mid digest"))
}

// ── Fixture access ───────────────────────────────────────────────────────────

fn lookup(fixtures: &str, name: &str) -> Vec<u8> {
    for line in fixtures.lines() {
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

fn transfer(name: &str) -> Vec<u8> {
    lookup(TRANSFER_FIXTURES, name)
}

fn wholefile(name: &str) -> Vec<u8> {
    lookup(WHOLEFILE_FIXTURES, name)
}

/// Rebuild one version-2 share from its frozen inputs, exactly as the generator
/// decided them. `new_v2` is the only way R1 makes a version-2 share (the
/// writer is unchanged).
fn rebuilt_share(prefix: &str, seg_index: u32, slot: u16) -> MiasmaShare {
    let shard_data = transfer(&format!("{prefix}_slot{slot}"));
    let key_share = transfer(&format!("key_share_seg{seg_index}_slot{slot}"));
    let nonce: [u8; 12] = transfer(&format!("nonce_seg{seg_index}_slot{slot}"))
        .try_into()
        .unwrap();
    let (_, start, end) = SEGMENTS[seg_index as usize];
    let original_len = (end - start) as u32;
    MiasmaShare::new_v2(
        &mid(),
        seg_index,
        slot,
        shard_data,
        key_share,
        nonce,
        original_len,
        TS,
    )
}

fn segment_shares(seg_index: u32) -> Vec<MiasmaShare> {
    (0..N as u16)
        .map(|slot| rebuilt_share(&format!("shard_data_seg{seg_index}"), seg_index, slot))
        .collect()
}

// ── (a) the library reproduces the frozen AAD and piece commitments ──────────

#[test]
fn the_library_builds_the_frozen_transfer_aad() {
    let m = mid();
    for (seg_index, start, end) in SEGMENTS {
        let plaintext_len = (end - start) as u32;
        // The struct form with its range checks.
        let built = SegmentAad::new(
            ObjectSuite::Suite2,
            AadContext::TransferSegment,
            &m,
            seg_index,
            K as usize,
            N as usize,
            plaintext_len as usize,
        )
        .unwrap()
        .encode();
        // The free-function form the key schedule uses.
        let free = encode_aad(
            ObjectSuite::Suite2,
            AadContext::TransferSegment.as_u8(),
            m.as_bytes(),
            seg_index,
            K,
            N,
            plaintext_len,
        );
        let frozen = transfer(&format!("aad_transfer_seg{seg_index}"));
        assert_eq!(built.len(), AAD_LEN);
        assert_eq!(built.to_vec(), frozen, "struct AAD, segment {seg_index}");
        assert_eq!(free.to_vec(), frozen, "free AAD, segment {seg_index}");
    }
}

#[test]
fn the_library_reproduces_the_frozen_piece_commitments() {
    let m = mid();
    for (seg_index, _, _) in SEGMENTS {
        for slot in 0..N as u16 {
            let share = rebuilt_share(&format!("shard_data_seg{seg_index}"), seg_index, slot);
            assert_eq!(share.version, 2, "a rebuilt share is version 2");
            let frozen = transfer(&format!("piece_commit_seg{seg_index}_slot{slot}"));
            assert_eq!(
                share.piece_commitment(&m).to_vec(),
                frozen,
                "piece commitment seg{seg_index} slot{slot}"
            );
        }
    }
}

// ── (b) a v4 trailer built from the frozen shares reads as Suite2, and the ───
//        old decoder refuses it

/// A valid v4 manifest over the two frozen segments. Its per-slot piece IDs are
/// the frozen commitments, so the manifest is the one that indexes these shares.
fn v4_manifest() -> ManifestV4 {
    let m = mid();
    let mut segments = Vec::new();
    for (seg_index, start, end) in SEGMENTS {
        let shares = segment_shares(seg_index);
        let plaintext_len = (end - start) as u32;
        let piece_ids: Vec<[u8; 32]> = (0..N as usize)
            .map(|slot| shares[slot].piece_commitment(&m))
            .collect();
        // The plain hash is not part of the reader's version split; a BLAKE3 of
        // the segment's decided plaintext keeps the entry internally valid.
        let plain_hash = *blake3::hash(&fill_vec(
            &format!("segment {seg_index} plaintext"),
            plaintext_len as usize,
        ))
        .as_bytes();
        segments.push(SegmentEntry {
            index: seg_index,
            plaintext_len,
            plain_hash,
            piece_ids,
        });
    }
    ManifestV4 {
        version: MANIFEST_VERSION_V4,
        mid: *m.as_bytes(),
        publisher: fill::<32>("publisher"),
        name: Some("report.txt".into()),
        data_shards: K,
        total_shards: N,
        segment_size: SEG_SIZE,
        total_bytes: TOTAL_BYTES,
        protection: Protection::None,
        segments,
        suite: ObjectSuite::Suite2.id(),
        ext: Vec::new(),
    }
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

fn v4_record_value() -> Vec<u8> {
    let mut value = bincode::serialize(&record()).unwrap();
    value.extend_from_slice(&v4_manifest().encode_trailer().unwrap());
    value
}

#[test]
fn the_frozen_shares_index_a_valid_v4_manifest() {
    let man = v4_manifest();
    man.validate()
        .expect("the v4 manifest over the frozen shares is valid");
    // Each listed piece ID is the frozen commitment for that slot.
    for (seg_index, _, _) in SEGMENTS {
        for slot in 0..N as u16 {
            let frozen = transfer(&format!("piece_commit_seg{seg_index}_slot{slot}"));
            assert_eq!(
                man.segments[seg_index as usize].piece_ids[slot as usize].to_vec(),
                frozen
            );
        }
    }
}

#[test]
fn the_v4_trailer_reads_as_suite2_on_the_version_accepting_reader() {
    let value = v4_record_value();
    let (rec, m) = decode_record_value_any(&value).unwrap();
    assert_eq!(rec.mid_digest, *mid().as_bytes());
    match m {
        Some(DecodedManifest::V4(v4)) => {
            assert_eq!(v4.version, MANIFEST_VERSION_V4);
            assert_eq!(v4.object_suite().unwrap(), ObjectSuite::Suite2);
            assert_eq!(v4.suite, ObjectSuite::Suite2.id());
            // The suite names the version-2 share.
            assert_eq!(v4.object_suite().unwrap().spec().share_version, 2);
        }
        other => panic!("expected a V4 manifest, got {other:?}"),
    }
}

#[test]
fn the_v4_trailer_through_the_old_decoder_is_update_miasma() {
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
fn a_version_2_share_matches_the_manifest_share_version() {
    let value = v4_record_value();
    let (_, m) = decode_record_value_any(&value).unwrap();
    let m = m.unwrap();
    assert_eq!(m.expected_share_version(), 2);
    for (seg_index, _, _) in SEGMENTS {
        for s in segment_shares(seg_index) {
            assert_eq!(s.version, m.expected_share_version());
            assert_eq!(
                ObjectSuite::from_share_version(s.version).unwrap(),
                ObjectSuite::Suite2
            );
        }
    }
}

// ── wholefile_v2: the manifest-less v2 key schedule, frozen ───────────────────

fn wf_aad(name: &str) -> [u8; AAD_LEN] {
    wholefile(name).try_into().unwrap()
}

#[test]
fn the_library_reproduces_the_frozen_wholefile_key_schedule() {
    let m = mid();
    let k_enc: [u8; 32] = wholefile("k_enc").try_into().unwrap();
    let pw_key: [u8; 32] = wholefile("pw_key").try_into().unwrap();
    let nonce: [u8; 12] = wholefile("nonce").try_into().unwrap();
    let plaintext = wholefile("plaintext");
    let plaintext_len = plaintext.len() as u32;

    for (ctx_name, ctx) in [
        ("wholefile", AadContext::WholeFile),
        ("directed", AadContext::Directed),
    ] {
        // The library rebuilds the same 49-byte AAD for this context.
        let built = encode_aad(
            ObjectSuite::Suite2,
            ctx.as_u8(),
            m.as_bytes(),
            0,
            K,
            N,
            plaintext_len,
        );
        assert_eq!(built, wf_aad(&format!("aad_{ctx_name}")), "{ctx_name} AAD");

        // No password: seal reproduces the frozen ciphertext, and open round-trips.
        let ct = seal_segment(Zeroizing::new(k_enc), &nonce, &plaintext, &built, None);
        assert_eq!(
            ct,
            wholefile(&format!("ct_{ctx_name}")),
            "{ctx_name} ciphertext"
        );
        let opened = open_segment(&k_enc, &nonce, &ct, &built, None).expect("opens");
        assert_eq!(opened, plaintext, "{ctx_name} round trip");

        // With a password key.
        let ct_pw = seal_segment(
            Zeroizing::new(k_enc),
            &nonce,
            &plaintext,
            &built,
            Some(&pw_key),
        );
        assert_eq!(
            ct_pw,
            wholefile(&format!("ct_{ctx_name}_pw")),
            "{ctx_name} ciphertext (password)"
        );
        let opened_pw =
            open_segment(&k_enc, &nonce, &ct_pw, &built, Some(&pw_key)).expect("opens with pw");
        assert_eq!(opened_pw, plaintext, "{ctx_name} round trip (password)");
    }
}

#[test]
fn the_frozen_wholefile_shares_are_version_2_and_split_to_suite2() {
    let m = mid();
    for slot in 0..N as u16 {
        let shard_data = wholefile(&format!("shard_data_slot{slot}"));
        let key_share = wholefile(&format!("key_share_slot{slot}"));
        let nonce: [u8; 12] = wholefile(&format!("nonce_slot{slot}")).try_into().unwrap();
        let share = MiasmaShare::new_v2(&m, 0, slot, shard_data, key_share, nonce, SEG_SIZE, TS);
        assert_eq!(share.version, 2);
        // The version-split reader (design 1.5, no-trailer path) maps this to Suite2.
        assert_eq!(
            ObjectSuite::from_share_version(share.version).unwrap(),
            ObjectSuite::Suite2
        );
        // The share's commitment is the frozen one.
        assert_eq!(
            share.piece_commitment(&m).to_vec(),
            wholefile(&format!("piece_commit_slot{slot}"))
        );
    }
}

#[test]
fn a_version_1_share_stays_suite1() {
    // The no-trailer path must keep mapping a version-1 share to Suite1: the new
    // reader does not disturb how a legacy share is read.
    let m = mid();
    let v1 = MiasmaShare::new(
        &m,
        0,
        0,
        vec![1, 2, 3],
        vec![4, 5, 6],
        fill::<12>("v1 nonce"),
        3,
        TS,
    );
    assert_eq!(v1.version, 1);
    assert_eq!(
        ObjectSuite::from_share_version(v1.version).unwrap(),
        ObjectSuite::Suite1
    );
}

// Keep the unused v3 import honest: a v4 manifest's structural validation reuses
// the v3 rules, and this test documents that a v3 manifest is a distinct type
// the Suite2 path does not produce.
#[test]
fn a_v3_manifest_is_a_distinct_type() {
    let m = mid();
    let v3 = TransferManifest::new(
        &m,
        fill::<32>("publisher"),
        v4_manifest().params(),
        SEG_SIZE,
        TOTAL_BYTES,
        Protection::None,
    );
    assert_eq!(v3.version, 3);
    assert_eq!(
        ObjectSuite::from_manifest_version(v3.version).unwrap(),
        ObjectSuite::Suite1
    );
}

// ── the "old format" status label splits by suite ────────────────────────────

#[test]
fn a_v4_manifest_is_not_shown_as_the_legacy_format() {
    // The status of a read object comes from its suite: a v4 (Suite2) manifest
    // is the current form, a v3 (Suite1) manifest the legacy one. This is the
    // input to the "old format" state (design 2.2); the reader reaches the suite
    // through `DecodedManifest::object_suite`.
    let value = v4_record_value();
    let (_, m) = decode_record_value_any(&value).unwrap();
    let suite = m.unwrap().object_suite().unwrap();
    assert_eq!(suite, ObjectSuite::Suite2);
    assert!(!suite.is_legacy(), "a Suite2 object is not the legacy form");
    assert_eq!(suite.status_label(), "current");

    // Suite1 is the legacy form shown as "old format".
    assert!(ObjectSuite::Suite1.is_legacy());
    assert_eq!(ObjectSuite::Suite1.status_label(), "legacy");
    // A manifest-less version-2 share also splits to the current suite.
    assert!(!ObjectSuite::from_share_version(2).unwrap().is_legacy());
    // A version-1 share stays legacy.
    assert!(ObjectSuite::from_share_version(1).unwrap().is_legacy());
}
