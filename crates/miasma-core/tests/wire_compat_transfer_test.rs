//! The transfer manifest (v3) and the share formats, frozen byte for byte.
//!
//! A transfer publishes, for each piece (share) of each segment, a commitment
//! in a `TransferManifest`; the manifest rides as a framed trailer after the
//! `DhtRecord` in a signed DHT value; and each share is a bincode
//! `MiasmaShare`. All of that is on the network and on disk in released
//! builds, so a build that writes other bytes for the same values, or stops
//! reading these, can no longer exchange files with them.
//!
//! Every fixture is one line (`name hex`) of `tests/fixtures/transfer_v3/frozen.hex`.
//! A set of real shares (random keys and nonces, frozen once from `dissolve`)
//! is the input; everything else is rebuilt from those shares and fixed
//! structure, so it is reproducible. The tests check that
//!
//! * (a) the current encoder writes exactly these bytes: the manifest, its
//!   hash, the trailer, the record value and the signed record (Ed25519 is
//!   deterministic), and the piece commitments;
//! * (b) the current decoder reads each of them and gives the fields back, and
//!   real shares reconstruct the plaintext (per segment with the manifest's
//!   `plain_hash`, and through the older whole-file `retrieve` path);
//! * (c) the refusals that old and new builds rely on: a manifest or trailer
//!   of another version is refused with the specific message, a trailer whose
//!   length does not match is an error and not a silent downgrade, a record
//!   without trailer is a legacy record, and a password-protected manifest
//!   keeps its public parameters and sealed name.
//!
//! Test-only key material is derived with BLAKE3 from a label (`fill`); no key,
//! nonce, salt or password is a literal. The file was written once by
//! `print_fixtures` (run with `--ignored --nocapture`). Regenerating existing
//! lines after a failing test would hide a break instead of fixing it: a new
//! format (manifest v4, share v2) gets new lines and a new file.

use ed25519_dalek::SigningKey;
use miasma_core::dissolution::segment::{dissolve_segment_at, retrieve_segment};
use miasma_core::dissolution::SegmentMeta;
use miasma_core::network::sybil::SignedDhtRecord;
use miasma_core::network::types::{DhtRecord, ShardLocation};
use miasma_core::transfer::manifest::{
    decode_record_value, encode_record_value, open_signed_record, SegmentEntry, TransferManifest,
    MANIFEST_VERSION, TRAILER_MAGIC,
};
use miasma_core::transfer::protection::{PasswordProtection, Protection};
use miasma_core::{
    dissolve, retrieve, ContentId, DissolutionParams, MiasmaError, MiasmaShare, ShareVerification,
};

const FIXTURES: &str = include_str!("fixtures/transfer_v3/frozen.hex");

const TS: u64 = 1_700_000_000;
const SEG_SIZE: u32 = 64;
const TOTAL_BYTES: usize = 100;
const LEGACY_PLAINTEXT: &[u8] = b"frozen whole-file share set, version one";

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 4,
        total_shards: 6,
    }
}

fn legacy_params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 3,
        total_shards: 5,
    }
}

/// Deterministic test-only bytes: BLAKE3 in key-derivation mode over a label.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key("miasma frozen transfer fixtures v3 (test-only)");
    h.update(label.as_bytes());
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

fn plaintext() -> [u8; TOTAL_BYTES] {
    fill("transfer plaintext")
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

fn transfer_password() -> String {
    format!("Fx-{}-#9", hex::encode(fill::<12>("transfer password")))
}

// ─── Fixture access ──────────────────────────────────────────────────────────

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

/// The twelve frozen shares of the two segments: `[segment][slot]`.
fn frozen_segments() -> Vec<Vec<MiasmaShare>> {
    (0..2u32)
        .map(|s| {
            (0..6u16)
                .map(|slot| {
                    MiasmaShare::from_bytes(&frozen(&format!("seg{s}_share{slot}"))).unwrap()
                })
                .collect()
        })
        .collect()
}

fn segment_bounds(s: usize) -> (usize, usize) {
    if s == 0 {
        (0, SEG_SIZE as usize)
    } else {
        (SEG_SIZE as usize, TOTAL_BYTES)
    }
}

// ─── Values rebuilt from the shares ──────────────────────────────────────────

fn manifest_with(segs: &[Vec<MiasmaShare>], protection: Protection) -> TransferManifest {
    let plain = plaintext();
    let mid = mid();
    let mut m = TransferManifest::new(
        &mid,
        publisher(),
        params(),
        SEG_SIZE,
        TOTAL_BYTES as u64,
        protection,
    );
    for (i, shares) in segs.iter().enumerate() {
        let (a, b) = segment_bounds(i);
        m.push_segment(SegmentEntry::from_dissolved(i as u32, &mid, &plain[a..b], shares).unwrap())
            .unwrap();
    }
    m
}

fn plain_manifest(segs: &[Vec<MiasmaShare>]) -> TransferManifest {
    manifest_with(segs, Protection::None).with_name(Some("report.txt"))
}

fn record() -> DhtRecord {
    DhtRecord {
        mid_digest: *mid().as_bytes(),
        data_shards: 4,
        total_shards: 6,
        version: 1,
        locations: (0..2u16)
            .map(|i| ShardLocation {
                peer_id_bytes: fill::<32>(&format!("peer {i}")).to_vec(),
                shard_index: i,
                segment_index: 0,
                addrs: vec![format!("/ip4/127.0.0.1/tcp/{}", 4001 + i)],
            })
            .collect(),
        published_at: TS,
    }
}

/// Every fixture rebuilt from the shares: name and the bytes written now.
fn rebuilt(segs: &[Vec<MiasmaShare>]) -> Vec<(String, Vec<u8>)> {
    let m = plain_manifest(segs);
    let value = encode_record_value(&record(), Some(&m)).unwrap();
    let signed = SignedDhtRecord::sign(record().dht_key(), value.clone(), &signing_key());
    let mut commitments = Vec::new();
    for shares in segs {
        for s in shares {
            commitments.extend_from_slice(&s.piece_commitment(&mid()));
        }
    }
    vec![
        ("manifest_plain".into(), m.to_bytes().unwrap()),
        (
            "manifest_plain_hash".into(),
            m.manifest_hash().unwrap().to_vec(),
        ),
        ("manifest_trailer".into(), m.encode_trailer().unwrap()),
        (
            "record_bare".into(),
            encode_record_value(&record(), None).unwrap(),
        ),
        ("record_value".into(), value),
        ("signed_record".into(), bincode::serialize(&signed).unwrap()),
        ("piece_commitments".into(), commitments),
    ]
}

// ─── (a) the encoder writes the frozen bytes ─────────────────────────────────

#[test]
fn encoders_write_the_frozen_bytes() {
    let segs = frozen_segments();
    for (name, bytes) in rebuilt(&segs) {
        assert!(
            bytes == frozen(&name),
            "the bytes written for `{name}` differ from the frozen fixture"
        );
    }
}

#[test]
fn shares_are_re_encoded_to_the_same_bytes() {
    for (s, shares) in frozen_segments().iter().enumerate() {
        for (slot, share) in shares.iter().enumerate() {
            let name = format!("seg{s}_share{slot}");
            assert!(
                share.to_bytes().unwrap() == frozen(&name),
                "share `{name}` is not re-encoded to its frozen bytes"
            );
        }
    }
    for i in 0..5 {
        let name = format!("legacy_share{i}");
        let share = MiasmaShare::from_bytes(&frozen(&name)).unwrap();
        assert!(share.to_bytes().unwrap() == frozen(&name));
    }
}

#[test]
fn the_wire_layout_of_a_share_and_a_trailer_is_as_documented() {
    // Share: version:u8, mid_prefix:[u8;8], segment_index:u32le, slot_index:u16le,
    // then the two length-prefixed vectors, shard_hash, nonce, original_len, timestamp.
    let segs = frozen_segments();
    let share = &segs[1][3];
    let b = share.to_bytes().unwrap();
    assert_eq!(b[0], 1, "share version");
    assert_eq!(&b[1..9], &mid().as_bytes()[..8], "mid prefix");
    assert_eq!(u32::from_le_bytes(b[9..13].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(b[13..15].try_into().unwrap()), 3);
    assert_eq!(
        u64::from_le_bytes(b[15..23].try_into().unwrap()) as usize,
        share.shard_data.len()
    );
    assert_eq!(share.original_len as usize, TOTAL_BYTES - SEG_SIZE as usize);
    assert_eq!(share.timestamp, TS);
    assert_eq!(
        share.shard_hash,
        *blake3::hash(&share.shard_data).as_bytes()
    );

    // Trailer: "MNFT" || version:u8 || len:u32le || manifest.
    let t = frozen("manifest_trailer");
    let m = frozen("manifest_plain");
    assert_eq!(&t[..4], TRAILER_MAGIC);
    assert_eq!(t[4], MANIFEST_VERSION);
    assert_eq!(MANIFEST_VERSION, 3);
    assert_eq!(
        u32::from_le_bytes(t[5..9].try_into().unwrap()) as usize,
        m.len()
    );
    assert_eq!(&t[9..], &m[..]);
    // The record value is the record, then the trailer.
    let v = frozen("record_value");
    let bare = frozen("record_bare");
    assert_eq!(&v[..bare.len()], &bare[..]);
    assert_eq!(&v[bare.len()..], &t[..]);
    // The manifest starts with its version byte.
    assert_eq!(m[0], 3);
    // The hash is BLAKE3 over the manifest bytes.
    assert_eq!(
        frozen("manifest_plain_hash"),
        blake3::hash(&m).as_bytes().to_vec()
    );
}

// ─── (b) the decoder reads them ──────────────────────────────────────────────

#[test]
fn the_decoder_reads_the_frozen_manifest() {
    let m = TransferManifest::from_bytes(&frozen("manifest_plain")).unwrap();
    assert_eq!(m.version, 3);
    assert_eq!(&m.mid, mid().as_bytes());
    assert_eq!(m.publisher, publisher());
    assert_eq!(m.name.as_deref(), Some("report.txt"));
    assert_eq!(m.original_name(None).as_deref(), Some("report.txt"));
    assert_eq!((m.data_shards, m.total_shards), (4, 6));
    assert_eq!(m.segment_size, SEG_SIZE);
    assert_eq!(m.total_bytes, TOTAL_BYTES as u64);
    assert!(matches!(m.protection, Protection::None));
    assert_eq!(m.segments.len(), 2);
    let plain = plaintext();
    let segs = frozen_segments();
    for (i, seg) in m.segments.iter().enumerate() {
        let (a, b) = segment_bounds(i);
        assert_eq!(seg.index as usize, i);
        assert_eq!(seg.plaintext_len as usize, b - a);
        assert_eq!(seg.plain_hash, *blake3::hash(&plain[a..b]).as_bytes());
        assert_eq!(seg.piece_ids.len(), 6);
        for (slot, id) in seg.piece_ids.iter().enumerate() {
            assert_eq!(*id, segs[i][slot].piece_commitment(&mid()));
            assert_eq!(m.expected_piece(i as u32, slot as u16), Some(id));
        }
    }
}

#[test]
fn the_decoder_reads_the_frozen_record_value_and_signed_record() {
    let (rec, m) = decode_record_value(&frozen("record_value")).unwrap();
    assert_eq!(rec.mid_digest, *mid().as_bytes());
    assert_eq!((rec.data_shards, rec.total_shards, rec.version), (4, 6, 1));
    assert_eq!(rec.published_at, TS);
    assert_eq!(rec.locations.len(), 2);
    assert_eq!(rec.locations[1].shard_index, 1);
    assert_eq!(rec.locations[1].addrs, vec!["/ip4/127.0.0.1/tcp/4002"]);
    let m = m.expect("the value carries a manifest");
    assert_eq!(m.to_bytes().unwrap(), frozen("manifest_plain"));

    // A record with no trailer is a legacy record.
    let (rec, none) = decode_record_value(&frozen("record_bare")).unwrap();
    assert_eq!(rec.mid_digest, *mid().as_bytes());
    assert!(none.is_none());

    // The signed envelope opens for the right key and signer, and only then.
    let key = record().dht_key();
    let signed = frozen("signed_record");
    let opened = open_signed_record(&key, &signed, Some(&publisher())).unwrap();
    assert_eq!(opened.signer, publisher());
    assert_eq!(
        opened.manifest.unwrap().to_bytes().unwrap(),
        frozen("manifest_plain")
    );
    let other: [u8; 32] = fill("somebody else");
    assert!(open_signed_record(&key, &signed, Some(&other)).is_err());
    assert!(open_signed_record(&fill::<32>("another key"), &signed, None).is_err());
}

#[test]
fn frozen_segments_reconstruct_the_plaintext_and_match_the_manifest() {
    let m = TransferManifest::from_bytes(&frozen("manifest_plain")).unwrap();
    let segs = frozen_segments();
    let plain = plaintext();
    let mid = mid();
    let mut joined = Vec::new();
    for (i, shares) in segs.iter().enumerate() {
        let meta = SegmentMeta {
            index: i as u32,
            offset_bytes: segment_bounds(i).0 as u64,
            plaintext_len: m.segments[i].plaintext_len,
            share_count: 6,
        };
        // Any four of the six shares are enough: take the last four.
        let part = retrieve_segment(&mid, &shares[2..], &meta, params()).unwrap();
        assert_eq!(
            *blake3::hash(&part).as_bytes(),
            m.segments[i].plain_hash,
            "plain_hash of segment {i}"
        );
        joined.extend_from_slice(&part);
    }
    assert_eq!(joined, plain);
}

#[test]
fn the_frozen_whole_file_share_set_still_reconstructs() {
    let mid = ContentId::from_str(&String::from_utf8(frozen("legacy_mid")).unwrap()).unwrap();
    assert_eq!(
        mid,
        ContentId::compute(LEGACY_PLAINTEXT, &legacy_params().to_param_bytes())
    );
    let shares: Vec<MiasmaShare> = (0..5)
        .map(|i| MiasmaShare::from_bytes(&frozen(&format!("legacy_share{i}"))).unwrap())
        .collect();
    for (i, s) in shares.iter().enumerate() {
        assert_eq!(s.version, 1);
        assert_eq!(s.slot_index as usize, i);
        assert_eq!(s.segment_index, 0);
        assert_eq!(s.original_len as usize, LEGACY_PLAINTEXT.len());
        assert_eq!(s.mid_prefix, mid.as_bytes()[..8]);
        assert!(ShareVerification::coarse_verify(s, &mid));
    }
    // Every choice of three shares reconstructs it.
    for a in 0..5 {
        for b in (a + 1)..5 {
            for c in (b + 1)..5 {
                let pick = vec![shares[a].clone(), shares[b].clone(), shares[c].clone()];
                let out = retrieve(&mid, &pick, legacy_params()).unwrap();
                assert_eq!(out, LEGACY_PLAINTEXT);
            }
        }
    }
    // Two are not enough, and altered data is not accepted.
    assert!(retrieve(&mid, &shares[..2], legacy_params()).is_err());
    let mut bad = shares[..3].to_vec();
    bad[0].shard_data[0] ^= 1;
    bad[1].shard_data[0] ^= 1;
    bad[2].shard_data[0] ^= 1;
    assert!(retrieve(&mid, &bad, legacy_params()).is_err());
}

// ─── (c) refusals and compatibility rules ────────────────────────────────────

fn trailer_offset() -> usize {
    frozen("record_value").len() - frozen("manifest_trailer").len()
}

fn error_text(e: MiasmaError) -> String {
    e.to_string()
}

#[test]
fn an_older_or_newer_trailer_version_is_refused_with_its_message() {
    let off = trailer_offset();
    for older in [1u8, 2] {
        let mut v = frozen("record_value");
        v[off + 4] = older;
        let msg = error_text(decode_record_value(&v).unwrap_err());
        assert!(
            msg.contains(&format!("manifest version {older} is no longer supported")),
            "unexpected text for trailer version {older}"
        );
        assert!(msg.contains("ask the sender to publish the file again"));
    }
    let mut v = frozen("record_value");
    v[off + 4] = 4;
    let msg = error_text(decode_record_value(&v).unwrap_err());
    assert!(
        msg.contains("manifest version 4 is newer than this build supports (3); update Miasma"),
        "unexpected text for trailer version 4"
    );
}

#[test]
fn a_manifest_of_another_version_is_refused() {
    for version in [0u8, 1, 2, 4, 255] {
        let mut m = frozen("manifest_plain");
        m[0] = version;
        assert!(
            TransferManifest::from_bytes(&m).is_err(),
            "manifest version {version} must be refused"
        );
    }
}

#[test]
fn the_trailer_must_be_exactly_as_long_as_it_says() {
    let mut longer = frozen("record_value");
    longer.extend_from_slice(&fill::<8>("junk after the trailer"));
    let msg = error_text(decode_record_value(&longer).unwrap_err());
    assert!(msg.contains("trailer declares"), "unexpected text");

    let mut shorter = frozen("record_value");
    shorter.pop();
    assert!(decode_record_value(&shorter).is_err());

    // Anything after the record that is not a trailer is an error, not a
    // silent fall back to "no manifest".
    let mut stray = frozen("record_bare");
    stray.extend_from_slice(&fill::<16>("stray bytes"));
    let msg = error_text(decode_record_value(&stray).unwrap_err());
    assert!(msg.contains("unrecognized data after the record"));
}

#[test]
fn a_manifest_that_names_another_record_is_refused() {
    let mut v = frozen("record_value");
    // Flip a byte of the record's MID digest (the first field).
    v[0] ^= 1;
    assert!(decode_record_value(&v).is_err());
}

#[test]
fn bytes_after_the_manifest_payload_are_ignored_by_the_manifest_decoder() {
    // `bincode::deserialize` leaves trailing bytes alone. The trailer length is
    // what delimits the payload, so a later format that adds fields to the end
    // of the manifest changes the version byte as well and is refused by it.
    let mut m = frozen("manifest_plain");
    m.extend_from_slice(&fill::<16>("appended manifest fields"));
    let back = TransferManifest::from_bytes(&m).unwrap();
    assert_eq!(back.segments.len(), 2);
}

#[test]
fn a_password_protected_manifest_keeps_its_public_parameters_and_sealed_name() {
    let m = TransferManifest::from_bytes(&frozen("manifest_password")).unwrap();
    assert!(m.name_is_sealed());
    let pp = match &m.protection {
        Protection::Password(p) => p.clone(),
        Protection::None => panic!("expected a password-protected manifest"),
    };
    assert_eq!((pp.m_kib, pp.t_cost, pp.p_cost), (64, 1, 1));
    let key = pp.unlock(&transfer_password()).unwrap();
    assert_eq!(m.original_name(Some(&key)).as_deref(), Some("secret.txt"));
    assert!(m.original_name(None).is_none());
    assert!(matches!(
        pp.unlock(&format!("{}x", transfer_password())),
        Err(MiasmaError::WrongPassword)
    ));
    // The bytes are the ones the encoder writes for the same value.
    assert_eq!(m.to_bytes().unwrap(), frozen("manifest_password"));
}

// ─── Generator (run once, by hand) ───────────────────────────────────────────

/// Prints every line of `frozen.hex`. Run with
/// `cargo test --test wire_compat_transfer_test print_fixtures -- --ignored --nocapture`
/// and put the `FIXTURE` lines (without that word) into the file. Only for a
/// new format: never to make a failing test pass.
#[test]
#[ignore = "prints the fixture file; run by hand, once"]
fn print_fixtures() {
    let plain = plaintext();
    let mid = mid();
    let mut segs: Vec<Vec<MiasmaShare>> = Vec::new();
    for s in 0..2usize {
        let (a, b) = segment_bounds(s);
        let (_, shares) =
            dissolve_segment_at(&plain[a..b], &mid, s as u32, a as u64, params(), TS).unwrap();
        assert_eq!(shares.len(), 6);
        for (slot, share) in shares.iter().enumerate() {
            assert_eq!(share.slot_index as usize, slot);
            println!(
                "FIXTURE seg{s}_share{slot} {}",
                hex::encode(share.to_bytes().unwrap())
            );
        }
        segs.push(shares);
    }
    for (name, bytes) in rebuilt(&segs) {
        println!("FIXTURE {name} {}", hex::encode(bytes));
    }

    let pw = transfer_password();
    let (pp, key) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
    let m =
        manifest_with(&segs, Protection::Password(pp)).with_sealed_name(Some("secret.txt"), &key);
    println!(
        "FIXTURE manifest_password {}",
        hex::encode(m.to_bytes().unwrap())
    );

    let (lmid, lshares) = dissolve(LEGACY_PLAINTEXT, legacy_params()).unwrap();
    println!(
        "FIXTURE legacy_mid {}",
        hex::encode(lmid.to_string().as_bytes())
    );
    for (i, s) in lshares.iter().enumerate() {
        println!(
            "FIXTURE legacy_share{i} {}",
            hex::encode(s.to_bytes().unwrap())
        );
    }
}
