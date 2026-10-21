//! A password-protected transfer (manifest v3, share v1), frozen byte for byte.
//!
//! `wire_compat_transfer_test.rs` freezes the unprotected transfer and a
//! protected *manifest* on its own. No real share ever went through the
//! password key schedule (`UnlockedKey::segment_key`, label
//! `miasma-seg-key-v1`) there. This file closes that gap: a small transfer that
//! was created with a password, as real shares, so the readers of today are
//! checked against the bytes the released builds wrote.
//!
//! Every fixture is one line (`name hex`) of
//! `tests/fixtures/transfer_protected_v1/frozen.hex`. The shares carry random
//! keys and nonces (frozen once from `dissolve_segment_with_at`); the
//! manifest, record and commitments are rebuilt from those shares and fixed
//! structure. The Argon2id salt is random too and travels in the manifest.
//! The tests check that
//!
//! * (a) the current encoder writes exactly these bytes (manifest, hash, record
//!   value, signed record, piece commitments) and re-encodes every share to its
//!   frozen bytes;
//! * (b) the current readers open the set with the right password: the sealed
//!   name, the key check, and every segment back to the plaintext;
//! * (c) a wrong password is refused with the exact message and before any
//!   share is read, and a segment cannot be opened without the password or
//!   with another password's key;
//! * (d) the public parameters of the protection (Argon2id cost, salt and check
//!   lengths, the sealed-name prefix and size) are pinned.
//!
//! Test-only material (publisher seed, password, plaintext) is derived with
//! BLAKE3 from a label (`fill`); no key, nonce, salt or password is a literal.
//! The file was written once by `print_fixtures` (run with
//! `--ignored --nocapture`). Regenerating it after a failing test would hide a
//! break: a new format gets new lines and a new file.

use ed25519_dalek::SigningKey;
use miasma_core::crypto::rs::rs_decode;
use miasma_core::crypto::sss::sss_combine;
use miasma_core::dissolution::segment::{
    dissolve_segment_with_at, retrieve_segment, retrieve_segment_with,
};
use miasma_core::dissolution::SegmentMeta;
use miasma_core::network::sybil::SignedDhtRecord;
use miasma_core::network::types::{DhtRecord, ShardLocation};
use miasma_core::transfer::manifest::{
    decode_record_value, encode_record_value, open_signed_record, SegmentEntry, TransferManifest,
    MANIFEST_VERSION, SEALED_NAME_PREFIX,
};
use miasma_core::transfer::protection::{PasswordProtection, Protection, KEY_CHECK_LEN, SALT_LEN};
use miasma_core::{ContentId, DissolutionParams, MiasmaError, MiasmaShare};

const FIXTURES: &str = include_str!("fixtures/transfer_protected_v1/frozen.hex");

const TS: u64 = 1_700_000_000;
const SEG_SIZE: u32 = 40;
const TOTAL_BYTES: usize = 70;
const NAME: &str = "secret.txt";
/// Argon2id cost used for the fixture: small enough for a debug build.
const COST: (u32, u32, u32) = (64, 1, 1);

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 3,
        total_shards: 5,
    }
}

/// Deterministic test-only bytes: BLAKE3 in key-derivation mode over a label.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h =
        blake3::Hasher::new_derive_key("miasma frozen protected transfer fixtures v1 (test-only)");
    h.update(label.as_bytes());
    let mut out: [u8; N] = std::array::from_fn(|i| i as u8);
    h.finalize_xof().fill(&mut out);
    out
}

fn plaintext() -> [u8; TOTAL_BYTES] {
    fill("protected transfer plaintext")
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
    format!("Fx-{}-#9", hex::encode(fill::<12>("protected password")))
}

fn other_password() -> String {
    format!("Fx-{}-#9", hex::encode(fill::<12>("another password")))
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

/// The ten frozen shares of the two segments: `[segment][slot]`.
fn frozen_segments() -> Vec<Vec<MiasmaShare>> {
    (0..2u32)
        .map(|s| {
            (0..5u16)
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

fn frozen_manifest() -> TransferManifest {
    TransferManifest::from_bytes(&frozen("manifest_password")).unwrap()
}

fn frozen_protection() -> PasswordProtection {
    match frozen_manifest().protection {
        Protection::Password(p) => p,
        Protection::None => panic!("the frozen manifest must be password protected"),
    }
}

fn meta(s: usize) -> SegmentMeta {
    SegmentMeta {
        index: s as u32,
        offset_bytes: segment_bounds(s).0 as u64,
        plaintext_len: (segment_bounds(s).1 - segment_bounds(s).0) as u32,
        share_count: 5,
    }
}

// ─── Values rebuilt from the shares ──────────────────────────────────────────

fn manifest_with(
    segs: &[Vec<MiasmaShare>],
    pp: PasswordProtection,
    key: &miasma_core::transfer::protection::UnlockedKey,
) -> TransferManifest {
    let plain = plaintext();
    let mid = mid();
    let mut m = TransferManifest::new(
        &mid,
        publisher(),
        params(),
        SEG_SIZE,
        TOTAL_BYTES as u64,
        Protection::Password(pp),
    );
    for (i, shares) in segs.iter().enumerate() {
        let (a, b) = segment_bounds(i);
        m.push_segment(SegmentEntry::from_dissolved(i as u32, &mid, &plain[a..b], shares).unwrap())
            .unwrap();
    }
    m.with_sealed_name(Some(NAME), key)
}

fn record() -> DhtRecord {
    DhtRecord {
        mid_digest: *mid().as_bytes(),
        data_shards: 3,
        total_shards: 5,
        version: 1,
        locations: (0..2u16)
            .map(|i| ShardLocation {
                peer_id_bytes: fill::<32>(&format!("peer {i}")).to_vec(),
                shard_index: i,
                segment_index: 0,
                addrs: vec![format!("/ip4/127.0.0.1/tcp/{}", 4101 + i)],
            })
            .collect(),
        published_at: TS,
    }
}

/// Every value derived from the manifest and shares: name and the bytes now.
fn rebuilt(m: &TransferManifest, segs: &[Vec<MiasmaShare>]) -> Vec<(String, Vec<u8>)> {
    let value = encode_record_value(&record(), Some(m)).unwrap();
    let signed = SignedDhtRecord::sign(record().dht_key(), value.clone(), &signing_key());
    let mut commitments = Vec::new();
    for shares in segs {
        for s in shares {
            commitments.extend_from_slice(&s.piece_commitment(&mid()));
        }
    }
    vec![
        (
            "manifest_password_hash".into(),
            m.manifest_hash().unwrap().to_vec(),
        ),
        (
            "manifest_password_trailer".into(),
            m.encode_trailer().unwrap(),
        ),
        ("record_value".into(), value),
        ("signed_record".into(), bincode::serialize(&signed).unwrap()),
        ("piece_commitments".into(), commitments),
    ]
}

// ─── (a) the encoder writes the frozen bytes ─────────────────────────────────

#[test]
fn the_current_encoder_writes_the_frozen_bytes() {
    let segs = frozen_segments();
    let m = frozen_manifest();
    // The manifest as read now is written back to the same bytes.
    assert!(
        m.to_bytes().unwrap() == frozen("manifest_password"),
        "the manifest is not re-encoded to its frozen bytes"
    );
    for (name, bytes) in rebuilt(&m, &segs) {
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
            assert_eq!(share.version, 1);
            assert_eq!(share.segment_index as usize, s);
            assert_eq!(share.slot_index as usize, slot);
            assert_eq!(share.timestamp, TS);
            assert_eq!(share.original_len as usize, meta(s).plaintext_len as usize);
        }
    }
}

// ─── (b) the readers open it with the right password ─────────────────────────

#[test]
fn the_right_password_opens_the_name_and_every_segment() {
    let m = frozen_manifest();
    let pp = frozen_protection();
    let key = pp.unlock(&transfer_password()).expect("right password");
    assert_eq!(m.original_name(Some(&key)).as_deref(), Some(NAME));

    let segs = frozen_segments();
    let plain = plaintext();
    let mid = mid();
    let mut joined = Vec::new();
    for (i, shares) in segs.iter().enumerate() {
        // Any three of the five shares are enough: the first three, then the last three.
        for pick in [&shares[..3], &shares[2..]] {
            let part = retrieve_segment_with(&mid, pick, &meta(i), params(), Some(&key)).unwrap();
            assert_eq!(
                *blake3::hash(&part).as_bytes(),
                m.segments[i].plain_hash,
                "plain_hash of segment {i}"
            );
            let (a, b) = segment_bounds(i);
            assert_eq!(part, plain[a..b]);
        }
        joined.extend_from_slice(
            &retrieve_segment_with(&mid, &shares[1..4], &meta(i), params(), Some(&key)).unwrap(),
        );
    }
    assert_eq!(joined, plain);
}

#[test]
fn the_segment_ciphertext_is_aes_gcm_under_the_hkdf_segment_key_without_aad() {
    // Take a segment apart with the public primitives: the key shares give
    // `K_enc`, the shards give the ciphertext, and the AES key is the HKDF
    // output of the password key, not `K_enc` itself.
    let key = frozen_protection()
        .unlock(&transfer_password())
        .expect("right password");
    let mid = mid();
    let plain = plaintext();
    for (s, shares) in frozen_segments().iter().enumerate() {
        let sel = &shares[1..4];
        let k_enc = sss_combine(
            &sel.iter().map(|x| x.key_share.clone()).collect::<Vec<_>>(),
            3,
        )
        .unwrap();
        let rs: Vec<(usize, Vec<u8>)> = sel
            .iter()
            .map(|x| (x.slot_index as usize, x.shard_data.clone()))
            .collect();
        let m = meta(s);
        let ct = rs_decode(&rs, 3, 5, m.plaintext_len as usize + 16).unwrap();
        let k_seg = key.segment_key(&k_enc, &mid, s as u32).unwrap();
        assert_ne!(
            k_seg.as_slice(),
            k_enc.as_slice(),
            "the AES key is not K_enc"
        );
        let nonce = sel[0].nonce;
        let (a, b) = segment_bounds(s);
        // Decrypts under the derived key, with no associated data...
        let out = miasma_core::crypto::aead::decrypt(&ct, &k_seg, &nonce).unwrap();
        assert_eq!(out, plain[a..b]);
        // ...encrypting again gives the very same bytes (nonce = the shares' nonce)...
        assert!(
            miasma_core::crypto::aead::encrypt_with_key(&plain[a..b], &k_seg, &nonce).unwrap()
                == ct
        );
        // ...and K_enc alone does not open it.
        let raw: [u8; 32] = k_enc.as_slice().try_into().unwrap();
        assert!(miasma_core::crypto::aead::decrypt(&ct, &raw, &nonce).is_err());
        // Segment keys are bound to the segment index.
        let other = key.segment_key(&k_enc, &mid, s as u32 + 1).unwrap();
        assert!(miasma_core::crypto::aead::decrypt(&ct, &other, &nonce).is_err());
    }
}

#[test]
fn the_decoder_reads_the_frozen_record_value_and_signed_record() {
    let (rec, m) = decode_record_value(&frozen("record_value")).unwrap();
    assert_eq!(rec.mid_digest, *mid().as_bytes());
    assert_eq!((rec.data_shards, rec.total_shards, rec.version), (3, 5, 1));
    let m = m.expect("the value carries a manifest");
    assert_eq!(m.to_bytes().unwrap(), frozen("manifest_password"));

    let key = record().dht_key();
    let opened = open_signed_record(&key, &frozen("signed_record"), Some(&publisher())).unwrap();
    assert_eq!(opened.signer, publisher());
    assert_eq!(
        opened.manifest.unwrap().to_bytes().unwrap(),
        frozen("manifest_password")
    );
}

// ─── (c) wrong password and missing password ─────────────────────────────────

#[test]
fn a_wrong_password_is_refused_with_the_exact_message_before_any_share_is_read() {
    let pp = frozen_protection();
    for wrong in [
        other_password(),
        format!("{}x", transfer_password()),
        transfer_password().to_uppercase(),
        String::new(),
    ] {
        let err = match pp.unlock(&wrong) {
            Err(e) => e,
            Ok(_) => panic!("a wrong password must not unlock"),
        };
        assert!(matches!(err, MiasmaError::WrongPassword));
        assert_eq!(err.to_string(), "wrong password");
    }
}

#[test]
fn a_segment_cannot_be_opened_without_the_password_or_with_another_key() {
    let segs = frozen_segments();
    let mid = mid();
    // No key at all: the AEAD refuses.
    let err = retrieve_segment(&mid, &segs[0][..3], &meta(0), params()).unwrap_err();
    assert!(
        err.to_string().starts_with("decryption failed"),
        "unexpected text: {err}"
    );
    // The key of another password (a different salt and key): the AEAD refuses.
    let (_, foreign) =
        PasswordProtection::create_with_cost(&other_password(), COST.0, COST.1, COST.2).unwrap();
    let err =
        retrieve_segment_with(&mid, &segs[0][..3], &meta(0), params(), Some(&foreign)).unwrap_err();
    assert!(
        err.to_string().starts_with("decryption failed"),
        "unexpected text: {err}"
    );
    // A flipped ciphertext byte is caught by the tag.
    let key = frozen_protection().unlock(&transfer_password()).unwrap();
    let mut bad = segs[1][..3].to_vec();
    bad[0].shard_data[0] ^= 1;
    // (the share's own hash no longer matches, so it is dropped before the AEAD)
    assert!(retrieve_segment_with(&mid, &bad, &meta(1), params(), Some(&key)).is_err());
    let mut bad = segs[1][..3].to_vec();
    for b in bad.iter_mut() {
        b.shard_data[0] ^= 1;
        b.shard_hash = *blake3::hash(&b.shard_data).as_bytes();
    }
    let err = retrieve_segment_with(&mid, &bad, &meta(1), params(), Some(&key)).unwrap_err();
    assert!(err.to_string().starts_with("decryption failed"));
}

#[test]
fn the_sealed_name_is_unreadable_without_the_key_and_in_another_transfer() {
    let m = frozen_manifest();
    assert!(m.name_is_sealed());
    assert!(m.original_name(None).is_none());
    let key = frozen_protection().unlock(&transfer_password()).unwrap();
    let sealed = frozen("sealed_name");
    assert_eq!(key.open_name(&mid(), &sealed).as_deref(), Some(NAME));
    // Bound to the transfer: another MID does not open it.
    let elsewhere = ContentId::compute(b"another file", &params().to_param_bytes());
    assert!(key.open_name(&elsewhere, &sealed).is_none());
    // A flipped bit anywhere (nonce, ciphertext or tag) is refused.
    for i in [0, 11, 12, sealed.len() - 1] {
        let mut t = sealed.clone();
        t[i] ^= 1;
        assert!(key.open_name(&mid(), &t).is_none(), "byte {i}");
    }
}

// ─── (d) the public parameters ───────────────────────────────────────────────

#[test]
fn the_public_parameters_and_the_sealed_name_are_pinned() {
    let bytes = frozen("manifest_password");
    assert_eq!(MANIFEST_VERSION, 3);
    assert_eq!(bytes[0], 3, "manifest version byte");
    let m = frozen_manifest();
    let pp = frozen_protection();
    assert_eq!((pp.m_kib, pp.t_cost, pp.p_cost), (64, 1, 1));
    assert_eq!(pp.salt.len(), SALT_LEN);
    assert_eq!(SALT_LEN, 16);
    assert_eq!(pp.key_check.len(), KEY_CHECK_LEN);
    assert_eq!(KEY_CHECK_LEN, 16);
    // The protection travels as `Protection::Password` (second variant: index 1
    // as a u32le) with the three costs, the salt and the check.
    let mut want = Vec::new();
    want.extend_from_slice(&1u32.to_le_bytes());
    want.extend_from_slice(&pp.m_kib.to_le_bytes());
    want.extend_from_slice(&pp.t_cost.to_le_bytes());
    want.extend_from_slice(&pp.p_cost.to_le_bytes());
    want.extend_from_slice(&pp.salt);
    want.extend_from_slice(&pp.key_check);
    assert!(
        bytes.windows(want.len()).any(|w| w == want.as_slice()),
        "the password protection is not laid out as documented"
    );
    // The salt is the one in the frozen file, not a freshly drawn one.
    assert_eq!(pp.salt.to_vec(), frozen("pw_salt"));
    assert_eq!(pp.key_check.to_vec(), frozen("pw_key_check"));

    // The name is carried sealed: prefix, then URL-safe base64 of
    // nonce(12) || ciphertext(len of the name) || tag(16).
    assert_eq!(SEALED_NAME_PREFIX, "miasma-sealed-name-v1:");
    let name = m.name.as_deref().unwrap();
    let b64 = name
        .strip_prefix(SEALED_NAME_PREFIX)
        .expect("sealed prefix");
    assert!(
        !name.contains(NAME),
        "the clear name must not be in the manifest"
    );
    let sealed = frozen("sealed_name");
    assert_eq!(sealed.len(), 12 + NAME.len() + 16);
    assert_eq!(b64.len(), (sealed.len() * 4).div_ceil(3));
    assert!(!b64.contains('=') && !b64.contains('+') && !b64.contains('/'));
    // The sealed name in the manifest is the frozen one.
    use base64::Engine as _;
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .unwrap(),
        sealed
    );
    // Segment structure of the manifest.
    assert_eq!((m.data_shards, m.total_shards), (3, 5));
    assert_eq!(m.segment_size, SEG_SIZE);
    assert_eq!(m.total_bytes, TOTAL_BYTES as u64);
    assert_eq!(m.segments.len(), 2);
    assert_eq!(&m.mid, mid().as_bytes());
    assert_eq!(m.publisher, publisher());
}

// ─── Generator (run once, by hand) ───────────────────────────────────────────

/// Prints every line of `frozen.hex`. Run with
/// `cargo test --test wire_compat_transfer_protected_test print_fixtures -- --ignored --nocapture`
/// and put the `FIXTURE` lines (without that word) into the file. Only for a
/// new format: never to make a failing test pass.
#[test]
#[ignore = "prints the fixture file; run by hand, once"]
fn print_fixtures() {
    let plain = plaintext();
    let mid = mid();
    let pw = transfer_password();
    let (pp, key) = PasswordProtection::create_with_cost(&pw, COST.0, COST.1, COST.2).unwrap();
    let mut segs: Vec<Vec<MiasmaShare>> = Vec::new();
    for s in 0..2usize {
        let (a, b) = segment_bounds(s);
        let (_, shares) = dissolve_segment_with_at(
            &plain[a..b],
            &mid,
            s as u32,
            a as u64,
            params(),
            Some(&key),
            TS,
        )
        .unwrap();
        assert_eq!(shares.len(), 5);
        for (slot, share) in shares.iter().enumerate() {
            println!(
                "FIXTURE seg{s}_share{slot} {}",
                hex::encode(share.to_bytes().unwrap())
            );
        }
        segs.push(shares);
    }
    let m = manifest_with(&segs, pp.clone(), &key);
    println!(
        "FIXTURE manifest_password {}",
        hex::encode(m.to_bytes().unwrap())
    );
    for (name, bytes) in rebuilt(&m, &segs) {
        println!("FIXTURE {name} {}", hex::encode(bytes));
    }
    println!("FIXTURE pw_salt {}", hex::encode(pp.salt));
    println!("FIXTURE pw_key_check {}", hex::encode(pp.key_check));
    // The sealed name as carried in the manifest.
    let mid_for_name = mid;
    let sealed = key.seal_name(&mid_for_name, NAME).unwrap();
    // `with_sealed_name` seals with a fresh nonce, so take the one in the manifest.
    use base64::Engine as _;
    let carried = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(
            m.name
                .as_deref()
                .unwrap()
                .strip_prefix(SEALED_NAME_PREFIX)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(carried.len(), sealed.len());
    println!("FIXTURE sealed_name {}", hex::encode(carried));
}
