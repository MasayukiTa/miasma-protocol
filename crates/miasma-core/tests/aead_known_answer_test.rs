//! Known-answer tests for the encryption of shares: fixed inputs, fixed bytes.
//!
//! A change of a label, of the nonce layout, of the associated data or of the
//! key schedule makes a share that a released build wrote unreadable (or lets
//! an old build accept something it should not). These tests fail on any such
//! change, because they compare against bytes written once and never again.
//!
//! What is pinned, with the function that does it:
//!
//! * AES-256-GCM as used for every segment and the whole-file path:
//!   `miasma_core::crypto::aead::encrypt_with_key` / `decrypt`. The output is
//!   `ciphertext || 16-byte tag`, with the 12-byte nonce kept outside, and no
//!   associated data. Lengths 0, 1, 15, 16, 17 and 64 cover the block
//!   boundaries.
//! * The password key schedule of
//!   `miasma_core::transfer::protection::PasswordProtection::unlock`
//!   (Argon2id v0x13 -> `pw_key`), the wrong-password check
//!   (`HKDF-SHA256(salt = none, ikm = pw_key, info = "miasma-pw-check-v1")`),
//!   the segment key `UnlockedKey::segment_key`
//!   (`HKDF-SHA256(salt = pw_key, ikm = K_enc,
//!   info = "miasma-seg-key-v1" || mid || segment_index_le)`), and the sealed
//!   name `UnlockedKey::seal_name` / `open_name`
//!   (`HKDF-SHA256(salt = pw_key, ikm = mid, info = "miasma-name-key-v1")`).
//!   Each is also recomputed here from the primitives with the label spelled
//!   out, so a label that changes in the library cannot also change here.
//! * The segment pipeline without a password
//!   (`dissolve_segment_with_at` / `retrieve_segment`): the AES key is
//!   `K_enc` itself, the nonce is the one stored in every share.
//! * The whole-file path (`pipeline::dissolve_at` / `retrieve`): same key rule.
//!
//! Inputs are derived with BLAKE3 from a label (`fill`): no key, nonce, salt
//! or password is a literal in this file. Expected bytes are in
//! `tests/fixtures/aead_kat_v1/frozen.hex`, written once by `print_fixtures`
//! (`--ignored --nocapture`). The shares of the two paths without a password
//! are read from the frozen set of `wire_compat_transfer_test.rs`
//! (`tests/fixtures/transfer_v3/frozen.hex`), which this file never changes.
//! A new suite gets a new file; these lines are never regenerated to make a
//! failing test pass.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use miasma_core::crypto::aead::{decrypt, encrypt_with_key, KEY_LEN, NONCE_LEN};
use miasma_core::crypto::rs::rs_decode;
use miasma_core::crypto::sss::sss_combine;
use miasma_core::dissolution::segment::retrieve_segment;
use miasma_core::dissolution::SegmentMeta;
use miasma_core::transfer::protection::{PasswordProtection, KEY_CHECK_LEN, SALT_LEN};
use miasma_core::{retrieve, ContentId, DissolutionParams, MiasmaError, MiasmaShare};
use sha2::Sha256;

const FIXTURES: &str = include_str!("fixtures/aead_kat_v1/frozen.hex");
const TRANSFER_FIXTURES: &str = include_str!("fixtures/transfer_v3/frozen.hex");

const LENGTHS: [usize; 6] = [0, 1, 15, 16, 17, 64];
const COST: (u32, u32, u32) = (64, 1, 1);
const NAME: &str = "kat-name.txt";

/// Deterministic test-only bytes: BLAKE3 in key-derivation mode over a label.
fn fill_vec(label: &str, len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("miasma aead known answers v1 (test-only)");
    h.update(label.as_bytes());
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

fn fill<const N: usize>(label: &str) -> [u8; N] {
    fill_vec(label, N).try_into().unwrap()
}

fn lookup(text: &str, name: &str) -> Vec<u8> {
    for line in text.lines() {
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

fn frozen(name: &str) -> Vec<u8> {
    lookup(FIXTURES, name)
}

fn transfer_frozen(name: &str) -> Vec<u8> {
    lookup(TRANSFER_FIXTURES, name)
}

fn aes_key() -> [u8; KEY_LEN] {
    fill("aes key")
}

fn aes_nonce() -> [u8; NONCE_LEN] {
    fill("aes nonce")
}

fn message(len: usize) -> Vec<u8> {
    fill_vec(&format!("message {len}"), len)
}

// ─── Primitive recomputation (no library helper involved) ────────────────────

fn password() -> String {
    format!("Fx-{}-#9", hex::encode(fill::<12>("password")))
}

fn salt() -> [u8; SALT_LEN] {
    fill("argon2 salt")
}

fn k_enc() -> [u8; 32] {
    fill("segment random key K_enc")
}

fn kat_params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 3,
        total_shards: 5,
    }
}

fn kat_mid() -> ContentId {
    ContentId::compute(&message(64), &kat_params().to_param_bytes())
}

fn other_mid() -> ContentId {
    ContentId::compute(&message(63), &kat_params().to_param_bytes())
}

fn indep_pw_key(pw: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let params = Params::new(COST.0, COST.1, COST.2, Some(32)).unwrap();
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pw.as_bytes(), salt, &mut out)
        .unwrap();
    out
}

fn indep_key_check(pw_key: &[u8; 32]) -> [u8; KEY_CHECK_LEN] {
    let mut out = [0u8; KEY_CHECK_LEN];
    Hkdf::<Sha256>::new(None, pw_key)
        .expand(b"miasma-pw-check-v1", &mut out)
        .unwrap();
    out
}

fn indep_segment_key(pw_key: &[u8; 32], k_enc: &[u8], mid: &ContentId, index: u32) -> [u8; 32] {
    let mut info = b"miasma-seg-key-v1".to_vec();
    info.extend_from_slice(mid.as_bytes());
    info.extend_from_slice(&index.to_le_bytes());
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(pw_key), k_enc)
        .expand(&info, &mut out)
        .unwrap();
    out
}

fn indep_name_key(pw_key: &[u8; 32], mid: &ContentId) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(pw_key), mid.as_bytes())
        .expand(b"miasma-name-key-v1", &mut out)
        .unwrap();
    out
}

/// A `PasswordProtection` with the fixed salt and the key check as the
/// primitives compute it, as the manifest would carry it.
fn protection_from(pw_key: &[u8; 32]) -> PasswordProtection {
    PasswordProtection {
        m_kib: COST.0,
        t_cost: COST.1,
        p_cost: COST.2,
        salt: salt(),
        key_check: indep_key_check(pw_key),
    }
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

#[test]
fn aes_256_gcm_known_answers() {
    let (key, nonce) = (aes_key(), aes_nonce());
    for len in LENGTHS {
        let pt = message(len);
        let want = frozen(&format!("gcm_{len}"));
        let ct = encrypt_with_key(&pt, &key, &nonce).unwrap();
        assert!(ct == want, "ciphertext for {len} bytes differs");
        // `ciphertext || tag`: the tag is 16 bytes at the end.
        assert_eq!(ct.len(), len + 16);
        assert_eq!(decrypt(&ct, &key, &nonce).unwrap(), pt);
        // Any single flipped bit (body, tag, nonce, key) is refused.
        for i in [0, ct.len() / 2, ct.len() - 1] {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            assert!(decrypt(&bad, &key, &nonce).is_err(), "byte {i} of {len}");
        }
        let mut n2 = nonce;
        n2[0] ^= 1;
        assert!(decrypt(&ct, &key, &n2).is_err());
        let mut k2 = key;
        k2[31] ^= 1;
        assert!(decrypt(&ct, &k2, &nonce).is_err());
    }
}

#[test]
fn the_ciphertext_is_aes_gcm_with_no_associated_data() {
    let (key, nonce) = (aes_key(), aes_nonce());
    let pt = message(33);
    let ct = encrypt_with_key(&pt, &key, &nonce).unwrap();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let n = Nonce::from_slice(&nonce);
    // Opens as plain AES-GCM with empty AAD, and with nothing else.
    let ok = cipher
        .decrypt(n, Payload { msg: &ct, aad: b"" })
        .expect("empty AAD");
    assert_eq!(ok, pt);
    assert!(cipher
        .decrypt(
            n,
            Payload {
                msg: &ct,
                aad: b"x"
            }
        )
        .is_err());
    // And what the library writes is what plain AES-GCM writes.
    let same = cipher.encrypt(n, Payload { msg: &pt, aad: b"" }).unwrap();
    assert_eq!(same, ct);
}

// ─── Password key schedule ───────────────────────────────────────────────────

#[test]
fn the_password_key_schedule_gives_the_frozen_keys() {
    let pw = password();
    let pw_key = indep_pw_key(&pw, &salt());
    assert_eq!(pw_key.to_vec(), frozen("pw_key"), "Argon2id output");
    let check = indep_key_check(&pw_key);
    assert_eq!(check.to_vec(), frozen("pw_key_check"), "key check");

    // The library accepts that check for that password, from the fixed salt.
    let pp = protection_from(&pw_key);
    let unlocked = pp.unlock(&pw).expect("right password");

    let mid = kat_mid();
    let ke = k_enc();
    let cases = [
        ("seg_key_0", mid.clone(), 0u32),
        ("seg_key_1", mid.clone(), 1u32),
        ("seg_key_other_mid", other_mid(), 0u32),
    ];
    for (name, m, idx) in cases {
        let from_lib = unlocked.segment_key(&ke, &m, idx).unwrap();
        let from_primitives = indep_segment_key(&pw_key, &ke, &m, idx);
        assert_eq!(
            from_lib.as_slice(),
            &from_primitives,
            "{name}: library vs primitives"
        );
        assert_eq!(
            from_primitives.to_vec(),
            frozen(name),
            "{name}: frozen bytes"
        );
    }

    // One encrypted segment: the segment key, the stored nonce, no AAD.
    let ct = encrypt_with_key(
        &message(64),
        &indep_segment_key(&pw_key, &ke, &mid, 0),
        &aes_nonce(),
    )
    .unwrap();
    assert!(ct == frozen("seg_ct_0"), "segment ciphertext differs");
}

#[test]
fn a_wrong_password_is_refused_with_the_exact_message() {
    let pw_key = indep_pw_key(&password(), &salt());
    let pp = protection_from(&pw_key);
    let other = format!("Fx-{}-#9", hex::encode(fill::<12>("another password")));
    for wrong in [other, format!("{}x", password()), String::new()] {
        let err = match pp.unlock(&wrong) {
            Err(e) => e,
            Ok(_) => panic!("a wrong password must not unlock"),
        };
        assert!(matches!(err, MiasmaError::WrongPassword));
        assert_eq!(err.to_string(), "wrong password");
    }
}

#[test]
fn the_sealed_name_is_bound_to_the_password_key_and_the_mid() {
    let pw = password();
    let pw_key = indep_pw_key(&pw, &salt());
    let unlocked = protection_from(&pw_key).unlock(&pw).unwrap();
    let sealed = frozen("name_sealed");
    // Layout: nonce(12) || ciphertext || tag(16).
    assert_eq!(sealed.len(), NONCE_LEN + NAME.len() + 16);
    assert_eq!(
        unlocked.open_name(&kat_mid(), &sealed).as_deref(),
        Some(NAME)
    );
    // Recomputed with the label spelled out, no library helper.
    let key = indep_name_key(&pw_key, &kat_mid());
    let plain = decrypt(
        &sealed[NONCE_LEN..],
        &key,
        sealed[..NONCE_LEN].try_into().unwrap(),
    )
    .expect("name key from the primitives");
    assert_eq!(plain, NAME.as_bytes());
    // Not another transfer's name, not with a flipped bit.
    assert!(unlocked.open_name(&other_mid(), &sealed).is_none());
    let mut bad = sealed.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(unlocked.open_name(&kat_mid(), &bad).is_none());
}

// ─── The two paths without a password, read from the #130 shares ─────────────

/// Take a set of shares apart with the public primitives and return
/// `(K_enc, ciphertext, nonce)`.
fn take_apart(shares: &[MiasmaShare], k: usize, n: usize) -> (Vec<u8>, Vec<u8>, [u8; NONCE_LEN]) {
    let sel = &shares[1..1 + k];
    let k_enc = sss_combine(
        &sel.iter().map(|x| x.key_share.clone()).collect::<Vec<_>>(),
        k as u8,
    )
    .unwrap();
    let rs: Vec<(usize, Vec<u8>)> = sel
        .iter()
        .map(|x| (x.slot_index as usize, x.shard_data.clone()))
        .collect();
    let ct = rs_decode(&rs, k, n, sel[0].original_len as usize + 16).unwrap();
    (k_enc.to_vec(), ct, sel[0].nonce)
}

#[test]
fn a_plain_segment_is_aes_gcm_under_k_enc_with_the_stored_nonce() {
    let mid = ContentId::compute(
        &fill_vec_transfer_plaintext(),
        &DissolutionParams {
            data_shards: 4,
            total_shards: 6,
        }
        .to_param_bytes(),
    );
    let params = DissolutionParams {
        data_shards: 4,
        total_shards: 6,
    };
    for s in 0..2u32 {
        let shares: Vec<MiasmaShare> = (0..6u16)
            .map(|slot| {
                MiasmaShare::from_bytes(&transfer_frozen(&format!("seg{s}_share{slot}"))).unwrap()
            })
            .collect();
        let meta = SegmentMeta {
            index: s,
            offset_bytes: if s == 0 { 0 } else { 64 },
            plaintext_len: shares[0].original_len,
            share_count: 6,
        };
        let plain = retrieve_segment(&mid, &shares[2..], &meta, params).unwrap();
        let (k_enc, ct, nonce) = take_apart(&shares, 4, 6);
        assert_eq!(k_enc.len(), KEY_LEN);
        let key: [u8; KEY_LEN] = k_enc.as_slice().try_into().unwrap();
        // The AES key is K_enc itself; the nonce is the one in every share.
        assert_eq!(decrypt(&ct, &key, &nonce).unwrap(), plain);
        assert!(
            encrypt_with_key(&plain, &key, &nonce).unwrap() == ct,
            "re-encrypting segment {s} does not give the stored ciphertext"
        );
        assert!(shares.iter().all(|x| x.nonce == nonce));
    }
}

/// The 100-byte plaintext of the #130 transfer set (same derivation).
fn fill_vec_transfer_plaintext() -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("miasma frozen transfer fixtures v3 (test-only)");
    h.update(b"transfer plaintext");
    let mut out = vec![0u8; 100];
    h.finalize_xof().fill(&mut out);
    out
}

#[test]
fn the_whole_file_path_is_aes_gcm_under_k_enc_with_the_stored_nonce() {
    const PLAIN: &[u8] = b"frozen whole-file share set, version one";
    let params = DissolutionParams {
        data_shards: 3,
        total_shards: 5,
    };
    let mid =
        ContentId::from_str(&String::from_utf8(transfer_frozen("legacy_mid")).unwrap()).unwrap();
    let shares: Vec<MiasmaShare> = (0..5)
        .map(|i| MiasmaShare::from_bytes(&transfer_frozen(&format!("legacy_share{i}"))).unwrap())
        .collect();
    assert_eq!(retrieve(&mid, &shares[1..4], params).unwrap(), PLAIN);
    let (k_enc, ct, nonce) = take_apart(&shares, 3, 5);
    let key: [u8; KEY_LEN] = k_enc.as_slice().try_into().unwrap();
    assert_eq!(decrypt(&ct, &key, &nonce).unwrap(), PLAIN);
    assert!(encrypt_with_key(PLAIN, &key, &nonce).unwrap() == ct);
    // The MID binds the plaintext and the parameters string.
    assert_eq!(params.to_param_bytes(), b"k=3,n=5,v=1");
    assert_eq!(mid, ContentId::compute(PLAIN, b"k=3,n=5,v=1"));
}

// ─── Generator (run once, by hand) ───────────────────────────────────────────

/// Prints every line of `frozen.hex`. Run with
/// `cargo test --test aead_known_answer_test print_fixtures -- --ignored --nocapture`
/// and put the `FIXTURE` lines (without that word) into the file. Only for a
/// new suite: never to make a failing test pass.
#[test]
#[ignore = "prints the fixture file; run by hand, once"]
fn print_fixtures() {
    let (key, nonce) = (aes_key(), aes_nonce());
    for len in LENGTHS {
        let ct = encrypt_with_key(&message(len), &key, &nonce).unwrap();
        println!("FIXTURE gcm_{len} {}", hex::encode(ct));
    }
    let pw = password();
    let pw_key = indep_pw_key(&pw, &salt());
    println!("FIXTURE pw_key {}", hex::encode(pw_key));
    println!(
        "FIXTURE pw_key_check {}",
        hex::encode(indep_key_check(&pw_key))
    );
    let unlocked = protection_from(&pw_key).unlock(&pw).unwrap();
    let (mid, ke) = (kat_mid(), k_enc());
    for (name, m, idx) in [
        ("seg_key_0", mid.clone(), 0u32),
        ("seg_key_1", mid.clone(), 1u32),
        ("seg_key_other_mid", other_mid(), 0u32),
    ] {
        let k = unlocked.segment_key(&ke, &m, idx).unwrap();
        println!("FIXTURE {name} {}", hex::encode(k.as_slice()));
    }
    let seg0 = unlocked.segment_key(&ke, &mid, 0).unwrap();
    let ct = encrypt_with_key(&message(64), &seg0, &nonce).unwrap();
    println!("FIXTURE seg_ct_0 {}", hex::encode(ct));
    let sealed = unlocked.seal_name(&mid, NAME).unwrap();
    println!("FIXTURE name_sealed {}", hex::encode(sealed));
}
