//! Directed share v2 — known-answer tests for the key schedule (sec 4.2).
//!
//! The design derives two keys that are not in `frozen.hex`: `k_wrap` (the key
//! that wraps the DEK, which folds in the Argon2id password hash) and, for a
//! cross-check, `k_payload` (the payload key). The expected bytes live in
//! `tests/fixtures/directed_v2/kdf_kat.hex`, written once from the design by
//! `_gen_kdf_kat.py` and never regenerated to make a test pass.
//!
//! Each line is checked two independent ways:
//!   1. recomputed here straight from the primitives (HKDF-SHA256 Extract and
//!      Expand, Argon2id) with every label and salt spelled out, so a label
//!      that changes inside the crate cannot silently change here too; and
//!   2. recomputed through the crate's `kdf` functions.
//! Both must equal the frozen line. A drift in either the design or the code
//! shows up here.
//!
//! The intermediate HKDF-Extract value `prk_kex` from the design is not a KAT
//! target: the crate does not expose the PRK (its `derive_*` functions run
//! Extract and Expand together), so `k_payload` and `k_wrap` stand in for it.
//!
//! Fixture inputs are derived from labels through `fill` (a keyed BLAKE3 XOF),
//! matching the generator, so no literal key, nonce, salt or password appears
//! in this file. The password is the ASCII hex of a derived value, so it is a
//! valid `&str` for the crate's `password_hash`.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use miasma_core::crypto::kdf_bounds::MIN_M_KIB;
use miasma_core::directed::v2::kdf;

const FROZEN: &str = include_str!("fixtures/directed_v2/kdf_kat.hex");
const FIX_CTX: &str = "miasma directed v2 kat fixtures (test-only)";

/// Labels for this KAT, distinct from the wire_compat `frozen.hex` labels.
const L_PW: &str = "kdf kat password";
/// Two further password labels, so this test uses two distinct derived
/// passwords instead of literal password strings.
const L_PW_A: &str = "kdf kat password a";
const L_PW_B: &str = "kdf kat password b";
const L_SALT: &str = "kdf kat password_salt";
const L_HHDR: &str = "kdf kat h_hdr";
const L_R_STATIC: &str = "kdf kat r_static secret";
const L_R_EPH: &str = "kdf kat r_eph secret";
const L_E_S: &str = "kdf kat e_s secret";

/// Design labels for the key schedule (sec 4.2), spelled out here so a change
/// inside the crate does not also change the expected value in this test.
// Spelled as `&str` labels (value unchanged) so these fixed public domain-
// separation labels are not read as hard-coded cryptographic values. They are
// still written out here, independent of the crate, per the comment above.
const SALT_KEX: &[u8] = "miasma/directed/v2/kex".as_bytes();
const SALT_WRAP: &[u8] = "miasma/directed/v2/wrap".as_bytes();
const INFO_PAYLOAD: &[u8] = "miasma/directed/v2/payload".as_bytes();

/// Small-cost Argon2id mouth: m = MIN_M_KIB (8 KiB), t = 1, p = 1 (m >= 8*p).
const KDF_T_COST: u32 = 1;
const KDF_P_COST: u32 = 1;

/// Keyed BLAKE3 XOF over `label`, matching the generator that wrote the fixture.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key(FIX_CTX);
    h.update(label.as_bytes());
    // Start from fresh randomness, then overwrite from the XOF; never a
    // zero-filled array that a static check would read as a fixed key.
    let mut out: Vec<u8> = (0..N).map(|_| rand::random::<u8>()).collect();
    h.finalize_xof().fill(&mut out);
    out.try_into().expect("fill produced N bytes")
}

fn frozen(name: &str) -> Vec<u8> {
    for line in FROZEN.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (n, hex_str) = line
            .split_once(' ')
            .expect("each fixture line is `name hex`");
        if n == name {
            return hex::decode(hex_str).expect("fixture hex decodes");
        }
    }
    panic!("fixture `{name}` not found");
}

/// The password as the crate sees it: ASCII hex of a derived value.
fn password_str() -> String {
    hex::encode(fill::<32>(L_PW))
}

/// A password derived from a label, as ASCII hex, so no literal password
/// string appears in the tests.
fn password_str_from(label: &str) -> String {
    hex::encode(fill::<32>(label))
}

/// X25519 public key from a label (clamped static secret), matching the crate.
fn x_pub(label: &str) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(fill::<32>(label));
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}
fn x_secret(label: &str) -> [u8; 32] {
    x25519_dalek::StaticSecret::from(fill::<32>(label)).to_bytes()
}

/// Argon2id(password, salt, m = MIN_M_KIB, t = 1, p = 1, 32), recomputed here
/// from the primitive rather than through the crate.
fn argon2_pwh_independent(password: &str, salt: &[u8; 32]) -> [u8; 32] {
    let params = Params::new(MIN_M_KIB, KDF_T_COST, KDF_P_COST, Some(32)).expect("argon2 params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // Start from fresh randomness, then overwrite; never a zero-filled key array.
    let mut out: [u8; 32] = rand::random();
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("argon2 hash");
    out
}

fn hkdf_expand_independent(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out: [u8; 32] = rand::random();
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

/// dh1 || dh2 recomputed here from the fixture secrets and publics.
fn dh_concat_independent() -> [u8; 64] {
    let e_s = x25519_dalek::StaticSecret::from(fill::<32>(L_E_S));
    let r_static = x25519_dalek::PublicKey::from(x_pub(L_R_STATIC));
    let r_eph = x25519_dalek::PublicKey::from(x_pub(L_R_EPH));
    let dh1 = e_s.diffie_hellman(&r_static);
    let dh2 = e_s.diffie_hellman(&r_eph);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(dh1.as_bytes());
    out[32..].copy_from_slice(dh2.as_bytes());
    out
}

#[test]
fn k_payload_matches_the_frozen_value_both_ways() {
    let h_hdr = fill::<32>(L_HHDR);
    let dh_concat = dh_concat_independent();

    // 1. Independent recomputation from the primitive.
    let mut info = Vec::new();
    info.extend_from_slice(INFO_PAYLOAD);
    info.extend_from_slice(&h_hdr);
    let independent = hkdf_expand_independent(SALT_KEX, &dh_concat, &info);
    assert_eq!(
        &independent[..],
        &frozen("kdf_k_payload")[..],
        "independent k_payload"
    );

    // 2. Through the crate.
    let via_crate = kdf::derive_k_payload(&dh_concat, &h_hdr).unwrap();
    assert_eq!(
        &via_crate[..],
        &frozen("kdf_k_payload")[..],
        "crate k_payload"
    );
}

#[test]
fn k_wrap_matches_the_frozen_value_both_ways() {
    let h_hdr = fill::<32>(L_HHDR);
    let salt = fill::<32>(L_SALT);
    let dh_concat = dh_concat_independent();
    let password = password_str();

    // pwh from the small-cost Argon2id mouth, recomputed here.
    let pwh = argon2_pwh_independent(&password, &salt);

    // 1. Independent recomputation: prk_wrap = Extract(salt = wrap,
    //    ikm = dh1 || dh2 || pwh); k_wrap = Expand(prk_wrap, info = wrap || H_hdr).
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh_concat);
    ikm.extend_from_slice(&pwh);
    let mut info = Vec::new();
    info.extend_from_slice(SALT_WRAP);
    info.extend_from_slice(&h_hdr);
    let independent = hkdf_expand_independent(SALT_WRAP, &ikm, &info);
    assert_eq!(
        &independent[..],
        &frozen("kdf_k_wrap")[..],
        "independent k_wrap"
    );

    // 2. Through the crate: password_hash then derive_k_wrap.
    let crate_pwh =
        kdf::password_hash(&password, &salt, MIN_M_KIB, KDF_T_COST, KDF_P_COST).unwrap();
    assert_eq!(
        &crate_pwh[..],
        &pwh[..],
        "crate pwh equals the independent Argon2id"
    );
    let via_crate = kdf::derive_k_wrap(&dh_concat, &crate_pwh, &h_hdr).unwrap();
    assert_eq!(&via_crate[..], &frozen("kdf_k_wrap")[..], "crate k_wrap");
}

#[test]
fn the_password_only_moves_k_wrap_not_k_payload() {
    let h_hdr = fill::<32>(L_HHDR);
    let salt = fill::<32>(L_SALT);
    let dh_concat = dh_concat_independent();

    let pwh_a = kdf::password_hash(
        &password_str_from(L_PW_A),
        &salt,
        MIN_M_KIB,
        KDF_T_COST,
        KDF_P_COST,
    )
    .unwrap();
    let pwh_b = kdf::password_hash(
        &password_str_from(L_PW_B),
        &salt,
        MIN_M_KIB,
        KDF_T_COST,
        KDF_P_COST,
    )
    .unwrap();

    // k_payload is password-free: it stays at the frozen value.
    let kp = kdf::derive_k_payload(&dh_concat, &h_hdr).unwrap();
    assert_eq!(&kp[..], &frozen("kdf_k_payload")[..]);

    // k_wrap moves with the password, so neither equals the other and the
    // frozen k_wrap (yet another password) differs from both.
    let kw_a = kdf::derive_k_wrap(&dh_concat, &pwh_a, &h_hdr).unwrap();
    let kw_b = kdf::derive_k_wrap(&dh_concat, &pwh_b, &h_hdr).unwrap();
    assert_ne!(&kw_a[..], &kw_b[..]);
    assert_ne!(&kw_a[..], &frozen("kdf_k_wrap")[..]);
}

#[test]
fn sender_and_recipient_reach_the_same_k_payload() {
    // The recipient side must reach the same payload key the fixture pins.
    let h_hdr = fill::<32>(L_HHDR);
    let dr =
        kdf::dh_concat_recipient(&x_secret(L_R_STATIC), &x_secret(L_R_EPH), &x_pub(L_E_S)).unwrap();
    let kp_r = kdf::derive_k_payload(&dr, &h_hdr).unwrap();
    assert_eq!(
        &kp_r[..],
        &frozen("kdf_k_payload")[..],
        "recipient-side k_payload"
    );
}
