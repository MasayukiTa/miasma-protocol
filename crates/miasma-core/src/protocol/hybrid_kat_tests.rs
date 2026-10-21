//! Encapsulation / decapsulation checks for the ML-KEM-768 primitive used by
//! `hybrid`.
//!
//! The official FIPS 203 ACVP encapsulation vectors could not be fetched in
//! the environment these tests were written in, so none are embedded here.
//! In their place, every expected value below is computed with SHA-3 / SHAKE
//! directly from the formulas in FIPS 203 (Algorithms 17 and 18), using
//! hash crates that are independent of the `ml-kem` code path:
//!
//! * shared secret  `K = G(m || H(ek))[0..32]`, with `G` = SHA3-512, `H` = SHA3-256
//! * rejection key  `K_bar = J(z || c)`, with `J` = SHAKE256 (32 bytes) and
//!   `z` the last 32 bytes of the 64-byte key-generation seed
//!
//! plus fixed-input regression pins for the ciphertext and key. Replace the
//! pins with the official vectors when they are available offline.

use ml_kem::kem::Decapsulate;
use ml_kem::{DecapsulationKey768, EncapsulationKey768, Key, KeyExport, Seed, B32};
use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

const CT_LEN: usize = 1088;

fn seed_bytes() -> Vec<u8> {
    (0u8..64).collect()
}

fn dk_from_seed() -> DecapsulationKey768 {
    DecapsulationKey768::from_seed(Seed::try_from(&seed_bytes()[..]).unwrap())
}

/// A 32-byte message that differs per `tag`.
fn message(tag: u8) -> B32 {
    let raw: Vec<u8> = (0u8..32)
        .map(|i| i.wrapping_mul(7).wrapping_add(tag))
        .collect();
    B32::try_from(&raw[..]).unwrap()
}

fn h(data: &[u8]) -> Vec<u8> {
    Sha3_256::digest(data).to_vec()
}

fn g(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    for p in parts {
        Digest::update(&mut hasher, p);
    }
    hasher.finalize().to_vec()
}

fn j(z: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut x = Shake256::default();
    x.update(z);
    x.update(ct);
    let mut r = x.finalize_xof();
    let mut out = [0u8; 32];
    r.read(&mut out);
    out
}

fn ek_bytes(dk: &DecapsulationKey768) -> Vec<u8> {
    dk.encapsulation_key().to_bytes().to_vec()
}

#[test]
fn shared_secret_follows_the_fips_203_formula() {
    let dk = dk_from_seed();
    let ek = dk.encapsulation_key();
    let hek = h(&ek_bytes(&dk));
    for tag in [0u8, 1, 0x5a, 0xff] {
        let m = message(tag);
        let (ct, k) = ek.encapsulate_deterministic(&m);
        assert_eq!(ct.len(), CT_LEN);
        let expected = g(&[m.as_ref(), &hek]);
        assert_eq!(k.as_slice(), &expected[..32], "K for message tag {tag}");
        // Same message, same ciphertext (the operation is deterministic).
        let (ct2, k2) = ek.encapsulate_deterministic(&m);
        assert_eq!(ct, ct2);
        assert_eq!(k, k2);
        // And the key holder recovers the same secret.
        assert_eq!(dk.decapsulate(&ct), k);
    }
}

#[test]
fn different_messages_give_different_ciphertexts_and_secrets() {
    let dk = dk_from_seed();
    let ek = dk.encapsulation_key();
    let (ct_a, k_a) = ek.encapsulate_deterministic(&message(1));
    let (ct_b, k_b) = ek.encapsulate_deterministic(&message(2));
    assert_ne!(ct_a, ct_b);
    assert_ne!(k_a, k_b);
}

#[test]
fn a_changed_ciphertext_gives_the_implicit_rejection_key() {
    let seed = seed_bytes();
    let z = &seed[32..];
    let dk = dk_from_seed();
    let (ct, k) = dk
        .encapsulation_key()
        .encapsulate_deterministic(&message(3));
    for pos in [0usize, 1, 10, 500, 1087] {
        let mut bad = ct.clone();
        bad[pos] ^= 0x01;
        let got = dk.decapsulate(&bad);
        assert_ne!(got, k, "flip at {pos} must not give the real secret");
        assert_eq!(
            got.as_slice(),
            &j(z, bad.as_ref())[..],
            "flip at {pos}: not J(z || c)"
        );
    }
}

#[test]
fn an_all_zero_ciphertext_is_rejected_the_same_way() {
    let seed = seed_bytes();
    let dk = dk_from_seed();
    let zero = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(&[0u8; CT_LEN][..]).unwrap();
    assert_eq!(
        dk.decapsulate(&zero).as_slice(),
        &j(&seed[32..], &[0u8; CT_LEN])[..]
    );
}

#[test]
fn another_key_does_not_recover_the_secret() {
    let dk = dk_from_seed();
    let other_seed: Vec<u8> = (64u8..128).collect();
    let other = DecapsulationKey768::from_seed(Seed::try_from(&other_seed[..]).unwrap());
    let (ct, k) = dk
        .encapsulation_key()
        .encapsulate_deterministic(&message(4));
    let got = other.decapsulate(&ct);
    assert_ne!(got, k);
    assert_eq!(got.as_slice(), &j(&other_seed[32..], ct.as_ref())[..]);
}

#[test]
fn an_encapsulation_key_with_an_out_of_range_coefficient_is_refused() {
    let dk = dk_from_seed();
    let mut bytes = ek_bytes(&dk);
    // The first 12-bit coefficient becomes 4095, which is above q = 3329.
    bytes[0] = 0xff;
    bytes[1] |= 0x0f;
    let key = Key::<EncapsulationKey768>::try_from(&bytes[..]).unwrap();
    assert!(EncapsulationKey768::new(&key).is_err());
}

/// Regression pins for fixed inputs (seed 00..3f, message tag 0). These were
/// produced by this crate version, then checked against the formulas above;
/// they are not official vectors.
#[test]
fn fixed_input_pins() {
    let dk = dk_from_seed();
    let (ct, k) = dk
        .encapsulation_key()
        .encapsulate_deterministic(&message(0));
    let ct_hash = hex::encode(Sha3_256::digest(ct.as_slice()));
    let k_hex = hex::encode(k);
    assert_eq!(ct_hash, PIN_CT_SHA3_256);
    assert_eq!(k_hex, PIN_K);
}

const PIN_CT_SHA3_256: &str = "d1a2bb06a654f6a782e869c682616f2d5fb3d9623915c39c619d164322a5cd50";
const PIN_K: &str = "e8d298689c230e8d1c13b952999c5e717e6b1e9f07a0d01839466215a57d2cd6";
