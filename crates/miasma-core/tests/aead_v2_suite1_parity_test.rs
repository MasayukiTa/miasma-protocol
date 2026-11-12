//! Suite1 stays byte-for-byte what the shipped code does, and Suite2 does not
//! reach into it.
//!
//! WP-A3 adds the Suite2 parts without touching the writer. This test pins the
//! half of the acceptance that the Suite2 file does not: the Suite1 decryption
//! result equals the result of the code that ships today. It drives the real
//! `miasma_core::crypto::aead::{encrypt_with_key, decrypt}` (the AES-256-GCM
//! with no associated data and `K_aes = K_enc` that every v1 segment and the
//! whole-file path use) and checks the round trip, then checks that the
//! `ObjectSuite::Suite1` descriptor names exactly that schedule (no AAD, the
//! v1 labels) while `Suite2` names the new one.
//!
//! No key, nonce or plaintext is a literal: each is derived with BLAKE3 in
//! key-derivation mode from a label, as the other known-answer tests do. No
//! fixture is read or written here; this is a parity check against live code,
//! not a frozen vector.

use miasma_core::crypto::aead::{decrypt, encrypt_with_key, KEY_LEN, NONCE_LEN};
use miasma_core::format::{seal_segment, AadLayout, ObjectSuite};
use zeroize::Zeroizing;

/// Deterministic test-only bytes: BLAKE3 in key-derivation mode over a label.
fn fill_vec(label: &str, len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("miasma aead v2 suite1 parity (test-only)");
    h.update(label.as_bytes());
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

fn fill<const N: usize>(label: &str) -> [u8; N] {
    fill_vec(label, N).try_into().unwrap()
}

/// The lengths that cover the AES block boundaries.
const LENGTHS: [usize; 6] = [0, 1, 15, 16, 17, 64];

/// Suite1, no password: the AES key is `K_enc` itself and there is no
/// associated data. A plaintext sealed this way must open again through the
/// same `crypto::aead` the shipped code calls, for every boundary length.
#[test]
fn suite1_decryption_matches_the_shipped_aead() {
    for len in LENGTHS {
        let key: [u8; KEY_LEN] = fill(&format!("suite1 K_enc {len}"));
        let nonce: [u8; NONCE_LEN] = fill(&format!("suite1 nonce {len}"));
        let pt = fill_vec(&format!("suite1 plaintext {len}"), len);

        let ct = encrypt_with_key(&pt, &key, &nonce).expect("v1 seal");
        assert_eq!(
            ct.len(),
            len + 16,
            "len {len}: ciphertext carries the 16-byte tag"
        );

        let opened = decrypt(&ct, &key, &nonce).expect("the shipped decryptor opens it");
        assert_eq!(
            opened, pt,
            "len {len}: Suite1 round trip through the live code"
        );
    }
}

/// The wrong nonce, or a flipped ciphertext byte, is refused by the shipped
/// decryptor: Suite1 keeps the authentication it has today.
#[test]
fn suite1_decryption_refuses_a_tampered_input() {
    let key: [u8; KEY_LEN] = fill("suite1 tamper K_enc");
    let nonce: [u8; NONCE_LEN] = fill("suite1 tamper nonce");
    let pt = fill_vec("suite1 tamper plaintext", 64);
    let mut ct = encrypt_with_key(&pt, &key, &nonce).expect("v1 seal");

    let mut other_nonce = nonce;
    other_nonce[0] ^= 1;
    assert!(
        decrypt(&ct, &key, &other_nonce).is_err(),
        "a changed nonce is refused"
    );

    ct[0] ^= 1;
    assert!(
        decrypt(&ct, &key, &nonce).is_err(),
        "a flipped ciphertext byte is refused"
    );
}

/// A ciphertext written by the Suite2 sealer does not open through the shipped
/// Suite1 decryptor: the AES key differs (HKDF over the label and the AAD, not
/// `K_enc`), so the version tag cannot be rewritten to cross the two.
#[test]
fn a_suite2_ciphertext_does_not_open_as_suite1() {
    // A 49-byte AAD built only from fixed-width fields; its exact contents do
    // not matter here, only that Suite2 binds it and Suite1 does not.
    let mut aad = [0u8; 49];
    aad[0..4].copy_from_slice(b"MSA2");
    aad[4..6].copy_from_slice(&ObjectSuite::Suite2.id().to_le_bytes());
    aad[6] = 2; // whole-file context
    aad[7..39].copy_from_slice(&fill::<32>("parity mid"));
    aad[45..49].copy_from_slice(&64u32.to_le_bytes());

    let k_enc: [u8; KEY_LEN] = fill("parity K_enc");
    let nonce: [u8; NONCE_LEN] = fill("parity nonce");
    let pt = fill_vec("parity plaintext", 64);

    let v2_ct = seal_segment(Zeroizing::new(k_enc), &nonce, &pt, &aad, None);
    // The shipped Suite1 decryptor uses K_enc directly with no AAD; it must not
    // open a Suite2 ciphertext.
    assert!(
        decrypt(&v2_ct, &k_enc, &nonce).is_err(),
        "a Suite1 decryptor must not open a Suite2 ciphertext",
    );
}

/// The descriptor says which schedule each suite uses: Suite1 has no AAD and
/// the v1 labels, Suite2 the 49-byte AAD and the v2 labels.
#[test]
fn the_descriptor_separates_suite1_from_suite2() {
    let s1 = ObjectSuite::Suite1.spec();
    let s2 = ObjectSuite::Suite2.spec();

    assert!(
        matches!(s1.aad, AadLayout::None),
        "Suite1 binds no associated data"
    );
    assert!(
        matches!(s2.aad, AadLayout::Msa2),
        "Suite2 binds the 49-byte AAD"
    );
    assert_eq!(s1.segment_key_label, b"miasma-seg-key-v1");
    assert_eq!(s1.name_key_label, b"miasma-name-key-v1");
    assert_eq!(s2.segment_key_label, b"miasma-seg-key-v2");
    assert_eq!(s2.name_key_label, b"miasma-name-key-v2");
    assert_eq!(s1.share_version, 1);
    assert_eq!(s2.share_version, 2);
}
