//! Directed share v2 — outer-field tampering (one byte at a time, §8.3).
//!
//! A sealed v2 send carries six outer fields beyond the header: `payload_nonce`,
//! `encrypted_payload`, `dek_nonce`, `wrapped_dek`, `sender_binding`, and
//! `signature`. Flipping a single byte of any of them must be caught, and the
//! tests below also pin *which* stage catches it:
//!
//! - `payload_nonce` / `encrypted_payload`: the payload AEAD (`open_payload`)
//!   fails, and the transcript signature over `sig_msg` no longer verifies.
//! - `dek_nonce` / `wrapped_dek`: the DEK wrap (`open_wrapped_dek`) fails, and
//!   the transcript signature no longer verifies.
//! - `sender_binding`: it is not an AEAD input, so decryption still succeeds;
//!   the change is caught only by the transcript signature.
//! - `signature`: the ciphertexts still open, but `verify_transcript` rejects
//!   the flipped signature.
//!
//! No literal keys, nonces, salts or passwords appear here: the envelope is
//! sealed by `seal::seal_outer_with`/`seal_content_with` driven by `OsRng`, and
//! `pwh` comes from `kdf::password_hash` over a randomly generated salt.

use miasma_core::directed::v2::kdf;
use miasma_core::directed::v2::seal::{self, SealInput, SealedOuter};
use miasma_core::directed::v2::transcript::{self, Header, OuterRefs};

use ed25519_dalek::SigningKey;
use miasma_core::crypto::kdf_bounds::MIN_M_KIB;

/// Everything a sealed v2 send needs, all drawn from randomness.
struct World {
    r_static_secret: [u8; 32],
    r_static_pub: [u8; 32],
    r_eph_secret: [u8; 32],
    r_eph_pub: [u8; 32],
    e_s_secret: [u8; 32],
    e_s_pub: [u8; 32],
    sender_sk: SigningKey,
    sender_identity: [u8; 32],
    sender_sharing: [u8; 32],
    recipient_identity: [u8; 32],
    envelope_id: [u8; 32],
    offer_id: [u8; 16],
    password_salt: [u8; 32],
    dek: [u8; 32],
    password: String,
}

fn world() -> World {
    let r_static = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let r_eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let e_s = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let sharing = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let sender_sk = SigningKey::from_bytes(&rand::random());
    World {
        r_static_secret: r_static.to_bytes(),
        r_static_pub: x25519_dalek::PublicKey::from(&r_static).to_bytes(),
        r_eph_secret: r_eph.to_bytes(),
        r_eph_pub: x25519_dalek::PublicKey::from(&r_eph).to_bytes(),
        e_s_secret: e_s.to_bytes(),
        e_s_pub: x25519_dalek::PublicKey::from(&e_s).to_bytes(),
        sender_identity: sender_sk.verifying_key().to_bytes(),
        sender_sk,
        sender_sharing: x25519_dalek::PublicKey::from(&sharing).to_bytes(),
        recipient_identity: rand::random(),
        envelope_id: rand::random(),
        offer_id: rand::random(),
        password_salt: rand::random(),
        dek: rand::random(),
        password: "a correct horse battery".to_string(),
    }
}

fn header<'a>(w: &'a World) -> Header<'a> {
    Header {
        version: 2,
        suite: 2,
        envelope_id: &w.envelope_id,
        sender_identity: &w.sender_identity,
        sender_pubkey: &w.sender_sharing,
        recipient_identity: &w.recipient_identity,
        recipient_pubkey: &w.r_static_pub,
        ephemeral_pubkey: &w.e_s_pub,
        recipient_ephemeral: &w.r_eph_pub,
        offer_id: &w.offer_id,
        kdf_m_kib: MIN_M_KIB.max(8),
        kdf_t_cost: 1,
        kdf_p_cost: 1,
        password_salt: &w.password_salt,
        created_at: 1_700_000_000,
        expires_at: 1_700_003_600,
        retention_secs: 3600,
    }
}

/// A fully sealed send: the outer layers, the sender binding, the transcript
/// signature, and the recipient-side key-exchange secret needed to open it.
struct Sealed {
    outer: SealedOuter,
    sender_binding: [u8; 64],
    signature: [u8; 64],
    h_hdr: [u8; 32],
    dr: [u8; 64],
    pwh: [u8; 32],
    sender_identity: [u8; 32],
}

fn seal_one(w: &World) -> Sealed {
    let mut rng = rand::rngs::OsRng;
    let ds = kdf::dh_concat_sender(&w.e_s_secret, &w.r_static_pub, &w.r_eph_pub).unwrap();
    let pwh = kdf::password_hash(&w.password, &w.password_salt, MIN_M_KIB.max(8), 1, 1).unwrap();
    let hdr = header(w);
    let outer = seal::seal_outer_with(
        &mut rng,
        &hdr,
        &SealInput {
            dh_concat: &ds,
            pwh: &pwh,
            dek: &w.dek,
            payload_plaintext: b"preview: mid, size, name",
        },
    )
    .unwrap();

    // Bind the sender's sharing key to its identity, then sign the transcript.
    let sender_binding =
        miasma_core::directed::v2::credential::sign_binding(&w.sender_sk, &w.sender_sharing);
    let outer_refs = OuterRefs {
        payload_nonce: &outer.payload_nonce,
        encrypted_payload: &outer.encrypted_payload,
        dek_nonce: &outer.dek_nonce,
        wrapped_dek: &outer.wrapped_dek,
        sender_binding: &sender_binding,
    };
    let (signature, _th) = seal::sign_sealed(&w.sender_sk, &hdr, &outer_refs);

    let dr = kdf::dh_concat_recipient(&w.r_static_secret, &w.r_eph_secret, &w.e_s_pub).unwrap();

    Sealed {
        outer,
        sender_binding,
        signature,
        h_hdr: hdr.h_hdr(),
        dr: *dr,
        pwh: *pwh,
        sender_identity: w.sender_identity,
    }
}

/// Recompute `sig_msg` from the current outer bytes and check the signature.
fn transcript_verifies(s: &Sealed) -> bool {
    let outer_refs = OuterRefs {
        payload_nonce: &s.outer.payload_nonce,
        encrypted_payload: &s.outer.encrypted_payload,
        dek_nonce: &s.outer.dek_nonce,
        wrapped_dek: &s.outer.wrapped_dek,
        sender_binding: &s.sender_binding,
    };
    let sm = transcript::sig_msg(&s.h_hdr, &outer_refs);
    transcript::verify_transcript(&s.sender_identity, &sm, &s.signature)
}

fn payload_opens(s: &Sealed) -> bool {
    seal::open_payload(
        &s.dr,
        &s.h_hdr,
        &s.outer.payload_nonce,
        &s.outer.encrypted_payload,
    )
    .is_ok()
}

fn wrap_opens(s: &Sealed) -> bool {
    seal::open_wrapped_dek(
        &s.dr,
        &s.pwh,
        &s.h_hdr,
        &s.outer.dek_nonce,
        &s.outer.wrapped_dek,
    )
    .is_ok()
}

/// Baseline: an untouched sealed send opens on every layer and verifies.
#[test]
fn an_untouched_outer_opens_and_verifies() {
    let w = world();
    let s = seal_one(&w);
    assert!(payload_opens(&s), "payload should open before tampering");
    assert!(wrap_opens(&s), "wrap should open before tampering");
    assert!(
        transcript_verifies(&s),
        "transcript should verify before tampering"
    );
}

/// Flip one byte of `payload_nonce`: the payload AEAD fails, and the transcript
/// signature (which binds the nonce) no longer verifies. The wrap is unaffected.
#[test]
fn flipping_payload_nonce_breaks_payload_decrypt_and_signature() {
    let w = world();
    let mut s = seal_one(&w);
    s.outer.payload_nonce[0] ^= 0x01;
    assert!(
        !payload_opens(&s),
        "payload must not open with a flipped nonce"
    );
    assert!(
        !transcript_verifies(&s),
        "the signature must reject a flipped payload_nonce"
    );
    // The DEK wrap does not depend on payload_nonce, so it still opens.
    assert!(wrap_opens(&s), "wrap is independent of payload_nonce");
}

/// Flip one byte of `encrypted_payload`: the payload AEAD tag fails, and the
/// transcript signature (which binds a hash of the ciphertext) rejects it.
#[test]
fn flipping_encrypted_payload_breaks_payload_decrypt_and_signature() {
    let w = world();
    let mut s = seal_one(&w);
    s.outer.encrypted_payload[0] ^= 0x01;
    assert!(
        !payload_opens(&s),
        "payload must not open with a flipped byte"
    );
    assert!(
        !transcript_verifies(&s),
        "the signature must reject a flipped encrypted_payload"
    );
    assert!(wrap_opens(&s), "wrap is independent of encrypted_payload");
}

/// Flip one byte of `dek_nonce`: the DEK wrap fails, and the transcript
/// signature rejects it. The payload is unaffected.
#[test]
fn flipping_dek_nonce_breaks_wrap_decrypt_and_signature() {
    let w = world();
    let mut s = seal_one(&w);
    s.outer.dek_nonce[0] ^= 0x01;
    assert!(!wrap_opens(&s), "wrap must not open with a flipped nonce");
    assert!(
        !transcript_verifies(&s),
        "the signature must reject a flipped dek_nonce"
    );
    assert!(payload_opens(&s), "payload is independent of dek_nonce");
}

/// Flip one byte of `wrapped_dek`: the DEK wrap tag fails, and the transcript
/// signature (which binds a hash of the wrap) rejects it.
#[test]
fn flipping_wrapped_dek_breaks_wrap_decrypt_and_signature() {
    let w = world();
    let mut s = seal_one(&w);
    s.outer.wrapped_dek[0] ^= 0x01;
    assert!(!wrap_opens(&s), "wrap must not open with a flipped byte");
    assert!(
        !transcript_verifies(&s),
        "the signature must reject a flipped wrapped_dek"
    );
    assert!(payload_opens(&s), "payload is independent of wrapped_dek");
}

/// Flip one byte of `sender_binding`: it is not an AEAD input, so both
/// ciphertexts still open; only the transcript signature catches the change.
#[test]
fn flipping_sender_binding_is_caught_only_by_the_signature() {
    let w = world();
    let mut s = seal_one(&w);
    s.sender_binding[0] ^= 0x01;
    // Neither AEAD covers sender_binding, so both still open.
    assert!(
        payload_opens(&s),
        "payload is independent of sender_binding"
    );
    assert!(wrap_opens(&s), "wrap is independent of sender_binding");
    // But the signature is over sig_msg, which folds in sender_binding.
    assert!(
        !transcript_verifies(&s),
        "the signature must reject a flipped sender_binding"
    );
}

/// Flip one byte of `signature`: the ciphertexts still open, but
/// `verify_transcript` rejects the altered signature.
#[test]
fn flipping_signature_is_caught_only_by_the_signature() {
    let w = world();
    let mut s = seal_one(&w);
    s.signature[0] ^= 0x01;
    // The signature is not an AEAD input, so both ciphertexts still open.
    assert!(payload_opens(&s), "payload is independent of the signature");
    assert!(wrap_opens(&s), "wrap is independent of the signature");
    // Verification of the flipped signature must fail.
    assert!(
        !transcript_verifies(&s),
        "a flipped signature must not verify"
    );
}
