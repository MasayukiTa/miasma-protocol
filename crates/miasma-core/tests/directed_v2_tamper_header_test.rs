//! Directed share v2 — header-field tampering (one field at a time, §3.3, §8.3).
//!
//! The header carries thirteen authenticated items (§3.3): `version`, `suite`,
//! `envelope_id`, `sender_identity`, `sender_pubkey`, `recipient_identity`,
//! `recipient_pubkey`, `ephemeral_pubkey`, `recipient_ephemeral`, `offer_id`,
//! the KDF cost triple (`kdf_m_kib`/`kdf_t_cost`/`kdf_p_cost`), `password_salt`,
//! `created_at`, `expires_at`, and `retention_secs`. All of them feed
//! `Header::canonical_bytes`, so changing any single one changes `H_hdr`.
//!
//! `H_hdr` enters two places: the AAD of the payload and wrap AEAD layers, and
//! the first input of `sig_msg`. So a changed field must be caught twice over:
//!
//! - (a) the payload AEAD (`open_payload`) and the DEK wrap (`open_wrapped_dek`)
//!   both fail, because the recipient now forms a different AAD; and
//! - (b) the transcript signature no longer verifies, because `sig_msg` folds in
//!   the changed `H_hdr`.
//!
//! Each test seals a correct send once, then rebuilds the header with exactly
//! one field altered, recomputes `H_hdr` from it, and asserts (a) and (b). The
//! other layers' sealed bytes are untouched; only the recomputed `H_hdr` drives
//! the failure, which is what a verifier would recompute from a tampered header.
//!
//! No literal keys, nonces, salts or passwords appear here: every secret is
//! drawn from `OsRng`, and `pwh` comes from `kdf::password_hash` over a randomly
//! generated salt.

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

/// The header fields that make the canonical send. KDF costs are kept at the
/// floor so no Argon2 work is spent on the header shape itself.
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

/// A fully sealed send, kept with the recipient-side key-exchange secret and the
/// password hash so a verifier can be replayed against any recomputed `H_hdr`.
struct Sealed {
    outer: SealedOuter,
    sender_binding: [u8; 64],
    signature: [u8; 64],
    /// `H_hdr` of the untouched header (the value the sender actually sealed).
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

/// Does the payload AEAD open when the recipient uses `h_hdr` as the header AAD?
fn payload_opens_with(s: &Sealed, h_hdr: &[u8; 32]) -> bool {
    seal::open_payload(
        &s.dr,
        h_hdr,
        &s.outer.payload_nonce,
        &s.outer.encrypted_payload,
    )
    .is_ok()
}

/// Does the DEK wrap open when the recipient uses `h_hdr` as the header AAD?
fn wrap_opens_with(s: &Sealed, h_hdr: &[u8; 32]) -> bool {
    seal::open_wrapped_dek(
        &s.dr,
        &s.pwh,
        h_hdr,
        &s.outer.dek_nonce,
        &s.outer.wrapped_dek,
    )
    .is_ok()
}

/// Does the transcript signature verify when `sig_msg` is built over `h_hdr`?
fn transcript_verifies_with(s: &Sealed, h_hdr: &[u8; 32]) -> bool {
    let outer_refs = OuterRefs {
        payload_nonce: &s.outer.payload_nonce,
        encrypted_payload: &s.outer.encrypted_payload,
        dek_nonce: &s.outer.dek_nonce,
        wrapped_dek: &s.outer.wrapped_dek,
        sender_binding: &s.sender_binding,
    };
    let sm = transcript::sig_msg(h_hdr, &outer_refs);
    transcript::verify_transcript(&s.sender_identity, &sm, &s.signature)
}

/// Shared body: `tampered` is the field-altered header. Assert its `H_hdr`
/// differs from the sealed one, that neither AEAD opens under the new AAD, and
/// that the transcript signature rejects the new `sig_msg` — i.e. both (a) and
/// (b) catch a one-field change.
fn assert_tampered_header_is_caught(s: &Sealed, tampered: &Header<'_>, field: &str) {
    let h2 = tampered.h_hdr();
    assert_ne!(s.h_hdr, h2, "changing {field} must change H_hdr");
    assert!(
        !payload_opens_with(s, &h2),
        "payload AEAD must fail after {field} changed (AAD mismatch)"
    );
    assert!(
        !wrap_opens_with(s, &h2),
        "DEK wrap must fail after {field} changed (AAD mismatch)"
    );
    assert!(
        !transcript_verifies_with(s, &h2),
        "transcript signature must reject a changed {field}"
    );
}

/// Baseline: the untouched header opens both layers and verifies. This pins that
/// the helpers pass only when nothing is wrong, so the tamper assertions below
/// are meaningful.
#[test]
fn an_untouched_header_opens_and_verifies() {
    let w = world();
    let s = seal_one(&w);
    assert!(
        payload_opens_with(&s, &s.h_hdr),
        "payload should open before tampering"
    );
    assert!(
        wrap_opens_with(&s, &s.h_hdr),
        "wrap should open before tampering"
    );
    assert!(
        transcript_verifies_with(&s, &s.h_hdr),
        "transcript should verify before tampering"
    );
}

#[test]
fn tampering_version_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let hdr = Header {
        version: 3,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "version");
}

#[test]
fn tampering_suite_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let hdr = Header {
        suite: 3,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "suite");
}

#[test]
fn tampering_envelope_id_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.envelope_id;
    other[0] ^= 0x01;
    let hdr = Header {
        envelope_id: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "envelope_id");
}

#[test]
fn tampering_sender_identity_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.sender_identity;
    other[0] ^= 0x01;
    let hdr = Header {
        sender_identity: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "sender_identity");
}

#[test]
fn tampering_sender_pubkey_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.sender_sharing;
    other[0] ^= 0x01;
    let hdr = Header {
        sender_pubkey: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "sender_pubkey");
}

#[test]
fn tampering_recipient_identity_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.recipient_identity;
    other[0] ^= 0x01;
    let hdr = Header {
        recipient_identity: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "recipient_identity");
}

#[test]
fn tampering_recipient_pubkey_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.r_static_pub;
    other[0] ^= 0x01;
    let hdr = Header {
        recipient_pubkey: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "recipient_pubkey");
}

#[test]
fn tampering_ephemeral_pubkey_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.e_s_pub;
    other[0] ^= 0x01;
    let hdr = Header {
        ephemeral_pubkey: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "ephemeral_pubkey");
}

#[test]
fn tampering_recipient_ephemeral_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.r_eph_pub;
    other[0] ^= 0x01;
    let hdr = Header {
        recipient_ephemeral: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "recipient_ephemeral");
}

#[test]
fn tampering_offer_id_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.offer_id;
    other[0] ^= 0x01;
    let hdr = Header {
        offer_id: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "offer_id");
}

#[test]
fn tampering_kdf_m_kib_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let hdr = Header {
        kdf_m_kib: header(&w).kdf_m_kib + 1,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "kdf_m_kib");
}

#[test]
fn tampering_kdf_t_cost_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let hdr = Header {
        kdf_t_cost: header(&w).kdf_t_cost + 1,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "kdf_t_cost");
}

#[test]
fn tampering_kdf_p_cost_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let hdr = Header {
        kdf_p_cost: header(&w).kdf_p_cost + 1,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "kdf_p_cost");
}

#[test]
fn tampering_password_salt_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let mut other = w.password_salt;
    other[0] ^= 0x01;
    let hdr = Header {
        password_salt: &other,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "password_salt");
}

#[test]
fn tampering_created_at_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let hdr = Header {
        created_at: header(&w).created_at + 1,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "created_at");
}

#[test]
fn tampering_expires_at_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let hdr = Header {
        expires_at: header(&w).expires_at + 1,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "expires_at");
}

#[test]
fn tampering_retention_secs_breaks_aad_and_signature() {
    let w = world();
    let s = seal_one(&w);
    let hdr = Header {
        retention_secs: header(&w).retention_secs + 1,
        ..header(&w)
    };
    assert_tampered_header_is_caught(&s, &hdr, "retention_secs");
}
