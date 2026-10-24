//! Directed share v2 — cross-version codec interoperability (integration).
//!
//! These checks exercise the v2 request types from outside the crate, across
//! the v1/v2 boundary, to pin the compatibility contract the rollout depends on:
//!
//! * a v2 `Invite` is the v1 `Invite { envelope }` bytes with the v2 `ext`
//!   appended, so a v1 decoder reads it as a `version = 2` invite and ignores
//!   the trailing extension;
//! * a v2 `Invite` round-trips through the v2 codec unchanged; and
//! * a 1.0.0 `Invite` (a v1 `DirectedRequest::Invite`, with no `ext`) fails to
//!   decode as a v2 `DirectedRequestV2`, because the appended extension is
//!   absent.
//!
//! No key, nonce or salt is written as a literal. Every secret-shaped value is
//! either a fresh `rand::random()` draw or derived from a label through `fill`
//! (a keyed BLAKE3 XOF), so the file carries no fixed cryptographic material.

use miasma_core::directed::protocol::DirectedRequest;
use miasma_core::directed::v2::wire::{DirectedRequestV2, InviteExtV2, KdfParams, SUITE_V2};
use miasma_core::directed::{DirectedEnvelope, EnvelopeState};

/// Context for the label-derived test material. Test-only; not a protocol label.
const FILL_CTX: &str = "miasma directed v2 codec interop (test-only)";

/// Keyed BLAKE3 XOF over `label`. Gives deterministic, non-literal bytes for a
/// field without writing a fixed key, nonce or salt into the file.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key(FILL_CTX);
    h.update(label.as_bytes());
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

/// A v1-shaped envelope carrying `version = SUITE_V2`, built from fresh random
/// and label-derived bytes (no fixed key material).
fn sample_envelope() -> DirectedEnvelope {
    DirectedEnvelope {
        envelope_id: rand::random(),
        version: SUITE_V2,
        sender_pubkey: fill("sender sharing pub"),
        recipient_pubkey: fill("recipient sharing pub"),
        ephemeral_pubkey: fill("ephemeral pub"),
        encrypted_payload: rand::random::<[u8; 48]>().to_vec(),
        payload_nonce: rand::random(),
        password_salt: rand::random(),
        expires_at: 1_700_003_600,
        created_at: 1_700_000_000,
        state: EnvelopeState::Pending,
        challenge_hash: None,
        password_attempts_remaining: 0,
        challenge_attempts_remaining: 0,
        challenge_expires_at: 0,
        retention_secs: 3600,
    }
}

/// The v2 extension that follows the envelope inside an `Invite`, built from
/// fresh random and label-derived bytes (no fixed key material).
fn sample_ext() -> InviteExtV2 {
    InviteExtV2 {
        suite: SUITE_V2,
        kdf: KdfParams {
            m_kib: 65536,
            t_cost: 3,
            p_cost: 1,
        },
        sender_identity: fill("sender identity pub"),
        sender_binding: fill("sender binding"),
        recipient_identity: fill("recipient identity pub"),
        offer_id: rand::random(),
        recipient_ephemeral: fill("r_eph pub"),
        wrapped_dek: rand::random::<[u8; 48]>().to_vec(),
        dek_nonce: rand::random(),
        signature: fill("transcript signature"),
    }
}

/// (a) A v2 `Invite`, serialized with bincode, reads back as a v1
/// `DirectedRequest::Invite` with `version == 2`; the trailing `ext` is ignored.
#[test]
fn a_v2_invite_decodes_as_a_v1_invite_and_ignores_the_trailing_ext() {
    let envelope = sample_envelope();
    let v2 = DirectedRequestV2::Invite {
        envelope: envelope.clone(),
        ext: sample_ext(),
    };
    let bytes = bincode::serialize(&v2).expect("v2 invite serializes");

    let v1: DirectedRequest =
        bincode::deserialize(&bytes).expect("a v1 decoder reads the v2 invite bytes");
    match v1 {
        DirectedRequest::Invite { envelope: e } => {
            // The v1 reader sees the appended ext as trailing bytes and ignores
            // it; the envelope it recovers is the original, carrying version 2.
            assert_eq!(e.version, SUITE_V2);
            assert_eq!(e.version, 2);
            assert_eq!(e.envelope_id, envelope.envelope_id);
            assert_eq!(e.sender_pubkey, envelope.sender_pubkey);
            assert_eq!(e.recipient_pubkey, envelope.recipient_pubkey);
            assert_eq!(e.encrypted_payload, envelope.encrypted_payload);
        }
        other => panic!("a v2 invite did not read as a v1 Invite: {other:?}"),
    }
}

/// (b) A v2 `Invite` round-trips through bincode (the v2 codec): the fields
/// come back unchanged.
#[test]
fn a_v2_invite_round_trips_through_the_v2_codec() {
    let envelope = sample_envelope();
    let ext = sample_ext();
    let req = DirectedRequestV2::Invite {
        envelope: envelope.clone(),
        ext: ext.clone(),
    };
    let bytes = bincode::serialize(&req).expect("v2 invite serializes");

    let back: DirectedRequestV2 =
        bincode::deserialize(&bytes).expect("the v2 codec reads its own invite bytes");
    match back {
        DirectedRequestV2::Invite {
            envelope: e,
            ext: x,
        } => {
            assert_eq!(e.envelope_id, envelope.envelope_id);
            assert_eq!(e.version, envelope.version);
            assert_eq!(e.ephemeral_pubkey, envelope.ephemeral_pubkey);
            assert_eq!(e.payload_nonce, envelope.payload_nonce);
            assert_eq!(e.password_salt, envelope.password_salt);
            assert_eq!(e.encrypted_payload, envelope.encrypted_payload);

            assert_eq!(x.suite, SUITE_V2);
            assert_eq!(x.kdf, ext.kdf);
            assert_eq!(x.sender_identity, ext.sender_identity);
            assert_eq!(x.sender_binding, ext.sender_binding);
            assert_eq!(x.recipient_identity, ext.recipient_identity);
            assert_eq!(x.offer_id, ext.offer_id);
            assert_eq!(x.recipient_ephemeral, ext.recipient_ephemeral);
            assert_eq!(x.wrapped_dek, ext.wrapped_dek);
            assert_eq!(x.dek_nonce, ext.dek_nonce);
            assert_eq!(x.signature, ext.signature);
        }
        other => panic!("v2 invite did not round-trip as an Invite: {other:?}"),
    }
}

/// (c) A 1.0.0 `Invite` (a v1 `DirectedRequest::Invite`, no `ext`) fails to
/// decode as a v2 `DirectedRequestV2`: the appended extension is missing, so
/// bincode runs out of input before the `ext` fields.
#[test]
fn a_v1_invite_without_ext_fails_to_decode_as_v2() {
    let envelope = sample_envelope();
    let v1 = DirectedRequest::Invite {
        envelope: envelope.clone(),
    };
    let bytes = bincode::serialize(&v1).expect("v1 invite serializes");

    // The v2 reader needs the trailing `ext`; a 1.0.0 invite has none, so the
    // decode must fail rather than silently produce a half-formed value.
    let decoded = bincode::deserialize::<DirectedRequestV2>(&bytes);
    assert!(
        decoded.is_err(),
        "a v1 Invite without ext must not decode as a v2 DirectedRequestV2"
    );
}
