//! Directed share v2 — codec framing over in-memory async I/O (integration).
//!
//! These checks drive the `/miasma/directed/2.0.0` codec
//! ([`DirectedCodecV2`]) through the `libp2p::request_response::Codec` trait
//! over `futures` in-memory readers and writers, from outside the crate. They
//! pin the framing the rollout depends on:
//!
//! * a request or response written by the codec reads back equal, and the frame
//!   on the wire is a 4-byte little-endian length prefix followed by the bincode
//!   body (the same shape as the v1 `/miasma/directed/1.0.0` codec);
//! * a declared length above [`DIRECTED_MSG_MAX`] is refused with
//!   `InvalidData` after reading only the 4-byte prefix, before any body buffer
//!   of the declared size is allocated; and
//! * a frame cut short after the length prefix fails with `UnexpectedEof`
//!   rather than returning a half-formed value.
//!
//! No key, nonce, salt or password is written as a literal. Every
//! secret-shaped value is either a fresh `rand::random()` draw or derived from a
//! label through `fill` (a keyed BLAKE3 XOF), so this file carries no fixed
//! cryptographic material.

use futures::executor::block_on;
use futures::io::Cursor;
use libp2p::request_response::Codec;

use miasma_core::directed::protocol::DIRECTED_MSG_MAX;
use miasma_core::directed::v2::behaviour::{DirectedCodecV2, DIRECTED_PROTOCOL_V2};
use miasma_core::directed::v2::wire::{
    DirectedRequestV2, DirectedResponseV2, InviteExtV2, KdfParams, SignedOffer, SUITE_V2,
};
use miasma_core::directed::{DirectedEnvelope, EnvelopeState};

/// Context for the label-derived test material. Test-only; not a protocol label.
const FILL_CTX: &str = "miasma directed v2 codec io (test-only)";

/// Keyed BLAKE3 XOF over `label`. Gives deterministic, non-literal bytes for a
/// field without writing a fixed key, nonce or salt into the file.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key(FILL_CTX);
    h.update(label.as_bytes());
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

/// `N` random bytes as an array, drawn one byte at a time so any `N` works
/// (`rand::random::<[u8; N]>()` only covers `N <= 32`) and no fixed value
/// appears.
fn rand_arr<const N: usize>() -> [u8; N] {
    let bytes: Vec<u8> = (0..N).map(|_| rand::random::<u8>()).collect();
    bytes.try_into().expect("N bytes collected")
}

/// The v2 stream protocol id as a `StreamProtocol`, which the codec's
/// read/write methods take by reference.
fn proto() -> libp2p::StreamProtocol {
    libp2p::StreamProtocol::new(DIRECTED_PROTOCOL_V2)
}

/// A v1-shaped envelope carrying `version = SUITE_V2`, built from fresh random
/// and label-derived bytes (no fixed key material).
fn sample_envelope() -> DirectedEnvelope {
    DirectedEnvelope {
        envelope_id: rand_arr(),
        version: SUITE_V2,
        sender_pubkey: fill("sender sharing pub"),
        recipient_pubkey: fill("recipient sharing pub"),
        ephemeral_pubkey: fill("ephemeral pub"),
        encrypted_payload: (0..48).map(|_| rand::random::<u8>()).collect::<Vec<u8>>(),
        payload_nonce: rand_arr(),
        password_salt: rand_arr(),
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
        offer_id: rand_arr(),
        recipient_ephemeral: fill("r_eph pub"),
        wrapped_dek: (0..48).map(|_| rand::random::<u8>()).collect::<Vec<u8>>(),
        dek_nonce: rand_arr(),
        signature: fill("transcript signature"),
    }
}

/// A recipient's signed prekey offer, built from fresh random and label-derived
/// bytes (no fixed key material).
fn sample_offer() -> SignedOffer {
    SignedOffer {
        suite: SUITE_V2,
        offer_id: rand_arr(),
        request_id: rand_arr(),
        requester: (0..38).map(|_| rand::random::<u8>()).collect::<Vec<u8>>(),
        recipient_identity: fill("recipient identity pub"),
        recipient_sharing: fill("recipient sharing pub"),
        recipient_binding: fill("recipient binding"),
        recipient_ephemeral: fill("r_eph pub"),
        ttl_secs: 20,
        signature: fill("offer signature"),
    }
}

/// Every v2 request variant written by the codec reads back equal, and the
/// frame is a 4-byte LE length prefix followed by the bincode body.
#[test]
fn the_v2_codec_round_trips_every_request_variant_over_async_io() {
    let mut codec = DirectedCodecV2;
    let p = proto();
    let reqs = vec![
        DirectedRequestV2::Invite {
            envelope: sample_envelope(),
            ext: sample_ext(),
        },
        DirectedRequestV2::Confirm {
            envelope_id: rand_arr(),
            // A challenge-code-shaped string; not a credential.
            challenge_code: "ABCD-EFGH".to_string(),
        },
        DirectedRequestV2::SenderRevoke {
            envelope_id: rand_arr(),
        },
        DirectedRequestV2::StatusQuery {
            envelope_id: rand_arr(),
        },
        DirectedRequestV2::PrekeyRequest {
            request_id: rand_arr(),
            suites: vec![SUITE_V2],
        },
    ];
    for req in reqs {
        let want = bincode::serialize(&req).expect("request serializes");

        // Write through the codec into an in-memory `Vec<u8>` writer.
        let mut out: Vec<u8> = Vec::new();
        block_on(codec.write_request(&p, &mut out, req)).expect("codec writes the request");

        // The frame is a 4-byte LE length then the bincode body.
        assert_eq!(&out[..4], &(want.len() as u32).to_le_bytes());
        assert_eq!(&out[4..], want.as_slice());

        // Read it back through the codec from an in-memory reader.
        let mut rd = Cursor::new(out);
        let back = block_on(codec.read_request(&p, &mut rd)).expect("codec reads the request");
        assert_eq!(
            bincode::serialize(&back).expect("round-trip serializes"),
            want
        );
    }
}

/// The new v2 response variants written by the codec read back equal, with the
/// same 4-byte-length framing.
#[test]
fn the_v2_codec_round_trips_the_new_response_variants_over_async_io() {
    let mut codec = DirectedCodecV2;
    let p = proto();
    let resps = vec![
        DirectedResponseV2::PrekeyOffer {
            offer: sample_offer(),
        },
        DirectedResponseV2::InviteStored {
            envelope_id: rand_arr(),
            transcript_hash: rand_arr(),
        },
        DirectedResponseV2::Status {
            envelope_id: rand_arr(),
            state: EnvelopeState::ChallengeIssued,
        },
        DirectedResponseV2::Error("directed-v2:offer_unknown: no such offer".to_string()),
    ];
    for res in resps {
        let want = bincode::serialize(&res).expect("response serializes");

        let mut out: Vec<u8> = Vec::new();
        block_on(codec.write_response(&p, &mut out, res)).expect("codec writes the response");

        assert_eq!(&out[..4], &(want.len() as u32).to_le_bytes());
        assert_eq!(&out[4..], want.as_slice());

        let mut rd = Cursor::new(out);
        let back = block_on(codec.read_response(&p, &mut rd)).expect("codec reads the response");
        assert_eq!(
            bincode::serialize(&back).expect("round-trip serializes"),
            want
        );
    }
}

/// A declared length above `DIRECTED_MSG_MAX` is refused with `InvalidData`,
/// and the refusal happens after reading only the 4-byte prefix: the reader is
/// handed exactly those four bytes and no body, so if it tried to allocate and
/// fill a buffer of the declared size it would instead block or hit EOF. The
/// error must be `InvalidData` (the limit check), not `UnexpectedEof`.
#[test]
fn the_v2_codec_refuses_an_oversized_declared_length_before_allocating() {
    let mut codec = DirectedCodecV2;
    let p = proto();
    let oversized = (DIRECTED_MSG_MAX + 1) as u32;

    // Only the 4-byte length prefix is present; there is no body to read.
    let mut rd = Cursor::new(oversized.to_le_bytes().to_vec());
    let err =
        block_on(codec.read_request(&p, &mut rd)).expect_err("an oversized length is refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    let mut rd = Cursor::new(oversized.to_le_bytes().to_vec());
    let err =
        block_on(codec.read_response(&p, &mut rd)).expect_err("an oversized length is refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// A frame whose body is cut short fails with `UnexpectedEof` rather than
/// returning a half-formed value: the declared length is within the limit, but
/// the reader runs out of input before the body is complete.
#[test]
fn the_v2_codec_reports_a_truncated_body_as_unexpected_eof() {
    let mut codec = DirectedCodecV2;
    let p = proto();

    // Write a valid request, then drop its last body byte.
    let req = DirectedRequestV2::StatusQuery {
        envelope_id: rand_arr(),
    };
    let mut out: Vec<u8> = Vec::new();
    block_on(codec.write_request(&p, &mut out, req)).expect("codec writes the request");
    assert!(out.len() > 4, "the frame has a body to truncate");
    out.truncate(out.len() - 1);

    let mut rd = Cursor::new(out);
    let err = block_on(codec.read_request(&p, &mut rd)).expect_err("a truncated body is rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// A declared length of zero yields an empty body, which bincode cannot decode
/// into a `DirectedRequestV2` (it needs at least the enum tag): the codec
/// surfaces `InvalidData` from the decode step, not a panic.
#[test]
fn the_v2_codec_rejects_an_empty_body_as_invalid_data() {
    let mut codec = DirectedCodecV2;
    let p = proto();

    // A length prefix of 0 and no body: within the limit, but decodes to nothing.
    let mut rd = Cursor::new(0u32.to_le_bytes().to_vec());
    let err = block_on(codec.read_request(&p, &mut rd)).expect_err("an empty body is rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
