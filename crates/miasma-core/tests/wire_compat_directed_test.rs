//! The directed (private share) wire format, frozen byte for byte.
//!
//! A directed share travels as a bincode `DirectedRequest` / `DirectedResponse`
//! in a 4-byte little-endian length frame over `/miasma/directed/1.0.0`, and the
//! `DirectedEnvelope` it carries is also kept on disk as JSON. These bytes are
//! the contract with already-released builds: a build that writes something else
//! for the same values, or stops reading one of these strings, splits senders
//! and recipients of different versions.
//!
//! Every fixture is one line (`name hex`) of `tests/fixtures/directed_v1/frozen.hex`.
//! The tests check that
//!
//! * (a) the current encoder produces exactly these bytes for a canonical value,
//! * (b) the current decoder reads them and gives the original fields back,
//! * (c) a real envelope made by `create_envelope` (frozen once) still opens
//!   with the same keys: the key derivation labels, the Argon2id cost and the
//!   XChaCha20-Poly1305 layers are part of the format,
//! * (d) trailing bytes after a message are ignored by the decoder, an
//!   envelope with `version != 1` is refused by a running node with the
//!   message "unsupported directed envelope version N", and a request variant
//!   this build does not know fails to decode.
//!
//! # What the planned v2 depends on
//!
//! `bincode::deserialize` accepts bytes after the value it decoded. A v2
//! envelope that only appends fields therefore still decodes in this build (as
//! a v1 value with the extras ignored), and the receive path then answers with
//! the version error instead of failing to parse. (d) pins that behaviour: if a
//! later change makes the decoder strict about trailing data, or moves the
//! `version` byte, the compatibility plan stops working and these tests fail.
//!
//! # Test-only key material
//!
//! No key, nonce, salt or password is written as a literal. Every secret-shaped
//! value is derived with BLAKE3 from a label (`fill`), and the real-envelope
//! fixture is a ciphertext frozen in the fixture file. The derivation is
//! deterministic on purpose: the fixtures must be reproducible.
//!
//! The file was written once by `print_fixtures` (run with `--ignored
//! --nocapture`; it prints the lines). Regenerating the existing v1 lines after
//! a failing test would hide a break instead of fixing it; a new format gets a
//! new file and a new version.

use std::sync::Arc;
use std::time::Duration;

use futures::executor::block_on;
use libp2p::request_response::Codec;
use miasma_core::directed::protocol::DIRECTED_MSG_MAX;
use miasma_core::directed::{
    create_envelope, decrypt_directed_content, decrypt_envelope_payload, derive_content_key,
    finalize_envelope, DirectedCodec, DirectedEnvelope, DirectedRequest, DirectedResponse,
    EnvelopeState, RetentionPeriod,
};
use miasma_core::{ContentId, LocalShareStore, MiasmaCoordinator, MiasmaNode, NodeType};

const FIXTURES: &str = include_str!("fixtures/directed_v1/frozen.hex");
const PROTOCOL: &str = "/miasma/directed/1.0.0";
const REAL_PLAINTEXT: &[u8] = b"frozen directed fixture plaintext, version one";
const REAL_PARAMS: &[u8] = b"k=10,n=20,v=1";

/// Deterministic test-only bytes: BLAKE3 in key-derivation mode over a label.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key("miasma frozen directed fixtures v1 (test-only)");
    h.update(label.as_bytes());
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

// ─── Canonical values ────────────────────────────────────────────────────────

fn pending_envelope() -> DirectedEnvelope {
    DirectedEnvelope {
        envelope_id: fill("envelope id"),
        version: 1,
        sender_pubkey: fill("sender pubkey"),
        recipient_pubkey: fill("recipient pubkey"),
        ephemeral_pubkey: fill("ephemeral pubkey"),
        encrypted_payload: fill::<77>("encrypted payload").to_vec(),
        payload_nonce: fill("payload nonce"),
        password_salt: fill("password salt"),
        expires_at: 1_700_086_400,
        created_at: 1_700_000_000,
        state: EnvelopeState::Pending,
        challenge_hash: None,
        password_attempts_remaining: 3,
        challenge_attempts_remaining: 3,
        challenge_expires_at: 0,
        retention_secs: 86_400,
    }
}

/// An envelope that has moved through the lifecycle: every mutable field set.
fn confirmed_envelope() -> DirectedEnvelope {
    DirectedEnvelope {
        state: EnvelopeState::Confirmed,
        challenge_hash: Some(fill("challenge hash")),
        password_attempts_remaining: 2,
        challenge_attempts_remaining: 1,
        challenge_expires_at: 1_700_000_300,
        ..pending_envelope()
    }
}

fn envelope_id() -> [u8; 32] {
    fill("envelope id")
}

fn challenge_code() -> String {
    let b = fill::<4>("challenge code");
    let h = hex::encode_upper(b);
    format!("{}-{}", &h[..4], &h[4..])
}

const STATES: [(EnvelopeState, &str); 9] = [
    (EnvelopeState::Pending, "pending"),
    (EnvelopeState::ChallengeIssued, "challenge_issued"),
    (EnvelopeState::Confirmed, "confirmed"),
    (EnvelopeState::Retrieved, "retrieved"),
    (EnvelopeState::SenderRevoked, "sender_revoked"),
    (EnvelopeState::RecipientDeleted, "recipient_deleted"),
    (EnvelopeState::Expired, "expired"),
    (EnvelopeState::ChallengeFailed, "challenge_failed"),
    (EnvelopeState::PasswordFailed, "password_failed"),
];

fn bin<T: serde::Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).unwrap()
}

/// Every deterministic fixture: name and the bytes the current encoder writes.
fn all() -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = vec![
        ("envelope_pending".into(), bin(&pending_envelope())),
        ("envelope_confirmed".into(), bin(&confirmed_envelope())),
        (
            "envelope_pending_json".into(),
            serde_json::to_vec(&pending_envelope()).unwrap(),
        ),
        (
            "envelope_confirmed_json".into(),
            serde_json::to_vec(&confirmed_envelope()).unwrap(),
        ),
        (
            "req_invite".into(),
            bin(&DirectedRequest::Invite {
                envelope: pending_envelope(),
            }),
        ),
        (
            "req_invite_confirmed".into(),
            bin(&DirectedRequest::Invite {
                envelope: confirmed_envelope(),
            }),
        ),
        (
            "req_confirm".into(),
            bin(&DirectedRequest::Confirm {
                envelope_id: envelope_id(),
                challenge_code: challenge_code(),
            }),
        ),
        (
            "req_sender_revoke".into(),
            bin(&DirectedRequest::SenderRevoke {
                envelope_id: envelope_id(),
            }),
        ),
        (
            "req_status_query".into(),
            bin(&DirectedRequest::StatusQuery {
                envelope_id: envelope_id(),
            }),
        ),
        (
            "resp_invite_accepted".into(),
            bin(&DirectedResponse::InviteAccepted {
                envelope_id: envelope_id(),
            }),
        ),
        (
            "resp_confirmed".into(),
            bin(&DirectedResponse::Confirmed {
                envelope_id: envelope_id(),
            }),
        ),
        (
            "resp_challenge_failed".into(),
            bin(&DirectedResponse::ChallengeFailed {
                envelope_id: envelope_id(),
                attempts_remaining: 2,
            }),
        ),
        (
            "resp_revoked".into(),
            bin(&DirectedResponse::Revoked {
                envelope_id: envelope_id(),
            }),
        ),
        (
            "resp_error".into(),
            bin(&DirectedResponse::Error(
                "unsupported directed envelope version 2".into(),
            )),
        ),
    ];
    for (state, name) in STATES {
        v.push((
            format!("resp_status_{name}"),
            bin(&DirectedResponse::Status {
                envelope_id: envelope_id(),
                state,
            }),
        ));
    }
    v
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

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

fn proto() -> libp2p::StreamProtocol {
    libp2p::StreamProtocol::new(PROTOCOL)
}

fn id_of(e: &DirectedEnvelope) -> [u8; 32] {
    e.envelope_id
}

// ─── (a) the encoder writes exactly the frozen bytes ─────────────────────────

#[test]
fn encoders_write_the_frozen_bytes() {
    for (name, bytes) in all() {
        assert!(
            bytes == frozen(&name),
            "the bytes written for `{name}` differ from the frozen fixture"
        );
    }
}

#[test]
fn the_enum_numbering_is_the_wire_format() {
    // bincode writes an enum as a u32 little-endian variant index. These are the
    // numbers an old build uses to pick a variant; new variants go at the end.
    let tag = |name: &str| u32::from_le_bytes(frozen(name)[..4].try_into().unwrap());
    assert_eq!(tag("req_invite"), 0);
    assert_eq!(tag("req_confirm"), 1);
    assert_eq!(tag("req_sender_revoke"), 2);
    assert_eq!(tag("req_status_query"), 3);
    assert_eq!(tag("resp_invite_accepted"), 0);
    assert_eq!(tag("resp_confirmed"), 1);
    assert_eq!(tag("resp_challenge_failed"), 2);
    assert_eq!(tag("resp_revoked"), 3);
    assert_eq!(tag("resp_error"), 5);
    // Status is variant 4; the state follows the 32-byte id as a u32 index.
    for (i, (_, name)) in STATES.iter().enumerate() {
        let b = frozen(&format!("resp_status_{name}"));
        assert_eq!(u32::from_le_bytes(b[..4].try_into().unwrap()), 4);
        assert_eq!(b.len(), 4 + 32 + 4);
        assert_eq!(
            u32::from_le_bytes(b[36..40].try_into().unwrap()),
            i as u32,
            "state index of {name}"
        );
    }
    // Invite: variant tag, then the envelope starts with its 32-byte id and the
    // version byte at offset 36. A v2 envelope is recognised by that byte.
    let invite = frozen("req_invite");
    assert_eq!(invite[36], 1, "version byte of an Invite envelope");
}

// ─── (b) the decoder reads them ──────────────────────────────────────────────

fn check_envelope(e: &DirectedEnvelope, want: &DirectedEnvelope) {
    assert_eq!(e.envelope_id, want.envelope_id);
    assert_eq!(e.version, want.version);
    assert_eq!(e.sender_pubkey, want.sender_pubkey);
    assert_eq!(e.recipient_pubkey, want.recipient_pubkey);
    assert_eq!(e.ephemeral_pubkey, want.ephemeral_pubkey);
    assert_eq!(e.encrypted_payload, want.encrypted_payload);
    assert_eq!(e.payload_nonce, want.payload_nonce);
    assert_eq!(e.password_salt, want.password_salt);
    assert_eq!(e.expires_at, want.expires_at);
    assert_eq!(e.created_at, want.created_at);
    assert_eq!(e.state, want.state);
    assert_eq!(e.challenge_hash, want.challenge_hash);
    assert_eq!(
        e.password_attempts_remaining,
        want.password_attempts_remaining
    );
    assert_eq!(
        e.challenge_attempts_remaining,
        want.challenge_attempts_remaining
    );
    assert_eq!(e.challenge_expires_at, want.challenge_expires_at);
    assert_eq!(e.retention_secs, want.retention_secs);
}

#[test]
fn the_decoder_reads_the_frozen_envelopes() {
    for (name, want) in [
        ("envelope_pending", pending_envelope()),
        ("envelope_confirmed", confirmed_envelope()),
    ] {
        let e: DirectedEnvelope = bincode::deserialize(&frozen(name)).unwrap();
        check_envelope(&e, &want);
    }
    for (name, want) in [
        ("envelope_pending_json", pending_envelope()),
        ("envelope_confirmed_json", confirmed_envelope()),
    ] {
        let e: DirectedEnvelope = serde_json::from_slice(&frozen(name)).unwrap();
        check_envelope(&e, &want);
    }
}

#[test]
fn an_envelope_json_without_a_challenge_hash_still_reads() {
    // `challenge_hash` is the one field with `#[serde(default)]`: JSON written
    // before it existed has no such key.
    let mut v: serde_json::Value = serde_json::from_slice(&frozen("envelope_pending_json")).unwrap();
    v.as_object_mut().unwrap().remove("challenge_hash");
    let e: DirectedEnvelope = serde_json::from_value(v).unwrap();
    assert!(e.challenge_hash.is_none());
}

#[test]
fn the_decoder_reads_the_frozen_requests_and_responses() {
    match bincode::deserialize::<DirectedRequest>(&frozen("req_invite")).unwrap() {
        DirectedRequest::Invite { envelope } => check_envelope(&envelope, &pending_envelope()),
        other => panic!("expected Invite, got {other:?}"),
    }
    match bincode::deserialize::<DirectedRequest>(&frozen("req_invite_confirmed")).unwrap() {
        DirectedRequest::Invite { envelope } => check_envelope(&envelope, &confirmed_envelope()),
        other => panic!("expected Invite, got {other:?}"),
    }
    match bincode::deserialize::<DirectedRequest>(&frozen("req_confirm")).unwrap() {
        DirectedRequest::Confirm {
            envelope_id: id,
            challenge_code: code,
        } => {
            assert_eq!(id, envelope_id());
            assert!(code == challenge_code(), "challenge code differs");
        }
        other => panic!("expected Confirm, got {other:?}"),
    }
    match bincode::deserialize::<DirectedRequest>(&frozen("req_sender_revoke")).unwrap() {
        DirectedRequest::SenderRevoke { envelope_id: id } => assert_eq!(id, envelope_id()),
        other => panic!("expected SenderRevoke, got {other:?}"),
    }
    match bincode::deserialize::<DirectedRequest>(&frozen("req_status_query")).unwrap() {
        DirectedRequest::StatusQuery { envelope_id: id } => assert_eq!(id, envelope_id()),
        other => panic!("expected StatusQuery, got {other:?}"),
    }

    let resp = |n: &str| bincode::deserialize::<DirectedResponse>(&frozen(n)).unwrap();
    assert!(matches!(
        resp("resp_invite_accepted"),
        DirectedResponse::InviteAccepted { envelope_id: id } if id == envelope_id()
    ));
    assert!(matches!(
        resp("resp_confirmed"),
        DirectedResponse::Confirmed { envelope_id: id } if id == envelope_id()
    ));
    assert!(matches!(
        resp("resp_challenge_failed"),
        DirectedResponse::ChallengeFailed { envelope_id: id, attempts_remaining: 2 }
            if id == envelope_id()
    ));
    assert!(matches!(
        resp("resp_revoked"),
        DirectedResponse::Revoked { envelope_id: id } if id == envelope_id()
    ));
    match resp("resp_error") {
        DirectedResponse::Error(m) => assert_eq!(m, "unsupported directed envelope version 2"),
        other => panic!("expected Error, got {other:?}"),
    }
    for (state, name) in STATES {
        match resp(&format!("resp_status_{name}")) {
            DirectedResponse::Status {
                envelope_id: id,
                state: s,
            } => {
                assert_eq!(id, envelope_id());
                assert_eq!(s, state);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }
}

// ─── The codec: 4-byte little-endian length, then bincode ────────────────────

#[test]
fn the_codec_frames_requests_and_responses_as_frozen() {
    let mut c = DirectedCodec;
    let p = proto();
    for (name, req) in [
        (
            "req_invite",
            DirectedRequest::Invite {
                envelope: pending_envelope(),
            },
        ),
        (
            "req_confirm",
            DirectedRequest::Confirm {
                envelope_id: envelope_id(),
                challenge_code: challenge_code(),
            },
        ),
        (
            "req_sender_revoke",
            DirectedRequest::SenderRevoke {
                envelope_id: envelope_id(),
            },
        ),
        (
            "req_status_query",
            DirectedRequest::StatusQuery {
                envelope_id: envelope_id(),
            },
        ),
    ] {
        let mut out: Vec<u8> = Vec::new();
        block_on(c.write_request(&p, &mut out, req)).unwrap();
        assert!(
            out == frame(&frozen(name)),
            "the frame written for `{name}` differs from the frozen one"
        );
        let mut rd = futures::io::Cursor::new(out);
        let back = block_on(c.read_request(&p, &mut rd)).unwrap();
        assert_eq!(bin(&back), frozen(name));
    }
    for (name, resp) in [
        (
            "resp_invite_accepted",
            DirectedResponse::InviteAccepted {
                envelope_id: envelope_id(),
            },
        ),
        (
            "resp_error",
            DirectedResponse::Error("unsupported directed envelope version 2".into()),
        ),
        (
            "resp_status_confirmed",
            DirectedResponse::Status {
                envelope_id: envelope_id(),
                state: EnvelopeState::Confirmed,
            },
        ),
    ] {
        let mut out: Vec<u8> = Vec::new();
        block_on(c.write_response(&p, &mut out, resp)).unwrap();
        assert!(
            out == frame(&frozen(name)),
            "the frame written for `{name}` differs from the frozen one"
        );
        let mut rd = futures::io::Cursor::new(out);
        let back = block_on(c.read_response(&p, &mut rd)).unwrap();
        assert_eq!(bin(&back), frozen(name));
    }
}

#[test]
fn the_codec_enforces_its_size_limit_and_rejects_short_frames() {
    let mut c = DirectedCodec;
    let p = proto();
    // A declared length over the limit is refused before anything is read.
    let mut rd = futures::io::Cursor::new(((DIRECTED_MSG_MAX + 1) as u32).to_le_bytes().to_vec());
    let err = block_on(c.read_request(&p, &mut rd)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    // A frame shorter than its declared length ends early.
    let mut short = frame(&frozen("req_invite"));
    short.truncate(short.len() - 1);
    let mut rd = futures::io::Cursor::new(short);
    let err = block_on(c.read_request(&p, &mut rd)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

// ─── (d) trailing bytes, versions and unknown variants ───────────────────────

#[test]
fn trailing_bytes_after_a_message_are_ignored() {
    // The planned v2 envelope appends fields. This is the behaviour it needs:
    // the bytes after the last known field do not make the message unreadable.
    let extra = fill::<40>("appended v2 fields");
    for name in [
        "req_invite",
        "req_invite_confirmed",
        "req_confirm",
        "req_sender_revoke",
        "req_status_query",
    ] {
        let mut bytes = frozen(name);
        let want = bytes.clone();
        bytes.extend_from_slice(&extra);
        let back: DirectedRequest = bincode::deserialize(&bytes)
            .unwrap_or_else(|_| panic!("trailing bytes made `{name}` unreadable"));
        assert_eq!(bin(&back), want, "`{name}` changed when bytes were appended");
    }
    for (_, name) in STATES {
        let mut bytes = frozen(&format!("resp_status_{name}"));
        let want = bytes.clone();
        bytes.extend_from_slice(&extra);
        let back: DirectedResponse = bincode::deserialize(&bytes).unwrap();
        assert_eq!(bin(&back), want);
    }
    for name in ["envelope_pending", "envelope_confirmed"] {
        let mut bytes = frozen(name);
        bytes.extend_from_slice(&extra);
        assert!(bincode::deserialize::<DirectedEnvelope>(&bytes).is_ok());
    }
}

#[test]
fn the_codec_reads_a_frame_that_has_extra_bytes_inside_it() {
    let mut c = DirectedCodec;
    let p = proto();
    let mut payload = frozen("req_invite");
    payload.extend_from_slice(&fill::<40>("appended v2 fields"));
    let mut rd = futures::io::Cursor::new(frame(&payload));
    match block_on(c.read_request(&p, &mut rd)).unwrap() {
        DirectedRequest::Invite { envelope } => check_envelope(&envelope, &pending_envelope()),
        other => panic!("expected Invite, got {other:?}"),
    }
}

#[test]
fn a_v2_invite_reads_as_an_invite_with_version_two() {
    // What a v2 sender's Invite looks like to this build: the version byte is 2
    // and extra fields follow the envelope. It decodes; the version is what
    // the receive path acts on (see the node test below).
    let mut bytes = frozen("req_invite");
    bytes[36] = 2;
    bytes.extend_from_slice(&fill::<64>("v2 trailing envelope fields"));
    match bincode::deserialize::<DirectedRequest>(&bytes).unwrap() {
        DirectedRequest::Invite { envelope } => {
            assert_eq!(envelope.version, 2);
            let mut want = pending_envelope();
            want.version = 2;
            check_envelope(&envelope, &want);
        }
        other => panic!("expected Invite, got {other:?}"),
    }
}

#[test]
fn a_request_variant_this_build_does_not_know_does_not_decode() {
    // New variants are appended after StatusQuery (index 3). A build that
    // predates them cannot read them: the inbound request fails, it is not
    // taken for something else.
    let mut bytes = 4u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&envelope_id());
    assert!(bincode::deserialize::<DirectedRequest>(&bytes).is_err());
    let mut bytes = 6u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&envelope_id());
    assert!(bincode::deserialize::<DirectedResponse>(&bytes).is_err());
    // An EnvelopeState index past the last one is refused too.
    let mut bytes = 4u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&envelope_id());
    bytes.extend_from_slice(&9u32.to_le_bytes());
    assert!(bincode::deserialize::<DirectedResponse>(&bytes).is_err());
}

// ─── (c) a real envelope still opens ─────────────────────────────────────────

struct RealKeys {
    sender_secret: [u8; 32],
    recipient_secret: [u8; 32],
    recipient_pub: [u8; 32],
    password: String,
}

fn real_keys() -> RealKeys {
    let recipient_secret: [u8; 32] = fill("real recipient secret");
    let recipient_static = x25519_dalek::StaticSecret::from(recipient_secret);
    RealKeys {
        sender_secret: fill("real sender secret"),
        recipient_secret,
        recipient_pub: x25519_dalek::PublicKey::from(&recipient_static).to_bytes(),
        password: format!("pw-{}", hex::encode(fill::<12>("real password"))),
    }
}

#[test]
fn a_real_v1_envelope_still_opens_with_the_same_keys_and_password() {
    let k = real_keys();
    let env: DirectedEnvelope = bincode::deserialize(&frozen("real_envelope")).unwrap();
    assert_eq!(env.version, 1);
    assert_eq!(env.recipient_pubkey, k.recipient_pub);
    assert_eq!(env.state, EnvelopeState::Pending);
    assert_eq!(env.retention_secs, 86_400);
    assert_eq!(env.expires_at, env.created_at + 86_400);
    // The sender's JSON copy is the same envelope.
    let json: DirectedEnvelope = serde_json::from_slice(&frozen("real_envelope_json")).unwrap();
    check_envelope(&json, &env);
    assert_eq!(serde_json::to_vec(&env).unwrap(), frozen("real_envelope_json"));
    assert_eq!(bin(&env), frozen("real_envelope"));

    // Payload layer: ECDH only, no password.
    let payload = decrypt_envelope_payload(&k.recipient_secret, &env).unwrap();
    let mid = String::from_utf8(frozen("real_mid")).unwrap();
    assert_eq!(payload.mid, mid);
    assert_eq!(payload.data_shards, 10);
    assert_eq!(payload.total_shards, 20);
    assert_eq!(payload.filename.as_deref(), Some("report.pdf"));
    assert_eq!(payload.file_size, REAL_PLAINTEXT.len() as u64);

    // The MID in the payload names the protected bytes.
    let protected = frozen("real_protected");
    assert_eq!(
        ContentId::compute(&protected, REAL_PARAMS).to_string(),
        payload.mid
    );

    // Content layer: ECDH and the password.
    let key = derive_content_key(&k.recipient_secret, &env, &k.password).unwrap();
    let plain = decrypt_directed_content(&key, &payload.content_nonce, &protected).unwrap();
    assert_eq!(plain, REAL_PLAINTEXT);

    // Another password does not open it, and neither does another recipient.
    let wrong = format!("{}x", k.password);
    let wrong_key = derive_content_key(&k.recipient_secret, &env, &wrong).unwrap();
    assert!(decrypt_directed_content(&wrong_key, &payload.content_nonce, &protected).is_err());
    let other: [u8; 32] = fill("another recipient secret");
    assert!(decrypt_envelope_payload(&other, &env).is_err());
}

// ─── (d) a running node refuses a version it does not know ───────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_node_answers_an_unknown_envelope_version_with_the_version_error() {
    let outcome = tokio::time::timeout(Duration::from_secs(90), async {
        let k = real_keys();
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let data_b = tempfile::tempdir().unwrap();

        // Receiver: knows its directed recipient key and where to keep the inbox.
        let mut node_b = MiasmaNode::new(
            &fill::<32>("node b master"),
            NodeType::Full,
            "/ip4/127.0.0.1/tcp/0",
        )
        .unwrap();
        node_b.set_directed_data_dir(data_b.path().to_path_buf());
        node_b.set_directed_recipient_pubkey(k.recipient_pub);
        let (topology_tx, mut topology_rx) = tokio::sync::mpsc::channel(8);
        node_b.set_topology_notifier(topology_tx);
        let peer_b = node_b.local_peer_id;
        let addrs_b: Vec<String> = node_b
            .collect_listen_addrs(400)
            .await
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert!(!addrs_b.is_empty(), "receiver has no listen address");

        let mut node_a = MiasmaNode::new(
            &fill::<32>("node a master"),
            NodeType::Full,
            "/ip4/127.0.0.1/tcp/0",
        )
        .unwrap();
        let addrs_a: Vec<String> = node_a
            .collect_listen_addrs(400)
            .await
            .iter()
            .map(|a| a.to_string())
            .collect();

        let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
        let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());
        let coord_a = MiasmaCoordinator::start(node_a, store_a, addrs_a).await;
        let _coord_b = MiasmaCoordinator::start(node_b, store_b, vec![]).await;

        // A directed request goes to a peer that is already connected: dial it
        // through the bootstrap path and wait for the link.
        let addr_b: libp2p::Multiaddr = addrs_b[0].parse().unwrap();
        coord_a.add_bootstrap_peer(peer_b, addr_b).await.unwrap();
        coord_a.bootstrap_dht().await.unwrap();
        coord_a
            .wait_until_peer_connected(peer_b, Duration::from_secs(10))
            .await
            .expect("the sender never connected to the receiver");

        let mut env: DirectedEnvelope = bincode::deserialize(&frozen("real_envelope")).unwrap();
        for version in [2u8, 0, 255] {
            env.version = version;
            let resp = coord_a
                .send_directed_request(
                    peer_b,
                    addrs_b.clone(),
                    DirectedRequest::Invite {
                        envelope: env.clone(),
                    },
                )
                .await
                .expect("the request should get a response");
            match resp {
                DirectedResponse::Error(m) => assert_eq!(
                    m,
                    format!("unsupported directed envelope version {version}")
                ),
                other => panic!("version {version}: expected the version error, got {other:?}"),
            }
        }

        // The same envelope at version 1 is taken in.
        env.version = 1;
        let resp = coord_a
            .send_directed_request(
                peer_b,
                addrs_b.clone(),
                DirectedRequest::Invite {
                    envelope: env.clone(),
                },
            )
            .await
            .expect("the v1 invite should get a response");
        assert!(
            matches!(resp, DirectedResponse::InviteAccepted { envelope_id: id } if id == id_of(&env)),
            "a version 1 invite for the right recipient must be accepted, got {resp:?}"
        );
        // The accepted envelope is handed on to the daemon; the refused ones were not.
        let mut handed_on = 0;
        while let Ok(ev) = topology_rx.try_recv() {
            if let miasma_core::network::types::TopologyEvent::DirectedEnvelopeReceived {
                envelope,
                ..
            } = ev
            {
                assert_eq!(envelope.version, 1);
                handed_on += 1;
            }
        }
        assert_eq!(handed_on, 1, "only the version 1 invite is handed on");
    })
    .await;
    outcome.expect("the node test timed out");
}

// ─── Generator (run once, by hand) ───────────────────────────────────────────

/// Prints every line of `frozen.hex`. Run with
/// `cargo test --test wire_compat_directed_test print_fixtures -- --ignored --nocapture`
/// and put the `FIXTURE` lines (without that word) into the file. Only for a
/// new format: never to make a failing test pass.
#[test]
#[ignore = "prints the fixture file; run by hand, once"]
fn print_fixtures() {
    for (name, bytes) in all() {
        println!("FIXTURE {name} {}", hex::encode(bytes));
    }
    let k = real_keys();
    let (mut env, protected, envelope_key) = create_envelope(
        &k.sender_secret,
        &k.recipient_pub,
        &k.password,
        RetentionPeriod::OneDay,
        REAL_PLAINTEXT,
        Some("report.pdf".to_string()),
    )
    .unwrap();
    let mid = ContentId::compute(&protected, REAL_PARAMS).to_string();
    finalize_envelope(&mut env, &envelope_key, &mid, 10, 20).unwrap();
    println!("FIXTURE real_envelope {}", hex::encode(bin(&env)));
    println!(
        "FIXTURE real_envelope_json {}",
        hex::encode(serde_json::to_vec(&env).unwrap())
    );
    println!("FIXTURE real_protected {}", hex::encode(&protected));
    println!("FIXTURE real_mid {}", hex::encode(mid.as_bytes()));
}
