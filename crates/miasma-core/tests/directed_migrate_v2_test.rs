//! Migration of a stored v1 directed envelope into the v2 recipient record
//! (design 7). The on-disk wire shape is unchanged: a v1 `DirectedEnvelope`
//! reads straight back as the flattened `wire` part, and the local view is
//! built from the wire fields and the sidecars.
//!
//! These tests exercise `IncomingRecord::migrate_v1` directly, with records
//! assembled in memory (no files are written), so they do not depend on the
//! data directory or the state key. The frozen v1 JSON tests and
//! `state_migration_test` are not touched by this file.
//!
//! No key, nonce, salt or password is written as a literal; the only secret-
//! shaped value is a confirmation hash from the real `generate_challenge`.

use miasma_core::directed::{
    generate_challenge, ChallengeLocal, DirectedEnvelope, EnvelopeState, IncomingRecord,
    MonoDeadline, Now, Protection, LEGACY_SENDER, MAX_RETENTION_SECS,
};

/// A v1 envelope in the given state, with every byte-shaped field a fixed non-
/// secret marker. `expires_at` is deliberately `u64::MAX` to prove the clamp.
fn v1_envelope(state: EnvelopeState) -> DirectedEnvelope {
    DirectedEnvelope {
        envelope_id: [0x42u8; 32],
        version: 1,
        sender_pubkey: [0x01u8; 32],
        recipient_pubkey: [0x02u8; 32],
        ephemeral_pubkey: [0x03u8; 32],
        encrypted_payload: vec![0x04; 64],
        payload_nonce: [0x05u8; 24],
        password_salt: [0x06u8; 32],
        expires_at: u64::MAX,
        created_at: 1_000,
        state,
        challenge_hash: None,
        password_attempts_remaining: 2,
        challenge_attempts_remaining: 3,
        challenge_expires_at: 0,
        retention_secs: 86_400,
    }
}

/// A v1 record as read from disk: the wire part only, no local view yet.
fn unmigrated(state: EnvelopeState) -> IncomingRecord {
    IncomingRecord {
        wire: v1_envelope(state),
        ext: None,
        local: None,
    }
}

fn mono(issued: u64, ttl: u64) -> MonoDeadline {
    MonoDeadline {
        issued_mono_ms: issued,
        ttl_ms: ttl,
        wall_expires_at: 0,
    }
}

fn challenge_local(tries: u8) -> ChallengeLocal {
    let (_code, hash) = generate_challenge();
    ChallengeLocal {
        hash,
        attempts_remaining: tries,
        expires: mono(0, 300_000),
    }
}

const NOW: Now = Now {
    wall_secs: 50_000,
    mono_ms: 7_000,
};

/// A v1 envelope has no local part, so no event applies until it is migrated.
#[test]
fn an_unmigrated_record_rejects_every_event() {
    use miasma_core::directed::IncomingEvent;
    let mut r = unmigrated(EnvelopeState::ChallengeIssued);
    assert!(r.local.is_none());
    assert!(r.step(IncomingEvent::RecipientDelete, NOW).is_err());
    // effective_state falls back to the wire state when not migrated.
    assert_eq!(r.effective_state(), EnvelopeState::ChallengeIssued);
}

/// A `Pending` v1 record (a two-write that stopped halfway) becomes
/// `ChallengeIssued` with a freshly rebuilt challenge, and is marked LegacyV1
/// with no ephemeral secret.
#[test]
fn a_pending_v1_record_is_rebuilt_as_challenge_issued() {
    let mut r = unmigrated(EnvelopeState::Pending);
    let rebuilt = challenge_local(3);
    r.migrate_v1(Some("peer-z".into()), Some(rebuilt), None, NOW);
    let local = r.local.as_ref().expect("local built");
    assert_eq!(local.state, EnvelopeState::ChallengeIssued);
    assert!(local.challenge.is_some(), "a rebuilt challenge is present");
    assert_eq!(local.sender_peer_id, "peer-z");
    assert_eq!(local.protection, Protection::LegacyV1);
    assert!(local.r_eph_secret.is_none());
    assert_eq!(local.password_attempts_remaining, 2);
    // The wire bytes are untouched.
    assert_eq!(r.wire.state, EnvelopeState::Pending);
    assert_eq!(r.wire.expires_at, u64::MAX);
}

/// A non-`Pending` v1 record keeps its file state and takes the existing
/// challenge (from the `.challenge` sidecar), if any.
#[test]
fn a_confirmed_v1_record_keeps_its_state_and_existing_challenge() {
    let mut r = unmigrated(EnvelopeState::Confirmed);
    let existing = challenge_local(1);
    r.migrate_v1(Some("peer-y".into()), None, Some(existing), NOW);
    let local = r.local.as_ref().expect("local built");
    assert_eq!(local.state, EnvelopeState::Confirmed);
    assert_eq!(
        local.challenge.as_ref().map(|c| c.attempts_remaining),
        Some(1),
        "the existing challenge is carried over"
    );
    assert_eq!(local.sender_peer_id, "peer-y");
    assert_eq!(local.protection, Protection::LegacyV1);
}

/// With no `.peer` sidecar the sender is the legacy placeholder.
#[test]
fn a_missing_peer_sidecar_becomes_the_legacy_placeholder() {
    let mut r = unmigrated(EnvelopeState::ChallengeIssued);
    r.migrate_v1(None, None, Some(challenge_local(3)), NOW);
    let local = r.local.as_ref().unwrap();
    assert_eq!(local.sender_peer_id, LEGACY_SENDER);
}

/// The effective expiry is clamped: a `u64::MAX` sender value cannot keep the
/// record past `migrated_at + MAX_RETENTION_SECS`, and `received_at` is the
/// migration wall time.
#[test]
fn the_effective_expiry_is_clamped_to_the_retention_ceiling() {
    let mut r = unmigrated(EnvelopeState::ChallengeIssued);
    r.migrate_v1(Some("peer-x".into()), None, Some(challenge_local(3)), NOW);
    let local = r.local.as_ref().unwrap();
    assert_eq!(local.received_at, NOW.wall_secs);
    assert_eq!(
        local.effective_expires_at,
        NOW.wall_secs + MAX_RETENTION_SECS,
        "a u64::MAX sender expiry is clamped to now + MAX_RETENTION_SECS"
    );
}

/// A sender `expires_at` nearer than the ceiling is kept as the sender's value.
#[test]
fn a_near_sender_expiry_is_kept_below_the_ceiling() {
    let mut env = v1_envelope(EnvelopeState::ChallengeIssued);
    env.expires_at = NOW.wall_secs + 100;
    let mut r = IncomingRecord {
        wire: env,
        ext: None,
        local: None,
    };
    r.migrate_v1(Some("peer-w".into()), None, Some(challenge_local(3)), NOW);
    let local = r.local.as_ref().unwrap();
    assert_eq!(local.effective_expires_at, NOW.wall_secs + 100);
}

/// Migration is idempotent: a record that already has a local part is left
/// unchanged by a second call.
#[test]
fn migrating_an_already_migrated_record_is_a_no_op() {
    let mut r = unmigrated(EnvelopeState::Confirmed);
    r.migrate_v1(Some("peer-a".into()), None, Some(challenge_local(2)), NOW);
    let first = r.local.as_ref().unwrap().sender_peer_id.clone();
    // A second call with a different peer must not overwrite the local view.
    let later = Now {
        wall_secs: NOW.wall_secs + 10_000,
        mono_ms: NOW.mono_ms + 10_000,
    };
    r.migrate_v1(Some("peer-b".into()), None, Some(challenge_local(3)), later);
    assert_eq!(r.local.as_ref().unwrap().sender_peer_id, first);
}

/// After migration the record is a working state machine: a correct Confirm on
/// a rebuilt Pending record moves it to Confirmed.
#[test]
fn a_migrated_pending_record_confirms_with_the_rebuilt_code() {
    use miasma_core::directed::IncomingEvent;
    let (code, hash) = generate_challenge();
    let rebuilt = ChallengeLocal {
        hash,
        attempts_remaining: 3,
        expires: mono(0, 300_000),
    };
    let mut r = unmigrated(EnvelopeState::Pending);
    r.migrate_v1(Some("peer-a".into()), Some(rebuilt), None, NOW);
    let now = Now {
        wall_secs: NOW.wall_secs,
        mono_ms: 1_000,
    };
    let fx = r.step(IncomingEvent::Confirm { code }, now).unwrap();
    assert_eq!(r.effective_state(), EnvelopeState::Confirmed);
    assert!(fx.clear_challenge && !fx.reached_terminal);
}
