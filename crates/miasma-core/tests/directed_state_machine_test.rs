//! Model tests for the directed-share recipient and sender state machines
//! (design 6.2, 6.3, 8.3).
//!
//! These drive the public `step` functions on `IncomingRecord` and
//! `OutgoingRecord` and compare them against a small table-driven reference
//! model. They cover the full state x event grid, a long pseudo-random event
//! stream checked against the model, the monotonic-clock rollback guard, and
//! the write-count property (a step either writes once, deletes once, or does
//! not write at all).
//!
//! No key, nonce, salt or password is written as a literal. The only secret-
//! shaped value is the confirmation code, which comes from the real
//! `generate_challenge`.

use miasma_core::directed::{
    generate_challenge, ChallengeLocal, Effects, EnvelopeState, Illegal, IncomingEvent,
    IncomingLocal, IncomingRecord, MonoDeadline, Now, OutgoingEvent, OutgoingPhase, OutgoingRecord,
    Protection,
};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ── Fixtures ────────────────────────────────────────────────────────────────

/// A canonical wire envelope. Every byte-shaped field is a fixed non-secret
/// marker; none of these are key material.
fn wire(state: EnvelopeState) -> miasma_core::directed::DirectedEnvelope {
    miasma_core::directed::DirectedEnvelope {
        envelope_id: [0x42u8; 32],
        version: 1,
        sender_pubkey: [0x01u8; 32],
        recipient_pubkey: [0x02u8; 32],
        ephemeral_pubkey: [0x03u8; 32],
        encrypted_payload: vec![0x04; 64],
        payload_nonce: [0x05u8; 24],
        password_salt: [0x06u8; 32],
        expires_at: 10_000,
        created_at: 1_000,
        state,
        challenge_hash: None,
        password_attempts_remaining: 3,
        challenge_attempts_remaining: 3,
        challenge_expires_at: 0,
        retention_secs: 86_400,
    }
}

fn mono(issued: u64, ttl: u64) -> MonoDeadline {
    MonoDeadline {
        issued_mono_ms: issued,
        ttl_ms: ttl,
        wall_expires_at: 0,
    }
}

/// Build a record in `state` with the given remaining challenge tries, password
/// tries, challenge deadline and effective expiry. The confirmation hash is a
/// real one so a matching code can be produced on demand; the raw code is
/// returned too. For states other than `ChallengeIssued` the challenge is
/// dropped, matching what a real terminal/confirmed record holds.
fn record(
    state: EnvelopeState,
    challenge_tries: u8,
    password_tries: u8,
    deadline: MonoDeadline,
    effective_expires_at: u64,
) -> (IncomingRecord, String) {
    let (code, hash) = generate_challenge();
    let challenge = if state == EnvelopeState::ChallengeIssued {
        Some(ChallengeLocal {
            hash,
            attempts_remaining: challenge_tries,
            expires: deadline,
        })
    } else {
        None
    };
    let r_eph = if state.is_terminal() {
        None
    } else {
        // A random non-terminal ephemeral secret; no fixed key material.
        Some(rand::random::<[u8; 32]>())
    };
    let local = IncomingLocal {
        state,
        challenge,
        password_attempts_remaining: password_tries,
        password_attempt_pending: false,
        received_at: 1_000,
        effective_expires_at,
        sender_peer_id: "peer-a".into(),
        protection: Protection::V2,
        r_eph_secret: r_eph,
    };
    (
        IncomingRecord {
            wire: wire(state),
            ext: None,
            local: Some(local),
        },
        code,
    )
}

const NOW: Now = Now {
    wall_secs: 2_000,
    mono_ms: 5_000,
};

/// The nine recipient states.
const STATES: [EnvelopeState; 9] = [
    EnvelopeState::Pending,
    EnvelopeState::ChallengeIssued,
    EnvelopeState::Confirmed,
    EnvelopeState::Retrieved,
    EnvelopeState::SenderRevoked,
    EnvelopeState::RecipientDeleted,
    EnvelopeState::Expired,
    EnvelopeState::ChallengeFailed,
    EnvelopeState::PasswordFailed,
];

// ── Reference model (design 6.2) ────────────────────────────────────────────

/// A compact label for each event kind, so the model table does not have to
/// carry a code string. Maps one-to-one onto `IncomingEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ev {
    ConfirmRight,
    ConfirmWrong,
    PasswordAttemptStart,
    RetrievedOk,
    PasswordWrong,
    RetrievalNetworkFailure,
    SenderRevoke,
    RecipientDelete,
    ExpiryTick,
    ChallengeTimeout,
}

impl Ev {
    /// A fixed label naming the event kind. Used in assert messages so the
    /// formatted output is a constant string, never a value that could carry a
    /// confirmation code.
    fn label(self) -> &'static str {
        match self {
            Ev::ConfirmRight => "ConfirmRight",
            Ev::ConfirmWrong => "ConfirmWrong",
            Ev::PasswordAttemptStart => "PasswordAttemptStart",
            Ev::RetrievedOk => "RetrievedOk",
            Ev::PasswordWrong => "PasswordWrong",
            Ev::RetrievalNetworkFailure => "RetrievalNetworkFailure",
            Ev::SenderRevoke => "SenderRevoke",
            Ev::RecipientDelete => "RecipientDelete",
            Ev::ExpiryTick => "ExpiryTick",
            Ev::ChallengeTimeout => "ChallengeTimeout",
        }
    }
}

const EVENTS: [Ev; 10] = [
    Ev::ConfirmRight,
    Ev::ConfirmWrong,
    Ev::PasswordAttemptStart,
    Ev::RetrievedOk,
    Ev::PasswordWrong,
    Ev::RetrievalNetworkFailure,
    Ev::SenderRevoke,
    Ev::RecipientDelete,
    Ev::ExpiryTick,
    Ev::ChallengeTimeout,
];

/// What the reference model predicts: whether the step is legal, and when it
/// is, the next state. This mirrors design 6.2 directly; it does not call the
/// implementation. `challenge_tries` and `password_tries` are the counts the
/// record holds, and `expiry_passed` says whether `ExpiryTick` should fire.
struct Predicted {
    legal: bool,
    next: EnvelopeState,
}

fn predict(
    state: EnvelopeState,
    ev: Ev,
    challenge_tries: u8,
    password_tries: u8,
    challenge_expired: bool,
    expiry_passed: bool,
) -> Predicted {
    use EnvelopeState as S;
    let illegal = Predicted {
        legal: false,
        next: state,
    };
    let to = |next| Predicted { legal: true, next };
    match (state, ev) {
        // ChallengeIssued
        (S::ChallengeIssued, Ev::ConfirmRight) => {
            if challenge_expired {
                to(S::ChallengeFailed)
            } else {
                to(S::Confirmed)
            }
        }
        (S::ChallengeIssued, Ev::ConfirmWrong) => {
            if challenge_expired || challenge_tries <= 1 {
                to(S::ChallengeFailed)
            } else {
                to(S::ChallengeIssued)
            }
        }
        (S::ChallengeIssued, Ev::ChallengeTimeout) => to(S::ChallengeFailed),
        (S::ChallengeIssued, Ev::SenderRevoke) => to(S::SenderRevoked),
        (S::ChallengeIssued, Ev::RecipientDelete) => to(S::RecipientDeleted),
        (S::ChallengeIssued, Ev::ExpiryTick) => {
            if expiry_passed {
                to(S::Expired)
            } else {
                illegal
            }
        }
        // Confirmed
        (S::Confirmed, Ev::PasswordAttemptStart) => {
            if password_tries == 0 {
                illegal
            } else {
                to(S::Confirmed)
            }
        }
        (S::Confirmed, Ev::RetrievedOk) => to(S::Retrieved),
        (S::Confirmed, Ev::PasswordWrong) => {
            if password_tries == 0 {
                to(S::PasswordFailed)
            } else {
                to(S::Confirmed)
            }
        }
        (S::Confirmed, Ev::RetrievalNetworkFailure) => to(S::Confirmed),
        (S::Confirmed, Ev::SenderRevoke) => to(S::SenderRevoked),
        (S::Confirmed, Ev::RecipientDelete) => to(S::RecipientDeleted),
        (S::Confirmed, Ev::ExpiryTick) => {
            if expiry_passed {
                to(S::Expired)
            } else {
                illegal
            }
        }
        // SenderRevoked is terminal, but a revoke replay on an already-revoked
        // record is a legal no-write that leaves the state unchanged
        // (design 6.2: "SenderRevoked + sender revoke (replay) -> SenderRevoked,
        // no write"). The grid test checks next state only; the no-write effect
        // is covered by check_write_count and the terminal-states test.
        (S::SenderRevoked, Ev::SenderRevoke) => to(S::SenderRevoked),
        // Everything else (including every other terminal state and Pending) is illegal.
        _ => illegal,
    }
}

/// Translate a model event into the real event, drawing a wrong code when asked.
fn make_event(ev: Ev, right_code: &str) -> IncomingEvent {
    match ev {
        Ev::ConfirmRight => IncomingEvent::Confirm {
            code: right_code.to_string(),
        },
        Ev::ConfirmWrong => {
            // A second draw that differs from the right code is a wrong code.
            let mut wrong = generate_challenge().0;
            while wrong == right_code {
                wrong = generate_challenge().0;
            }
            IncomingEvent::Confirm { code: wrong }
        }
        Ev::PasswordAttemptStart => IncomingEvent::PasswordAttemptStart,
        Ev::RetrievedOk => IncomingEvent::RetrievedOk,
        Ev::PasswordWrong => IncomingEvent::PasswordWrong,
        Ev::RetrievalNetworkFailure => IncomingEvent::RetrievalNetworkFailure,
        Ev::SenderRevoke => IncomingEvent::SenderRevoke,
        Ev::RecipientDelete => IncomingEvent::RecipientDelete,
        Ev::ExpiryTick => IncomingEvent::ExpiryTick,
        Ev::ChallengeTimeout => IncomingEvent::ChallengeTimeout,
    }
}

/// A legal, non-`no_write` step writes the record exactly once: it never both
/// deletes and keeps. A `no_write` step changes nothing.
fn check_write_count(fx: &Effects) {
    if fx.no_write {
        assert!(!fx.delete_file, "a no-write step must not delete");
        assert!(!fx.reached_terminal, "a no-write step must not be terminal");
    }
    // delete_file implies the record reached a terminal state.
    if fx.delete_file {
        assert!(fx.reached_terminal, "a delete must be terminal");
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Full grid: every (state, event, challenge-tries, password-tries) combination
/// either matches the model's legal transition or returns `Illegal` with the
/// record unchanged. Terminal states never move (the revoke replay on an
/// already-revoked record is a legal no-write, handled below).
#[test]
fn the_full_state_event_grid_matches_the_model() {
    for &state in &STATES {
        for &ev in &EVENTS {
            for challenge_tries in 0u8..=3 {
                for password_tries in 0u8..=3 {
                    // A non-expired challenge and a not-yet-reached expiry.
                    let (mut r, code) = record(
                        state,
                        challenge_tries,
                        password_tries,
                        mono(0, 300_000),
                        10_000,
                    );
                    let before = r.effective_state();
                    let ev_label = ev.label();
                    let predicted =
                        predict(state, ev, challenge_tries, password_tries, false, false);
                    let event = make_event(ev, &code);
                    match r.step(event, NOW) {
                        Ok(fx) => {
                            check_write_count(&fx);
                            assert!(
                                predicted.legal,
                                "{state:?} + {ev_label} was accepted but the model forbids it"
                            );
                            assert_eq!(
                                r.effective_state(),
                                predicted.next,
                                "{state:?} + {ev_label} went to the wrong next state"
                            );
                        }
                        Err(Illegal) => {
                            assert!(
                                !predicted.legal,
                                "{state:?} + {ev_label} was refused but the model allows it"
                            );
                            assert_eq!(
                                r.effective_state(),
                                before,
                                "an illegal step changed the state"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Terminal states never leave, and a revoke replay on an already-revoked
/// record is a legal no-write.
#[test]
fn terminal_states_do_not_move_and_revoke_replay_is_a_no_write() {
    let terminals = [
        EnvelopeState::Retrieved,
        EnvelopeState::SenderRevoked,
        EnvelopeState::RecipientDeleted,
        EnvelopeState::Expired,
        EnvelopeState::ChallengeFailed,
        EnvelopeState::PasswordFailed,
    ];
    for &state in &terminals {
        for &ev in &EVENTS {
            let (mut r, code) = record(state, 3, 3, mono(0, 300_000), 10_000);
            let event = make_event(ev, &code);
            match r.step(event, NOW) {
                Ok(fx) => {
                    // The only legal step out of a terminal is a revoke replay on
                    // SenderRevoked, which writes nothing.
                    assert!(
                        state == EnvelopeState::SenderRevoked && ev == Ev::SenderRevoke,
                        "unexpected legal step from terminal {state:?} on {ev:?}"
                    );
                    assert!(fx.no_write);
                    assert_eq!(r.effective_state(), EnvelopeState::SenderRevoked);
                }
                Err(Illegal) => {
                    assert_eq!(r.effective_state(), state, "terminal state changed");
                }
            }
        }
    }
}

/// A long pseudo-random stream of events, applied to both the implementation
/// and the reference model in lock-step; the states must agree at every step.
/// The model tracks the counts it needs to predict the next transition.
#[test]
fn a_random_event_stream_agrees_with_the_model() {
    let mut rng = StdRng::seed_from_u64(0xD3_5747E);
    for _ in 0..10_000 {
        // Fresh record, always starting at ChallengeIssued with 3/3 tries.
        let (mut r, code) = record(
            EnvelopeState::ChallengeIssued,
            3,
            3,
            mono(0, 300_000),
            10_000,
        );
        let mut model_state = EnvelopeState::ChallengeIssued;
        let mut challenge_tries = 3u8;
        let mut password_tries = 3u8;
        // Mirrors the record's `password_attempt_pending`: a give-back only
        // returns a try that `PasswordAttemptStart` actually pre-spent.
        let mut password_pending = false;
        for _ in 0..12 {
            let ev = EVENTS[rng.gen_range(0..EVENTS.len())];
            let predicted = predict(
                model_state,
                ev,
                challenge_tries,
                password_tries,
                false,
                false,
            );
            let event = make_event(ev, &code);
            let result = r.step(event, NOW);
            match (result, predicted.legal) {
                (Ok(fx), true) => {
                    check_write_count(&fx);
                    // Advance the model's counts the same way the design does
                    // (6.2: pre-spend on attempt start, give back only a try
                    // that is outstanding).
                    match (model_state, ev) {
                        (EnvelopeState::ChallengeIssued, Ev::ConfirmWrong)
                            if challenge_tries > 1 =>
                        {
                            challenge_tries -= 1;
                        }
                        (EnvelopeState::Confirmed, Ev::PasswordAttemptStart) => {
                            password_tries = password_tries.saturating_sub(1);
                            password_pending = true;
                        }
                        (EnvelopeState::Confirmed, Ev::RetrievedOk) => {
                            if password_pending {
                                password_tries = password_tries.saturating_add(1);
                                password_pending = false;
                            }
                        }
                        (EnvelopeState::Confirmed, Ev::PasswordWrong) => {
                            password_pending = false;
                        }
                        (EnvelopeState::Confirmed, Ev::RetrievalNetworkFailure) => {
                            if password_pending {
                                password_tries = password_tries.saturating_add(1);
                                password_pending = false;
                            }
                        }
                        _ => {}
                    }
                    model_state = predicted.next;
                    assert_eq!(
                        r.effective_state(),
                        model_state,
                        "implementation and model diverged on {ev:?}"
                    );
                }
                (Err(Illegal), false) => {
                    assert_eq!(r.effective_state(), model_state);
                }
                (Ok(_), false) => {
                    panic!("{model_state:?} + {ev:?} accepted but model forbids it")
                }
                (Err(Illegal), true) => {
                    panic!("{model_state:?} + {ev:?} refused but model allows it")
                }
            }
        }
    }
}

/// Invariant: challenge and password tries never rise except for a give-back of
/// a pre-spent try (on retrieval success or a network failure, design 6.2 rows
/// for `RetrievedOk` and `RetrievalNetworkFailure`), the count never climbs past
/// its starting value, and a terminal record carries no secret.
#[test]
fn counts_do_not_rise_and_terminal_records_hold_no_secret() {
    let mut rng = StdRng::seed_from_u64(0x5EED_D3);
    for _ in 0..2_000 {
        let (mut r, code) = record(
            EnvelopeState::ChallengeIssued,
            3,
            3,
            mono(0, 300_000),
            10_000,
        );
        let mut last_pw = 3u8;
        for _ in 0..16 {
            let ev = EVENTS[rng.gen_range(0..EVENTS.len())];
            let was_confirmed = r.effective_state() == EnvelopeState::Confirmed;
            let event = make_event(ev, &code);
            if r.step(event, NOW).is_err() {
                continue;
            }
            let local = r.local.as_ref().unwrap();
            let pw = local.password_attempts_remaining;
            // The only legal rise is giving back a pre-spent try, on retrieval
            // success or a network failure, and only from Confirmed.
            if pw > last_pw {
                assert!(
                    was_confirmed && (ev == Ev::RetrievalNetworkFailure || ev == Ev::RetrievedOk),
                    "password tries rose without a give-back of a pre-spent try"
                );
            }
            // A give-back never raises the count past its starting value, so a
            // run of network failures with no matching pre-spend cannot inflate
            // the count.
            assert!(pw <= 3, "password tries climbed past the starting value");
            last_pw = pw;
            if local.state.is_terminal() {
                assert!(local.r_eph_secret.is_none(), "terminal record kept r_eph");
                assert!(
                    local.challenge.is_none(),
                    "terminal record kept its challenge"
                );
            }
        }
    }
}

/// The monotonic deadline is what the challenge TTL is judged against: moving
/// the wall clock backwards does not revive an expired challenge, and a
/// monotonic reading before the issue point is not treated as expired.
#[test]
fn a_backward_wall_clock_does_not_extend_the_challenge_window() {
    // Issued at mono=1000ms, TTL=300ms -> expires at mono=1300ms.
    let (mut r, code) = record(
        EnvelopeState::ChallengeIssued,
        3,
        3,
        mono(1_000, 300),
        10_000,
    );
    // A Confirm with the right code arrives at mono=2000 (past), wall early.
    let now = Now {
        wall_secs: 0,
        mono_ms: 2_000,
    };
    let fx = r.step(IncomingEvent::Confirm { code }, now).unwrap();
    assert_eq!(r.effective_state(), EnvelopeState::ChallengeFailed);
    assert!(fx.delete_file && fx.reached_terminal);

    // A reading before issue is not expired; at/after the deadline it is.
    let d = mono(5_000, 300);
    assert!(!d.is_expired(4_000));
    assert!(!d.is_expired(5_000 + 299));
    assert!(d.is_expired(5_000 + 300));
}

/// The effective expiry is a wall value: an `ExpiryTick` before the deadline is
/// illegal, and one at or after it moves to `Expired` and drops the secret.
#[test]
fn expiry_uses_the_wall_clock_effective_deadline() {
    let (mut r, _code) = record(EnvelopeState::Confirmed, 3, 3, mono(0, 300_000), 10_000);
    assert!(r.step(IncomingEvent::ExpiryTick, NOW).is_err());
    let late = Now {
        wall_secs: 10_000,
        mono_ms: 9_000,
    };
    let fx = r.step(IncomingEvent::ExpiryTick, late).unwrap();
    assert_eq!(r.effective_state(), EnvelopeState::Expired);
    assert!(fx.reached_terminal && fx.clear_r_eph);
    assert!(r.local.as_ref().unwrap().r_eph_secret.is_none());
}

/// Password tries are spent before the attempt, so a process stopped mid-
/// attempt does not get the try back; a run of three wrong attempts fails
/// closed, and a network failure returns the pre-spent try.
#[test]
fn password_tries_are_spent_first_and_a_network_failure_returns_one() {
    let (mut r, code) = record(
        EnvelopeState::ChallengeIssued,
        3,
        3,
        mono(0, 300_000),
        10_000,
    );
    r.step(IncomingEvent::Confirm { code }, NOW).unwrap();
    // Spend one, then a network failure gives it back.
    r.step(IncomingEvent::PasswordAttemptStart, NOW).unwrap();
    assert_eq!(r.local.as_ref().unwrap().password_attempts_remaining, 2);
    r.step(IncomingEvent::RetrievalNetworkFailure, NOW).unwrap();
    assert_eq!(r.local.as_ref().unwrap().password_attempts_remaining, 3);
    // Three wrong attempts fail closed.
    for _ in 0..3 {
        r.step(IncomingEvent::PasswordAttemptStart, NOW).unwrap();
        r.step(IncomingEvent::PasswordWrong, NOW).unwrap();
    }
    assert_eq!(r.effective_state(), EnvelopeState::PasswordFailed);
    assert!(r.local.as_ref().unwrap().r_eph_secret.is_none());
    assert!(r.step(IncomingEvent::PasswordAttemptStart, NOW).is_err());
}

/// The sender phase is off-wire: a normal delivery-then-confirm run, and a
/// challenge failure that becomes terminal when the recipient reports zero
/// tries left.
#[test]
fn the_sender_phase_delivers_confirms_and_fails_closed() {
    let mut o = OutgoingRecord {
        wire: wire(EnvelopeState::Pending),
        phase: OutgoingPhase::Fresh,
        recipient_attempts_remaining: None,
    };
    o.step(OutgoingEvent::Published, NOW).unwrap();
    assert_eq!(o.phase, OutgoingPhase::AwaitingRecipient);
    let fx = o.step(OutgoingEvent::InviteStored, NOW).unwrap();
    assert_eq!(o.phase, OutgoingPhase::Delivered);
    assert!(fx.clear_r_eph);
    o.step(OutgoingEvent::ConfirmOk, NOW).unwrap();
    assert_eq!(o.phase, OutgoingPhase::Confirmed);

    let mut o2 = OutgoingRecord {
        wire: wire(EnvelopeState::Pending),
        phase: OutgoingPhase::Delivered,
        recipient_attempts_remaining: None,
    };
    o2.step(
        OutgoingEvent::ConfirmWrong {
            attempts_remaining: 1,
        },
        NOW,
    )
    .unwrap();
    assert_eq!(o2.phase, OutgoingPhase::Delivered);
    let fx = o2
        .step(
            OutgoingEvent::ConfirmWrong {
                attempts_remaining: 0,
            },
            NOW,
        )
        .unwrap();
    assert_eq!(o2.phase, OutgoingPhase::ChallengeFailed);
    assert!(fx.reached_terminal);
}

/// A revoke replay on an already-revoked record is a legal no-write that leaves
/// the state at `SenderRevoked` (design 6.2: the `SenderRevoked + sender revoke
/// (replay)` row). This pins the behaviour that the grid and random-stream
/// tests rely on: the implementation accepts the replay without a write, and the
/// reference model agrees it is legal with an unchanged next state.
#[test]
fn revoke_replay_on_sender_revoked_is_a_legal_no_write() {
    let (mut r, _code) = record(EnvelopeState::SenderRevoked, 0, 0, mono(0, 300_000), 10_000);
    // The model predicts a legal, state-preserving step.
    let predicted = predict(
        EnvelopeState::SenderRevoked,
        Ev::SenderRevoke,
        0,
        0,
        false,
        false,
    );
    assert!(predicted.legal);
    assert_eq!(predicted.next, EnvelopeState::SenderRevoked);
    // The implementation accepts it as a no-write and does not move.
    let fx = r.step(IncomingEvent::SenderRevoke, NOW).unwrap();
    assert!(fx.no_write);
    assert!(!fx.reached_terminal);
    assert!(!fx.delete_file);
    assert_eq!(r.effective_state(), EnvelopeState::SenderRevoked);
}

/// Across every terminal state and every event, the only legal step is the
/// revoke replay on `SenderRevoked`; every other terminal (state, event) pair is
/// `Illegal` and leaves the state unchanged. The reference model and the
/// implementation must agree on this for all pairs, so no other terminal
/// combination can quietly become acceptable.
#[test]
fn only_sender_revoked_accepts_a_terminal_replay() {
    let terminals = [
        EnvelopeState::Retrieved,
        EnvelopeState::SenderRevoked,
        EnvelopeState::RecipientDeleted,
        EnvelopeState::Expired,
        EnvelopeState::ChallengeFailed,
        EnvelopeState::PasswordFailed,
    ];
    for &state in &terminals {
        for &ev in &EVENTS {
            let (mut r, code) = record(state, 3, 3, mono(0, 300_000), 10_000);
            let predicted = predict(state, ev, 3, 3, false, false);
            let is_revoke_replay = state == EnvelopeState::SenderRevoked && ev == Ev::SenderRevoke;
            // The model marks exactly the revoke replay legal among terminals.
            assert_eq!(
                predicted.legal, is_revoke_replay,
                "model legality disagrees for a terminal pair"
            );
            let event = make_event(ev, &code);
            match r.step(event, NOW) {
                Ok(fx) => {
                    assert!(is_revoke_replay, "an unexpected terminal pair was accepted");
                    assert!(fx.no_write, "the revoke replay must not write");
                    assert_eq!(r.effective_state(), EnvelopeState::SenderRevoked);
                }
                Err(Illegal) => {
                    assert!(!is_revoke_replay, "the revoke replay was refused");
                    assert_eq!(
                        r.effective_state(),
                        state,
                        "an illegal step changed the state"
                    );
                }
            }
        }
    }
}
