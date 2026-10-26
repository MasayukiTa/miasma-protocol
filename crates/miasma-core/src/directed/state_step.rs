//! The recipient and sender transition functions, kept apart from the type
//! definitions in `state.rs` for readability. The tables are design 6.2
//! (recipient) and 6.3 (sender).

use super::envelope::EnvelopeState;
use super::state::{
    Effects, Illegal, IncomingEvent, IncomingRecord, Now, OutgoingEvent, OutgoingPhase,
    OutgoingRecord,
};

impl IncomingRecord {
    /// Apply one event to a recipient record (design 6.2). On success the
    /// record is mutated in place and the [`Effects`] tell the caller what to
    /// persist or drop in the same write. On [`Illegal`] the record is left
    /// untouched.
    ///
    /// Password-attempt accounting decrements before the attempt is made
    /// (`PasswordAttemptStart`) so a process killed mid-attempt does not get the
    /// try back; a genuine network failure returns it (`RetrievalNetworkFailure`).
    pub fn step(&mut self, event: IncomingEvent, now: Now) -> Result<Effects, Illegal> {
        let Some(local) = self.local.as_mut() else {
            // A record with no local part has not been set up as a state machine
            // yet; no event applies until it is migrated (see `migrate_v1`).
            return Err(Illegal);
        };
        let state = local.state;
        let mut fx = Effects::default();

        // Terminal states never move again; a revoke replay is reported without a
        // write (design 6.2, last two rows).
        if state.is_terminal() {
            if matches!(event, IncomingEvent::SenderRevoke) && state == EnvelopeState::SenderRevoked
            {
                fx.no_write = true;
                return Ok(fx);
            }
            return Err(Illegal);
        }

        match (state, event) {
            // ── ChallengeIssued ──────────────────────────────────────────────
            (EnvelopeState::ChallengeIssued, IncomingEvent::Confirm { code }) => {
                let challenge = local.challenge.as_mut().ok_or(Illegal)?;
                if challenge.expires.is_expired(now.mono_ms) {
                    // Expiry beats a late-but-correct code.
                    local.state = EnvelopeState::ChallengeFailed;
                    local.challenge = None;
                    local.clear_r_eph();
                    fx.clear_challenge = true;
                    fx.clear_r_eph = true;
                    fx.reached_terminal = true;
                    fx.delete_file = true;
                    return Ok(fx);
                }
                if super::challenge::verify_challenge(&code, &challenge.hash) {
                    local.state = EnvelopeState::Confirmed;
                    local.challenge = None;
                    fx.clear_challenge = true;
                    return Ok(fx);
                }
                // Wrong code: spend one try. The last try moves to terminal.
                if challenge.attempts_remaining > 1 {
                    challenge.attempts_remaining -= 1;
                    return Ok(fx);
                }
                challenge.attempts_remaining = 0;
                local.state = EnvelopeState::ChallengeFailed;
                local.challenge = None;
                local.clear_r_eph();
                fx.clear_challenge = true;
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                fx.delete_file = true;
                Ok(fx)
            }
            (EnvelopeState::ChallengeIssued, IncomingEvent::ChallengeTimeout) => {
                local.state = EnvelopeState::ChallengeFailed;
                local.challenge = None;
                local.clear_r_eph();
                fx.clear_challenge = true;
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                fx.delete_file = true;
                Ok(fx)
            }

            // ── Confirmed ────────────────────────────────────────────────────
            (EnvelopeState::Confirmed, IncomingEvent::PasswordAttemptStart) => {
                // Decrement first, then let the caller try; a crash keeps the
                // lower count. Mark the pre-spend so a later network-failure
                // give-back returns exactly this try and no more.
                if local.password_attempts_remaining == 0 {
                    return Err(Illegal);
                }
                local.password_attempts_remaining -= 1;
                local.password_attempt_pending = true;
                Ok(fx)
            }
            (EnvelopeState::Confirmed, IncomingEvent::RetrievedOk) => {
                // Retrieval succeeded: return the pre-spent try (design 6.2,
                // "give the remaining back"), but only if one is actually
                // outstanding, then clear the mark.
                if local.password_attempt_pending {
                    local.password_attempts_remaining =
                        local.password_attempts_remaining.saturating_add(1);
                    local.password_attempt_pending = false;
                }
                local.state = EnvelopeState::Retrieved;
                local.clear_r_eph();
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                Ok(fx)
            }
            (EnvelopeState::Confirmed, IncomingEvent::PasswordWrong) => {
                // The try was spent by `PasswordAttemptStart` and the attempt
                // resolved as wrong, so the pre-spend is final: clear the mark
                // and do not give it back. When none remain, the record fails
                // closed; otherwise it stays Confirmed for the next attempt.
                local.password_attempt_pending = false;
                if local.password_attempts_remaining == 0 {
                    local.state = EnvelopeState::PasswordFailed;
                    local.clear_r_eph();
                    fx.clear_r_eph = true;
                    fx.reached_terminal = true;
                }
                Ok(fx)
            }
            (EnvelopeState::Confirmed, IncomingEvent::RetrievalNetworkFailure) => {
                // The password was right; give the pre-spent try back, but only
                // when one is outstanding. Without this guard a run of network
                // failures with no matching pre-spend would raise the count past
                // its starting value. Clear the mark once returned.
                if local.password_attempt_pending {
                    local.password_attempts_remaining =
                        local.password_attempts_remaining.saturating_add(1);
                    local.password_attempt_pending = false;
                }
                Ok(fx)
            }

            // ── Either non-terminal state ────────────────────────────────────
            (
                EnvelopeState::ChallengeIssued | EnvelopeState::Confirmed,
                IncomingEvent::SenderRevoke,
            ) => {
                local.state = EnvelopeState::SenderRevoked;
                local.challenge = None;
                local.clear_r_eph();
                fx.clear_challenge = true;
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                Ok(fx)
            }
            (
                EnvelopeState::ChallengeIssued | EnvelopeState::Confirmed,
                IncomingEvent::RecipientDelete,
            ) => {
                local.state = EnvelopeState::RecipientDeleted;
                local.challenge = None;
                local.clear_r_eph();
                fx.clear_challenge = true;
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                Ok(fx)
            }
            (
                EnvelopeState::ChallengeIssued | EnvelopeState::Confirmed,
                IncomingEvent::ExpiryTick,
            ) => {
                if now.wall_secs < local.effective_expires_at {
                    return Err(Illegal);
                }
                local.state = EnvelopeState::Expired;
                local.challenge = None;
                local.clear_r_eph();
                fx.clear_challenge = true;
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                Ok(fx)
            }

            // Any other pair is illegal and changes nothing.
            _ => Err(Illegal),
        }
    }
}

impl OutgoingRecord {
    /// Apply one event to a sender record (design 6.3). The sender-only phase
    /// lives in [`OutgoingPhase`] and never travels on the wire.
    pub fn step(&mut self, event: OutgoingEvent, _now: Now) -> Result<Effects, Illegal> {
        let mut fx = Effects::default();
        match (self.phase, event) {
            // ── Publishing / AwaitingRecipient ───────────────────────────────
            (OutgoingPhase::Fresh, OutgoingEvent::Published) => {
                self.phase = OutgoingPhase::AwaitingRecipient;
                Ok(fx)
            }
            (
                OutgoingPhase::Fresh | OutgoingPhase::AwaitingRecipient,
                OutgoingEvent::InviteStored,
            ) => {
                self.phase = OutgoingPhase::Delivered;
                fx.clear_r_eph = true; // drops DEK and pwh (sender secrets)
                Ok(fx)
            }
            (
                OutgoingPhase::Fresh | OutgoingPhase::AwaitingRecipient,
                OutgoingEvent::DeliveredLegacy,
            ) => {
                self.phase = OutgoingPhase::DeliveredLegacy;
                fx.clear_r_eph = true;
                Ok(fx)
            }
            (OutgoingPhase::AwaitingRecipient, OutgoingEvent::RetentionPassed) => {
                self.phase = OutgoingPhase::Expired;
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                Ok(fx)
            }
            (OutgoingPhase::AwaitingRecipient, OutgoingEvent::UserRevoke) => {
                self.phase = OutgoingPhase::SenderRevoked;
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                Ok(fx)
            }
            (
                OutgoingPhase::Fresh | OutgoingPhase::AwaitingRecipient,
                OutgoingEvent::DeliveryFailed,
            ) => {
                self.phase = OutgoingPhase::DeliveryFailed;
                fx.clear_r_eph = true;
                fx.reached_terminal = true;
                Ok(fx)
            }

            // ── Delivered / Confirmed ────────────────────────────────────────
            (
                OutgoingPhase::Delivered | OutgoingPhase::DeliveredLegacy,
                OutgoingEvent::ConfirmOk,
            ) => {
                self.phase = OutgoingPhase::Confirmed;
                Ok(fx)
            }
            (
                OutgoingPhase::Delivered | OutgoingPhase::DeliveredLegacy,
                OutgoingEvent::ConfirmWrong { attempts_remaining },
            ) => {
                self.recipient_attempts_remaining = Some(attempts_remaining);
                if attempts_remaining == 0 {
                    self.phase = OutgoingPhase::ChallengeFailed;
                    fx.reached_terminal = true;
                }
                Ok(fx)
            }
            (OutgoingPhase::Delivered | OutgoingPhase::Confirmed, OutgoingEvent::UserRevoke) => {
                self.phase = OutgoingPhase::SenderRevoked;
                fx.reached_terminal = true;
                Ok(fx)
            }
            (
                OutgoingPhase::Delivered | OutgoingPhase::Confirmed,
                OutgoingEvent::RetentionPassed,
            ) => {
                self.phase = OutgoingPhase::Expired;
                fx.reached_terminal = true;
                Ok(fx)
            }

            _ => Err(Illegal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directed::envelope::DirectedEnvelope;
    use crate::directed::state::{ChallengeLocal, IncomingLocal, MonoDeadline, Protection};

    fn wire(state: EnvelopeState) -> DirectedEnvelope {
        DirectedEnvelope {
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

    /// A record in `ChallengeIssued` with the given remaining tries and
    /// challenge deadline. Returns the record together with the real
    /// confirmation code (from [`generate_challenge`]) and a different,
    /// guaranteed-wrong code, so tests never depend on a private hashing helper.
    fn issued(tries: u8, deadline: MonoDeadline) -> (IncomingRecord, String, String) {
        use crate::directed::challenge::generate_challenge;
        let (code, hash) = generate_challenge();
        // A second draw that is not equal to the first is the wrong code.
        let mut wrong = generate_challenge().0;
        while wrong == code {
            wrong = generate_challenge().0;
        }
        let local = IncomingLocal {
            state: EnvelopeState::ChallengeIssued,
            challenge: Some(ChallengeLocal {
                hash,
                attempts_remaining: tries,
                expires: deadline,
            }),
            password_attempts_remaining: 3,
            password_attempt_pending: false,
            received_at: 1_000,
            effective_expires_at: 10_000,
            sender_peer_id: "peer-a".into(),
            protection: Protection::V2,
            // A v2 record with no recorded transcript hash; same meaning as an
            // older record that predates the field.
            transcript_hash: None,
            // A random non-terminal ephemeral secret; no fixed key material.
            r_eph_secret: Some(rand::random::<[u8; 32]>()),
        };
        let record = IncomingRecord {
            wire: wire(EnvelopeState::ChallengeIssued),
            ext: None,
            local: Some(local),
        };
        (record, code, wrong)
    }

    const NOW: Now = Now {
        wall_secs: 2_000,
        mono_ms: 5_000,
    };

    #[test]
    fn correct_code_confirms_and_clears_the_challenge() {
        let (mut r, code, _wrong) = issued(3, mono(0, 300_000));
        let fx = r.step(IncomingEvent::Confirm { code }, NOW).unwrap();
        assert_eq!(r.effective_state(), EnvelopeState::Confirmed);
        assert!(fx.clear_challenge && !fx.reached_terminal && !fx.delete_file);
        assert!(r.local.as_ref().unwrap().challenge.is_none());
    }

    #[test]
    fn wrong_code_spends_one_try_then_fails_closed_and_is_deleted() {
        let (mut r, _code, wrong) = issued(2, mono(0, 300_000));
        let fx = r
            .step(
                IncomingEvent::Confirm {
                    code: wrong.clone(),
                },
                NOW,
            )
            .unwrap();
        assert_eq!(r.effective_state(), EnvelopeState::ChallengeIssued);
        assert_eq!(
            r.local
                .as_ref()
                .unwrap()
                .challenge
                .as_ref()
                .unwrap()
                .attempts_remaining,
            1
        );
        assert!(!fx.reached_terminal);
        let fx2 = r.step(IncomingEvent::Confirm { code: wrong }, NOW).unwrap();
        assert_eq!(r.effective_state(), EnvelopeState::ChallengeFailed);
        assert!(fx2.reached_terminal && fx2.delete_file && fx2.clear_r_eph);
        assert!(r.local.as_ref().unwrap().r_eph_secret.is_none());
    }

    /// Moving the wall clock backwards must not revive an expired challenge: the
    /// monotonic reading is what counts.
    #[test]
    fn a_backward_wall_clock_cannot_extend_the_challenge_window() {
        // Issued at mono=1000ms, TTL=300ms -> expires at mono=1300ms.
        let (mut r, code, _wrong) = issued(3, mono(1_000, 300));
        // A Confirm arrives at mono=2000ms (past), though wall is early.
        let now = Now {
            wall_secs: 0,
            mono_ms: 2_000,
        };
        let fx = r.step(IncomingEvent::Confirm { code }, now).unwrap();
        assert_eq!(r.effective_state(), EnvelopeState::ChallengeFailed);
        assert!(fx.delete_file);
    }

    #[test]
    fn a_monotonic_reading_before_issue_is_not_treated_as_expired() {
        let d = mono(5_000, 300);
        assert!(!d.is_expired(4_000));
        assert!(!d.is_expired(5_000 + 299));
        assert!(d.is_expired(5_000 + 300));
    }

    #[test]
    fn password_attempts_decrement_first_and_fail_closed_at_zero() {
        let (mut r, code, _wrong) = issued(3, mono(0, 300_000));
        r.step(IncomingEvent::Confirm { code }, NOW).unwrap();
        // Confirmed with 3 password tries.
        for _ in 0..3 {
            r.step(IncomingEvent::PasswordAttemptStart, NOW).unwrap();
            r.step(IncomingEvent::PasswordWrong, NOW).unwrap();
        }
        assert_eq!(r.effective_state(), EnvelopeState::PasswordFailed);
        // A further attempt is illegal (terminal).
        assert!(r.step(IncomingEvent::PasswordAttemptStart, NOW).is_err());
    }

    #[test]
    fn a_network_failure_returns_the_spent_try() {
        let (mut r, code, _wrong) = issued(3, mono(0, 300_000));
        r.step(IncomingEvent::Confirm { code }, NOW).unwrap();
        r.step(IncomingEvent::PasswordAttemptStart, NOW).unwrap();
        assert_eq!(r.local.as_ref().unwrap().password_attempts_remaining, 2);
        r.step(IncomingEvent::RetrievalNetworkFailure, NOW).unwrap();
        assert_eq!(r.local.as_ref().unwrap().password_attempts_remaining, 3);
    }

    #[test]
    fn retrieved_is_terminal_and_drops_the_secret() {
        let (mut r, code, _wrong) = issued(3, mono(0, 300_000));
        r.step(IncomingEvent::Confirm { code }, NOW).unwrap();
        r.step(IncomingEvent::PasswordAttemptStart, NOW).unwrap();
        let fx = r.step(IncomingEvent::RetrievedOk, NOW).unwrap();
        assert_eq!(r.effective_state(), EnvelopeState::Retrieved);
        assert!(fx.reached_terminal && fx.clear_r_eph);
        assert!(r.local.as_ref().unwrap().r_eph_secret.is_none());
        // No event applies after a terminal state.
        assert!(r.step(IncomingEvent::RecipientDelete, NOW).is_err());
    }

    #[test]
    fn a_revoke_replay_on_an_already_revoked_record_is_a_no_write() {
        let (mut r, _code, _wrong) = issued(3, mono(0, 300_000));
        r.step(IncomingEvent::SenderRevoke, NOW).unwrap();
        assert_eq!(r.effective_state(), EnvelopeState::SenderRevoked);
        let fx = r.step(IncomingEvent::SenderRevoke, NOW).unwrap();
        assert!(fx.no_write && !fx.reached_terminal);
    }

    #[test]
    fn expiry_tick_before_the_deadline_is_illegal() {
        let (mut r, _code, _wrong) = issued(3, mono(0, 300_000));
        // effective_expires_at = 10_000; now = 2_000.
        assert!(r.step(IncomingEvent::ExpiryTick, NOW).is_err());
        let late = Now {
            wall_secs: 10_000,
            mono_ms: 9_000,
        };
        let fx = r.step(IncomingEvent::ExpiryTick, late).unwrap();
        assert_eq!(r.effective_state(), EnvelopeState::Expired);
        assert!(fx.reached_terminal);
    }

    #[test]
    fn sender_phase_delivers_then_confirms() {
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
    }

    #[test]
    fn sender_challenge_failure_is_terminal_when_tries_hit_zero() {
        let mut o = OutgoingRecord {
            wire: wire(EnvelopeState::Pending),
            phase: OutgoingPhase::Delivered,
            recipient_attempts_remaining: None,
        };
        o.step(
            OutgoingEvent::ConfirmWrong {
                attempts_remaining: 1,
            },
            NOW,
        )
        .unwrap();
        assert_eq!(o.phase, OutgoingPhase::Delivered);
        let fx = o
            .step(
                OutgoingEvent::ConfirmWrong {
                    attempts_remaining: 0,
                },
                NOW,
            )
            .unwrap();
        assert_eq!(o.phase, OutgoingPhase::ChallengeFailed);
        assert!(fx.reached_terminal);
    }

    /// `new_incoming` takes a zeroizing ephemeral secret and stores it in the
    /// bare-array field; `r_eph()` hands back the same bytes, and a `None`
    /// argument stays `None`.
    #[test]
    fn new_incoming_stores_the_zeroizing_secret() {
        use crate::directed::challenge::generate_challenge;
        use zeroize::Zeroizing;

        let (_code, hash) = generate_challenge();
        let challenge = ChallengeLocal {
            hash,
            attempts_remaining: 3,
            expires: mono(0, 300_000),
        };
        let secret = rand::random::<[u8; 32]>();
        let rec = IncomingRecord::new_incoming(
            wire(EnvelopeState::ChallengeIssued),
            None,
            "peer-a".into(),
            Protection::V2,
            challenge,
            3,
            Some(Zeroizing::new(secret)),
            NOW,
        );
        let local = rec.local.as_ref().unwrap();
        // The stored bytes round-trip through the zeroizing accessor.
        assert_eq!(local.r_eph().map(|z| *z), Some(secret));

        // A `None` secret is kept as `None`.
        let (_code2, hash2) = generate_challenge();
        let challenge2 = ChallengeLocal {
            hash: hash2,
            attempts_remaining: 3,
            expires: mono(0, 300_000),
        };
        let rec_none = IncomingRecord::new_incoming(
            wire(EnvelopeState::ChallengeIssued),
            None,
            "peer-a".into(),
            Protection::V2,
            challenge2,
            3,
            None,
            NOW,
        );
        assert!(rec_none.local.as_ref().unwrap().r_eph().is_none());
    }

    /// The `IncomingLocal` debug output never prints the ephemeral secret bytes:
    /// it shows a redaction marker instead.
    #[test]
    fn incoming_local_debug_redacts_the_ephemeral_secret() {
        use crate::directed::challenge::generate_challenge;
        use zeroize::Zeroizing;

        let (_code, hash) = generate_challenge();
        let challenge = ChallengeLocal {
            hash,
            attempts_remaining: 3,
            expires: mono(0, 300_000),
        };
        let secret = rand::random::<[u8; 32]>();
        let rec = IncomingRecord::new_incoming(
            wire(EnvelopeState::ChallengeIssued),
            None,
            "peer-a".into(),
            Protection::V2,
            challenge,
            3,
            Some(Zeroizing::new(secret)),
            NOW,
        );
        let shown = format!("{:?}", rec.local.as_ref().unwrap());
        assert!(shown.contains("<redacted>"));
        // No byte of the secret appears in the debug string.
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!shown.contains(&hex));
    }

    /// Retrieval success returns the try that `PasswordAttemptStart` pre-spent
    /// (design 6.2, the `RetrievedOk` row gives the remaining back).
    #[test]
    fn retrieval_success_returns_the_pre_spent_try() {
        let (mut r, code, _wrong) = issued(3, mono(0, 300_000));
        r.step(IncomingEvent::Confirm { code }, NOW).unwrap();
        r.step(IncomingEvent::PasswordAttemptStart, NOW).unwrap();
        assert_eq!(r.local.as_ref().unwrap().password_attempts_remaining, 2);
        r.step(IncomingEvent::RetrievedOk, NOW).unwrap();
        // The pre-spent try is returned on success.
        assert_eq!(r.effective_state(), EnvelopeState::Retrieved);
        assert_eq!(r.local.as_ref().unwrap().password_attempts_remaining, 3);
    }

    /// A run of network failures with no matching `PasswordAttemptStart` never
    /// raises the count past its starting value: only an outstanding pre-spent
    /// try is given back, and the mark is cleared once returned.
    #[test]
    fn a_run_of_network_failures_never_raises_the_count_past_the_start() {
        let (mut r, code, _wrong) = issued(3, mono(0, 300_000));
        r.step(IncomingEvent::Confirm { code }, NOW).unwrap();
        // One pre-spend, then many network failures. The first returns the
        // pre-spent try; the rest are no-ops for the count.
        r.step(IncomingEvent::PasswordAttemptStart, NOW).unwrap();
        assert_eq!(r.local.as_ref().unwrap().password_attempts_remaining, 2);
        for _ in 0..10 {
            r.step(IncomingEvent::RetrievalNetworkFailure, NOW).unwrap();
            assert_eq!(
                r.local.as_ref().unwrap().password_attempts_remaining,
                3,
                "the count must not climb past its starting value"
            );
        }
    }

    /// The `IncomingEvent::Confirm` debug output never prints the confirmation
    /// code: it shows a redaction marker instead.
    #[test]
    fn the_confirm_event_debug_redacts_the_code() {
        use crate::directed::challenge::generate_challenge;
        let (code, _hash) = generate_challenge();
        let ev = IncomingEvent::Confirm { code: code.clone() };
        let shown = format!("{ev:?}");
        assert!(shown.contains("<redacted>"));
        assert!(
            !shown.contains(&code),
            "the confirmation code must not appear in the debug output"
        );
    }

    /// The `InviteExtV2` debug output never prints the credential bytes.
    #[test]
    fn the_invite_ext_debug_redacts_the_credential() {
        use crate::directed::state::InviteExtV2;
        // A random, non-fixed credential value; no fixed key material.
        let credential: Vec<u8> = (0..48).map(|_| rand::random::<u8>()).collect();
        let ext = InviteExtV2 {
            credential: credential.clone(),
        };
        let shown = format!("{ext:?}");
        assert!(shown.contains("<redacted>"));
        let hex: String = credential.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !shown.contains(&hex),
            "the credential bytes must not appear in the debug output"
        );
    }
}
