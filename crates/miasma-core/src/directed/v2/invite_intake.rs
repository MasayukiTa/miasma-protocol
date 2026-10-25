//! Intake of a received v2 Invite: verify it, then store it once (§3.4, §6.2,
//! §6.4).
//!
//! [`intake_invite`] runs the recipient-side checks of design §3.4 on a
//! [`DirectedRequestV2::Invite`], and on success builds a fresh
//! [`IncomingRecord`] and writes it with the create-only store
//! ([`DirectedInbox::store_incoming_v2_new`]). A failed check returns a typed
//! [`InviteIntakeError`] and nothing is written.
//!
//! Idempotence: the store is create-only, so a resent Invite with the same
//! envelope id does not write twice. When the id is already present, the stored
//! record's transcript hash and bound PeerId are recomputed and compared; a
//! match returns the same `Ok` outcome (the recorded transcript hash), a
//! mismatch returns [`InviteIntakeError::IdConflict`].
//!
//! This module does not decrypt the payload: the node does not hold the sharing
//! secret, and the signature already detects tampering (§3.4, last paragraph).
//! It also does not touch the networking types; a PeerId is passed in as the
//! caller-derived bytes to compare, matching the style of
//! [`super::offer::check_offer`].
//!
//! Secrets never reach a `Debug` or a log here: [`InviteIntakeError`] names a
//! reason only, and the record types redact their own key-bearing fields.

use crate::directed::challenge::{
    generate_challenge, CHALLENGE_MAX_ATTEMPTS, CHALLENGE_TTL_SECS, PASSWORD_MAX_ATTEMPTS,
};
use crate::directed::envelope::{DirectedEnvelope, EnvelopeState};
use crate::directed::inbox::DirectedInbox;
use crate::directed::state::{
    ChallengeLocal, IncomingLocal, IncomingRecord, MonoDeadline, Now, Protection,
};

use super::credential::verify_binding;
use super::kdf::check_kdf_bounds;
use super::transcript::{self, Header, OuterRefs};
use super::wire::{InviteExtV2, SUITE_V2};

/// Why an Invite was refused. Each variant names a reason and carries no
/// secret; it maps to one of [`super::wire::codes`]. Manual `Copy`/`Eq` are
/// derived because every field is a plain discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteIntakeError {
    /// `envelope.version` or `ext.suite` was not the v2 value.
    UnsupportedSuite,
    /// A lifecycle field carried a value other than the fixed one the recipient
    /// requires (`state`, `challenge_hash`, and the three counters).
    BadLifecycle,
    /// An Argon2id cost parameter was outside the shared bounds.
    KdfOutOfRange,
    /// The envelope's effective window has already closed.
    Expired,
    /// The offer id was not the one this Invite was expected to answer, or the
    /// recipient ephemeral public key did not match the offer's `r_eph`.
    OfferMismatch,
    /// `ext.recipient_identity` or `envelope.recipient_pubkey` did not name this
    /// recipient.
    NotForThisRecipient,
    /// The sender identity's PeerId did not match the Invite transport PeerId.
    PeerMismatch,
    /// The sender sharing-key binding did not verify.
    BadBinding,
    /// The transcript signature did not verify.
    BadSignature,
    /// The envelope id is already stored under a different transcript or a
    /// different bound PeerId.
    IdConflict,
    /// Persisting the record failed (I/O or inbox limit). The detail is kept off
    /// the type so no path or secret lands in `Debug`.
    Storage,
}

/// What the recipient knows before an Invite arrives, supplied by the caller.
///
/// PeerId values are compared as byte strings so this module stays free of the
/// networking types (same approach as [`super::offer::SenderExpectation`]). The
/// caller derives `sender_identity_peer_id` from `ext.sender_identity` and
/// supplies `transport_peer_id` from the connection that carried the Invite and
/// `sender_peer_id_display` as the string to record.
pub struct InviteRecipientContext<'a> {
    /// This recipient's Ed25519 identity public key.
    pub own_identity: &'a [u8; 32],
    /// This recipient's X25519 sharing public key (`R_static`).
    pub own_sharing: &'a [u8; 32],
    /// The offer id this recipient handed out and still holds unspent.
    pub expected_offer_id: &'a [u8; 16],
    /// The `r_eph` public key of the unspent offer.
    pub offer_r_eph_pub: &'a [u8; 32],
    /// The `r_eph` secret of the unspent offer, stored with the record so the
    /// recipient can later open the DEK wrap. Cleared on every terminal step.
    pub offer_r_eph_secret: &'a [u8; 32],
    /// PeerId bytes derived by the caller from `ext.sender_identity`.
    pub sender_identity_peer_id: &'a [u8],
    /// PeerId bytes of the connection that carried the Invite.
    pub transport_peer_id: &'a [u8],
    /// The sender PeerId string to record on the stored record.
    pub sender_peer_id_display: &'a str,
}

/// The outcome of a successful intake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntakeOutcome {
    /// The transcript hash that pins this Invite (returned in `InviteStored`).
    pub transcript_hash: [u8; 32],
    /// True when this call created the record; false when an identical Invite
    /// was already stored (an idempotent resend).
    pub created: bool,
}

/// Recompute `transcript_hash` for an Invite from its envelope and extension.
///
/// The header is folded exactly as the sender folded it (§3.3); `sig_msg` binds
/// the outer ciphertexts and the sender binding; the signature pins it. This is
/// the value a successful intake returns and the value a resend is compared
/// against.
fn invite_transcript_hash(envelope: &DirectedEnvelope, ext: &InviteExtV2) -> [u8; 32] {
    let header = Header {
        version: envelope.version,
        suite: ext.suite,
        envelope_id: &envelope.envelope_id,
        sender_identity: &ext.sender_identity,
        sender_pubkey: &envelope.sender_pubkey,
        recipient_identity: &ext.recipient_identity,
        recipient_pubkey: &envelope.recipient_pubkey,
        ephemeral_pubkey: &envelope.ephemeral_pubkey,
        recipient_ephemeral: &ext.recipient_ephemeral,
        offer_id: &ext.offer_id,
        kdf_m_kib: ext.kdf.m_kib,
        kdf_t_cost: ext.kdf.t_cost,
        kdf_p_cost: ext.kdf.p_cost,
        password_salt: &envelope.password_salt,
        created_at: envelope.created_at,
        expires_at: envelope.expires_at,
        retention_secs: envelope.retention_secs,
    };
    let h_hdr = header.h_hdr();
    let outer = OuterRefs {
        payload_nonce: &envelope.payload_nonce,
        encrypted_payload: &envelope.encrypted_payload,
        dek_nonce: &ext.dek_nonce,
        wrapped_dek: &ext.wrapped_dek,
        sender_binding: &ext.sender_binding,
    };
    let sig_msg = transcript::sig_msg(&h_hdr, &outer);
    transcript::transcript_hash(&sig_msg, &ext.signature)
}

/// Run the §3.4 recipient checks on `(envelope, ext)` and verify the transcript.
///
/// On success returns `(h_hdr, sig_msg)` is not needed by the caller, so only
/// the transcript hash is returned. The checks stop at the first failure and
/// never touch the payload.
fn verify_invite(
    envelope: &DirectedEnvelope,
    ext: &InviteExtV2,
    ctx: &InviteRecipientContext<'_>,
    now: Now,
) -> Result<[u8; 32], InviteIntakeError> {
    // 1. version / suite are the v2 values.
    if envelope.version != SUITE_V2 || ext.suite != SUITE_V2 {
        return Err(InviteIntakeError::UnsupportedSuite);
    }
    // 2. the five lifecycle fields carry their fixed values (§2.2).
    let lifecycle_ok = envelope.state == EnvelopeState::Pending
        && envelope.challenge_hash.is_none()
        && envelope.password_attempts_remaining == 0
        && envelope.challenge_attempts_remaining == 0
        && envelope.challenge_expires_at == 0;
    if !lifecycle_ok {
        return Err(InviteIntakeError::BadLifecycle);
    }
    // 3. KDF cost is within the shared bounds, checked before any key work.
    if check_kdf_bounds(ext.kdf.m_kib, ext.kdf.t_cost, ext.kdf.p_cost).is_err() {
        return Err(InviteIntakeError::KdfOutOfRange);
    }
    // Expiry: a window that has already closed (including a past `expires_at`)
    // is refused before any further work.
    if envelope.is_expired(now.wall_secs) {
        return Err(InviteIntakeError::Expired);
    }
    // 4. the offer id is the one we handed out, and 6. the recipient ephemeral
    //    matches the offer's r_eph public key.
    if &ext.offer_id != ctx.expected_offer_id {
        return Err(InviteIntakeError::OfferMismatch);
    }
    if &ext.recipient_ephemeral != ctx.offer_r_eph_pub {
        return Err(InviteIntakeError::OfferMismatch);
    }
    // 7. the invite names this recipient (identity and sharing key).
    if &ext.recipient_identity != ctx.own_identity || &envelope.recipient_pubkey != ctx.own_sharing
    {
        return Err(InviteIntakeError::NotForThisRecipient);
    }
    // 8. the sender identity's PeerId matches the Invite transport PeerId.
    if ctx.sender_identity_peer_id != ctx.transport_peer_id {
        return Err(InviteIntakeError::PeerMismatch);
    }
    // 9. the sender sharing-key binding is correct for
    //    (sender_identity, envelope.sender_pubkey).
    if !verify_binding(
        &ext.sender_identity,
        &envelope.sender_pubkey,
        &ext.sender_binding,
    ) {
        return Err(InviteIntakeError::BadBinding);
    }
    // 10. the transcript signature verifies (verify_strict, inside
    //     verify_transcript). Recompute H_hdr and sig_msg from the wire values.
    let header = Header {
        version: envelope.version,
        suite: ext.suite,
        envelope_id: &envelope.envelope_id,
        sender_identity: &ext.sender_identity,
        sender_pubkey: &envelope.sender_pubkey,
        recipient_identity: &ext.recipient_identity,
        recipient_pubkey: &envelope.recipient_pubkey,
        ephemeral_pubkey: &envelope.ephemeral_pubkey,
        recipient_ephemeral: &ext.recipient_ephemeral,
        offer_id: &ext.offer_id,
        kdf_m_kib: ext.kdf.m_kib,
        kdf_t_cost: ext.kdf.t_cost,
        kdf_p_cost: ext.kdf.p_cost,
        password_salt: &envelope.password_salt,
        created_at: envelope.created_at,
        expires_at: envelope.expires_at,
        retention_secs: envelope.retention_secs,
    };
    let h_hdr = header.h_hdr();
    let outer = OuterRefs {
        payload_nonce: &envelope.payload_nonce,
        encrypted_payload: &envelope.encrypted_payload,
        dek_nonce: &ext.dek_nonce,
        wrapped_dek: &ext.wrapped_dek,
        sender_binding: &ext.sender_binding,
    };
    let sig_msg = transcript::sig_msg(&h_hdr, &outer);
    if !transcript::verify_transcript(&ext.sender_identity, &sig_msg, &ext.signature) {
        return Err(InviteIntakeError::BadSignature);
    }
    Ok(transcript::transcript_hash(&sig_msg, &ext.signature))
}

/// Verify a received Invite and store it once (§3.4, §6.4).
///
/// On success the record is written with a create-only store and the recorded
/// transcript hash is returned. A resent Invite (same envelope id) is not
/// written twice: when a record is already present, its transcript hash and
/// bound PeerId are recomputed and compared, so an identical resend returns the
/// same outcome with `created = false`, and a different transcript or PeerId
/// under the same id returns [`InviteIntakeError::IdConflict`].
///
/// A failed check returns the typed error and writes nothing. The ephemeral
/// retrieval secret from the offer is stored with the record so the recipient
/// can later open the DEK wrap; it is dropped on every terminal step by the
/// state machine.
pub fn intake_invite(
    inbox: &DirectedInbox,
    envelope: &DirectedEnvelope,
    ext: &InviteExtV2,
    ctx: &InviteRecipientContext<'_>,
    now: Now,
) -> Result<IntakeOutcome, InviteIntakeError> {
    // 1-10: verify, stopping at the first failure. Nothing is written yet.
    let transcript_hash = verify_invite(envelope, ext, ctx, now)?;

    // 11: if the id is already present, this is a resend. Compare the stored
    // record's transcript and bound PeerId; an identical one is idempotent, a
    // different one is a conflict. The id lock inside the store serialises this
    // against a concurrent writer for the same id.
    let id_hex = envelope.id_hex();
    if let Ok(existing) = inbox.load_incoming_v2(&id_hex) {
        return match existing_matches(&existing, &transcript_hash, ctx.sender_peer_id_display) {
            true => Ok(IntakeOutcome {
                transcript_hash,
                created: false,
            }),
            false => Err(InviteIntakeError::IdConflict),
        };
    }

    // 12: build the fresh record and write it once. The ephemeral retrieval
    // secret is wrapped in `Zeroizing` on the way in; `new_incoming` unwraps it
    // into the stored field and the wrapper is zeroized at the end of the call.
    let challenge = fresh_challenge(now);
    let mut record = IncomingRecord::new_incoming(
        envelope.clone(),
        // The record's local extension is a different, opaque-credential type
        // (`state::InviteExtV2`); the wire extension does not fit it and is kept
        // on the wire, so `None` is stored here. See the module report.
        None,
        ctx.sender_peer_id_display.to_string(),
        Protection::V2,
        challenge,
        PASSWORD_MAX_ATTEMPTS,
        Some(zeroize::Zeroizing::new(*ctx.offer_r_eph_secret)),
        now,
    );
    // Pin the transcript hash on the record so a later resend under the same id
    // can be judged identical (same hash) or a conflict (different hash). The
    // local part was just built by `new_incoming`, so it is present.
    if let Some(local) = record.local.as_mut() {
        local.transcript_hash = Some(transcript_hash);
    }

    match inbox.store_incoming_v2_new(&record) {
        Ok(true) => Ok(IntakeOutcome {
            transcript_hash,
            created: true,
        }),
        // A concurrent writer created the same id between the load above and
        // this write. Re-read and compare; identical is idempotent.
        Ok(false) => match inbox.load_incoming_v2(&id_hex) {
            Ok(existing)
                if existing_matches(&existing, &transcript_hash, ctx.sender_peer_id_display) =>
            {
                Ok(IntakeOutcome {
                    transcript_hash,
                    created: false,
                })
            }
            Ok(_) => Err(InviteIntakeError::IdConflict),
            Err(_) => Err(InviteIntakeError::Storage),
        },
        Err(_) => Err(InviteIntakeError::Storage),
    }
}

/// Whether a stored record is the same Invite as the one just verified: the same
/// bound sender PeerId and the same transcript hash.
///
/// A v2 intake pins the transcript hash on the record's local part when it
/// writes it, so a resend is judged on both the bound PeerId and that stored
/// hash: a match on both is idempotent, and the same id carrying a different
/// transcript (or bound to a different PeerId) is a conflict (design 3.4-11,
/// 2.5).
///
/// A record without a stored transcript hash predates this field (an older
/// on-disk record, or a v1 migration, which has none). For those the hash
/// cannot be compared, so the decision falls back to the bound PeerId alone,
/// preserving the earlier behaviour and the on-disk compatibility.
fn existing_matches(
    existing: &IncomingRecord,
    transcript_hash: &[u8; 32],
    sender_peer_id_display: &str,
) -> bool {
    let Some(local) = existing.local.as_ref() else {
        // No local part at all (a bare wire record): nothing to match against.
        return false;
    };
    if local.sender_peer_id != sender_peer_id_display {
        return false;
    }
    match local.transcript_hash.as_ref() {
        // A v2 record pins the transcript: both the PeerId and the hash must
        // match for the resend to be idempotent; a different hash is a conflict.
        Some(stored) => stored == transcript_hash,
        // An older record or a v1 migration has no stored hash; fall back to the
        // PeerId match (already confirmed above) to keep the prior behaviour.
        None => true,
    }
}

/// Build the confirmation challenge the first write issues (§6.2 first row):
/// a fresh code, `CHALLENGE_MAX_ATTEMPTS` tries, and a TTL measured on the
/// monotonic clock from `now.mono_ms`.
fn fresh_challenge(now: Now) -> ChallengeLocal {
    let (_code, hash) = generate_challenge();
    ChallengeLocal {
        hash,
        attempts_remaining: CHALLENGE_MAX_ATTEMPTS,
        expires: MonoDeadline {
            issued_mono_ms: now.mono_ms,
            ttl_ms: CHALLENGE_TTL_SECS.saturating_mul(1_000),
            wall_expires_at: now.wall_secs.saturating_add(CHALLENGE_TTL_SECS),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directed::v2::credential::sign_binding;
    use crate::directed::v2::transcript::{self as tx};
    use crate::directed::v2::wire::KdfParams;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

    /// A fresh signing key from the OS RNG; no fixed key bytes appear here.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&rand::random())
    }

    /// A fresh X25519 keypair, returned as (secret_bytes, public_bytes).
    fn x25519_pair() -> ([u8; 32], [u8; 32]) {
        let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk = XPublicKey::from(&sk);
        (sk.to_bytes(), pk.to_bytes())
    }

    /// Random bytes of any length, drawn one at a time so no fixed array
    /// literal and no `[0u8; N]` initialiser is used for key-shaped material.
    fn rand_vec(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    /// Everything the test holds for one party pair and one built Invite.
    struct Built {
        envelope: DirectedEnvelope,
        ext: InviteExtV2,
        own_identity: [u8; 32],
        own_sharing: [u8; 32],
        offer_id: [u8; 16],
        r_eph_pub: [u8; 32],
        r_eph_secret: [u8; 32],
        peer_id: Vec<u8>,
        peer_id_display: String,
        /// The sender identity key, kept so a test can forge a second, different
        /// Invite under the same id, offer and PeerId (same signer).
        sender_sk: SigningKey,
    }

    /// Build a correct, self-consistent v2 Invite: a sender identity and sharing
    /// key, a recipient identity and sharing key, an unspent offer `r_eph`, a
    /// correct sender binding, and a transcript signature over the exact header
    /// and outer values carried on the wire. The payload ciphertext, DEK wrap
    /// and nonces are random: intake never decrypts, it only checks the
    /// signature, so their contents are irrelevant to a correct Invite.
    fn build_valid(now_wall: u64) -> Built {
        let sender_sk = signing_key();
        let sender_identity = sender_sk.verifying_key().to_bytes();
        let (_sender_sharing_sk, sender_sharing_pub) = x25519_pair();

        let recipient_sk = signing_key();
        let recipient_identity = recipient_sk.verifying_key().to_bytes();
        let (_recipient_sharing_sk, recipient_sharing_pub) = x25519_pair();
        let (r_eph_secret, r_eph_pub) = x25519_pair();
        let (_e_s_sk, e_s_pub) = x25519_pair();

        let envelope_id: [u8; 32] = rand::random();
        let offer_id: [u8; 16] = rand::random();
        let password_salt: [u8; 32] = rand::random();
        let payload_nonce: [u8; 24] = rand::random();
        let dek_nonce: [u8; 24] = rand::random();
        let encrypted_payload = rand_vec(40);
        let wrapped_dek = rand_vec(48);
        // The published Argon2id cost is the design's fixed generation value; it
        // is a public parameter (not a key, nonce, salt or password) and sits
        // inside the shared bounds, so the checks pass.
        let kdf = KdfParams {
            m_kib: 65536,
            t_cost: 3,
            p_cost: 1,
        };
        let created_at = now_wall;
        let expires_at = now_wall.saturating_add(3600);
        let retention_secs = 3600u64;

        // The sender binds its identity to its sharing key (§3.2).
        let sender_binding = sign_binding(&sender_sk, &sender_sharing_pub);

        let envelope = DirectedEnvelope {
            envelope_id,
            version: SUITE_V2,
            sender_pubkey: sender_sharing_pub,
            recipient_pubkey: recipient_sharing_pub,
            ephemeral_pubkey: e_s_pub,
            encrypted_payload: encrypted_payload.clone(),
            payload_nonce,
            password_salt,
            expires_at,
            created_at,
            state: EnvelopeState::Pending,
            challenge_hash: None,
            password_attempts_remaining: 0,
            challenge_attempts_remaining: 0,
            challenge_expires_at: 0,
            retention_secs,
        };

        // Fold the same header the intake recomputes, then sign sig_msg.
        let header = Header {
            version: envelope.version,
            suite: SUITE_V2,
            envelope_id: &envelope.envelope_id,
            sender_identity: &sender_identity,
            sender_pubkey: &envelope.sender_pubkey,
            recipient_identity: &recipient_identity,
            recipient_pubkey: &envelope.recipient_pubkey,
            ephemeral_pubkey: &envelope.ephemeral_pubkey,
            recipient_ephemeral: &r_eph_pub,
            offer_id: &offer_id,
            kdf_m_kib: kdf.m_kib,
            kdf_t_cost: kdf.t_cost,
            kdf_p_cost: kdf.p_cost,
            password_salt: &envelope.password_salt,
            created_at: envelope.created_at,
            expires_at: envelope.expires_at,
            retention_secs: envelope.retention_secs,
        };
        let h_hdr = header.h_hdr();
        let outer = OuterRefs {
            payload_nonce: &envelope.payload_nonce,
            encrypted_payload: &envelope.encrypted_payload,
            dek_nonce: &dek_nonce,
            wrapped_dek: &wrapped_dek,
            sender_binding: &sender_binding,
        };
        let sig_msg = tx::sig_msg(&h_hdr, &outer);
        let signature = tx::sign_transcript(&sender_sk, &sig_msg);

        let ext = InviteExtV2 {
            suite: SUITE_V2,
            kdf,
            sender_identity,
            sender_binding,
            recipient_identity,
            offer_id,
            recipient_ephemeral: r_eph_pub,
            wrapped_dek,
            dek_nonce,
            signature,
        };

        // The intake compares PeerId byte strings only; a stable random string
        // stands in for the derived sender PeerId and the transport PeerId.
        let peer_id = rand_vec(38);
        let peer_id_display = hex::encode(&peer_id);

        Built {
            envelope,
            ext,
            own_identity: recipient_identity,
            own_sharing: recipient_sharing_pub,
            offer_id,
            r_eph_pub,
            r_eph_secret,
            peer_id,
            peer_id_display,
            sender_sk,
        }
    }

    impl Built {
        fn ctx(&self) -> InviteRecipientContext<'_> {
            InviteRecipientContext {
                own_identity: &self.own_identity,
                own_sharing: &self.own_sharing,
                expected_offer_id: &self.offer_id,
                offer_r_eph_pub: &self.r_eph_pub,
                offer_r_eph_secret: &self.r_eph_secret,
                sender_identity_peer_id: &self.peer_id,
                transport_peer_id: &self.peer_id,
                sender_peer_id_display: &self.peer_id_display,
            }
        }

        /// A second, self-consistent Invite from the same sender, under the same
        /// envelope id, offer, recipient and PeerId, but with a different
        /// published ciphertext and fresh outer nonces. The sender re-signs the
        /// transcript, so the second Invite has a different transcript hash and
        /// is a genuine content conflict rather than an identical resend.
        fn resigned_with_different_content(&self) -> (DirectedEnvelope, InviteExtV2) {
            let sender_identity = self.sender_sk.verifying_key().to_bytes();
            // Keep every header field the same except the outer ciphertext and
            // its nonces, so only the content differs. Reuse the first
            // envelope's keys, salt, timestamps and id.
            let mut envelope = self.envelope.clone();
            let mut new_payload = self.envelope.encrypted_payload.clone();
            // Flip one byte so the published ciphertext (and thus its hash)
            // differs; the length is unchanged.
            new_payload[0] ^= 0x01;
            envelope.encrypted_payload = new_payload;
            envelope.payload_nonce = rand::random();
            let dek_nonce: [u8; 24] = rand::random();
            let wrapped_dek = rand_vec(48);

            // Re-fold the header exactly as the intake will, over the shared
            // header values, then re-sign the new outer values.
            let header = Header {
                version: envelope.version,
                suite: self.ext.suite,
                envelope_id: &envelope.envelope_id,
                sender_identity: &sender_identity,
                sender_pubkey: &envelope.sender_pubkey,
                recipient_identity: &self.ext.recipient_identity,
                recipient_pubkey: &envelope.recipient_pubkey,
                ephemeral_pubkey: &envelope.ephemeral_pubkey,
                recipient_ephemeral: &self.ext.recipient_ephemeral,
                offer_id: &self.ext.offer_id,
                kdf_m_kib: self.ext.kdf.m_kib,
                kdf_t_cost: self.ext.kdf.t_cost,
                kdf_p_cost: self.ext.kdf.p_cost,
                password_salt: &envelope.password_salt,
                created_at: envelope.created_at,
                expires_at: envelope.expires_at,
                retention_secs: envelope.retention_secs,
            };
            let h_hdr = header.h_hdr();
            let outer = OuterRefs {
                payload_nonce: &envelope.payload_nonce,
                encrypted_payload: &envelope.encrypted_payload,
                dek_nonce: &dek_nonce,
                wrapped_dek: &wrapped_dek,
                sender_binding: &self.ext.sender_binding,
            };
            let sig_msg = tx::sig_msg(&h_hdr, &outer);
            let signature = tx::sign_transcript(&self.sender_sk, &sig_msg);

            let ext = InviteExtV2 {
                suite: self.ext.suite,
                kdf: self.ext.kdf,
                sender_identity,
                sender_binding: self.ext.sender_binding,
                recipient_identity: self.ext.recipient_identity,
                offer_id: self.ext.offer_id,
                recipient_ephemeral: self.ext.recipient_ephemeral,
                wrapped_dek,
                dek_nonce,
                signature,
            };
            (envelope, ext)
        }
    }

    fn inbox() -> (TempDir, DirectedInbox) {
        let tmp = TempDir::new().expect("temp dir");
        let inbox = DirectedInbox::open(tmp.path()).expect("open inbox");
        (tmp, inbox)
    }

    fn now_at(wall: u64) -> Now {
        Now {
            wall_secs: wall,
            mono_ms: wall.saturating_mul(1_000),
        }
    }

    #[test]
    fn a_valid_invite_is_verified_and_stored_once() {
        let (_tmp, inbox) = inbox();
        let b = build_valid(1_700_000_000);
        let now = now_at(1_700_000_000);
        let out = intake_invite(&inbox, &b.envelope, &b.ext, &b.ctx(), now)
            .expect("a correct invite is accepted");
        assert!(out.created, "the first intake creates the record");
        // The record is on disk and carries the recipient-local state machine.
        let rec = inbox
            .load_incoming_v2(&b.envelope.id_hex())
            .expect("the record was written");
        let local = rec.local.as_ref().expect("a local part was written");
        assert_eq!(local.state, EnvelopeState::ChallengeIssued);
        assert_eq!(local.sender_peer_id, b.peer_id_display);
        assert_eq!(local.protection, Protection::V2);
        // The ephemeral retrieval secret is stored for later DEK opening.
        assert!(local.r_eph_secret.is_some());
    }

    #[test]
    fn a_tampered_signature_is_refused_and_nothing_is_stored() {
        let (_tmp, inbox) = inbox();
        let mut b = build_valid(1_700_000_000);
        // Flip one byte of the transcript signature.
        b.ext.signature[0] ^= 0x01;
        let now = now_at(1_700_000_000);
        let err = intake_invite(&inbox, &b.envelope, &b.ext, &b.ctx(), now)
            .expect_err("a tampered invite is refused");
        assert_eq!(err, InviteIntakeError::BadSignature);
        // Nothing was written.
        assert!(inbox.load_incoming_v2(&b.envelope.id_hex()).is_err());
    }

    #[test]
    fn a_tampered_payload_breaks_the_signature_and_is_not_stored() {
        let (_tmp, inbox) = inbox();
        let mut b = build_valid(1_700_000_000);
        // Change the published ciphertext after the signature was made: the
        // recomputed sig_msg no longer matches, so verification fails.
        b.envelope.encrypted_payload[0] ^= 0x01;
        let now = now_at(1_700_000_000);
        let err = intake_invite(&inbox, &b.envelope, &b.ext, &b.ctx(), now)
            .expect_err("a tampered payload is refused");
        assert_eq!(err, InviteIntakeError::BadSignature);
        assert!(inbox.load_incoming_v2(&b.envelope.id_hex()).is_err());
    }

    #[test]
    fn a_resent_invite_with_the_same_id_is_idempotent() {
        let (_tmp, inbox) = inbox();
        let b = build_valid(1_700_000_000);
        let now = now_at(1_700_000_000);
        let first =
            intake_invite(&inbox, &b.envelope, &b.ext, &b.ctx(), now).expect("first intake");
        assert!(first.created);
        // The identical Invite arrives again (a lost response, a retry).
        let second = intake_invite(&inbox, &b.envelope, &b.ext, &b.ctx(), now)
            .expect("a resend returns the same outcome");
        assert!(
            !second.created,
            "the resend does not create a second record"
        );
        assert_eq!(first.transcript_hash, second.transcript_hash);
        // Exactly one record exists for the id.
        let count = inbox
            .list_incoming_v2()
            .into_iter()
            .filter(|r| r.wire.envelope_id == b.envelope.envelope_id)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn a_second_invite_with_different_content_under_the_same_id_is_a_conflict() {
        let (_tmp, inbox) = inbox();
        let b = build_valid(1_700_000_000);
        let now = now_at(1_700_000_000);
        // The first Invite is accepted and stored, pinning its transcript hash.
        let first =
            intake_invite(&inbox, &b.envelope, &b.ext, &b.ctx(), now).expect("first intake");
        assert!(first.created);

        // A second, validly signed Invite from the same sender, under the same
        // envelope id, offer and PeerId, but carrying different content: its
        // transcript hash differs, so it must be refused as a conflict rather
        // than treated as an idempotent resend.
        let (env2, ext2) = b.resigned_with_different_content();
        // The id is unchanged, the content (and thus the transcript) is not.
        assert_eq!(env2.envelope_id, b.envelope.envelope_id);
        assert_ne!(
            invite_transcript_hash(&env2, &ext2),
            first.transcript_hash,
            "the forged second Invite must have a different transcript hash",
        );

        let err = intake_invite(&inbox, &env2, &ext2, &b.ctx(), now)
            .expect_err("a different transcript under the same id is a conflict");
        assert_eq!(err, InviteIntakeError::IdConflict);

        // The original record is untouched: still exactly one, still the first
        // transcript hash.
        let rec = inbox
            .load_incoming_v2(&b.envelope.id_hex())
            .expect("the first record is still present");
        assert_eq!(
            rec.local.as_ref().expect("local part").transcript_hash,
            Some(first.transcript_hash),
            "the stored transcript hash is the first Invite's, not the second's",
        );
        let count = inbox
            .list_incoming_v2()
            .into_iter()
            .filter(|r| r.wire.envelope_id == b.envelope.envelope_id)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn two_invites_arriving_out_of_order_each_store_independently() {
        let (_tmp, inbox) = inbox();
        // An older Invite (earlier created_at) and a newer one, each with its
        // own envelope id, offer and keys. The older one is delivered second.
        let older = build_valid(1_700_000_000);
        let newer = build_valid(1_700_000_500);
        // Newer arrives first.
        let now_newer = now_at(1_700_000_500);
        intake_invite(&inbox, &newer.envelope, &newer.ext, &newer.ctx(), now_newer)
            .expect("newer stored");
        // Older arrives afterwards; it must still store and not disturb newer.
        let now_older = now_at(1_700_000_600);
        intake_invite(&inbox, &older.envelope, &older.ext, &older.ctx(), now_older)
            .expect("older stored after newer");
        let newer_rec = inbox
            .load_incoming_v2(&newer.envelope.id_hex())
            .expect("newer still present");
        let older_rec = inbox
            .load_incoming_v2(&older.envelope.id_hex())
            .expect("older present");
        assert_eq!(
            newer_rec.local.as_ref().unwrap().state,
            EnvelopeState::ChallengeIssued
        );
        assert_eq!(
            older_rec.local.as_ref().unwrap().state,
            EnvelopeState::ChallengeIssued
        );
        // The two records are distinct ids.
        assert_ne!(newer_rec.wire.envelope_id, older_rec.wire.envelope_id);
    }

    #[test]
    fn the_error_debug_carries_no_secret() {
        // Every variant of the error is a bare discriminant; its Debug is the
        // variant name and names no credential, code or key. Check a sample of
        // variants render as their names only.
        for (err, name) in [
            (InviteIntakeError::BadSignature, "BadSignature"),
            (InviteIntakeError::BadBinding, "BadBinding"),
            (InviteIntakeError::KdfOutOfRange, "KdfOutOfRange"),
            (InviteIntakeError::IdConflict, "IdConflict"),
        ] {
            assert_eq!(format!("{err:?}"), name);
        }
        // A built-and-stored record's Debug must not leak the ephemeral secret
        // or the challenge hash. Render the stored record and check the known
        // secret bytes do not appear.
        let (_tmp, inbox) = inbox();
        let b = build_valid(1_700_000_000);
        let now = now_at(1_700_000_000);
        intake_invite(&inbox, &b.envelope, &b.ext, &b.ctx(), now).expect("stored");
        let rec = inbox
            .load_incoming_v2(&b.envelope.id_hex())
            .expect("loaded");
        let rendered = format!("{rec:?}");
        let secret_hex = hex::encode(b.r_eph_secret);
        assert!(
            !rendered.contains(&secret_hex),
            "the ephemeral retrieval secret must not appear in Debug"
        );
        assert!(rendered.contains("<redacted>"));
    }

    /// Build a recipient-local part with the given bound PeerId and stored
    /// transcript hash, with no fixed key material. The ephemeral secret is
    /// absent (a terminal-shaped record); only the PeerId and the stored hash
    /// matter to `existing_matches`.
    fn local_with(sender_peer_id: &str, transcript_hash: Option<[u8; 32]>) -> IncomingLocal {
        IncomingLocal {
            state: EnvelopeState::ChallengeIssued,
            challenge: None,
            password_attempts_remaining: 3,
            password_attempt_pending: false,
            received_at: 1_000,
            effective_expires_at: 10_000,
            sender_peer_id: sender_peer_id.to_string(),
            protection: Protection::V2,
            transcript_hash,
            r_eph_secret: None,
        }
    }

    /// A record whose local part pins no transcript hash stands in for a record
    /// written before the field existed (an older on-disk record or a v1
    /// migration). A resend under the same bound PeerId cannot compare hashes,
    /// so it falls back to the PeerId alone and is treated as an idempotent
    /// match, preserving the earlier behaviour and on-disk compatibility.
    #[test]
    fn a_record_without_a_stored_transcript_hash_matches_on_the_peer_id_alone() {
        let b = build_valid(1_700_000_000);
        // The hash the caller recomputed for the resend; its value is irrelevant
        // because the stored record pins no hash to compare it against.
        let resend_hash: [u8; 32] = rand::random();

        let mut record = IncomingRecord {
            wire: b.envelope.clone(),
            ext: None,
            local: Some(local_with(&b.peer_id_display, None)),
        };
        assert!(
            existing_matches(&record, &resend_hash, &b.peer_id_display),
            "a hashless record matches a resend from the same bound PeerId"
        );

        // A different bound PeerId never matches, even with no stored hash.
        record.local = Some(local_with("a-different-peer", None));
        assert!(
            !existing_matches(&record, &resend_hash, &b.peer_id_display),
            "a different bound PeerId is not an idempotent resend"
        );
    }

    /// A record that pins a transcript hash is idempotent only when both the
    /// bound PeerId and the stored hash match; the same id carrying a different
    /// transcript is a conflict.
    #[test]
    fn a_record_with_a_stored_transcript_hash_matches_only_on_both_peer_id_and_hash() {
        let b = build_valid(1_700_000_000);
        let stored: [u8; 32] = rand::random();
        // A second draw that differs from the first stands in for a different
        // transcript; no fixed hash value is written.
        let mut different: [u8; 32] = rand::random();
        while different == stored {
            different = rand::random();
        }

        let record = IncomingRecord {
            wire: b.envelope.clone(),
            ext: None,
            local: Some(local_with(&b.peer_id_display, Some(stored))),
        };

        // Same PeerId and same stored hash: idempotent.
        assert!(
            existing_matches(&record, &stored, &b.peer_id_display),
            "the same bound PeerId and the same stored hash is a resend"
        );
        // Same PeerId but a different hash: a content conflict.
        assert!(
            !existing_matches(&record, &different, &b.peer_id_display),
            "a different transcript hash under the same id is a conflict"
        );
        // A different PeerId never matches, even with the same stored hash.
        assert!(
            !existing_matches(&record, &stored, "a-different-peer"),
            "a different bound PeerId is not an idempotent resend"
        );
    }

    /// Guards that `IncomingLocal` is in scope in this module's tests: the type
    /// lives in `crate::directed::state`, and a missing import of it is exactly
    /// what stopped this test module from compiling. Building one through
    /// `local_with` (which returns `IncomingLocal`) and reading its fields back
    /// fails to compile if the import is dropped again. No fixed key material is
    /// used: the bound PeerId and the pinned transcript hash are both random.
    #[test]
    fn incoming_local_is_constructible_in_scope() {
        let peer_id = hex::encode(rand_vec(16));
        let pinned: [u8; 32] = rand::random();
        let local: IncomingLocal = local_with(&peer_id, Some(pinned));
        assert_eq!(local.sender_peer_id, peer_id);
        assert_eq!(local.transcript_hash, Some(pinned));
        assert_eq!(local.protection, Protection::V2);
        // The ephemeral secret is absent in this terminal-shaped record.
        assert!(local.r_eph_secret.is_none());
    }
}
