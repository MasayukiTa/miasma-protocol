//! Recipient- and sender-side records for directed shares, as explicit state
//! machines.
//!
//! The wire type [`DirectedEnvelope`](super::envelope::DirectedEnvelope) is the
//! immutable part a sender produces; it is unchanged here. A recipient keeps a
//! local record ([`IncomingRecord`]) that carries the wire bytes plus local
//! fields the sender never sees: the confirmation challenge, the authenticated
//! sender PeerId, the ephemeral retrieval secret, `received_at`, and an
//! effective expiry clamped to what this node is willing to keep. A sender
//! keeps an [`OutgoingRecord`] whose extra phase never travels on the wire.
//!
//! The only public way to change a record's state is [`IncomingRecord::step`]
//! and [`OutgoingRecord::step`]; both return the side effects a caller must
//! carry out in the same write, or [`Illegal`] when the event does not apply.
//! The transition tables are design sections 6.2 and 6.3.
//!
//! On-disk JSON uses the v1 key names for the wire part (`#[serde(flatten)]`),
//! so a record reads and writes with the same shape as before; the local part
//! is new keys with defaults, which an older build ignores.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::envelope::{DirectedEnvelope, EnvelopeState};

/// How the content key material is protected: the v2 scheme, or a record
/// carried over from a v1 envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Protection {
    /// v2: an ephemeral retrieval secret guards forward secrecy.
    V2,
    /// A record migrated from a v1 envelope; no ephemeral secret.
    #[default]
    LegacyV1,
}

/// Sender-supplied extension carried by a v2 Invite. The wire codec is out of
/// scope for this work package (WP-D5); the field exists so a record can hold
/// it once that lands. Unknown to v1.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InviteExtV2 {
    /// Opaque sender credential bytes, verified elsewhere.
    #[serde(default)]
    pub credential: Vec<u8>,
}

impl std::fmt::Debug for InviteExtV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The credential is key-bearing material; show only its length.
        f.debug_struct("InviteExtV2")
            .field("credential", &"<redacted>")
            .finish()
    }
}

/// The recipient's local, non-wire fields for one envelope.
#[derive(Clone, Serialize, Deserialize)]
pub struct IncomingLocal {
    /// Local state. The wire `state` byte is not read.
    pub state: EnvelopeState,
    /// BLAKE3 hash of the confirmation code, remaining tries, and its expiry on
    /// a monotonic basis. Absent once the challenge is spent.
    #[serde(default)]
    pub challenge: Option<ChallengeLocal>,
    /// Remaining password tries.
    pub password_attempts_remaining: u8,
    /// True while a `PasswordAttemptStart` has pre-spent one try that has not
    /// yet been resolved. A network-failure give-back returns the try only when
    /// this is set, so a give-back without a matching pre-spend cannot raise the
    /// count past its starting value. A new optional field with a serde default
    /// so the on-disk shape stays compatible with an older build.
    #[serde(default)]
    pub password_attempt_pending: bool,
    /// When this record was first written, in wall-clock Unix seconds (display).
    pub received_at: u64,
    /// Expiry this node enforces: never past `received_at + MAX_RETENTION_SECS`,
    /// and never past the sender's `expires_at`.
    pub effective_expires_at: u64,
    /// Authenticated libp2p sender PeerId seen on the Invite transport.
    pub sender_peer_id: String,
    /// Which protection scheme guards the content key.
    pub protection: Protection,
    /// Ephemeral retrieval secret (v2 only). Dropped on every terminal step.
    ///
    /// Stored as a bare array because `zeroize::Zeroizing` is not serde-enabled
    /// in this build; the bytes are overwritten with zero before the field is
    /// cleared (see [`IncomingLocal::clear_r_eph`]) and
    /// [`IncomingLocal::r_eph`] hands callers a `Zeroizing` copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r_eph_secret: Option<[u8; 32]>,
}

impl IncomingLocal {
    /// A zeroizing copy of the ephemeral retrieval secret, if present.
    pub fn r_eph(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.r_eph_secret.map(Zeroizing::new)
    }

    /// Overwrite the ephemeral secret with zero and drop it.
    pub fn clear_r_eph(&mut self) {
        if let Some(mut bytes) = self.r_eph_secret.take() {
            use zeroize::Zeroize;
            bytes.zeroize();
        }
    }
}

impl std::fmt::Debug for IncomingLocal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingLocal")
            .field("state", &self.state)
            .field("challenge_configured", &self.challenge.is_some())
            .field(
                "password_attempts_remaining",
                &self.password_attempts_remaining,
            )
            .field("password_attempt_pending", &self.password_attempt_pending)
            .field("received_at", &self.received_at)
            .field("effective_expires_at", &self.effective_expires_at)
            .field("sender_peer_id", &self.sender_peer_id)
            .field("protection", &self.protection)
            .field(
                "r_eph_secret",
                &self.r_eph_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The confirmation challenge as the recipient stores it.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeLocal {
    /// BLAKE3 hash of the formatted code; the raw code is compared constant-time.
    pub hash: [u8; 32],
    /// Remaining verification tries.
    pub attempts_remaining: u8,
    /// Expiry on the recipient's monotonic clock (see [`MonoDeadline`]).
    pub expires: MonoDeadline,
}

impl std::fmt::Debug for ChallengeLocal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeLocal")
            .field("hash", &"<redacted>")
            .field("attempts_remaining", &self.attempts_remaining)
            .field("expires", &self.expires)
            .finish()
    }
}

/// A deadline that a backward wall-clock step cannot extend.
///
/// The challenge TTL is checked against a monotonic reading taken when the
/// challenge was issued: `issued_mono` plus the TTL. A wall-clock value is kept
/// only for display. Comparing two monotonic readings is immune to the clock
/// being set back, so a stopped-and-restarted recipient cannot lengthen the
/// window by moving its clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonoDeadline {
    /// Monotonic reading at issue, in milliseconds.
    pub issued_mono_ms: u64,
    /// Time-to-live in milliseconds from `issued_mono_ms`.
    pub ttl_ms: u64,
    /// Wall-clock expiry for display only; never used to decide expiry.
    pub wall_expires_at: u64,
}

impl MonoDeadline {
    /// True when `now_mono_ms` is at or past the monotonic deadline. A reading
    /// earlier than the issue point (the clock source went backwards) is not
    /// treated as expired and does not shorten the window either.
    pub fn is_expired(&self, now_mono_ms: u64) -> bool {
        match now_mono_ms.checked_sub(self.issued_mono_ms) {
            Some(elapsed) => elapsed >= self.ttl_ms,
            None => false,
        }
    }
}

/// The two clock readings a step is judged against: wall-clock seconds (for the
/// effective expiry, which is a wall value) and a monotonic millisecond reading
/// (for the challenge TTL).
#[derive(Debug, Clone, Copy)]
pub struct Now {
    pub wall_secs: u64,
    pub mono_ms: u64,
}

/// Events the recipient record reacts to (design 6.2).
#[derive(Clone)]
pub enum IncomingEvent {
    /// A Confirm arrived with this code.
    Confirm { code: String },
    /// A password retrieval attempt is beginning.
    PasswordAttemptStart,
    /// The DEK opened: retrieval succeeded.
    RetrievedOk,
    /// The password was wrong for this attempt.
    PasswordWrong,
    /// Retrieval failed although the password was right (network fault): the
    /// attempt that was pre-decremented is given back.
    RetrievalNetworkFailure,
    /// The sender revoked (same bound PeerId).
    SenderRevoke,
    /// The recipient deleted their copy.
    RecipientDelete,
    /// A periodic check found the effective expiry passed.
    ExpiryTick,
    /// A periodic check found the challenge TTL passed.
    ChallengeTimeout,
}

impl std::fmt::Debug for IncomingEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The confirmation code is a secret; never print it.
        match self {
            IncomingEvent::Confirm { .. } => f
                .debug_struct("Confirm")
                .field("code", &"<redacted>")
                .finish(),
            IncomingEvent::PasswordAttemptStart => f.write_str("PasswordAttemptStart"),
            IncomingEvent::RetrievedOk => f.write_str("RetrievedOk"),
            IncomingEvent::PasswordWrong => f.write_str("PasswordWrong"),
            IncomingEvent::RetrievalNetworkFailure => f.write_str("RetrievalNetworkFailure"),
            IncomingEvent::SenderRevoke => f.write_str("SenderRevoke"),
            IncomingEvent::RecipientDelete => f.write_str("RecipientDelete"),
            IncomingEvent::ExpiryTick => f.write_str("ExpiryTick"),
            IncomingEvent::ChallengeTimeout => f.write_str("ChallengeTimeout"),
        }
    }
}

/// What the caller must do in the same write after a legal step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Effects {
    /// The challenge hash and code file must be dropped.
    pub clear_challenge: bool,
    /// The ephemeral retrieval secret must be dropped.
    pub clear_r_eph: bool,
    /// The record reached a terminal state.
    pub reached_terminal: bool,
    /// The record must be removed from disk after this write (an unconfirmed
    /// record that failed its challenge; design 6.6 item 1).
    pub delete_file: bool,
    /// Nothing changed and nothing should be written (a revoke replay).
    pub no_write: bool,
}

/// The event did not apply in the current state; the record is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Illegal;

impl std::fmt::Display for Illegal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("illegal directed-share transition for the current state")
    }
}

impl std::error::Error for Illegal {}

/// A recipient's local record: the immutable wire part, an optional v2
/// extension, and the local fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingRecord {
    /// The sender's immutable envelope, keyed exactly as v1 wrote it.
    #[serde(flatten)]
    pub wire: DirectedEnvelope,
    /// Sender-supplied v2 extension; absent for a v1 envelope.
    #[serde(default)]
    pub ext: Option<InviteExtV2>,
    /// Recipient-local state; absent in a record written by v1.
    #[serde(default)]
    pub local: Option<IncomingLocal>,
}

/// Sender-side phase, kept off the wire (design 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutgoingPhase {
    /// Just created, not yet published.
    #[default]
    Fresh,
    /// Content published, waiting for the recipient to take the Invite.
    AwaitingRecipient,
    /// The recipient stored the Invite (v2).
    Delivered,
    /// The recipient stored the Invite over the v1 path.
    DeliveredLegacy,
    /// The recipient confirmed.
    Confirmed,
    /// Past the retention period.
    Expired,
    /// The sender revoked.
    SenderRevoked,
    /// Delivery was refused (key / version / peer mismatch).
    DeliveryFailed,
    /// The recipient exhausted challenge tries.
    ChallengeFailed,
}

impl OutgoingPhase {
    /// Whether the phase is terminal (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Expired | Self::SenderRevoked | Self::DeliveryFailed | Self::ChallengeFailed
        )
    }
}

/// Events the sender record reacts to (design 6.3).
#[derive(Debug, Clone, Copy)]
pub enum OutgoingEvent {
    /// The content was published; the recipient cannot be reached yet.
    Published,
    /// An `InviteStored` response came back (v2 path).
    InviteStored,
    /// The recipient only speaks v1 and the Invite went over the v1 path.
    DeliveredLegacy,
    /// The retention period passed.
    RetentionPassed,
    /// The user revoked.
    UserRevoke,
    /// Delivery was refused: key / version / peer mismatch.
    DeliveryFailed,
    /// A Confirm succeeded.
    ConfirmOk,
    /// A Confirm was wrong; the recipient reported this many tries left.
    ConfirmWrong { attempts_remaining: u8 },
}

/// A sender's local record: the immutable wire part plus the off-wire phase and
/// the secrets the sender drops once delivery is acknowledged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingRecord {
    /// The sender's immutable envelope, keyed exactly as v1 wrote it.
    #[serde(flatten)]
    pub wire: DirectedEnvelope,
    /// Off-wire sender phase.
    #[serde(default)]
    pub phase: OutgoingPhase,
    /// The last remaining-challenge-tries count the recipient reported.
    #[serde(default)]
    pub recipient_attempts_remaining: Option<u8>,
}

/// Display placeholder for an unknown (legacy/unbound) sender, matching the
/// desktop constant.
pub const LEGACY_SENDER: &str = "<legacy/unbound>";

impl IncomingRecord {
    /// Build a fresh recipient record from a just-verified Invite, ready to be
    /// written once (design 6.2 first two rows, 6.4). The caller supplies the
    /// challenge already generated so the hash and the raw code come from one
    /// source.
    ///
    /// `expires_at` is the sender's value; the effective expiry is clamped to
    /// `received_wall_secs + MAX_RETENTION_SECS` so a far-future sender value
    /// cannot keep the record forever.
    #[allow(clippy::too_many_arguments)]
    pub fn new_incoming(
        wire: DirectedEnvelope,
        ext: Option<InviteExtV2>,
        sender_peer_id: String,
        protection: Protection,
        challenge: ChallengeLocal,
        password_attempts_remaining: u8,
        r_eph_secret: Option<Zeroizing<[u8; 32]>>,
        now: Now,
    ) -> Self {
        let effective_expires_at = clamp_expiry(wire.expires_at, now.wall_secs);
        let local = IncomingLocal {
            state: EnvelopeState::ChallengeIssued,
            challenge: Some(challenge),
            password_attempts_remaining,
            password_attempt_pending: false,
            received_at: now.wall_secs,
            effective_expires_at,
            sender_peer_id,
            protection,
            // The field is a bare array (serde-enabled); the argument carries a
            // zeroizing wrapper. Unwrap it into the stored array. The wrapper is
            // dropped (and zeroized) at the end of this call; the stored copy is
            // cleared by `clear_r_eph` on every terminal step.
            r_eph_secret: r_eph_secret.map(|z| *z),
        };
        Self {
            wire,
            ext,
            local: Some(local),
        }
    }

    /// Fill in the local part of a record read from a v1 file that has none
    /// (design 7). The wire bytes are untouched; only the local view is built.
    ///
    /// - `state`: the file's value, except a recipient-side `Pending` (a v1
    ///   two-write that stopped halfway) becomes `ChallengeIssued` with a fresh
    ///   challenge, since the sender has not confirmed yet.
    /// - `sender_peer_id`: the `.peer` sidecar value, or [`LEGACY_SENDER`].
    /// - `received_at`: now; `effective_expires_at = min(expires_at, now + MAX)`.
    /// - `protection = LegacyV1`.
    pub fn migrate_v1(
        &mut self,
        sender_peer_id: Option<String>,
        rebuilt_challenge: Option<ChallengeLocal>,
        existing_challenge: Option<ChallengeLocal>,
        now: Now,
    ) {
        if self.local.is_some() {
            return;
        }
        let file_state = self.wire.state;
        let (state, challenge) = if file_state == EnvelopeState::Pending {
            (EnvelopeState::ChallengeIssued, rebuilt_challenge)
        } else {
            (file_state, existing_challenge)
        };
        let effective_expires_at = clamp_expiry(self.wire.expires_at, now.wall_secs);
        self.local = Some(IncomingLocal {
            state,
            challenge,
            password_attempts_remaining: self.wire.password_attempts_remaining,
            password_attempt_pending: false,
            received_at: now.wall_secs,
            effective_expires_at,
            sender_peer_id: sender_peer_id.unwrap_or_else(|| LEGACY_SENDER.to_string()),
            protection: Protection::LegacyV1,
            r_eph_secret: None,
        });
    }

    /// The local state, or the wire state when a record has not been migrated.
    pub fn effective_state(&self) -> EnvelopeState {
        self.local
            .as_ref()
            .map(|l| l.state)
            .unwrap_or(self.wire.state)
    }
}

/// The effective expiry a receiver enforces: the sender's `expires_at`, but
/// never past `received_wall_secs + MAX_RETENTION_SECS`. A saturating add keeps
/// a far clock from overflowing.
fn clamp_expiry(sender_expires_at: u64, received_wall_secs: u64) -> u64 {
    let ceiling = received_wall_secs.saturating_add(super::envelope::MAX_RETENTION_SECS);
    sender_expires_at.min(ceiling)
}
