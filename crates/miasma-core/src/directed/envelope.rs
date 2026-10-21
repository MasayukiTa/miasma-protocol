//! Directed sharing envelope — recipient-bound encrypted content delivery.
//!
//! # Crypto design
//!
//! ```text
//! directed_key = HKDF-SHA256(
//!     ikm = ECDH(sender_ephemeral, recipient_pubkey) || Argon2id(password, salt),
//!     info = "miasma-directed-content-v1"
//! )
//! protected = XChaCha20-Poly1305(directed_key, nonce, plaintext)
//! ```
//!
//! The envelope payload (MID, k, n, content_nonce, filename, file_size)
//! is encrypted with a separate key derived from ECDH-only (no password),
//! so the recipient can preview the envelope metadata before entering
//! the password.  The actual content requires the password to decrypt.
//!
//! # Security properties
//!
//! - **Recipient binding**: Only the holder of the recipient's X25519 secret
//!   can compute the ECDH shared secret needed to derive the content key.
//! - **Password second factor**: Even with the recipient's private key,
//!   the password is required to derive the content decryption key.
//! - **Ephemeral sender key**: a fresh X25519 key is used per envelope and is
//!   not stored. This is not forward secrecy against the recipient: the
//!   ephemeral public key is recorded in the envelope, so if the
//!   recipient's long-term key is later compromised, the shared secret of
//!   past envelopes can be recomputed. Compromise of the sender's long-term
//!   key alone does not expose past shares.
//! - **Anti-misdirection**: One-time confirmation code prevents sending to
//!   the wrong recipient.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

use crate::MiasmaError;

/// Domain separation label for content encryption key derivation.
const DIRECTED_CONTENT_LABEL: &[u8] = b"miasma-directed-content-v1";
/// Domain separation label for envelope payload encryption.
const DIRECTED_ENVELOPE_LABEL: &[u8] = b"miasma-directed-envelope-v1";

/// Argon2id parameters for password hashing.
const ARGON2_T_COST: u32 = 3;
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_P_COST: u32 = 1;

// ─── Envelope types ──────────────────────────────────────────────────────────

/// State of a directed share envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeState {
    /// Invite sent, waiting for recipient to see it.
    Pending,
    /// Recipient generated confirmation code.
    ChallengeIssued,
    /// Sender confirmed correctly — content is retrievable.
    Confirmed,
    /// Recipient successfully retrieved content.
    Retrieved,
    /// Sender revoked the share.
    SenderRevoked,
    /// Recipient deleted their copy.
    RecipientDeleted,
    /// Past the retention period.
    Expired,
    /// Max challenge attempts exceeded.
    ChallengeFailed,
    /// Max password attempts exceeded.
    PasswordFailed,
}

impl EnvelopeState {
    /// Whether the envelope is in a terminal state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Retrieved
                | Self::SenderRevoked
                | Self::RecipientDeleted
                | Self::Expired
                | Self::ChallengeFailed
                | Self::PasswordFailed
        )
    }

    /// Whether retrieval is currently allowed.
    pub fn is_retrievable(&self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

/// Retention period options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionPeriod {
    TenMinutes,
    OneHour,
    OneDay,
    SevenDays,
    ThirtyDays,
    Custom(u64),
}

/// Shortest retention a sender may choose: the shortest preset
/// (`RetentionPeriod::TenMinutes`).
pub const MIN_RETENTION_SECS: u64 = 600;

/// Longest retention a sender may choose, and the longest time a recipient
/// keeps a share it received: the longest preset (`RetentionPeriod::ThirtyDays`).
///
/// A receiver never trusts the sender's `expires_at` beyond `now + MAX_RETENTION_SECS`,
/// because `expires_at` is chosen by the sender and `u64::MAX` would otherwise keep a
/// share on the recipient's disk with no end. A sender-side value outside
/// `[MIN_RETENTION_SECS, MAX_RETENTION_SECS]` is refused so that `now + retention`
/// cannot overflow.
pub const MAX_RETENTION_SECS: u64 = 2_592_000;

impl RetentionPeriod {
    /// The retention in seconds, or an error when it is outside
    /// `[MIN_RETENTION_SECS, MAX_RETENTION_SECS]`.
    pub fn checked_secs(&self) -> Result<u64, MiasmaError> {
        let secs = self.as_secs();
        if (MIN_RETENTION_SECS..=MAX_RETENTION_SECS).contains(&secs) {
            Ok(secs)
        } else {
            Err(MiasmaError::Storage(format!(
                "invalid retention: {secs} seconds is outside the allowed range \
                 {MIN_RETENTION_SECS} to {MAX_RETENTION_SECS} seconds"
            )))
        }
    }

    /// Duration in seconds.
    pub fn as_secs(&self) -> u64 {
        match self {
            Self::TenMinutes => 600,
            Self::OneHour => 3600,
            Self::OneDay => 86400,
            Self::SevenDays => 604800,
            Self::ThirtyDays => 2592000,
            Self::Custom(s) => *s,
        }
    }
}

/// The envelope payload — encrypted to the recipient.
/// Contains everything needed to retrieve and decrypt the content.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnvelopePayload {
    /// MID of the protected (double-encrypted) content on the network.
    pub mid: String,
    /// Reed-Solomon data shards (k).
    pub data_shards: u8,
    /// Reed-Solomon total shards (n).
    pub total_shards: u8,
    /// XChaCha20 nonce used for the outer directed encryption layer.
    pub content_nonce: [u8; 24],
    /// Original filename (if provided by sender).
    pub filename: Option<String>,
    /// Original plaintext size in bytes.
    pub file_size: u64,
}

impl fmt::Debug for EnvelopePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopePayload")
            .field("mid", &"<redacted>")
            .field("data_shards", &self.data_shards)
            .field("total_shards", &self.total_shards)
            .field("content_nonce", &"<redacted>")
            .field("filename_configured", &self.filename.is_some())
            .field("file_size", &self.file_size)
            .finish()
    }
}

/// A directed share envelope.
///
/// This is the full envelope stored on both sender and recipient sides.
/// The `encrypted_payload` field is encrypted to the recipient using ECDH;
/// only the recipient with the correct password can derive the content key.
#[derive(Clone, Serialize, Deserialize)]
pub struct DirectedEnvelope {
    /// Unique envelope identifier (random 32 bytes).
    pub envelope_id: [u8; 32],
    /// Protocol version.
    pub version: u8,
    /// Sender's self-asserted X25519 sharing public key. This value is not an
    /// authenticated sender identity; receivers must use the Invite transport
    /// PeerId binding for that purpose.
    pub sender_pubkey: [u8; 32],
    /// Recipient's X25519 sharing public key.
    pub recipient_pubkey: [u8; 32],
    /// Ephemeral X25519 public key for ECDH.
    pub ephemeral_pubkey: [u8; 32],
    /// Encrypted envelope payload (ECDH-encrypted, no password needed to preview).
    pub encrypted_payload: Vec<u8>,
    /// Nonce for payload encryption.
    pub payload_nonce: [u8; 24],
    /// Argon2id salt for password hashing.
    pub password_salt: [u8; 32],
    /// Expiry timestamp (Unix seconds).
    pub expires_at: u64,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Current state.
    pub state: EnvelopeState,
    /// BLAKE3 hash of the challenge code (set by recipient).
    #[serde(default)]
    pub challenge_hash: Option<[u8; 32]>,
    /// Remaining password attempts.
    pub password_attempts_remaining: u8,
    /// Remaining challenge attempts.
    pub challenge_attempts_remaining: u8,
    /// Challenge expiry timestamp.
    pub challenge_expires_at: u64,
    /// Retention period in seconds (for display).
    pub retention_secs: u64,
}

impl fmt::Debug for DirectedEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectedEnvelope")
            .field("envelope_id", &hex::encode(self.envelope_id))
            .field("version", &self.version)
            .field("sender_pubkey", &"<redacted>")
            .field("recipient_pubkey", &"<redacted>")
            .field("ephemeral_pubkey", &"<redacted>")
            .field("encrypted_payload_len", &self.encrypted_payload.len())
            .field("payload_nonce", &"<redacted>")
            .field("password_salt", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("state", &self.state)
            .field("challenge_hash_configured", &self.challenge_hash.is_some())
            .field(
                "password_attempts_remaining",
                &self.password_attempts_remaining,
            )
            .field(
                "challenge_attempts_remaining",
                &self.challenge_attempts_remaining,
            )
            .field("challenge_expires_at", &self.challenge_expires_at)
            .field("retention_secs", &self.retention_secs)
            .finish()
    }
}

impl DirectedEnvelope {
    /// Hex-encoded envelope ID for display and lookup.
    pub fn id_hex(&self) -> String {
        hex::encode(self.envelope_id)
    }

    /// Whether the envelope has expired.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.expires_at
    }

    /// Bring the sender-chosen retention fields of a received envelope into
    /// the range this node is willing to keep.
    ///
    /// - A window that ends at or before it starts (`expires_at <= created_at`)
    ///   is refused: no honest sender produces one.
    /// - `expires_at` is capped to `now + MAX_RETENTION_SECS` and `retention_secs`
    ///   to `MAX_RETENTION_SECS`, so a huge value (up to `u64::MAX`) cannot make
    ///   a share unlimited. An `expires_at` already in the past is kept as is:
    ///   the share is simply expired.
    pub fn normalize_received_retention(&mut self, now_secs: u64) -> Result<(), &'static str> {
        if self.expires_at <= self.created_at {
            return Err("invalid envelope retention window: it ends before it starts");
        }
        self.expires_at = self
            .expires_at
            .min(now_secs.saturating_add(MAX_RETENTION_SECS));
        self.retention_secs = self.retention_secs.min(MAX_RETENTION_SECS);
        Ok(())
    }

    /// Whether the challenge has expired.
    pub fn is_challenge_expired(&self, now_secs: u64) -> bool {
        self.challenge_expires_at > 0 && now_secs >= self.challenge_expires_at
    }

    /// Update state to Expired if past the retention period.
    pub fn check_expiry(&mut self, now_secs: u64) {
        if self.is_expired(now_secs) && !self.state.is_terminal() {
            self.state = EnvelopeState::Expired;
        }
    }
}

// ─── Sender operations ──────────────────────────────────────────────────────

/// Create a directed envelope for a recipient.
///
/// # Steps
/// 1. Generate envelope_id (random)
/// 2. Generate ephemeral X25519 keypair
/// 3. ECDH(ephemeral_secret, recipient_pubkey) → shared_secret
/// 4. Derive envelope_key from shared_secret (HKDF)
/// 5. Encrypt payload with envelope_key
/// 6. Derive directed_key from shared_secret + Argon2id(password)
/// 7. Encrypt plaintext content with directed_key → protected_data
///
/// Returns (envelope, protected_data, envelope_key) where protected_data
/// should be dissolved and published to the network. The MID of
/// protected_data goes into the envelope payload. The envelope_key is
/// needed by `finalize_envelope` to update the payload after dissolution.
///
/// The password must meet the private-share policy
/// ([`password_policy::check_directed`](crate::transfer::password_policy::check_directed));
/// otherwise [`MiasmaError::WeakPassword`] is returned before any key work.
/// Opening an envelope never applies this policy.
pub fn create_envelope(
    sender_secret: &[u8; 32],
    recipient_pubkey: &[u8; 32],
    password: &str,
    retention: RetentionPeriod,
    plaintext: &[u8],
    filename: Option<String>,
) -> Result<(DirectedEnvelope, Vec<u8>, Zeroizing<[u8; 32]>), MiasmaError> {
    crate::transfer::password_policy::check_directed(password)
        .map_err(MiasmaError::WeakPassword)?;
    build_envelope(
        sender_secret,
        recipient_pubkey,
        password,
        retention,
        plaintext,
        filename,
    )
}

/// [`create_envelope`] without the password policy. Test builds only: it
/// stands in for envelopes written before the policy existed.
#[cfg(test)]
pub(crate) fn create_envelope_unchecked(
    sender_secret: &[u8; 32],
    recipient_pubkey: &[u8; 32],
    password: &str,
    retention: RetentionPeriod,
    plaintext: &[u8],
    filename: Option<String>,
) -> Result<(DirectedEnvelope, Vec<u8>, Zeroizing<[u8; 32]>), MiasmaError> {
    build_envelope(
        sender_secret,
        recipient_pubkey,
        password,
        retention,
        plaintext,
        filename,
    )
}

fn build_envelope(
    sender_secret: &[u8; 32],
    recipient_pubkey: &[u8; 32],
    password: &str,
    retention: RetentionPeriod,
    plaintext: &[u8],
    filename: Option<String>,
) -> Result<(DirectedEnvelope, Vec<u8>, Zeroizing<[u8; 32]>), MiasmaError> {
    use rand::RngCore;

    // Refuse a retention that is out of range before doing any work.
    let retention_secs = retention.checked_secs()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 1. Generate envelope ID.
    let mut envelope_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut envelope_id);

    // 2. Generate the ephemeral X25519 key directly inside StaticSecret so
    // there is no additional raw private-key byte array to erase.
    let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_pubkey = x25519_dalek::PublicKey::from(&ephemeral_secret);

    // 3. ECDH shared secret.
    let recipient_x25519 = x25519_dalek::PublicKey::from(*recipient_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);
    if !shared_secret.was_contributory() {
        return Err(MiasmaError::Encryption(
            "non-contributory X25519 recipient public key".into(),
        ));
    }

    // 4. Generate password salt and hash password.
    let mut password_salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut password_salt);
    let password_hash = hash_password(password, &password_salt)?;

    // 5. Derive directed content key (ECDH + password).
    let directed_key = derive_directed_key(shared_secret.as_bytes(), &password_hash)?;

    // 6. Encrypt plaintext with directed key.
    let (content_nonce, protected_data) = xchacha20_encrypt(&directed_key, plaintext)?;

    // 7. Derive envelope key (ECDH only, no password — for payload preview).
    let envelope_key = derive_envelope_key(shared_secret.as_bytes())?;

    // 8. Build and encrypt payload.
    // The MID will be filled in after dissolution; use a placeholder.
    // Caller must update the envelope payload after dissolving protected_data.
    let payload = EnvelopePayload {
        mid: String::new(), // placeholder — set by caller after dissolve
        data_shards: 10,
        total_shards: 20,
        content_nonce,
        filename,
        file_size: plaintext.len() as u64,
    };
    let payload_bytes = bincode::serialize(&payload)
        .map_err(|e| MiasmaError::Encryption(format!("payload serialize: {e}")))?;
    let (payload_nonce, encrypted_payload) = xchacha20_encrypt(&envelope_key, &payload_bytes)?;

    // 9. Compute sender pubkey from secret.
    let sender_static = x25519_dalek::StaticSecret::from(*sender_secret);
    let sender_pubkey = x25519_dalek::PublicKey::from(&sender_static);

    let envelope = DirectedEnvelope {
        envelope_id,
        version: 1,
        sender_pubkey: *sender_pubkey.as_bytes(),
        recipient_pubkey: *recipient_pubkey,
        ephemeral_pubkey: *ephemeral_pubkey.as_bytes(),
        encrypted_payload,
        payload_nonce,
        password_salt,
        expires_at: now.saturating_add(retention_secs),
        created_at: now,
        state: EnvelopeState::Pending,
        challenge_hash: None,
        password_attempts_remaining: 3,
        challenge_attempts_remaining: 3,
        challenge_expires_at: 0,
        retention_secs,
    };

    Ok((envelope, protected_data, envelope_key))
}

/// Finalize the envelope after dissolution — sets the MID in the payload.
pub fn finalize_envelope(
    envelope: &mut DirectedEnvelope,
    envelope_key: &[u8; 32],
    mid: &str,
    data_shards: u8,
    total_shards: u8,
) -> Result<(), MiasmaError> {
    // Decrypt existing payload, update MID, re-encrypt.
    let payload_bytes = xchacha20_decrypt(
        envelope_key,
        &envelope.payload_nonce,
        &envelope.encrypted_payload,
    )?;
    let mut payload: EnvelopePayload = bincode::deserialize(&payload_bytes)
        .map_err(|e| MiasmaError::Encryption(format!("payload deserialize: {e}")))?;
    payload.mid = mid.to_string();
    payload.data_shards = data_shards;
    payload.total_shards = total_shards;

    let payload_bytes = bincode::serialize(&payload)
        .map_err(|e| MiasmaError::Encryption(format!("payload serialize: {e}")))?;
    let (nonce, encrypted) = xchacha20_encrypt(envelope_key, &payload_bytes)?;
    envelope.encrypted_payload = encrypted;
    envelope.payload_nonce = nonce;

    Ok(())
}

// ─── Recipient operations ───────────────────────────────────────────────────

/// Decrypt the envelope payload (ECDH-only, no password needed).
/// Returns the payload metadata for preview.
pub fn decrypt_envelope_payload(
    recipient_secret: &[u8; 32],
    envelope: &DirectedEnvelope,
) -> Result<EnvelopePayload, MiasmaError> {
    let recipient_static = x25519_dalek::StaticSecret::from(*recipient_secret);
    let ephemeral_pub = x25519_dalek::PublicKey::from(envelope.ephemeral_pubkey);
    let shared_secret = recipient_static.diffie_hellman(&ephemeral_pub);
    if !shared_secret.was_contributory() {
        return Err(MiasmaError::Encryption(
            "non-contributory X25519 envelope public key".into(),
        ));
    }

    let envelope_key = derive_envelope_key(shared_secret.as_bytes())?;
    let payload_bytes = xchacha20_decrypt(
        &envelope_key,
        &envelope.payload_nonce,
        &envelope.encrypted_payload,
    )?;

    bincode::deserialize(&payload_bytes)
        .map_err(|e| MiasmaError::Encryption(format!("payload deserialize: {e}")))
}

/// Derive the directed content key for decrypting the actual content.
/// Requires both the recipient's private key and the password.
pub fn derive_content_key(
    recipient_secret: &[u8; 32],
    envelope: &DirectedEnvelope,
    password: &str,
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let recipient_static = x25519_dalek::StaticSecret::from(*recipient_secret);
    let ephemeral_pub = x25519_dalek::PublicKey::from(envelope.ephemeral_pubkey);
    let shared_secret = recipient_static.diffie_hellman(&ephemeral_pub);
    if !shared_secret.was_contributory() {
        return Err(MiasmaError::Encryption(
            "non-contributory X25519 envelope public key".into(),
        ));
    }

    let password_hash = hash_password(password, &envelope.password_salt)?;
    derive_directed_key(shared_secret.as_bytes(), &password_hash)
}

/// Decrypt protected content using the directed key.
pub fn decrypt_directed_content(
    directed_key: &[u8; 32],
    content_nonce: &[u8; 24],
    protected_data: &[u8],
) -> Result<Vec<u8>, MiasmaError> {
    xchacha20_decrypt(directed_key, content_nonce, protected_data)
}

// ─── Sharing key utilities ──────────────────────────────────────────────────

/// Format a sharing key for display: "msk:" + base58(x25519_pubkey).
pub fn format_sharing_key(pubkey: &[u8; 32]) -> String {
    format!("msk:{}", bs58::encode(pubkey).into_string())
}

/// Parse a sharing key string: "msk:..." → X25519 pubkey bytes.
pub fn parse_sharing_key(key_str: &str) -> Result<[u8; 32], MiasmaError> {
    let body = key_str
        .strip_prefix("msk:")
        .ok_or_else(|| MiasmaError::InvalidMid("sharing key must start with 'msk:'".into()))?;

    let bytes = bs58::decode(body)
        .into_vec()
        .map_err(|e| MiasmaError::InvalidMid(format!("invalid base58: {e}")))?;

    if bytes.len() != 32 {
        return Err(MiasmaError::InvalidMid(format!(
            "sharing key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Format a sharing contact string: "msk:" + base58(x25519_pubkey) + "@" + PeerId.
pub fn format_sharing_contact(pubkey: &[u8; 32], peer_id: &str) -> String {
    format!("msk:{}@{}", bs58::encode(pubkey).into_string(), peer_id)
}

/// Parse a sharing contact: "msk:...@PeerId" → (X25519 pubkey, PeerId string).
pub fn parse_sharing_contact(contact: &str) -> Result<([u8; 32], String), MiasmaError> {
    let body = contact
        .strip_prefix("msk:")
        .ok_or_else(|| MiasmaError::InvalidMid("sharing contact must start with 'msk:'".into()))?;

    let parts: Vec<&str> = body.splitn(2, '@').collect();
    if parts.len() != 2 {
        return Err(MiasmaError::InvalidMid(
            "sharing contact must contain '@' separator".into(),
        ));
    }

    let key_bytes = bs58::decode(parts[0])
        .into_vec()
        .map_err(|e| MiasmaError::InvalidMid(format!("invalid base58: {e}")))?;

    if key_bytes.len() != 32 {
        return Err(MiasmaError::InvalidMid(format!(
            "sharing key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&key_bytes);
    Ok((pubkey, parts[1].to_string()))
}

// ─── Crypto helpers ─────────────────────────────────────────────────────────

/// Hash a password using Argon2id.
fn hash_password(password: &str, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| MiasmaError::Encryption(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, output.as_mut())
        .map_err(|e| MiasmaError::Encryption(format!("argon2 hash: {e}")))?;
    Ok(output)
}

/// Derive the directed content key from ECDH shared secret + password hash.
fn derive_directed_key(
    shared_secret: &[u8],
    password_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(shared_secret.len() + 32));
    ikm.extend_from_slice(shared_secret);
    ikm.extend_from_slice(password_hash);

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(DIRECTED_CONTENT_LABEL, key.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;

    Ok(key)
}

/// Derive the envelope key from ECDH shared secret only (no password).
fn derive_envelope_key(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(DIRECTED_ENVELOPE_LABEL, key.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// XChaCha20-Poly1305 encrypt.
fn xchacha20_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 24], Vec<u8>), MiasmaError> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
    use rand::RngCore;

    let mut nonce_bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| MiasmaError::Encryption(e.to_string()))?;
    Ok((nonce_bytes, ct))
}

/// XChaCha20-Poly1305 decrypt.
fn xchacha20_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, MiasmaError> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|e| MiasmaError::Encryption(format!("decryption failed: {e}")))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_payload_debug_redacts_mid_filename_and_nonce() {
        let payload = EnvelopePayload {
            mid: "miasma:private-mid".into(),
            data_shards: 3,
            total_shards: 5,
            content_nonce: [0xAB; 24],
            filename: Some("private-name.txt".into()),
            file_size: 42,
        };
        let rendered = format!("{payload:?}");
        assert!(!rendered.contains("private-mid"));
        assert!(!rendered.contains("private-name.txt"));
        assert!(!rendered.contains("171, 171"));
        assert!(rendered.contains("filename_configured: true"));
    }

    #[test]
    fn envelope_debug_redacts_challenge_hash_and_crypto_material() {
        let env = DirectedEnvelope {
            envelope_id: [1; 32],
            version: 1,
            sender_pubkey: [2; 32],
            recipient_pubkey: [3; 32],
            ephemeral_pubkey: [4; 32],
            encrypted_payload: vec![5, 6, 7, 8],
            payload_nonce: [9; 24],
            password_salt: [10; 32],
            expires_at: 20,
            created_at: 10,
            state: EnvelopeState::ChallengeIssued,
            challenge_hash: Some([11; 32]),
            password_attempts_remaining: 2,
            challenge_attempts_remaining: 2,
            challenge_expires_at: 15,
            retention_secs: 10,
        };
        let rendered = format!("{env:?}");
        for raw in [
            "[2, 2, 2",
            "[3, 3, 3",
            "[4, 4, 4",
            "[5, 6, 7, 8]",
            "[9, 9, 9",
            "[10, 10, 10",
            "[11, 11, 11",
        ] {
            assert!(!rendered.contains(raw));
        }
        assert!(rendered.contains("encrypted_payload_len: 4"));
        assert!(rendered.contains("challenge_hash_configured: true"));
    }

    fn test_keys() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let sender_secret_raw =
            crate::crypto::keyderive::derive_sharing_key(b"sender-master-key-32bytes-pad!!!")
                .unwrap();
        let sender_static = x25519_dalek::StaticSecret::from(*sender_secret_raw);
        let sender_pubkey = x25519_dalek::PublicKey::from(&sender_static);

        let recipient_secret_raw =
            crate::crypto::keyderive::derive_sharing_key(b"recip-master-key-32bytes-padd!!")
                .unwrap();
        let recipient_static = x25519_dalek::StaticSecret::from(*recipient_secret_raw);
        let recipient_pubkey = x25519_dalek::PublicKey::from(&recipient_static);

        (
            *sender_secret_raw,
            *sender_pubkey.as_bytes(),
            *recipient_secret_raw,
            *recipient_pubkey.as_bytes(),
        )
    }

    /// A policy-compliant password generated at run time.
    fn strong_pw() -> String {
        crate::transfer::password_policy::generate(16).to_string()
    }

    #[test]
    fn create_envelope_enforces_the_private_share_policy() {
        use crate::transfer::password_policy::{
            test_support::{compose, Other},
            PolicyViolation, DIRECTED_MIN_LEN,
        };
        let (sender_secret, _, _, recipient_pub) = test_keys();
        let try_pw = |pw: &str| {
            create_envelope(
                &sender_secret,
                &recipient_pub,
                pw,
                RetentionPeriod::OneHour,
                b"data",
                None,
            )
        };
        // Empty.
        let empty = String::new();
        match try_pw(&empty) {
            Err(MiasmaError::WeakPassword(v)) => {
                assert!(v.contains(&PolicyViolation::TooShortPrivate {
                    min: DIRECTED_MIN_LEN,
                    len: 0
                }));
            }
            _ => panic!("empty password accepted"),
        }
        // One below the floor, otherwise compliant.
        let eleven = compose(8, 2, 1, &[]);
        assert_eq!(eleven.chars().count(), DIRECTED_MIN_LEN - 1);
        match try_pw(&eleven) {
            Err(MiasmaError::WeakPassword(v)) => assert_eq!(
                v,
                vec![PolicyViolation::TooShortPrivate {
                    min: DIRECTED_MIN_LEN,
                    len: 11
                }]
            ),
            _ => panic!("11-character password accepted"),
        }
        // Characters, not bytes: 11 characters that take more than 12 bytes.
        let multibyte = compose(4, 1, 1, &[Other::NonAscii; 5]);
        assert_eq!(multibyte.chars().count(), 11);
        assert!(multibyte.len() > DIRECTED_MIN_LEN);
        assert!(matches!(
            try_pw(&multibyte),
            Err(MiasmaError::WeakPassword(_))
        ));
        // Whitespace only.
        assert!(matches!(
            try_pw(&compose(0, 0, 0, &[Other::Space; 20])),
            Err(MiasmaError::WeakPassword(_))
        ));
        // Exactly at the floor.
        let twelve = compose(9, 2, 1, &[]);
        assert_eq!(twelve.chars().count(), DIRECTED_MIN_LEN);
        assert!(try_pw(&twelve).is_ok());
        assert!(try_pw(&crate::transfer::password_policy::generate(12)).is_ok());
    }

    #[test]
    fn weak_password_error_text_carries_codes_only() {
        use crate::transfer::password_policy::{parse_codes, test_support::compose};
        let (sender_secret, _, _, recipient_pub) = test_keys();
        let weak = compose(7, 0, 0, &[]);
        let err = create_envelope(
            &sender_secret,
            &recipient_pub,
            &weak,
            RetentionPeriod::OneHour,
            b"data",
            None,
        )
        .unwrap_err();
        let shown = format!("{err} | {err:?}");
        assert!(!shown.contains(&weak));
        assert_eq!(
            err.to_string(),
            "weak password: too_short_private,no_digit,no_symbol"
        );
        assert_eq!(
            parse_codes(&err.to_string()).unwrap(),
            vec!["too_short_private", "no_digit", "no_symbol"]
        );
    }

    #[test]
    fn envelope_made_with_a_short_password_still_opens() {
        use crate::transfer::password_policy::test_support::compose;
        let (sender_secret, _, recipient_secret, recipient_pub) = test_keys();
        let short = compose(2, 1, 1, &[]);
        let plaintext = b"older share";
        // Not creatable now ...
        assert!(create_envelope(
            &sender_secret,
            &recipient_pub,
            &short,
            RetentionPeriod::OneHour,
            plaintext,
            None
        )
        .is_err());
        // ... but one made before the policy opens with its own password.
        let (envelope, protected, _k) = create_envelope_unchecked(
            &sender_secret,
            &recipient_pub,
            &short,
            RetentionPeriod::OneHour,
            plaintext,
            None,
        )
        .unwrap();
        let payload = decrypt_envelope_payload(&recipient_secret, &envelope).unwrap();
        let key = derive_content_key(&recipient_secret, &envelope, &short).unwrap();
        let out = decrypt_directed_content(&key, &payload.content_nonce, &protected).unwrap();
        assert_eq!(out, plaintext);
        // The empty password also derives a key without being refused.
        let empty = String::new();
        assert!(derive_content_key(&recipient_secret, &envelope, &empty).is_ok());
    }

    #[test]
    fn envelope_roundtrip() {
        let (sender_secret, _sender_pub, recipient_secret, recipient_pub) = test_keys();
        let plaintext = b"Hello, this is a secret message for you!";
        let pw = strong_pw();

        let (mut envelope, protected, envelope_key) = create_envelope(
            &sender_secret,
            &recipient_pub,
            &pw,
            RetentionPeriod::OneDay,
            plaintext,
            Some("message.txt".to_string()),
        )
        .unwrap();

        // Simulate dissolve + finalize.
        let mid = format!("miasma:{}", bs58::encode(&protected[..8]).into_string());
        finalize_envelope(&mut envelope, &envelope_key, &mid, 10, 20).unwrap();

        // Recipient decrypts payload (preview).
        let payload = decrypt_envelope_payload(&recipient_secret, &envelope).unwrap();
        assert_eq!(payload.mid, mid);
        assert_eq!(payload.filename, Some("message.txt".to_string()));
        assert_eq!(payload.file_size, plaintext.len() as u64);

        // Recipient derives content key and decrypts.
        let content_key = derive_content_key(&recipient_secret, &envelope, &pw).unwrap();
        let decrypted =
            decrypt_directed_content(&content_key, &payload.content_nonce, &protected).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails_decryption() {
        let (sender_secret, _sender_pub, recipient_secret, recipient_pub) = test_keys();
        let plaintext = b"Secret!";
        let pw = strong_pw();
        let other = strong_pw();

        let (envelope, protected, _envelope_key) = create_envelope(
            &sender_secret,
            &recipient_pub,
            &pw,
            RetentionPeriod::OneHour,
            plaintext,
            None,
        )
        .unwrap();

        let payload = decrypt_envelope_payload(&recipient_secret, &envelope).unwrap();

        // Wrong password → different key → AEAD fails.
        let wrong_key = derive_content_key(&recipient_secret, &envelope, &other).unwrap();
        let result = decrypt_directed_content(&wrong_key, &payload.content_nonce, &protected);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_recipient_cannot_decrypt_payload() {
        let (sender_secret, _sender_pub, _recipient_secret, recipient_pub) = test_keys();

        let (envelope, _protected, _envelope_key) = create_envelope(
            &sender_secret,
            &recipient_pub,
            &strong_pw(),
            RetentionPeriod::OneHour,
            b"data",
            None,
        )
        .unwrap();

        // Different recipient tries to decrypt.
        let wrong_secret =
            crate::crypto::keyderive::derive_sharing_key(b"wrong-master-key-32bytes-pad!!!!")
                .unwrap();
        let result = decrypt_envelope_payload(&wrong_secret, &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn create_envelope_rejects_non_contributory_recipient_key() {
        let (sender_secret, _, _, _) = test_keys();
        let password = strong_pw();
        let err = create_envelope(
            &sender_secret,
            &[0u8; 32],
            &password,
            RetentionPeriod::OneHour,
            b"data",
            None,
        )
        .unwrap_err();
        assert!(matches!(err, MiasmaError::Encryption(_)));
    }

    #[test]
    fn recipient_rejects_non_contributory_ephemeral_key() {
        let (sender_secret, _, recipient_secret, recipient_pub) = test_keys();
        let password = strong_pw();
        let (mut envelope, _, _) = create_envelope(
            &sender_secret,
            &recipient_pub,
            &password,
            RetentionPeriod::OneHour,
            b"data",
            None,
        )
        .unwrap();
        envelope.ephemeral_pubkey = [0u8; 32];

        assert!(decrypt_envelope_payload(&recipient_secret, &envelope).is_err());
        assert!(derive_content_key(&recipient_secret, &envelope, &password).is_err());
    }

    #[test]
    fn sharing_key_format_roundtrip() {
        let key = [0x42u8; 32];
        let formatted = format_sharing_key(&key);
        assert!(formatted.starts_with("msk:"));
        let parsed = parse_sharing_key(&formatted).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn sharing_contact_format_roundtrip() {
        let key = [0x42u8; 32];
        let peer_id = "12D3KooWTestPeerId";
        let contact = format_sharing_contact(&key, peer_id);
        let (parsed_key, parsed_peer) = parse_sharing_contact(&contact).unwrap();
        assert_eq!(parsed_key, key);
        assert_eq!(parsed_peer, peer_id);
    }

    #[test]
    fn envelope_expiry() {
        let (sender_secret, _, _, recipient_pub) = test_keys();
        let (mut envelope, _, _envelope_key) = create_envelope(
            &sender_secret,
            &recipient_pub,
            &strong_pw(),
            RetentionPeriod::TenMinutes,
            b"data",
            None,
        )
        .unwrap();

        assert!(!envelope.is_expired(envelope.created_at));
        assert!(envelope.is_expired(envelope.expires_at));
        assert!(envelope.is_expired(envelope.expires_at + 1));

        envelope.check_expiry(envelope.expires_at + 1);
        assert_eq!(envelope.state, EnvelopeState::Expired);
    }

    #[test]
    fn retention_periods() {
        assert_eq!(RetentionPeriod::TenMinutes.as_secs(), 600);
        assert_eq!(RetentionPeriod::OneHour.as_secs(), 3600);
        assert_eq!(RetentionPeriod::OneDay.as_secs(), 86400);
        assert_eq!(RetentionPeriod::SevenDays.as_secs(), 604800);
        assert_eq!(RetentionPeriod::ThirtyDays.as_secs(), 2592000);
        assert_eq!(RetentionPeriod::Custom(42).as_secs(), 42);
    }

    /// A fresh password for each call, so no password is written in this file.
    fn generated_password() -> String {
        hex::encode(rand::random::<[u8; 12]>())
    }

    #[test]
    fn the_retention_bounds_are_the_shortest_and_longest_preset() {
        assert_eq!(MIN_RETENTION_SECS, RetentionPeriod::TenMinutes.as_secs());
        assert_eq!(MAX_RETENTION_SECS, RetentionPeriod::ThirtyDays.as_secs());
        for preset in [
            RetentionPeriod::TenMinutes,
            RetentionPeriod::OneHour,
            RetentionPeriod::OneDay,
            RetentionPeriod::SevenDays,
            RetentionPeriod::ThirtyDays,
        ] {
            assert_eq!(preset.checked_secs().unwrap(), preset.as_secs());
        }
    }

    #[test]
    fn create_envelope_refuses_a_retention_that_would_overflow_or_never_end() {
        let (sender_secret, _, _, recipient_pub) = test_keys();
        for bad in [
            0,
            1,
            MIN_RETENTION_SECS - 1,
            MAX_RETENTION_SECS + 1,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let err = create_envelope(
                &sender_secret,
                &recipient_pub,
                &generated_password(),
                RetentionPeriod::Custom(bad),
                b"data",
                None,
            )
            .map(|_| ())
            .expect_err("an out-of-range retention must be refused");
            assert!(
                err.to_string().contains("invalid retention"),
                "retention {bad}: {err}"
            );
        }
    }

    #[test]
    fn create_envelope_accepts_the_ends_of_the_range() {
        let (sender_secret, _, _, recipient_pub) = test_keys();
        for ok in [MIN_RETENTION_SECS, 12345, MAX_RETENTION_SECS] {
            let (env, _, _) = create_envelope(
                &sender_secret,
                &recipient_pub,
                &generated_password(),
                RetentionPeriod::Custom(ok),
                b"data",
                None,
            )
            .unwrap();
            assert_eq!(env.retention_secs, ok);
            assert_eq!(env.expires_at, env.created_at + ok);
        }
    }

    fn envelope_with_window(created_at: u64, expires_at: u64) -> DirectedEnvelope {
        DirectedEnvelope {
            envelope_id: [9u8; 32],
            version: 1,
            sender_pubkey: [1u8; 32],
            recipient_pubkey: [2u8; 32],
            ephemeral_pubkey: [3u8; 32],
            encrypted_payload: vec![4u8; 16],
            payload_nonce: [5u8; 24],
            password_salt: [6u8; 32],
            expires_at,
            created_at,
            state: EnvelopeState::Pending,
            challenge_hash: None,
            password_attempts_remaining: 3,
            challenge_attempts_remaining: 3,
            challenge_expires_at: 0,
            retention_secs: expires_at.saturating_sub(created_at),
        }
    }

    #[test]
    fn a_received_unlimited_expiry_is_capped() {
        let now = 1_800_000_000;
        for expires_at in [u64::MAX, u64::MAX - 1, now + MAX_RETENTION_SECS + 1] {
            let mut env = envelope_with_window(now, expires_at);
            env.normalize_received_retention(now).unwrap();
            assert_eq!(env.expires_at, now + MAX_RETENTION_SECS);
            assert_eq!(env.retention_secs, MAX_RETENTION_SECS);
            assert!(!env.is_expired(now));
            assert!(env.is_expired(now + MAX_RETENTION_SECS));
        }
    }

    #[test]
    fn a_received_retention_secs_is_capped_on_its_own() {
        let now = 1_800_000_000;
        let mut env = envelope_with_window(now, now + 3600);
        env.retention_secs = u64::MAX;
        env.normalize_received_retention(now).unwrap();
        assert_eq!(env.expires_at, now + 3600);
        assert_eq!(env.retention_secs, MAX_RETENTION_SECS);
    }

    #[test]
    fn capping_does_not_overflow_when_the_clock_is_at_the_end_of_time() {
        let mut env = envelope_with_window(1, u64::MAX);
        env.normalize_received_retention(u64::MAX).unwrap();
        assert_eq!(env.expires_at, u64::MAX);
        let mut env = envelope_with_window(1, u64::MAX);
        env.normalize_received_retention(u64::MAX - 5).unwrap();
        assert_eq!(env.expires_at, u64::MAX);
    }

    #[test]
    fn a_received_window_that_ends_before_it_starts_is_refused() {
        let now = 1_800_000_000;
        for (created_at, expires_at) in [(now, now), (now, now - 1), (now, 0), (u64::MAX, u64::MAX)]
        {
            let mut env = envelope_with_window(created_at, expires_at);
            let err = env.normalize_received_retention(now).unwrap_err();
            assert!(err.contains("retention window"), "{err}");
        }
    }

    #[test]
    fn a_valid_envelope_is_not_changed_by_receiving() {
        // The values of the frozen v1 fixture: a past, well-formed window is kept
        // byte for byte, and so is one inside the cap.
        for now in [1_700_000_000, 1_800_000_000, 2_000_000_000] {
            let mut env = envelope_with_window(1_700_000_000, 1_700_086_400);
            env.retention_secs = 86_400;
            let before = bincode::serialize(&env).unwrap();
            env.normalize_received_retention(now).unwrap();
            assert_eq!(bincode::serialize(&env).unwrap(), before, "now = {now}");
        }
        let (sender_secret, _, _, recipient_pub) = test_keys();
        let (mut env, _, _) = create_envelope(
            &sender_secret,
            &recipient_pub,
            &generated_password(),
            RetentionPeriod::SevenDays,
            b"data",
            None,
        )
        .unwrap();
        let before = bincode::serialize(&env).unwrap();
        env.normalize_received_retention(env.created_at).unwrap();
        assert_eq!(bincode::serialize(&env).unwrap(), before);
    }
}
