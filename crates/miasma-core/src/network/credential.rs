/// Anonymous trust credentials for Miasma's admission and routing layers.
///
/// # Design
///
/// Miasma needs peers to prove trust-tier membership without revealing their
/// long-term PeerId. This module implements a pseudonymous credential system
/// using ephemeral Ed25519 keypairs:
///
/// 1. **Ephemeral identity** — each peer generates a fresh Ed25519 keypair per
///    epoch (default: 1 hour). The `holder_tag = BLAKE3(ephemeral_pubkey)` acts
///    as a pseudonym that is unlinkable across epochs.
///
/// 2. **Credential issuance** — when a peer passes admission (PoW + diversity),
///    the admitting peer (issuer) signs a credential binding the holder's
///    `holder_tag` to a trust tier and capability set.
///
/// 3. **Credential presentation** — to prove tier membership, the holder shows
///    the signed credential plus a context-bound signature from the ephemeral
///    key, proving they own the pseudonym without revealing their PeerId.
///
/// # Privacy properties
///
/// - **Cross-epoch unlinkability**: new ephemeral key each epoch → different
///   `holder_tag` → verifiers cannot link presentations across epochs.
/// - **Issuer-holder separation**: the issuer knows the PeerId→holder_tag
///   mapping (unavoidable — they admitted you), but other peers do not.
/// - **Non-transferability**: presenting requires the ephemeral secret key,
///   so stolen credentials cannot be used without the key.
/// - **Selective disclosure**: the credential reveals tier and capabilities
///   but not the holder's PeerId or network address.
///
/// # Upgrade path to BBS+
///
/// This scheme provides epoch-level unlinkability but presentations within
/// an epoch are linkable (same holder_tag). True BBS+ signatures would give
/// per-presentation unlinkability. The trait boundary (`CredentialScheme`) is
/// designed to allow dropping in BBS+ once pairing-based crypto is available
/// without changing the rest of the stack.
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Epoch duration in seconds (1 hour).
pub const EPOCH_DURATION_SECS: u64 = 3600;

/// Number of past epochs to accept (grace period for clock skew).
const EPOCH_GRACE: u64 = 1;

/// Domain separator for holder tag computation.
const DOMAIN_HOLDER_TAG: &[u8] = b"miasma-cred-holder-v1";

/// Domain separator for issuer signature.
const DOMAIN_ISSUE: &[u8] = b"miasma-cred-issue-v1";

/// Domain separator for context-bound presentation signature.
const DOMAIN_PRESENT: &[u8] = b"miasma-cred-present-v1";

// ─── Capability flags ───────────────────────────────────────────────────────

/// Can store shares on behalf of other peers.
pub const CAP_STORE: u8 = 0x01;
/// Can act as a relay for NAT traversal.
pub const CAP_RELAY: u8 = 0x02;
/// Can participate in DHT routing.
pub const CAP_ROUTE: u8 = 0x04;
/// Can issue credentials to other peers (trust authority).
pub const CAP_ISSUE: u8 = 0x08;

// ─── Credential tier ────────────────────────────────────────────────────────

/// Trust tier encoded in a credential. Extends the existing Claimed/Observed/
/// Verified model with an `Endorsed` tier for credential-backed trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CredentialTier {
    /// Passed Identify exchange (maps to existing Observed).
    Observed = 1,
    /// Passed PoW admission (maps to existing Verified).
    Verified = 2,
    /// Vouched by a credential-issuing authority.
    Endorsed = 3,
}

impl std::fmt::Display for CredentialTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialTier::Observed => write!(f, "Observed"),
            CredentialTier::Verified => write!(f, "Verified"),
            CredentialTier::Endorsed => write!(f, "Endorsed"),
        }
    }
}

// ─── Epoch helpers ──────────────────────────────────────────────────────────

/// Return the current epoch number.
pub fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / EPOCH_DURATION_SECS
}

/// Check whether `epoch` is within the acceptable window.
pub fn epoch_is_valid(epoch: u64, now_epoch: u64) -> bool {
    epoch >= now_epoch.saturating_sub(EPOCH_GRACE) && epoch <= now_epoch
}

// ─── Ephemeral identity ─────────────────────────────────────────────────────

/// Epoch-scoped ephemeral identity for pseudonymous credential presentation.
///
/// A new `EphemeralIdentity` should be generated each epoch. The holder_tag
/// derived from the ephemeral public key serves as the peer's pseudonym for
/// that epoch.
pub struct EphemeralIdentity {
    signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub epoch: u64,
}

impl EphemeralIdentity {
    /// Generate a fresh ephemeral identity for the given epoch.
    pub fn generate(epoch: u64) -> Self {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            epoch,
        }
    }

    /// Compute the holder tag: `BLAKE3(domain || ephemeral_pubkey)`.
    pub fn holder_tag(&self) -> [u8; 32] {
        compute_holder_tag(&self.verifying_key.to_bytes())
    }

    /// Ephemeral public key bytes.
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Sign a context-bound presentation proof.
    ///
    /// The `context` should bind the presentation to a specific interaction
    /// (e.g., a protocol message hash or verifier challenge) to prevent replay.
    pub fn sign_context(&self, credential_bytes: &[u8], context: &[u8]) -> Vec<u8> {
        let message = blake3::hash(&[DOMAIN_PRESENT, credential_bytes, context].concat());
        self.signing_key
            .sign(message.as_bytes())
            .to_bytes()
            .to_vec()
    }
}

/// Compute holder tag from raw ephemeral public key bytes.
pub fn compute_holder_tag(ephemeral_pubkey: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(&[DOMAIN_HOLDER_TAG, ephemeral_pubkey.as_slice()].concat()).as_bytes()
}

// ─── Credential body ────────────────────────────────────────────────────────

/// The claims inside a credential. This is what the issuer signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBody {
    /// Trust tier this credential attests.
    pub tier: CredentialTier,
    /// Epoch in which this credential was issued.
    pub epoch: u64,
    /// Capability bitfield (CAP_STORE, CAP_RELAY, CAP_ROUTE, CAP_ISSUE).
    pub capabilities: u8,
    /// Pseudonymous holder binding: `BLAKE3(ephemeral_pubkey)`.
    pub holder_tag: [u8; 32],
}

impl CredentialBody {
    /// Serialize for signing/verification.
    fn to_signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
}

// ─── Signed credential ──────────────────────────────────────────────────────

/// A credential signed by an issuer (trust authority).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCredential {
    pub body: CredentialBody,
    /// Ed25519 signature over `BLAKE3(DOMAIN_ISSUE || body_bytes)`.
    pub issuer_signature: Vec<u8>,
    /// Issuer's Ed25519 public key (identifies the trust authority).
    pub issuer_pubkey: [u8; 32],
}

impl SignedCredential {
    /// Serialize the credential for presentation signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
}

// ─── Credential presentation ────────────────────────────────────────────────

/// A credential presentation proves tier membership without revealing PeerId.
///
/// The holder shows the signed credential plus proof they own the ephemeral
/// key behind the `holder_tag`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPresentation {
    /// The signed credential from the issuer.
    pub credential: SignedCredential,
    /// The ephemeral public key (verifier checks `BLAKE3(this) == holder_tag`).
    pub ephemeral_pubkey: [u8; 32],
    /// Ed25519 signature from the ephemeral key over `BLAKE3(DOMAIN_PRESENT || credential_bytes || context)`.
    pub context_signature: Vec<u8>,
}

impl CredentialPresentation {
    /// Build a presentation from a signed credential and ephemeral identity.
    pub fn create(
        credential: &SignedCredential,
        identity: &EphemeralIdentity,
        context: &[u8],
    ) -> Self {
        let cred_bytes = credential.to_bytes();
        let context_signature = identity.sign_context(&cred_bytes, context);
        Self {
            credential: credential.clone(),
            ephemeral_pubkey: identity.pubkey_bytes(),
            context_signature,
        }
    }
}

// ─── Credential issuer ──────────────────────────────────────────────────────

/// Issues credentials to peers that pass admission.
///
/// In the current model, every Verified peer can issue credentials (since they
/// have proven their identity via PoW). In a future model, issuer authority
/// may be restricted to designated trust anchors.
pub struct CredentialIssuer {
    signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl CredentialIssuer {
    /// Create an issuer from an Ed25519 signing key.
    pub fn new(signing_key: ed25519_dalek::SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Public key bytes (used by verifiers to recognise this issuer).
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Issue a credential for a holder identified by their `holder_tag`.
    pub fn issue(
        &self,
        tier: CredentialTier,
        epoch: u64,
        capabilities: u8,
        holder_tag: [u8; 32],
    ) -> SignedCredential {
        let body = CredentialBody {
            tier,
            epoch,
            capabilities,
            holder_tag,
        };
        let body_bytes = body.to_signing_bytes();
        let message = blake3::hash(&[DOMAIN_ISSUE, &body_bytes].concat());
        let sig = self.signing_key.sign(message.as_bytes());

        SignedCredential {
            body,
            issuer_signature: sig.to_bytes().to_vec(),
            issuer_pubkey: self.pubkey_bytes(),
        }
    }
}

// ─── Verification ───────────────────────────────────────────────────────────

/// Why a credential presentation was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialError {
    /// Issuer public key not in the set of known trust authorities.
    UnknownIssuer,
    /// Issuer's signature over the credential body is invalid.
    InvalidIssuerSignature,
    /// Holder's context-bound presentation signature is invalid.
    InvalidHolderProof,
    /// `BLAKE3(ephemeral_pubkey) != credential.holder_tag`.
    HolderTagMismatch,
    /// Credential epoch is outside the acceptable window.
    ExpiredEpoch {
        credential_epoch: u64,
        current_epoch: u64,
    },
    /// Credential tier is below the required minimum.
    InsufficientTier {
        required: CredentialTier,
        actual: CredentialTier,
    },
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialError::UnknownIssuer => write!(f, "unknown issuer"),
            CredentialError::InvalidIssuerSignature => write!(f, "invalid issuer signature"),
            CredentialError::InvalidHolderProof => write!(f, "invalid holder proof"),
            CredentialError::HolderTagMismatch => write!(f, "holder tag mismatch"),
            CredentialError::ExpiredEpoch {
                credential_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "expired epoch: cred={credential_epoch} current={current_epoch}"
                )
            }
            CredentialError::InsufficientTier { required, actual } => {
                write!(f, "insufficient tier: need {required}, have {actual}")
            }
        }
    }
}

/// Verify a credential presentation.
///
/// Checks (in order):
/// 1. Issuer is in the `known_issuers` set.
/// 2. Issuer signature over credential body is valid.
/// 3. `BLAKE3(ephemeral_pubkey) == credential.body.holder_tag`.
/// 4. Holder's context signature is valid (proof of possession).
/// 5. Epoch is within the acceptable window.
/// 6. Tier meets the minimum requirement.
pub fn verify_presentation(
    presentation: &CredentialPresentation,
    context: &[u8],
    known_issuers: &[[u8; 32]],
    current_epoch: u64,
    min_tier: CredentialTier,
) -> Result<CredentialTier, CredentialError> {
    let cred = &presentation.credential;

    // 1. Check issuer is known.
    if !known_issuers.contains(&cred.issuer_pubkey) {
        return Err(CredentialError::UnknownIssuer);
    }

    // 2. Verify issuer signature.
    let body_bytes = cred.body.to_signing_bytes();
    let issue_message = blake3::hash(&[DOMAIN_ISSUE, &body_bytes].concat());
    let issuer_pubkey = ed25519_dalek::VerifyingKey::from_bytes(&cred.issuer_pubkey)
        .map_err(|_| CredentialError::InvalidIssuerSignature)?;
    let issuer_sig_bytes: [u8; 64] = cred
        .issuer_signature
        .as_slice()
        .try_into()
        .map_err(|_| CredentialError::InvalidIssuerSignature)?;
    let issuer_sig = ed25519_dalek::Signature::from_bytes(&issuer_sig_bytes);
    issuer_pubkey
        .verify(issue_message.as_bytes(), &issuer_sig)
        .map_err(|_| CredentialError::InvalidIssuerSignature)?;

    // 3. Check holder tag matches ephemeral pubkey.
    let expected_tag = compute_holder_tag(&presentation.ephemeral_pubkey);
    if expected_tag != cred.body.holder_tag {
        return Err(CredentialError::HolderTagMismatch);
    }

    // 4. Verify holder's context signature (proof of ephemeral key possession).
    let cred_bytes = cred.to_bytes();
    let present_message = blake3::hash(&[DOMAIN_PRESENT, &cred_bytes, context].concat());
    let holder_pubkey = ed25519_dalek::VerifyingKey::from_bytes(&presentation.ephemeral_pubkey)
        .map_err(|_| CredentialError::InvalidHolderProof)?;
    let holder_sig_bytes: [u8; 64] = presentation
        .context_signature
        .as_slice()
        .try_into()
        .map_err(|_| CredentialError::InvalidHolderProof)?;
    let holder_sig = ed25519_dalek::Signature::from_bytes(&holder_sig_bytes);
    holder_pubkey
        .verify(present_message.as_bytes(), &holder_sig)
        .map_err(|_| CredentialError::InvalidHolderProof)?;

    // 5. Check epoch freshness.
    if !epoch_is_valid(cred.body.epoch, current_epoch) {
        return Err(CredentialError::ExpiredEpoch {
            credential_epoch: cred.body.epoch,
            current_epoch,
        });
    }

    // 6. Check minimum tier.
    if cred.body.tier < min_tier {
        return Err(CredentialError::InsufficientTier {
            required: min_tier,
            actual: cred.body.tier,
        });
    }

    Ok(cred.body.tier)
}

// ─── Credential store ───────────────────────────────────────────────────────

/// Stores credentials held by this node (one per issuer per epoch).
pub struct CredentialWallet {
    /// Current ephemeral identity.
    identity: EphemeralIdentity,
    /// Credentials keyed by (issuer_pubkey, epoch).
    credentials: std::collections::HashMap<([u8; 32], u64), SignedCredential>,
}

impl CredentialWallet {
    /// Create a new wallet with a fresh ephemeral identity for the current epoch.
    pub fn new() -> Self {
        let epoch = current_epoch();
        Self {
            identity: EphemeralIdentity::generate(epoch),
            credentials: std::collections::HashMap::new(),
        }
    }

    /// Rotate the ephemeral identity if the epoch has changed.
    /// Returns `true` if rotation occurred (old credentials are now invalid).
    pub fn maybe_rotate(&mut self) -> bool {
        let now = current_epoch();
        if now != self.identity.epoch {
            self.identity = EphemeralIdentity::generate(now);
            // Prune expired credentials.
            self.credentials
                .retain(|&(_, epoch), _| epoch_is_valid(epoch, now));
            true
        } else {
            false
        }
    }

    /// Current holder tag (pseudonym for this epoch).
    pub fn holder_tag(&self) -> [u8; 32] {
        self.identity.holder_tag()
    }

    /// Current ephemeral public key.
    pub fn ephemeral_pubkey(&self) -> [u8; 32] {
        self.identity.pubkey_bytes()
    }

    /// Current epoch.
    pub fn epoch(&self) -> u64 {
        self.identity.epoch
    }

    /// Access the wallet's current ephemeral identity (for presentations).
    pub fn identity(&self) -> &EphemeralIdentity {
        &self.identity
    }

    /// Store a credential received from an issuer.
    pub fn store(&mut self, credential: SignedCredential) {
        let key = (credential.issuer_pubkey, credential.body.epoch);
        self.credentials.insert(key, credential);
    }

    /// Get the best (highest-tier) valid credential from any known issuer.
    pub fn best_credential(&self) -> Option<&SignedCredential> {
        let now = current_epoch();
        self.credentials
            .values()
            .filter(|c| epoch_is_valid(c.body.epoch, now))
            .max_by_key(|c| c.body.tier)
    }

    /// Create a presentation of the best available credential.
    pub fn present(&self, context: &[u8]) -> Option<CredentialPresentation> {
        let cred = self.best_credential()?;
        Some(CredentialPresentation::create(
            cred,
            &self.identity,
            context,
        ))
    }

    /// Number of stored credentials.
    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }
}

// ─── Known-issuer registry ──────────────────────────────────────────────────

/// Registry of known credential issuers (trust authorities).
///
/// In the bootstrap phase, every Verified peer is implicitly an issuer.
/// As the network matures, this can be narrowed to designated authorities.
pub struct IssuerRegistry {
    /// Set of known issuer public keys.
    issuers: std::collections::HashSet<[u8; 32]>,
    /// Whether to auto-add verified peers as issuers (bootstrap mode).
    pub bootstrap_mode: bool,
}

impl IssuerRegistry {
    pub fn new(bootstrap_mode: bool) -> Self {
        Self {
            issuers: std::collections::HashSet::new(),
            bootstrap_mode,
        }
    }

    /// Add an issuer's public key.
    pub fn add_issuer(&mut self, pubkey: [u8; 32]) {
        self.issuers.insert(pubkey);
    }

    /// Remove an issuer.
    pub fn remove_issuer(&mut self, pubkey: &[u8; 32]) {
        self.issuers.remove(pubkey);
    }

    /// Check if a pubkey is a known issuer.
    pub fn is_known(&self, pubkey: &[u8; 32]) -> bool {
        self.issuers.contains(pubkey)
    }

    /// All known issuers as a slice-compatible vec.
    pub fn issuer_list(&self) -> Vec<[u8; 32]> {
        self.issuers.iter().copied().collect()
    }

    /// Number of known issuers.
    pub fn issuer_count(&self) -> usize {
        self.issuers.len()
    }
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

/// Snapshot of credential subsystem state for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStats {
    /// Current epoch number.
    pub current_epoch: u64,
    /// Number of credentials in the wallet.
    pub held_credentials: usize,
    /// Best held credential tier (None if no credentials).
    pub best_tier: Option<String>,
    /// Number of known issuers.
    pub known_issuers: usize,
    /// Whether bootstrap mode is active (all verified peers = issuers).
    pub bootstrap_mode: bool,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_issuer() -> CredentialIssuer {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        CredentialIssuer::new(key)
    }

    #[test]
    fn issue_and_verify_credential() {
        let issuer = test_issuer();
        let identity = EphemeralIdentity::generate(current_epoch());
        let holder_tag = identity.holder_tag();

        let credential = issuer.issue(
            CredentialTier::Verified,
            identity.epoch,
            CAP_STORE | CAP_ROUTE,
            holder_tag,
        );

        let context = b"test-context-123";
        let presentation = CredentialPresentation::create(&credential, &identity, context);

        let result = verify_presentation(
            &presentation,
            context,
            &[issuer.pubkey_bytes()],
            current_epoch(),
            CredentialTier::Verified,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CredentialTier::Verified);
    }

    #[test]
    fn reject_unknown_issuer() {
        let issuer = test_issuer();
        let identity = EphemeralIdentity::generate(current_epoch());

        let credential = issuer.issue(
            CredentialTier::Verified,
            identity.epoch,
            CAP_ROUTE,
            identity.holder_tag(),
        );

        let presentation = CredentialPresentation::create(&credential, &identity, b"ctx");
        let unknown_issuer = [0xFFu8; 32]; // not the real issuer
        let result = verify_presentation(
            &presentation,
            b"ctx",
            &[unknown_issuer],
            current_epoch(),
            CredentialTier::Verified,
        );
        assert_eq!(result.unwrap_err(), CredentialError::UnknownIssuer);
    }

    #[test]
    fn reject_tampered_issuer_signature() {
        let issuer = test_issuer();
        let identity = EphemeralIdentity::generate(current_epoch());

        let mut credential = issuer.issue(
            CredentialTier::Verified,
            identity.epoch,
            CAP_ROUTE,
            identity.holder_tag(),
        );
        // Tamper with the signature.
        credential.issuer_signature[0] ^= 0xFF;

        let presentation = CredentialPresentation::create(&credential, &identity, b"ctx");
        let result = verify_presentation(
            &presentation,
            b"ctx",
            &[issuer.pubkey_bytes()],
            current_epoch(),
            CredentialTier::Verified,
        );
        assert_eq!(result.unwrap_err(), CredentialError::InvalidIssuerSignature);
    }

    #[test]
    fn reject_holder_tag_mismatch() {
        let issuer = test_issuer();
        let identity = EphemeralIdentity::generate(current_epoch());
        let other_identity = EphemeralIdentity::generate(current_epoch());

        // Issue credential with identity's tag, but present with other_identity's key.
        let credential = issuer.issue(
            CredentialTier::Verified,
            identity.epoch,
            CAP_ROUTE,
            identity.holder_tag(),
        );

        // Create presentation using wrong ephemeral key.
        let cred_bytes = credential.to_bytes();
        let context_sig = other_identity.sign_context(&cred_bytes, b"ctx");
        let presentation = CredentialPresentation {
            credential: credential.clone(),
            ephemeral_pubkey: other_identity.pubkey_bytes(),
            context_signature: context_sig,
        };

        let result = verify_presentation(
            &presentation,
            b"ctx",
            &[issuer.pubkey_bytes()],
            current_epoch(),
            CredentialTier::Verified,
        );
        assert_eq!(result.unwrap_err(), CredentialError::HolderTagMismatch);
    }

    #[test]
    fn reject_wrong_context() {
        let issuer = test_issuer();
        let identity = EphemeralIdentity::generate(current_epoch());

        let credential = issuer.issue(
            CredentialTier::Verified,
            identity.epoch,
            CAP_ROUTE,
            identity.holder_tag(),
        );

        let presentation = CredentialPresentation::create(&credential, &identity, b"context-A");
        // Verify with a different context → holder proof should fail.
        let result = verify_presentation(
            &presentation,
            b"context-B",
            &[issuer.pubkey_bytes()],
            current_epoch(),
            CredentialTier::Verified,
        );
        assert_eq!(result.unwrap_err(), CredentialError::InvalidHolderProof);
    }

    #[test]
    fn reject_expired_epoch() {
        let issuer = test_issuer();
        let old_epoch = current_epoch().saturating_sub(10); // way in the past
        let identity = EphemeralIdentity::generate(old_epoch);

        let credential = issuer.issue(
            CredentialTier::Verified,
            old_epoch,
            CAP_ROUTE,
            identity.holder_tag(),
        );

        let presentation = CredentialPresentation::create(&credential, &identity, b"ctx");
        let result = verify_presentation(
            &presentation,
            b"ctx",
            &[issuer.pubkey_bytes()],
            current_epoch(),
            CredentialTier::Verified,
        );
        assert!(matches!(
            result.unwrap_err(),
            CredentialError::ExpiredEpoch { .. }
        ));
    }

    #[test]
    fn reject_insufficient_tier() {
        let issuer = test_issuer();
        let identity = EphemeralIdentity::generate(current_epoch());

        let credential = issuer.issue(
            CredentialTier::Observed, // lower tier
            identity.epoch,
            CAP_ROUTE,
            identity.holder_tag(),
        );

        let presentation = CredentialPresentation::create(&credential, &identity, b"ctx");
        let result = verify_presentation(
            &presentation,
            b"ctx",
            &[issuer.pubkey_bytes()],
            current_epoch(),
            CredentialTier::Verified, // requires higher
        );
        assert!(matches!(
            result.unwrap_err(),
            CredentialError::InsufficientTier { .. }
        ));
    }

    #[test]
    fn endorsed_tier_exceeds_verified() {
        let issuer = test_issuer();
        let identity = EphemeralIdentity::generate(current_epoch());

        let credential = issuer.issue(
            CredentialTier::Endorsed,
            identity.epoch,
            CAP_ROUTE | CAP_STORE | CAP_RELAY,
            identity.holder_tag(),
        );

        let presentation = CredentialPresentation::create(&credential, &identity, b"ctx");
        let result = verify_presentation(
            &presentation,
            b"ctx",
            &[issuer.pubkey_bytes()],
            current_epoch(),
            CredentialTier::Verified,
        );
        assert_eq!(result.unwrap(), CredentialTier::Endorsed);
    }

    #[test]
    fn credential_wallet_lifecycle() {
        let issuer = test_issuer();
        let mut wallet = CredentialWallet::new();

        assert!(wallet.best_credential().is_none());

        let credential = issuer.issue(
            CredentialTier::Verified,
            wallet.epoch(),
            CAP_ROUTE,
            wallet.holder_tag(),
        );
        wallet.store(credential);

        assert_eq!(wallet.credential_count(), 1);
        let cred = wallet.best_credential().unwrap();
        assert_eq!(cred.body.tier, CredentialTier::Verified);

        // Can create a presentation.
        let presentation = wallet.present(b"ctx").unwrap();
        let result = verify_presentation(
            &presentation,
            b"ctx",
            &[issuer.pubkey_bytes()],
            current_epoch(),
            CredentialTier::Verified,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn issuer_registry_operations() {
        let mut reg = IssuerRegistry::new(true);
        let pk = [0x42u8; 32];

        assert!(!reg.is_known(&pk));
        reg.add_issuer(pk);
        assert!(reg.is_known(&pk));
        assert_eq!(reg.issuer_count(), 1);

        reg.remove_issuer(&pk);
        assert!(!reg.is_known(&pk));
    }

    #[test]
    fn holder_tag_deterministic() {
        let identity = EphemeralIdentity::generate(current_epoch());
        let tag1 = identity.holder_tag();
        let tag2 = compute_holder_tag(&identity.pubkey_bytes());
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn credential_serde_roundtrip() {
        let issuer = test_issuer();
        let identity = EphemeralIdentity::generate(current_epoch());

        let credential = issuer.issue(
            CredentialTier::Verified,
            identity.epoch,
            CAP_ROUTE | CAP_STORE,
            identity.holder_tag(),
        );

        let bytes = bincode::serialize(&credential).unwrap();
        let deserialized: SignedCredential = bincode::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.body, credential.body);
        assert_eq!(deserialized.issuer_signature, credential.issuer_signature);
    }

    #[test]
    fn epoch_validity_window() {
        let now = 100;
        assert!(epoch_is_valid(100, now)); // current
        assert!(epoch_is_valid(99, now)); // grace period
        assert!(!epoch_is_valid(98, now)); // too old
        assert!(!epoch_is_valid(101, now)); // future
    }

    #[test]
    fn capability_flags() {
        let caps = CAP_STORE | CAP_RELAY | CAP_ROUTE;
        assert!(caps & CAP_STORE != 0);
        assert!(caps & CAP_RELAY != 0);
        assert!(caps & CAP_ROUTE != 0);
        assert!(caps & CAP_ISSUE == 0);
    }
}
