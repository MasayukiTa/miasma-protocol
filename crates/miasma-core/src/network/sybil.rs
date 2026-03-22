/// S/Kademlia Sybil resistance — Phase 3 (ADR-004).
///
/// # Problem
/// Standard Kademlia allows an attacker to generate arbitrary node IDs cheaply,
/// enabling Sybil attacks: flooding a DHT key range with attacker-controlled
/// nodes to eclipse honest ones.
///
/// # S/Kademlia mitigations
///
/// 1. **NodeID generation cost**: a node's peer ID must satisfy a proof-of-work
///    (PoW) puzzle: `BLAKE3(pubkey || nonce)` must have `difficulty_bits` leading
///    zero bits. This makes generating many valid IDs expensive.
///
/// 2. **Signed DHT entries**: every DHT record carries a real Ed25519 signature
///    over `BLAKE3(domain_sep || key || value || signer_pubkey)`. Records with
///    invalid signatures are rejected. Domain separation prevents cross-protocol
///    signature reuse.
///
/// # Phase 3 parameters
/// - PoW difficulty: 8 leading zero bits (~256 hashes) — low for bootstrap,
///   increases as network grows.
/// - Signature scheme: Ed25519 via `ed25519-dalek`, same key material as
///   libp2p identity (derived via HKDF from master key).
use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// ─── Domain separation ──────────────────────────────────────────────────────

/// Domain separator for DHT record signatures.
/// Prevents a signature over a DHT record from being valid in any other context.
const DHT_RECORD_SIG_DOMAIN: &[u8] = b"miasma-v1-dht-record-sig";

// ─── PoW ─────────────────────────────────────────────────────────────────────

/// Proof-of-Work certificate for node ID registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdPoW {
    /// The Ed25519 public key bytes.
    pub pubkey: [u8; 32],
    /// Nonce found during mining.
    pub nonce: u64,
    /// BLAKE3 hash of (pubkey || nonce). Must have `difficulty` leading zero bits.
    pub hash: [u8; 32],
}

/// Default PoW difficulty for Phase 3 bootstrap (low — ~256 hashes).
/// Will increase as network grows.
pub const DEFAULT_POW_DIFFICULTY: u8 = 8;

/// Verify that a `NodeIdPoW` satisfies the required difficulty.
pub fn verify_pow(pow: &NodeIdPoW, difficulty_bits: u8) -> bool {
    // Re-compute hash — never trust the claimed hash.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&pow.pubkey);
    hasher.update(&pow.nonce.to_le_bytes());
    let computed = *hasher.finalize().as_bytes();

    if computed != pow.hash {
        return false;
    }

    leading_zeros(&computed) >= difficulty_bits as u32
}

/// Mine a `NodeIdPoW` for the given `pubkey` and `difficulty_bits`.
///
/// Returns when a valid nonce is found. Time complexity is O(2^difficulty_bits).
pub fn mine_pow(pubkey: [u8; 32], difficulty_bits: u8) -> NodeIdPoW {
    let mut nonce: u64 = 0;
    loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pubkey);
        hasher.update(&nonce.to_le_bytes());
        let hash = *hasher.finalize().as_bytes();

        if leading_zeros(&hash) >= difficulty_bits as u32 {
            return NodeIdPoW {
                pubkey,
                nonce,
                hash,
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Count leading zero bits in a byte array.
pub fn leading_zeros(bytes: &[u8; 32]) -> u32 {
    let full_zero_bytes = bytes.iter().take_while(|&&b| b == 0).count() as u32;
    let partial = bytes
        .iter()
        .find(|&&b| b != 0)
        .map(|b| b.leading_zeros())
        .unwrap_or(0);
    full_zero_bytes * 8 + partial
}

// ─── Signed DHT record ──────────────────────────────────────────────────────

/// A DHT record with a real Ed25519 signature over its content.
///
/// The signature covers `BLAKE3(domain_sep || key || value || signer_pubkey)`,
/// where `domain_sep` is `DHT_RECORD_SIG_DOMAIN`. This prevents cross-protocol
/// signature reuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDhtRecord {
    /// The key under which this record is stored.
    pub key: Vec<u8>,
    /// The record value.
    pub value: Vec<u8>,
    /// Ed25519 public key of the signing node (32 bytes).
    pub signer_pubkey: [u8; 32],
    /// Ed25519 signature over the signing message (64 bytes).
    /// Stored as Vec<u8> for serde compatibility (arrays >32 need custom impl).
    pub signature: Vec<u8>,
}

impl SignedDhtRecord {
    /// Compute the message bytes that must be signed.
    ///
    /// `BLAKE3(domain_sep || key || value || signer_pubkey)`
    ///
    /// Domain separation ensures this signature cannot be replayed in
    /// any other protocol context.
    pub fn signing_message(key: &[u8], value: &[u8], signer_pubkey: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DHT_RECORD_SIG_DOMAIN);
        hasher.update(key);
        hasher.update(value);
        hasher.update(signer_pubkey);
        *hasher.finalize().as_bytes()
    }

    /// Create a signed DHT record using the given signing key.
    pub fn sign(key: Vec<u8>, value: Vec<u8>, signing_key: &SigningKey) -> Self {
        let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        let msg = Self::signing_message(&key, &value, &pubkey_bytes);
        let sig: Signature = signing_key.sign(&msg);

        Self {
            key,
            value,
            signer_pubkey: pubkey_bytes,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Verify the Ed25519 signature over this record.
    ///
    /// Returns `true` if and only if the signature is cryptographically valid
    /// for the given key, value, and signer public key.
    pub fn verify_signature(&self) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.signer_pubkey) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);

        let msg = Self::signing_message(&self.key, &self.value, &self.signer_pubkey);
        verifying_key.verify(&msg, &sig).is_ok()
    }
}

// ─── Peer admission ─────────────────────────────────────────────────────────

/// Result of checking whether a peer should be admitted to the routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionResult {
    /// Peer passed all checks and may participate in routing.
    Admitted,
    /// PoW proof is missing or invalid.
    RejectedNoPoW,
    /// PoW difficulty is insufficient for the current network parameters.
    RejectedLowDifficulty,
}

/// Check whether a peer's PoW proof meets the admission requirements.
///
/// This is the gating function for Phase 3 routing admission. A peer must
/// present a valid PoW proof to be added to Kademlia.
///
/// If `pow` is `None`, the peer is rejected (PoW is mandatory).
pub fn check_peer_admission(pow: Option<&NodeIdPoW>, difficulty: u8) -> AdmissionResult {
    match pow {
        None => AdmissionResult::RejectedNoPoW,
        Some(pow) => {
            if verify_pow(pow, difficulty) {
                AdmissionResult::Admitted
            } else {
                AdmissionResult::RejectedLowDifficulty
            }
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_mine_and_verify_easy() {
        let pubkey = [0xABu8; 32];
        let pow = mine_pow(pubkey, 8); // 8 leading zero bits — fast
        assert!(verify_pow(&pow, 8));
        assert!(!verify_pow(&pow, 16)); // probably doesn't have 16
    }

    #[test]
    fn pow_invalid_hash_rejected() {
        let pubkey = [0x01u8; 32];
        let pow = mine_pow(pubkey, 4);
        let tampered = NodeIdPoW {
            hash: [0xFF; 32],
            ..pow
        };
        assert!(!verify_pow(&tampered, 4));
    }

    #[test]
    fn signed_record_real_signature() {
        // Generate a real Ed25519 signing key.
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);

        // Sign a record.
        let record =
            SignedDhtRecord::sign(b"test-key".to_vec(), b"test-value".to_vec(), &signing_key);

        // Verification must succeed.
        assert!(record.verify_signature(), "valid signature must verify");
    }

    #[test]
    fn signed_record_tampered_value_rejected() {
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let mut record = SignedDhtRecord::sign(
            b"test-key".to_vec(),
            b"original-value".to_vec(),
            &signing_key,
        );

        // Tamper with the value after signing.
        record.value = b"tampered-value".to_vec();

        // Verification must fail.
        assert!(
            !record.verify_signature(),
            "tampered record must fail verification"
        );
    }

    #[test]
    fn signed_record_wrong_key_rejected() {
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let mut record = SignedDhtRecord::sign(b"key".to_vec(), b"value".to_vec(), &signing_key);

        // Replace signer_pubkey with a different key.
        let other_key = SigningKey::from_bytes(&[0x99u8; 32]);
        record.signer_pubkey = other_key.verifying_key().to_bytes();

        // Verification must fail — signature doesn't match the claimed signer.
        assert!(
            !record.verify_signature(),
            "wrong signer key must fail verification"
        );
    }

    #[test]
    fn signed_record_zero_signature_rejected() {
        // The old stub accepted any non-zero signature. Now zero AND non-zero
        // fake signatures must both be rejected.
        let record = SignedDhtRecord {
            key: b"key".to_vec(),
            value: b"val".to_vec(),
            signer_pubkey: [0x01; 32],
            signature: vec![0x00; 64], // all zeros
        };
        assert!(
            !record.verify_signature(),
            "zero signature must be rejected"
        );
    }

    #[test]
    fn signed_record_random_nonzero_signature_rejected() {
        let record = SignedDhtRecord {
            key: b"key".to_vec(),
            value: b"val".to_vec(),
            signer_pubkey: [0x01; 32],
            signature: vec![0x02; 64], // non-zero but not a real signature
        };
        assert!(
            !record.verify_signature(),
            "fake non-zero signature must be rejected"
        );
    }

    #[test]
    fn domain_separation_prevents_cross_context_replay() {
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let record = SignedDhtRecord::sign(b"key".to_vec(), b"value".to_vec(), &signing_key);

        // Manually compute what the signature would be WITHOUT domain separation.
        let mut hasher = blake3::Hasher::new();
        // Intentionally skip domain separator:
        hasher.update(b"key");
        hasher.update(b"value");
        hasher.update(&record.signer_pubkey);
        let msg_without_domain = *hasher.finalize().as_bytes();

        // The actual signing message includes the domain separator.
        let msg_with_domain =
            SignedDhtRecord::signing_message(b"key", b"value", &record.signer_pubkey);

        // They must differ — domain separation works.
        assert_ne!(msg_without_domain, msg_with_domain);
    }

    #[test]
    fn peer_admission_requires_pow() {
        assert_eq!(
            check_peer_admission(None, 8),
            AdmissionResult::RejectedNoPoW
        );
    }

    #[test]
    fn peer_admission_accepts_valid_pow() {
        let pubkey = [0xAB; 32];
        let pow = mine_pow(pubkey, 8);
        assert_eq!(
            check_peer_admission(Some(&pow), 8),
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn peer_admission_rejects_low_difficulty() {
        let pubkey = [0xAB; 32];
        let pow = mine_pow(pubkey, 4);
        // Require 8 bits but proof only has 4.
        assert_eq!(
            check_peer_admission(Some(&pow), 8),
            AdmissionResult::RejectedLowDifficulty
        );
    }
}
