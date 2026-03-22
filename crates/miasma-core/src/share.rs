use serde::{Deserialize, Serialize};

use crate::{
    crypto::hash::{ContentId, MID_PREFIX_LEN},
    MiasmaError,
};

/// A single Miasma share — the atomic unit distributed across network nodes.
///
/// One `MiasmaShare` contains:
/// - One Reed-Solomon shard (encrypted ciphertext fragment)
/// - One Shamir secret share fragment of K_enc
/// - Metadata for routing and coarse integrity verification (ADR-003 ①)
///
/// # Coarse verification (ADR-003)
/// Before k shares are collected and K_enc can be reconstructed, integrity is
/// verified by:
///   1. `mid_prefix` — confirms this share belongs to the requested content
///   2. `shard_hash`  — BLAKE3(shard_data), confirms data was not tampered with
///
/// Full MAC verification (K_tag derived from K_enc) is only possible after k
/// shares are collected. This is an intentional design constraint, not a bug.
/// See docs/adr/003-share-integrity.md for full rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiasmaShare {
    /// Protocol version (currently 1).
    pub version: u8,

    /// First 8 bytes of the MID digest — used for coarse integrity check.
    /// Allows rejecting shares belonging to wrong content before k is reached.
    pub mid_prefix: [u8; MID_PREFIX_LEN],

    /// Segment index within the full-file dissolution (0 for single-segment files).
    pub segment_index: u32,

    /// Index of this shard within the Reed-Solomon encoding (0-based, 0..n-1).
    pub slot_index: u16,

    /// Reed-Solomon encoded + AES-256-GCM encrypted shard data.
    pub shard_data: Vec<u8>,

    /// Shamir secret share fragment of K_enc (the AES-256-GCM content key).
    pub key_share: Vec<u8>,

    /// BLAKE3(shard_data) — coarse integrity commitment (ADR-003 ①).
    /// Allows detecting tampered shard_data before k shares are available.
    pub shard_hash: [u8; 32],

    /// AES-256-GCM nonce used to encrypt the original data.
    /// Stored in every share (same value, not secret).
    pub nonce: [u8; 12],

    /// Original plaintext length (bytes), needed for RS decoding padding removal.
    pub original_len: u32,

    /// Unix timestamp (seconds) when this share was created.
    pub timestamp: u64,
}

impl MiasmaShare {
    /// Create a new `MiasmaShare`, computing `shard_hash` automatically.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mid: &ContentId,
        segment_index: u32,
        slot_index: u16,
        shard_data: Vec<u8>,
        key_share: Vec<u8>,
        nonce: [u8; 12],
        original_len: u32,
        timestamp: u64,
    ) -> Self {
        let shard_hash = *blake3::hash(&shard_data).as_bytes();
        Self {
            version: 1,
            mid_prefix: mid.prefix(),
            segment_index,
            slot_index,
            shard_data,
            key_share,
            shard_hash,
            nonce,
            original_len,
            timestamp,
        }
    }

    /// Serialize to bytes (bincode).
    pub fn to_bytes(&self) -> Result<Vec<u8>, MiasmaError> {
        bincode::serialize(self).map_err(|e| MiasmaError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes (bincode).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MiasmaError> {
        bincode::deserialize(bytes).map_err(|e| MiasmaError::Serialization(e.to_string()))
    }
}

/// Coarse and full share verification logic (ADR-003).
pub struct ShareVerification;

impl ShareVerification {
    /// Coarse verification — runs BEFORE k shares are collected.
    ///
    /// Checks:
    /// 1. `mid_prefix` matches the expected content's MID prefix
    /// 2. `shard_hash` == BLAKE3(`shard_data`) — detects tampered shard data
    ///
    /// Does NOT verify MAC (impossible without K_enc, which requires k shares).
    ///
    /// Returns `true` if the share passes coarse checks, `false` otherwise.
    pub fn coarse_verify(share: &MiasmaShare, expected_mid: &ContentId) -> bool {
        // 1. MID prefix check.
        if share.mid_prefix != expected_mid.prefix() {
            return false;
        }
        // 2. Shard hash check.
        let computed = *blake3::hash(&share.shard_data).as_bytes();
        computed == share.shard_hash
    }

    /// Full verification — runs AFTER k shares are collected and K_enc is recovered.
    ///
    /// Recomputes BLAKE3 of the reconstructed plaintext and compares with MID.
    pub fn full_verify(
        plaintext: &[u8],
        params: &[u8],
        expected_mid: &ContentId,
    ) -> Result<(), MiasmaError> {
        let computed = ContentId::compute(plaintext, params);
        if computed != *expected_mid {
            return Err(MiasmaError::HashMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn dummy_share(mid: &ContentId, slot: u16, data: Vec<u8>) -> MiasmaShare {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        MiasmaShare::new(mid, 0, slot, data, vec![0xAA; 32], [0u8; 12], 100, ts)
    }

    #[test]
    fn coarse_verify_valid_share() {
        let mid = ContentId::compute(b"test content", b"k=10,n=20,v=1");
        let share = dummy_share(&mid, 0, vec![1, 2, 3, 4, 5]);
        assert!(ShareVerification::coarse_verify(&share, &mid));
    }

    #[test]
    fn coarse_verify_wrong_mid_prefix() {
        let mid = ContentId::compute(b"content A", b"k=10,n=20,v=1");
        let other_mid = ContentId::compute(b"content B", b"k=10,n=20,v=1");
        let share = dummy_share(&mid, 0, vec![1, 2, 3]);
        // Share belongs to 'content A', but we check against 'content B'.
        assert!(!ShareVerification::coarse_verify(&share, &other_mid));
    }

    #[test]
    fn coarse_verify_tampered_shard_data() {
        let mid = ContentId::compute(b"test content", b"k=10,n=20,v=1");
        let mut share = dummy_share(&mid, 0, vec![1, 2, 3, 4, 5]);
        // Tamper with shard_data AFTER creation (shard_hash no longer matches).
        share.shard_data[0] ^= 0xFF;
        assert!(!ShareVerification::coarse_verify(&share, &mid));
    }

    #[test]
    fn full_verify_correct_content() {
        let content = b"miasma full verify test content";
        let params = b"k=10,n=20,v=1";
        let mid = ContentId::compute(content, params);
        assert!(ShareVerification::full_verify(content, params, &mid).is_ok());
    }

    #[test]
    fn full_verify_wrong_content_fails() {
        let content = b"correct content";
        let wrong = b"tampered content";
        let params = b"k=10,n=20,v=1";
        let mid = ContentId::compute(content, params);
        assert!(matches!(
            ShareVerification::full_verify(wrong, params, &mid),
            Err(MiasmaError::HashMismatch)
        ));
    }

    #[test]
    fn serialization_roundtrip() {
        let mid = ContentId::compute(b"serialize me", b"k=10,n=20,v=1");
        let share = dummy_share(&mid, 7, vec![0xBB; 64]);
        let bytes = share.to_bytes().unwrap();
        let recovered = MiasmaShare::from_bytes(&bytes).unwrap();
        assert_eq!(share.slot_index, recovered.slot_index);
        assert_eq!(share.shard_hash, recovered.shard_hash);
        assert_eq!(share.mid_prefix, recovered.mid_prefix);
    }

    /// ADR-003 test vector: forged share must be rejected.
    #[test]
    fn forged_share_rejected() {
        let mid = ContentId::compute(b"real content", b"k=10,n=20,v=1");
        let real_share = dummy_share(&mid, 0, vec![0xAA; 32]);

        // Forge: correct mid_prefix but wrong shard_data (hash will not match).
        let mut forged = real_share.clone();
        forged.shard_data = vec![0xFF; 32]; // tampered data
                                            // shard_hash still points to original — hash mismatch
        assert!(!ShareVerification::coarse_verify(&forged, &mid));
    }
}
