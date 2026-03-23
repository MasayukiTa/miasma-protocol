/// Dissolution and Retrieval pipeline — Phase 1 MVP.
///
/// Dissolution:  plaintext → encrypt → RS encode → SSS split → [MiasmaShare × n]
/// Retrieval:    [MiasmaShare × ≥k] → coarse verify → RS decode → SSS combine
///               → decrypt → full verify → plaintext
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    crypto::{
        aead::{decrypt, encrypt, KEY_LEN, NONCE_LEN},
        hash::ContentId,
        rs::{rs_decode, rs_encode},
        sss::{sss_combine, sss_split},
    },
    share::{MiasmaShare, ShareVerification},
    MiasmaError,
};

/// Protocol version embedded in every share.
const PROTOCOL_VERSION: u8 = 1;

/// Dissolution parameters — determine shard counts and MID computation.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct DissolutionParams {
    /// Number of data shards (k). Must collect ≥k shares to reconstruct.
    pub data_shards: usize,
    /// Total shards (n). Must be > data_shards.
    pub total_shards: usize,
}

impl Default for DissolutionParams {
    fn default() -> Self {
        Self {
            data_shards: 10,
            total_shards: 20,
        }
    }
}

impl DissolutionParams {
    /// Canonical byte encoding used for MID computation.
    /// Format: `k={k},n={n},v={PROTOCOL_VERSION}`
    pub fn to_param_bytes(&self) -> Vec<u8> {
        format!(
            "k={},n={},v={}",
            self.data_shards, self.total_shards, PROTOCOL_VERSION
        )
        .into_bytes()
    }

    pub fn recovery_shards(&self) -> usize {
        self.total_shards - self.data_shards
    }
}

/// Dissolve `plaintext` into `n` shares distributed across the network.
///
/// # IMPORTANT — Phase 1 scope
/// Dissolution supports 1KB–100GB (streaming I/O for large files).
/// This implementation handles in-memory content. Streaming dissolution
/// (for >1GB content) is a Phase 2 task (Section 16 of PRD).
///
/// Returns `(ContentId, Vec<MiasmaShare>)`.
/// After dissolution, the caller SHOULD NOT retain `plaintext` — all
/// identifying content should be dropped.
pub fn dissolve(
    plaintext: &[u8],
    params: DissolutionParams,
) -> Result<(ContentId, Vec<MiasmaShare>), MiasmaError> {
    // 1. Compute MID from plaintext before encryption.
    let param_bytes = params.to_param_bytes();
    let mid = ContentId::compute(plaintext, &param_bytes);

    // 2. Encrypt plaintext → (ciphertext, K_enc, nonce).
    let (ciphertext, k_enc, nonce) = encrypt(plaintext)?;

    // 3. Reed-Solomon encode ciphertext → n shards.
    let shards = rs_encode(&ciphertext, params.data_shards, params.total_shards)?;
    debug_assert_eq!(shards.len(), params.total_shards);

    // 4. SSS split K_enc → n key shares (any data_shards suffice to recover).
    let key_shares = sss_split(
        k_enc.as_ref(),
        params.data_shards as u8,
        params.total_shards as u8,
    )?;
    debug_assert_eq!(key_shares.len(), params.total_shards);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 5. Assemble MiasmaShare for each shard.
    let shares: Vec<MiasmaShare> = shards
        .into_iter()
        .zip(key_shares)
        .enumerate()
        .map(|(i, (shard_data, key_share))| {
            MiasmaShare::new(
                &mid,
                0, // segment_index: non-segmented dissolution is always segment 0
                i as u16,
                shard_data,
                key_share,
                nonce,
                plaintext.len() as u32,
                timestamp,
            )
        })
        .collect();

    Ok((mid, shares))
}

/// Reconstruct content from ≥k shares.
///
/// # Phase 1 scope
/// Full retrieval (including SSS + RS + decrypt) is memory-bound.
/// This function is suitable for content up to ~1GB in working memory.
/// 100GB file restoration is a Phase 2 task (streaming retrieval, Section 16).
///
/// # Steps
/// 1. Coarse-verify each share (shard_hash + mid_prefix) — rejects forgeries
///    before K_enc is available (ADR-003 ①).
/// 2. RS decode the ciphertext shards.
/// 3. SSS combine the key shares → K_enc.
/// 4. AES-256-GCM decrypt.
/// 5. BLAKE3 full-verify plaintext vs MID.
///
/// Returns the reconstructed plaintext.
///
/// # SECURITY NOTE (ADR-003)
/// K_tag cannot be verified before k shares are collected (K_tag is derived
/// from K_enc which requires k shares). Coarse verification (step 1) is the
/// only pre-k forgery defense. This is intentional.
pub fn retrieve(
    mid: &ContentId,
    shares: &[MiasmaShare],
    params: DissolutionParams,
) -> Result<Vec<u8>, MiasmaError> {
    if shares.len() < params.data_shards {
        return Err(MiasmaError::InsufficientShares {
            need: params.data_shards,
            got: shares.len(),
        });
    }

    // 1. Coarse-verify all provided shares; reject forgeries early.
    let valid: Vec<&MiasmaShare> = shares
        .iter()
        .filter(|s| ShareVerification::coarse_verify(s, mid))
        .collect();

    if valid.len() < params.data_shards {
        return Err(MiasmaError::InsufficientShares {
            need: params.data_shards,
            got: valid.len(),
        });
    }

    // Take first data_shards valid shares (random order is fine; network layer
    // should provide shares in randomised order to prevent timing correlation).
    let selected = &valid[..params.data_shards];

    // Read metadata from first share (same across all shares of one dissolution).
    let nonce: [u8; NONCE_LEN] = selected[0].nonce;
    // original_len stores the PLAINTEXT length. The RS encoding was applied to
    // the ciphertext, which is plaintext + 16 bytes (AES-GCM authentication tag).
    let plaintext_len = selected[0].original_len as usize;
    let ciphertext_len = plaintext_len + 16;

    // 2. RS decode the encrypted shards → ciphertext.
    let rs_shards: Vec<(usize, Vec<u8>)> = selected
        .iter()
        .map(|s| (s.slot_index as usize, s.shard_data.clone()))
        .collect();

    let ciphertext = rs_decode(
        &rs_shards,
        params.data_shards,
        params.total_shards,
        ciphertext_len,
    )?;

    // 3. SSS combine key shares → K_enc.
    let key_shares: Vec<Vec<u8>> = selected.iter().map(|s| s.key_share.clone()).collect();
    let k_enc = sss_combine(&key_shares, params.data_shards as u8)?;

    let key: [u8; KEY_LEN] = k_enc
        .as_slice()
        .try_into()
        .map_err(|_| MiasmaError::Sss("recovered K_enc has wrong length".into()))?;

    // 4. AES-256-GCM decrypt.
    let plaintext = decrypt(&ciphertext, &key, &nonce)?;

    // 5. Full integrity verification: BLAKE3(plaintext || params) == MID.
    let param_bytes = params.to_param_bytes();
    ShareVerification::full_verify(&plaintext, &param_bytes, mid)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONTENT: &[u8] = b"Miasma dissolution pipeline test content. \
        This is a realistic-length payload that exercises all pipeline stages. \
        The content must survive encrypt-encode-split-combine-decode-decrypt.";

    #[test]
    fn dissolve_and_retrieve_default_params() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(TEST_CONTENT, params).unwrap();
        assert_eq!(shares.len(), params.total_shards);

        let recovered = retrieve(&mid, &shares, params).unwrap();
        assert_eq!(recovered, TEST_CONTENT);
    }

    #[test]
    fn retrieve_with_minimum_k_shares() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(TEST_CONTENT, params).unwrap();

        // Use only first k shares.
        let subset = &shares[..params.data_shards];
        let recovered = retrieve(&mid, subset, params).unwrap();
        assert_eq!(recovered, TEST_CONTENT);
    }

    #[test]
    fn retrieve_with_missing_data_shards_uses_recovery() {
        let params = DissolutionParams::default();
        let (mid, all_shares) = dissolve(TEST_CONTENT, params).unwrap();

        // Drop first 5 data shards; use remaining data + recovery shards.
        let subset: Vec<MiasmaShare> = all_shares
            .into_iter()
            .filter(|s| s.slot_index >= 5)
            .collect();
        let recovered = retrieve(&mid, &subset, params).unwrap();
        assert_eq!(recovered, TEST_CONTENT);
    }

    #[test]
    fn forged_shares_are_rejected() {
        let params = DissolutionParams::default();
        let (mid, mut shares) = dissolve(TEST_CONTENT, params).unwrap();

        // Inject 5 forged shares (wrong shard_hash will fail coarse verify).
        for share in &mut shares[..5] {
            share.shard_data = vec![0xFF; share.shard_data.len()];
            // shard_hash is now stale — coarse verify will reject these.
        }

        // Retrieval should still succeed with the 15 remaining valid shares.
        let recovered = retrieve(&mid, &shares, params).unwrap();
        assert_eq!(recovered, TEST_CONTENT);
    }

    #[test]
    fn too_many_forged_shares_fails() {
        let params = DissolutionParams::default();
        let (mid, mut shares) = dissolve(TEST_CONTENT, params).unwrap();

        // Forge all 20 shares.
        for s in &mut shares {
            s.shard_data = vec![0xDE; s.shard_data.len()];
        }

        let result = retrieve(&mid, &shares, params);
        assert!(result.is_err());
    }

    #[test]
    fn insufficient_shares_fails() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(TEST_CONTENT, params).unwrap();
        let result = retrieve(&mid, &shares[..5], params);
        assert!(matches!(
            result,
            Err(MiasmaError::InsufficientShares { .. })
        ));
    }

    #[test]
    fn wrong_mid_full_verify_fails() {
        let params = DissolutionParams::default();
        let (_, shares) = dissolve(TEST_CONTENT, params).unwrap();
        let wrong_mid = ContentId::compute(b"different content", &params.to_param_bytes());
        // Coarse verify rejects ALL shares because mid_prefix won't match.
        let result = retrieve(&wrong_mid, &shares, params);
        assert!(result.is_err());
    }

    #[test]
    fn small_content_single_byte() {
        let params = DissolutionParams::default();
        let content = b"X";
        let (mid, shares) = dissolve(content, params).unwrap();
        let recovered = retrieve(&mid, &shares, params).unwrap();
        assert_eq!(recovered, content);
    }

    #[test]
    fn each_share_has_correct_mid_prefix() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(TEST_CONTENT, params).unwrap();
        for s in &shares {
            assert_eq!(s.mid_prefix, mid.prefix());
        }
    }
}
