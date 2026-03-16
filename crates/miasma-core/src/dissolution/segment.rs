/// Per-segment dissolution and retrieval.
///
/// Each segment is independently encrypted, RS-encoded, and SSS-split.
/// Segments share the same MID (derived from the full file) so that all
/// shares for a file can be routed and verified under a single identifier.
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    crypto::{
        aead::{decrypt, encrypt, KEY_LEN, NONCE_LEN},
        hash::ContentId,
        rs::{rs_decode, rs_encode},
        sss::{sss_combine, sss_split},
    },
    pipeline::DissolutionParams,
    share::{MiasmaShare, ShareVerification},
    MiasmaError,
};

use super::manifest::SegmentMeta;

/// Dissolve one segment of the full file into shares.
///
/// # Parameters
/// - `segment_data`: raw plaintext bytes for this segment
/// - `mid`: the full-file content identifier (same for all segments)
/// - `segment_index`: 0-based position of this segment
/// - `offset_bytes`: byte offset of this segment in the original file
/// - `params`: dissolution parameters (k, n)
///
/// Returns `(SegmentMeta, Vec<MiasmaShare>)`.
pub fn dissolve_segment(
    segment_data: &[u8],
    mid: &ContentId,
    segment_index: u32,
    offset_bytes: u64,
    params: DissolutionParams,
) -> Result<(SegmentMeta, Vec<MiasmaShare>), MiasmaError> {
    // 1. Encrypt segment plaintext → (ciphertext, K_enc, nonce).
    let (ciphertext, k_enc, nonce) = encrypt(segment_data)?;

    // 2. RS encode ciphertext → n shards.
    let shards = rs_encode(&ciphertext, params.data_shards, params.total_shards)?;
    debug_assert_eq!(shards.len(), params.total_shards);

    // 3. SSS split K_enc → n key shares (any data_shards suffice to recover).
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

    // 4. Assemble one MiasmaShare per shard.
    let shares: Vec<MiasmaShare> = shards
        .into_iter()
        .zip(key_shares)
        .enumerate()
        .map(|(i, (shard_data, key_share))| {
            MiasmaShare::new(
                mid,
                segment_index,
                i as u16,
                shard_data,
                key_share,
                nonce,
                segment_data.len() as u32,
                timestamp,
            )
        })
        .collect();

    let meta = SegmentMeta {
        index: segment_index,
        offset_bytes,
        plaintext_len: segment_data.len() as u32,
        share_count: params.total_shards as u16,
    };

    Ok((meta, shares))
}

/// Reconstruct one segment from ≥k shares.
///
/// Filters `shares` to those matching `meta.index` before processing.
/// Returns the decrypted segment plaintext.
pub fn retrieve_segment(
    mid: &ContentId,
    shares: &[MiasmaShare],
    meta: &SegmentMeta,
    params: DissolutionParams,
) -> Result<Vec<u8>, MiasmaError> {
    // 1. Coarse-verify and filter to shares for this segment.
    let valid: Vec<&MiasmaShare> = shares
        .iter()
        .filter(|s| s.segment_index == meta.index && ShareVerification::coarse_verify(s, mid))
        .collect();

    if valid.len() < params.data_shards {
        return Err(MiasmaError::InsufficientShares {
            need: params.data_shards,
            got: valid.len(),
        });
    }

    let selected = &valid[..params.data_shards];

    let nonce: [u8; NONCE_LEN] = selected[0].nonce;
    // original_len stores plaintext length; ciphertext = plaintext + 16 (AES-GCM tag)
    let ciphertext_len = meta.plaintext_len as usize + 16;

    // 2. RS decode encrypted shards → ciphertext.
    let rs_shards: Vec<(usize, Vec<u8>)> = selected
        .iter()
        .map(|s| (s.slot_index as usize, s.shard_data.clone()))
        .collect();

    let ciphertext = rs_decode(&rs_shards, params.data_shards, params.total_shards, ciphertext_len)?;

    // 3. SSS combine key shares → K_enc.
    let key_shares: Vec<Vec<u8>> = selected.iter().map(|s| s.key_share.clone()).collect();
    let k_enc = sss_combine(&key_shares, params.data_shards as u8)?;

    let key: [u8; KEY_LEN] = k_enc
        .as_slice()
        .try_into()
        .map_err(|_| MiasmaError::Sss("recovered K_enc has wrong length".into()))?;

    // 4. AES-256-GCM decrypt.
    decrypt(&ciphertext, &key, &nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::hash::ContentId, pipeline::DissolutionParams};

    const DATA: &[u8] = b"segment data for dissolution pipeline testing - realistic payload";

    fn mid() -> ContentId {
        ContentId::compute(DATA, b"k=10,n=20,v=1")
    }

    #[test]
    fn dissolve_retrieve_roundtrip() {
        let params = DissolutionParams::default();
        let m = mid();
        let (meta, shares) = dissolve_segment(DATA, &m, 0, 0, params).unwrap();

        assert_eq!(meta.index, 0);
        assert_eq!(meta.plaintext_len, DATA.len() as u32);
        assert_eq!(shares.len(), params.total_shards);

        let recovered = retrieve_segment(&m, &shares, &meta, params).unwrap();
        assert_eq!(recovered, DATA);
    }

    #[test]
    fn segment_index_embedded_in_shares() {
        let params = DissolutionParams::default();
        let m = mid();
        let (_, shares) = dissolve_segment(DATA, &m, 3, 192, params).unwrap();
        for share in &shares {
            assert_eq!(share.segment_index, 3);
        }
    }

    #[test]
    fn retrieve_with_minimum_k_shares() {
        let params = DissolutionParams::default();
        let m = mid();
        let (meta, shares) = dissolve_segment(DATA, &m, 0, 0, params).unwrap();

        let subset = &shares[..params.data_shards];
        let recovered = retrieve_segment(&m, subset, &meta, params).unwrap();
        assert_eq!(recovered, DATA);
    }

    #[test]
    fn retrieve_ignores_wrong_segment_shares() {
        let params = DissolutionParams::default();
        let m = mid();
        let (meta0, shares0) = dissolve_segment(DATA, &m, 0, 0, params).unwrap();
        let (_meta1, shares1) = dissolve_segment(DATA, &m, 1, DATA.len() as u64, params).unwrap();

        // Mix: shares from segment 1 should be filtered out when retrieving segment 0.
        let mut mixed: Vec<MiasmaShare> = shares0;
        mixed.extend(shares1);

        let recovered = retrieve_segment(&m, &mixed, &meta0, params).unwrap();
        assert_eq!(recovered, DATA);
    }

    #[test]
    fn insufficient_valid_shares_fails() {
        let params = DissolutionParams::default();
        let m = mid();
        let (meta, shares) = dissolve_segment(DATA, &m, 0, 0, params).unwrap();

        let result = retrieve_segment(&m, &shares[..5], &meta, params);
        assert!(matches!(
            result,
            Err(MiasmaError::InsufficientShares { .. })
        ));
    }
}
