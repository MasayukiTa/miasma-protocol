/// Segmented dissolution — streaming support for 1 KB – 100 GB files.
///
/// # Architecture
/// ```text
/// dissolve_file(data, params, segment_size)
///   ├─ compute full-file MID (streaming BLAKE3 over full plaintext)
///   ├─ for each segment (default 64 MiB chunks):
///   │    dissolve_segment(chunk, mid, index, offset, params)
///   │      encrypt(chunk) → (ciphertext, K_enc, nonce)
///   │      rs_encode(ciphertext) → n shards
///   │      sss_split(K_enc) → n key shares
///   │      assemble Vec<MiasmaShare>
///   └─ return (DissolutionManifest, Vec<Vec<MiasmaShare>>)
///
/// retrieve_file(manifest, all_shares)
///   ├─ for each segment in manifest.segments (ordered by index):
///   │    retrieve_segment(mid, filtered_shares, meta, params)
///   │      coarse verify + RS decode + SSS combine + AES decrypt
///   ├─ concatenate segment plaintexts
///   └─ BLAKE3 full-verify assembled output vs manifest.mid
/// ```
///
/// # Relationship to pipeline.rs
/// `pipeline::dissolve` / `retrieve` handles single-segment in-memory
/// content. This module extends that with multi-segment support and a
/// `ShareDistributor` for best-effort + repair distribution. Both paths
/// share the same `MiasmaShare` struct — `segment_index == 0` for
/// single-segment content from pipeline.rs.
///
/// # Large-file path (>RAM)
/// For files exceeding available RAM, iterate source data externally and
/// call `dissolve_segment` per chunk. Accumulate `SegmentMeta` and assemble
/// `DissolutionManifest` manually — the `dissolve_file` convenience function
/// requires the full buffer in memory.
pub mod distributor;
pub mod manifest;
pub mod segment;

pub use distributor::{DistributionResult, ShareDistributor, ShareSink};
pub use manifest::{DissolutionManifest, SegmentMeta, DEFAULT_SEGMENT_SIZE};
pub use segment::{dissolve_segment, retrieve_segment};

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    crypto::hash::ContentId,
    pipeline::DissolutionParams,
    share::{MiasmaShare, ShareVerification},
    MiasmaError,
};

/// Dissolve `data` into segments and return all shares.
///
/// `segment_size` controls the size of each segment in bytes.
/// Use `DEFAULT_SEGMENT_SIZE` (64 MiB) for production.
///
/// # Returns
/// `(DissolutionManifest, Vec<Vec<MiasmaShare>>)` where
/// `result.1[i]` holds the `total_shards` shares for segment `i`.
///
/// # Memory
/// Requires the full file in memory. For streaming dissolution of large
/// files, call `dissolve_segment` directly.
pub fn dissolve_file(
    data: &[u8],
    params: DissolutionParams,
    segment_size: usize,
) -> Result<(DissolutionManifest, Vec<Vec<MiasmaShare>>), MiasmaError> {
    let segment_size = segment_size.max(1); // guard against 0

    // 1. Compute full-file MID (streaming BLAKE3 over entire plaintext).
    let param_bytes = params.to_param_bytes();
    let mid = ContentId::compute(data, &param_bytes);

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 2. Segment and dissolve.
    let mut all_shares: Vec<Vec<MiasmaShare>> = Vec::new();
    let mut segments: Vec<SegmentMeta> = Vec::new();

    // Empty input: produce one zero-byte segment so manifest is never empty.
    if data.is_empty() {
        let (meta, shares) = dissolve_segment(&[], &mid, 0, 0, params)?;
        segments.push(meta);
        all_shares.push(shares);
    } else {
        for (seg_idx, chunk) in data.chunks(segment_size).enumerate() {
            let offset_bytes = (seg_idx * segment_size) as u64;
            let (meta, shares) =
                dissolve_segment(chunk, &mid, seg_idx as u32, offset_bytes, params)?;
            segments.push(meta);
            all_shares.push(shares);
        }
    }

    let manifest = DissolutionManifest {
        version: 1,
        mid,
        params,
        total_bytes: data.len() as u64,
        segment_size: segment_size as u32,
        segments,
        created_at,
    };

    Ok((manifest, all_shares))
}

/// Reassemble a full file from shares spanning all segments.
///
/// `all_shares` may contain shares from any segment in any order.
/// Segments are reassembled in the order specified by `manifest.segments`.
/// A full BLAKE3 integrity check is performed on the assembled output.
///
/// # Errors
/// - `InsufficientShares` if fewer than k valid shares exist for any segment.
/// - `HashMismatch` if the reassembled content does not match the manifest MID.
pub fn retrieve_file(
    manifest: &DissolutionManifest,
    all_shares: &[MiasmaShare],
) -> Result<Vec<u8>, MiasmaError> {
    let mut output = Vec::with_capacity(manifest.total_bytes as usize);

    for meta in &manifest.segments {
        // Collect owned shares for this segment so retrieve_segment can slice them.
        let seg_shares: Vec<MiasmaShare> = all_shares
            .iter()
            .filter(|s| s.segment_index == meta.index)
            .cloned()
            .collect();

        let seg_data = retrieve_segment(&manifest.mid, &seg_shares, meta, manifest.params)?;
        output.extend_from_slice(&seg_data);
    }

    // Full integrity check: BLAKE3 of assembled plaintext vs manifest MID.
    let param_bytes = manifest.params.to_param_bytes();
    ShareVerification::full_verify(&output, &param_bytes, &manifest.mid)?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: &[u8] = b"small file content for segmented dissolution testing";

    #[test]
    fn dissolve_file_single_segment() {
        let params = DissolutionParams::default();
        let (manifest, all_shares) = dissolve_file(SMALL, params, DEFAULT_SEGMENT_SIZE).unwrap();

        assert_eq!(manifest.segments.len(), 1);
        assert_eq!(manifest.total_bytes, SMALL.len() as u64);
        assert_eq!(all_shares.len(), 1);
        assert_eq!(all_shares[0].len(), params.total_shards);

        let flat: Vec<MiasmaShare> = all_shares.into_iter().flatten().collect();
        let recovered = retrieve_file(&manifest, &flat).unwrap();
        assert_eq!(recovered, SMALL);
    }

    #[test]
    fn dissolve_file_multi_segment() {
        // Use a tiny segment size (256 bytes) to force 3 segments over 700 bytes.
        let data = vec![0xABu8; 700];
        let params = DissolutionParams::default();
        let segment_size = 256;

        let (manifest, all_shares) = dissolve_file(&data, params, segment_size).unwrap();

        assert_eq!(manifest.segments.len(), 3); // 256 + 256 + 188
        assert_eq!(manifest.segments[0].plaintext_len, 256);
        assert_eq!(manifest.segments[1].plaintext_len, 256);
        assert_eq!(manifest.segments[2].plaintext_len, 188);

        let flat: Vec<MiasmaShare> = all_shares.into_iter().flatten().collect();
        let recovered = retrieve_file(&manifest, &flat).unwrap();
        assert_eq!(recovered.as_slice(), data.as_slice());
    }

    #[test]
    fn dissolve_file_empty_input() {
        let params = DissolutionParams::default();
        let (manifest, all_shares) = dissolve_file(&[], params, DEFAULT_SEGMENT_SIZE).unwrap();

        assert_eq!(manifest.segments.len(), 1);
        assert_eq!(manifest.total_bytes, 0);

        let flat: Vec<MiasmaShare> = all_shares.into_iter().flatten().collect();
        let recovered = retrieve_file(&manifest, &flat).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn segment_indices_are_sequential() {
        let data = vec![0x42u8; 600];
        let params = DissolutionParams::default();
        let (manifest, all_shares) = dissolve_file(&data, params, 256).unwrap();

        for (seg_i, shares) in all_shares.iter().enumerate() {
            for share in shares {
                assert_eq!(share.segment_index, seg_i as u32);
            }
        }
        assert_eq!(manifest.segments[0].offset_bytes, 0);
        assert_eq!(manifest.segments[1].offset_bytes, 256);
    }

    #[test]
    fn retrieve_with_k_shares_per_segment() {
        let data = vec![0x55u8; 400];
        let params = DissolutionParams::default();
        let (manifest, all_shares) = dissolve_file(&data, params, 256).unwrap();

        // Keep only first k shares per segment.
        let flat: Vec<MiasmaShare> = all_shares
            .into_iter()
            .flat_map(|seg| seg.into_iter().take(params.data_shards))
            .collect();

        let recovered = retrieve_file(&manifest, &flat).unwrap();
        assert_eq!(recovered.as_slice(), data.as_slice());
    }

    #[test]
    fn retrieve_with_missing_data_shards_uses_recovery_shards() {
        let data = vec![0xCCu8; 300];
        let params = DissolutionParams::default();
        let (manifest, all_shares) = dissolve_file(&data, params, 256).unwrap();

        // Drop first 5 data shards from each segment; RS recovery fills the gap.
        let flat: Vec<MiasmaShare> = all_shares
            .into_iter()
            .flat_map(|seg| seg.into_iter().filter(|s| s.slot_index >= 5))
            .collect();

        let recovered = retrieve_file(&manifest, &flat).unwrap();
        assert_eq!(recovered.as_slice(), data.as_slice());
    }

    #[test]
    fn manifest_serialization_preserves_mid() {
        let params = DissolutionParams::default();
        let (manifest, _) = dissolve_file(SMALL, params, DEFAULT_SEGMENT_SIZE).unwrap();
        let bytes = manifest.to_bytes().unwrap();
        let m2 = DissolutionManifest::from_bytes(&bytes).unwrap();
        assert_eq!(manifest.mid, m2.mid);
        assert_eq!(manifest.total_bytes, m2.total_bytes);
    }
}
