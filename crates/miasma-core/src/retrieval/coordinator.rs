/// RetrievalCoordinator — orchestrates share collection and reconstruction.
///
/// # Retrieval algorithm
/// 1. List candidate share addresses from `ShareSource` (filtered by MID prefix).
/// 2. **Shuffle** the list — ensures share requests are in random order so that
///    a network observer cannot correlate request timing to shard index.
/// 3. Fetch and coarse-verify each share. Reject forgeries (shard_hash mismatch
///    or wrong mid_prefix) without decrypting — ADR-003 §粗検証ロジック.
/// 4. **Stop** as soon as k valid shares are collected.
/// 5. Reconstruct plaintext via RS decode + SSS combine + AES decrypt.
/// 6. **Return `Vec<u8>` to caller** — never write plaintext to disk.
///    The caller decides persistence (Phase 1: in-memory only for ≤1 GB).
///
/// # Phase 1 vs Phase 2
/// Phase 1: `ShareSource = LocalShareSource` — fetches from local encrypted store.
/// Phase 2: `ShareSource = DhtShareSource` — resolves locations via DHT (onion-routed),
///          fetches from remote peers via libp2p. The coordinator logic is unchanged.
use rand::seq::SliceRandom as _;

use crate::{
    crypto::hash::ContentId,
    dissolution::{DissolutionManifest, SegmentMeta},
    pipeline::{self, DissolutionParams},
    share::{MiasmaShare, ShareVerification},
    MiasmaError,
};

use super::source::ShareSource;

/// Orchestrates share collection and reconstruction.
pub struct RetrievalCoordinator<Src> {
    source: Src,
}

impl<Src: ShareSource> RetrievalCoordinator<Src> {
    pub fn new(source: Src) -> Self {
        Self { source }
    }

    /// Retrieve single-segment content by MID.
    ///
    /// Collects shares in random order; stops after k valid shares are found.
    /// Forged or corrupted shares are silently skipped (coarse verify rejects them).
    ///
    /// # Privacy
    /// The random collection order prevents timing correlation between shard
    /// requests. Each shard request is issued sequentially so that a passive
    /// observer cannot link simultaneous requests to a single retrieval.
    ///
    /// # Returns
    /// Reconstructed plaintext as `Vec<u8>`. Never writes to disk.
    pub async fn retrieve(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
    ) -> Result<Vec<u8>, MiasmaError> {
        let valid = self.collect_k_shares(mid, 0, params).await?;
        pipeline::retrieve(mid, &valid, params)
    }

    /// Retrieve multi-segment content using a pre-fetched `DissolutionManifest`.
    ///
    /// Collects shares for each segment independently and concatenates the
    /// reconstructed segments in order. A full BLAKE3 integrity check is
    /// performed on the assembled output.
    ///
    /// # Returns
    /// Reconstructed plaintext as `Vec<u8>`. Never writes to disk.
    pub async fn retrieve_file(
        &self,
        manifest: &DissolutionManifest,
    ) -> Result<Vec<u8>, MiasmaError> {
        // Collect all candidate addresses once (same MID prefix for all segments).
        let candidates = self.source.list_candidates(&manifest.mid.prefix()).await;

        let mut all_shares: Vec<MiasmaShare> = Vec::new();

        for meta in &manifest.segments {
            let seg_shares = self
                .collect_segment_from_candidates(&manifest.mid, meta, manifest.params, &candidates)
                .await?;
            all_shares.extend(seg_shares);
        }

        crate::dissolution::retrieve_file(manifest, &all_shares)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Collect k coarse-verified shares for a single-segment dissolution
    /// (segment_index == 0).
    async fn collect_k_shares(
        &self,
        mid: &ContentId,
        segment_index: u32,
        params: DissolutionParams,
    ) -> Result<Vec<MiasmaShare>, MiasmaError> {
        let mut candidates = self.source.list_candidates(&mid.prefix()).await;

        if candidates.is_empty() {
            return Err(MiasmaError::InsufficientShares {
                need: params.data_shards,
                got: 0,
            });
        }

        // Shuffle — random request order prevents shard-index timing correlation.
        candidates.shuffle(&mut rand::thread_rng());

        let mut valid: Vec<MiasmaShare> = Vec::with_capacity(params.data_shards);

        for addr in &candidates {
            if valid.len() >= params.data_shards {
                break;
            }
            match self.source.fetch(addr).await? {
                Some(share)
                    if share.segment_index == segment_index
                        && ShareVerification::coarse_verify(&share, mid) =>
                {
                    valid.push(share);
                }
                _ => {
                    // Not found, wrong segment, or failed coarse verify — skip silently.
                }
            }
        }

        if valid.len() < params.data_shards {
            return Err(MiasmaError::InsufficientShares {
                need: params.data_shards,
                got: valid.len(),
            });
        }

        Ok(valid)
    }

    /// Collect k valid shares for a specific segment from a pre-fetched
    /// candidate list (avoids redundant `list_candidates` calls per segment).
    async fn collect_segment_from_candidates(
        &self,
        mid: &ContentId,
        meta: &SegmentMeta,
        params: DissolutionParams,
        candidates: &[String],
    ) -> Result<Vec<MiasmaShare>, MiasmaError> {
        // Build a per-segment shuffled copy of the candidates.
        let mut shuffled: Vec<&String> = candidates.iter().collect();
        shuffled.shuffle(&mut rand::thread_rng());

        let mut valid: Vec<MiasmaShare> = Vec::with_capacity(params.data_shards);

        for addr in shuffled {
            if valid.len() >= params.data_shards {
                break;
            }
            match self.source.fetch(addr).await? {
                Some(share)
                    if share.segment_index == meta.index
                        && ShareVerification::coarse_verify(&share, mid) =>
                {
                    valid.push(share);
                }
                _ => {}
            }
        }

        if valid.len() < params.data_shards {
            return Err(MiasmaError::InsufficientShares {
                need: params.data_shards,
                got: valid.len(),
            });
        }

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::hash::ContentId,
        dissolution::dissolve_file,
        pipeline::dissolve,
        store::LocalShareStore,
        MiasmaError,
    };
    use std::sync::Arc;
    use tempfile::TempDir;

    use super::super::source::LocalShareSource;

    fn make_coordinator(dir: &TempDir) -> (RetrievalCoordinator<LocalShareSource>, Arc<LocalShareStore>) {
        let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
        let src = LocalShareSource::new(store.clone());
        (RetrievalCoordinator::new(src), store)
    }

    #[tokio::test]
    async fn retrieve_single_segment() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, store) = make_coordinator(&dir);

        let params = DissolutionParams::default();
        let content = b"single segment retrieval test content";
        let (mid, shares) = dissolve(content, params).unwrap();

        for s in &shares {
            store.put(s).unwrap();
        }

        let recovered = coord.retrieve(&mid, params).await.unwrap();
        assert_eq!(recovered.as_slice(), content as &[u8]);
    }

    #[tokio::test]
    async fn retrieve_stops_at_k_shares() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, store) = make_coordinator(&dir);

        let params = DissolutionParams::default(); // k=10, n=20
        let content = b"stop at k test";
        let (mid, shares) = dissolve(content, params).unwrap();

        // Store only exactly k shares.
        for s in shares.iter().take(params.data_shards) {
            store.put(s).unwrap();
        }

        let recovered = coord.retrieve(&mid, params).await.unwrap();
        assert_eq!(recovered.as_slice(), content as &[u8]);
    }

    #[tokio::test]
    async fn retrieve_skips_forged_shares() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, store) = make_coordinator(&dir);

        let params = DissolutionParams::default(); // k=10, n=20
        let content = b"forgery rejection test content in the retrieval pipeline";
        let (mid, mut shares) = dissolve(content, params).unwrap();

        // Tamper first 5 shares (shard_hash will not match shard_data).
        for s in shares.iter_mut().take(5) {
            s.shard_data = vec![0xFF; s.shard_data.len()];
            // shard_hash is now stale — coarse_verify will reject.
        }

        for s in &shares {
            store.put(s).unwrap();
        }

        // 15 valid shares remain → retrieval should succeed.
        let recovered = coord.retrieve(&mid, params).await.unwrap();
        assert_eq!(recovered.as_slice(), content as &[u8]);
    }

    #[tokio::test]
    async fn retrieve_insufficient_shares_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, store) = make_coordinator(&dir);

        let params = DissolutionParams::default(); // k=10
        let content = b"not enough shares";
        let (mid, shares) = dissolve(content, params).unwrap();

        // Store only k-1 shares.
        for s in shares.iter().take(params.data_shards - 1) {
            store.put(s).unwrap();
        }

        let result = coord.retrieve(&mid, params).await;
        assert!(matches!(
            result,
            Err(MiasmaError::InsufficientShares { .. })
        ));
    }

    #[tokio::test]
    async fn retrieve_file_multi_segment() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, store) = make_coordinator(&dir);

        let params = DissolutionParams::default();
        let data = vec![0xBBu8; 600];
        let segment_size = 256;

        let (manifest, all_shares) =
            dissolve_file(&data, params, segment_size).unwrap();

        for seg_shares in &all_shares {
            for s in seg_shares {
                store.put(s).unwrap();
            }
        }

        let recovered = coord.retrieve_file(&manifest).await.unwrap();
        assert_eq!(recovered.as_slice(), data.as_slice());
    }

    #[tokio::test]
    async fn retrieve_file_with_k_shares_per_segment() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, store) = make_coordinator(&dir);

        let params = DissolutionParams::default();
        let data = vec![0xAAu8; 400];
        let (manifest, all_shares) = dissolve_file(&data, params, 200).unwrap();

        // Store only k shares per segment.
        for seg_shares in &all_shares {
            for s in seg_shares.iter().take(params.data_shards) {
                store.put(s).unwrap();
            }
        }

        let recovered = coord.retrieve_file(&manifest).await.unwrap();
        assert_eq!(recovered.as_slice(), data.as_slice());
    }

    #[tokio::test]
    async fn retrieve_empty_store_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, _store) = make_coordinator(&dir);

        let params = DissolutionParams::default();
        let mid = ContentId::compute(b"not stored", &params.to_param_bytes());

        let result = coord.retrieve(&mid, params).await;
        assert!(matches!(
            result,
            Err(MiasmaError::InsufficientShares { got: 0, .. })
        ));
    }
}
