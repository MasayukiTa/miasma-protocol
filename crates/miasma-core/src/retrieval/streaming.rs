/// Streaming retrieval — Phase 2 (Task 16).
///
/// For large files (> ~1 GB) where loading the entire plaintext into RAM is
/// impractical, `StreamingRetrievalCoordinator` fetches and reconstructs
/// content segment-by-segment, yielding each reconstructed segment over an
/// `async_stream`.
///
/// # Memory model
/// Only one segment is held in RAM at a time.  The segment size is set at
/// dissolution time (`DissolutionManifest::segment_size`); for a 100 GB file
/// at the default 64 MiB segment size, peak RAM usage ≈ 64 MiB.
///
/// # Usage
/// ```rust,ignore
/// use futures::StreamExt;
/// let mut stream = coordinator.retrieve_streaming(&manifest);
/// while let Some(chunk) = stream.next().await {
///     let bytes: Vec<u8> = chunk?;
///     sink.write_all(&bytes).await?;
/// }
/// ```
///
/// # Phase 1 vs Phase 2
/// Phase 1: single-call `RetrievalCoordinator::retrieve_file` loads all
///          segments into a Vec — fine for ≤ ~1 GB.
/// Phase 2: `StreamingRetrievalCoordinator` streams segments; the caller
///          controls backpressure via the `Stream` pull model.
use std::pin::Pin;

use futures::{stream, Stream, StreamExt};

use crate::{
    dissolution::{retrieve_segment, DissolutionManifest},
    share::{MiasmaShare, ShareVerification},
    MiasmaError,
};

use super::source::ShareSource;
use rand::seq::SliceRandom as _;

/// A coordinator that yields reconstructed segments as a `Stream`.
pub struct StreamingRetrievalCoordinator<Src> {
    source: Src,
}

impl<Src: ShareSource + Clone + Send + Sync + 'static> StreamingRetrievalCoordinator<Src> {
    pub fn new(source: Src) -> Self {
        Self { source }
    }

    /// Returns an `impl Stream<Item = Result<Vec<u8>, MiasmaError>>` where
    /// each item is one reconstructed plaintext segment in order.
    ///
    /// Segments are fetched sequentially (not concurrently) to cap RAM usage
    /// at one segment at a time.  Phase 2.1 may add a small look-ahead buffer.
    pub fn retrieve_streaming(
        &self,
        manifest: DissolutionManifest,
    ) -> Pin<Box<dyn Stream<Item = Result<Vec<u8>, MiasmaError>> + Send + '_>> {
        let source = self.source.clone();
        let params = manifest.params;
        let mid = manifest.mid.clone();
        let segments = manifest.segments.clone();

        let s = stream::iter(segments).then(move |meta| {
            let source = source.clone();
            let mid = mid.clone();
            async move {
                let mut candidates = source.list_candidates(&mid).await;
                candidates.shuffle(&mut rand::thread_rng());

                let mut valid: Vec<MiasmaShare> = Vec::with_capacity(params.data_shards);

                for addr in &candidates {
                    if valid.len() >= params.data_shards {
                        break;
                    }
                    match source.fetch(addr).await? {
                        Some(share)
                            if share.segment_index == meta.index
                                && ShareVerification::coarse_verify(&share, &mid) =>
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

                // Reconstruct this segment using the per-segment pipeline
                // (RS decode + SSS combine + AES decrypt).
                // Full-file BLAKE3 verification is the caller's responsibility
                // after all segments are assembled.
                retrieve_segment(&mid, &valid, &meta, params)
            }
        });

        Box::pin(s)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dissolution::dissolve_file, pipeline::DissolutionParams, store::LocalShareStore};
    use futures::StreamExt;
    use std::sync::Arc;
    use tempfile::TempDir;

    use super::super::source::LocalShareSource;

    fn make_streaming(
        dir: &TempDir,
    ) -> (
        StreamingRetrievalCoordinator<LocalShareSource>,
        Arc<LocalShareStore>,
    ) {
        let store = Arc::new(LocalShareStore::open(dir.path(), 200).unwrap());
        let src = LocalShareSource::new(store.clone());
        (StreamingRetrievalCoordinator::new(src), store)
    }

    #[tokio::test]
    async fn streaming_multi_segment_yields_all_segments() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, store) = make_streaming(&dir);

        let params = DissolutionParams::default();
        let data = vec![0xCCu8; 600];
        let segment_size = 200usize;

        let (manifest, all_shares) = dissolve_file(&data, params, segment_size).unwrap();
        for seg in &all_shares {
            for s in seg {
                store.put(s).unwrap();
            }
        }

        let mut stream = coord.retrieve_streaming(manifest.clone());
        let mut recovered: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            recovered.extend(chunk.unwrap());
        }

        assert_eq!(recovered, data);
    }
}
