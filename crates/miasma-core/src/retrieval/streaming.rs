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
    crypto::hash::ContentId,
    dissolution::{retrieve_segment, DissolutionManifest, SegmentMeta},
    pipeline::DissolutionParams,
    MiasmaError,
};

use super::{
    fetch::{collect_verified_shares, FetchPolicy},
    source::ShareSource,
};
use rand::seq::SliceRandom as _;
use zeroize::Zeroizing;

/// A coordinator that yields reconstructed segments as a `Stream`.
pub struct StreamingRetrievalCoordinator<Src> {
    source: Src,
    fetch_policy: FetchPolicy,
}

impl<Src: ShareSource + Clone + Send + Sync + 'static> StreamingRetrievalCoordinator<Src> {
    pub fn new(source: Src) -> Self {
        Self {
            source,
            fetch_policy: FetchPolicy::Sequential,
        }
    }

    pub fn with_fetch_policy(source: Src, fetch_policy: FetchPolicy) -> Self {
        Self {
            source,
            fetch_policy,
        }
    }

    /// Returns an `impl Stream<Item = Result<Zeroizing<Vec<u8>>, MiasmaError>>` where
    /// each item is one reconstructed plaintext segment in order.
    ///
    /// Segments are fetched sequentially (not concurrently) to cap RAM usage
    /// at one segment at a time.  Phase 2.1 may add a small look-ahead buffer.
    pub fn retrieve_streaming(
        &self,
        manifest: DissolutionManifest,
    ) -> Pin<Box<dyn Stream<Item = Result<Zeroizing<Vec<u8>>, MiasmaError>> + Send + '_>> {
        let source = self.source.clone();
        let params = manifest.params;
        let mid = manifest.mid.clone();
        let segments = manifest.segments.clone();
        let fetch_policy = self.fetch_policy;

        let s = stream::iter(segments).then(move |meta| {
            let source = source.clone();
            let mid = mid.clone();
            async move {
                let mut candidates = source.list_candidates_for_segment(&mid, meta.index).await;
                candidates.shuffle(&mut rand::thread_rng());

                let valid = collect_verified_shares(
                    &source,
                    candidates,
                    &mid,
                    meta.index,
                    params.data_shards,
                    fetch_policy,
                )
                .await?;

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
                // Wiped when the consumer drops the item, on every path.
                retrieve_segment(&mid, &valid, &meta, params).map(Zeroizing::new)
            }
        });

        Box::pin(s)
    }

    /// Like `retrieve_streaming`, but for the network retrieval path where no
    /// pre-built `DissolutionManifest` is available (the retriever never
    /// dissolved the file itself -- it only knows the MID and the segment
    /// count discovered from the DHT record).
    ///
    /// Segment metadata is derived lazily per segment from the first valid
    /// share's own `original_len` field, exactly as
    /// `RetrievalCoordinator::retrieve_segments` already does for the
    /// non-streaming network path -- `offset_bytes` is unused by
    /// `retrieve_segment` so it is filled with a placeholder.
    ///
    /// Unlike `retrieve_streaming`, the returned stream is `'static`: every
    /// value it needs (`source`, `mid`, `params`) is cloned/copied up front
    /// rather than borrowed, so it does not need to keep `self` alive --
    /// letting the network coordinator build a short-lived
    /// `StreamingRetrievalCoordinator` and return the stream from its own
    /// method without a self-borrow lifetime conflict.
    pub fn retrieve_streaming_by_mid(
        &self,
        mid: ContentId,
        segment_count: u32,
        params: DissolutionParams,
    ) -> Pin<Box<dyn Stream<Item = Result<Zeroizing<Vec<u8>>, MiasmaError>> + Send + 'static>> {
        let source = self.source.clone();
        let fetch_policy = self.fetch_policy;

        let s = stream::iter(0..segment_count).then(move |seg_idx| {
            let source = source.clone();
            let mid = mid.clone();
            async move {
                let mut candidates = source.list_candidates_for_segment(&mid, seg_idx).await;
                candidates.shuffle(&mut rand::thread_rng());

                let valid = collect_verified_shares(
                    &source,
                    candidates,
                    &mid,
                    seg_idx,
                    params.data_shards,
                    fetch_policy,
                )
                .await?;

                if valid.len() < params.data_shards {
                    return Err(MiasmaError::InsufficientShares {
                        need: params.data_shards,
                        got: valid.len(),
                    });
                }

                // Build a synthetic SegmentMeta from the first share's metadata
                // (same technique as `RetrievalCoordinator::retrieve_segments`).
                let meta = SegmentMeta {
                    index: seg_idx,
                    offset_bytes: 0, // not used by retrieve_segment
                    plaintext_len: valid[0].original_len,
                    share_count: params.total_shards as u16,
                };

                // Wiped when the consumer drops the item, on every path.
                retrieve_segment(&mid, &valid, &meta, params).map(Zeroizing::new)
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
            recovered.extend_from_slice(&chunk.unwrap());
        }

        assert_eq!(recovered, data);
    }

    /// Phase 2.3: the network path has no pre-built manifest, only the MID
    /// and a segment count discovered from a DHT record. Proves
    /// `retrieve_streaming_by_mid` reconstructs a multi-segment file
    /// byte-for-byte via that path, and that it actually yields more than
    /// one segment (a single-segment pass would trivially "match" a small
    /// file and hide a broken multi-segment loop).
    #[tokio::test]
    async fn streaming_by_mid_yields_all_segments() {
        let dir = tempfile::tempdir().unwrap();
        let (coord, store) = make_streaming(&dir);

        let params = DissolutionParams::default();
        let data = vec![0xABu8; 600];
        let segment_size = 200usize;

        let (manifest, all_shares) = dissolve_file(&data, params, segment_size).unwrap();
        assert!(
            manifest.segments.len() > 1,
            "test fixture must exercise the multi-segment loop"
        );
        for seg in &all_shares {
            for s in seg {
                store.put(s).unwrap();
            }
        }

        let mut stream = coord.retrieve_streaming_by_mid(
            manifest.mid.clone(),
            manifest.segments.len() as u32,
            params,
        );
        let mut recovered: Vec<u8> = Vec::new();
        let mut segment_count = 0usize;
        while let Some(chunk) = stream.next().await {
            recovered.extend_from_slice(&chunk.unwrap());
            segment_count += 1;
        }

        assert_eq!(recovered, data);
        assert_eq!(segment_count, manifest.segments.len());
    }
}
