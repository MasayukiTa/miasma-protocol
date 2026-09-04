/// ShareSource — abstraction over share collection backends.
///
/// Phase 1: `LocalShareSource` fetches from `LocalShareStore`.
/// Phase 2: `DhtShareSource` resolves shard locations via DHT record, then
///          fetches from remote peers via onion-routed libp2p connections.
use std::sync::Arc;

use crate::{crypto::hash::ContentId, share::MiasmaShare, store::LocalShareStore, MiasmaError};

/// Abstraction over share collection — allows the retrieval coordinator to
/// work identically against local storage (Phase 1) and the P2P network
/// (Phase 2) without changing any retrieval logic.
#[async_trait::async_trait]
pub trait ShareSource: Send + Sync {
    /// Return addresses of candidate shares for the given `mid`.
    ///
    /// - Phase 1 (`LocalShareSource`): scans local encrypted store by MID prefix.
    /// - Phase 2 (`DhtShareSource`): queries the DHT record to enumerate shard
    ///   locators, then returns synthetic locator strings.
    ///
    /// Implementations MAY return false positives (extra addresses); they
    /// MUST NOT return false negatives (missing addresses for valid shares).
    async fn list_candidates(&self, mid: &ContentId) -> Vec<String>;

    /// Return addresses of candidate shares for `mid`, scoped to a single
    /// segment when the backend can do so cheaply.
    ///
    /// For multi-segment content, `list_candidates` alone returns candidates
    /// for *every* segment's shards combined (it only filters by MID). Every
    /// caller retrieving segment-by-segment (`RetrievalCoordinator::retrieve_segments`,
    /// `StreamingRetrievalCoordinator::retrieve_streaming_by_mid`) then has to
    /// sequentially fetch-and-reject shares belonging to every *other* segment
    /// before it accumulates enough valid shares for its own segment — O(total
    /// segments × total shards) network round-trips per segment instead of
    /// O(total shards). See docs/tasks/p2p-content-transfer-hardening.md Phase 2.4.
    ///
    /// An implementation that has per-shard segment metadata available (e.g.
    /// `FallbackShareSource`, whose `DhtRecord` locations already carry a
    /// `segment_index` per `ShardLocation`) SHOULD override this to filter
    /// down to just that segment's candidates *before* any share is fetched,
    /// which is the fundamental fix: it avoids enumerating irrelevant
    /// candidates at all, rather than skipping them after a network round-trip.
    ///
    /// The default implementation is a correctness-preserving fallback for
    /// backends without per-segment location metadata (e.g. `LocalShareSource`,
    /// `DhtShareSource`): it returns the full unfiltered candidate list, exactly
    /// as `list_candidates` does. Callers still coarse-verify
    /// `share.segment_index == segment_index` after fetching, so overriding
    /// this method is a pure performance optimization — never overriding it
    /// cannot cause incorrect results, only slower ones.
    async fn list_candidates_for_segment(
        &self,
        mid: &ContentId,
        segment_index: u32,
    ) -> Vec<String> {
        let _ = segment_index;
        self.list_candidates(mid).await
    }

    /// Fetch a share by its address/locator. Returns `None` if not found.
    async fn fetch(&self, address: &str) -> Result<Option<MiasmaShare>, MiasmaError>;
}

/// Blanket impl so `Arc<T>` satisfies `ShareSource` whenever `T` does.
///
/// Phase 2.3: `StreamingRetrievalCoordinator<Src>` requires `Src: Clone`, but
/// `FallbackShareSource` (the network-backed source used by
/// `retrieve_from_network`) holds a `Mutex<Vec<TransportAttempt>>` for
/// diagnostics and so isn't itself `Clone`. Wrapping it in `Arc` (which is
/// always `Clone` regardless of what it wraps) is the standard way to make a
/// non-`Clone` implementation usable wherever a `Clone` bound is required,
/// without changing `FallbackShareSource` itself or adding a second
/// `ShareSource` impl per source type.
#[async_trait::async_trait]
impl<T: ShareSource + ?Sized> ShareSource for Arc<T> {
    async fn list_candidates(&self, mid: &ContentId) -> Vec<String> {
        (**self).list_candidates(mid).await
    }

    async fn list_candidates_for_segment(
        &self,
        mid: &ContentId,
        segment_index: u32,
    ) -> Vec<String> {
        (**self)
            .list_candidates_for_segment(mid, segment_index)
            .await
    }

    async fn fetch(&self, address: &str) -> Result<Option<MiasmaShare>, MiasmaError> {
        (**self).fetch(address).await
    }
}

// ─── LocalShareSource ─────────────────────────────────────────────────────────

/// Phase 1 share source backed by `LocalShareStore`.
///
/// Lists all locally stored shares whose `mid_prefix` matches, then fetches
/// them on demand. In Phase 2 this is replaced by DHT lookup + onion-routed
/// remote fetch.
#[derive(Clone)]
pub struct LocalShareSource {
    store: Arc<LocalShareStore>,
}

impl LocalShareSource {
    pub fn new(store: Arc<LocalShareStore>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl ShareSource for LocalShareSource {
    async fn list_candidates(&self, mid: &ContentId) -> Vec<String> {
        let prefix = mid.prefix();
        self.store.search_by_mid_prefix(&prefix)
    }

    async fn fetch(&self, address: &str) -> Result<Option<MiasmaShare>, MiasmaError> {
        if self.store.contains(address) {
            self.store.get(address).map(Some)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pipeline::dissolve, pipeline::DissolutionParams};
    use tempfile::TempDir;

    fn make_store(dir: &TempDir) -> Arc<LocalShareStore> {
        Arc::new(LocalShareStore::open(dir.path(), 100).unwrap())
    }

    #[tokio::test]
    async fn list_candidates_returns_matching_shares() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);
        let src = LocalShareSource::new(store.clone());

        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(b"retrieval source test", params).unwrap();

        for s in &shares {
            store.put(s).unwrap();
        }

        let candidates = src.list_candidates(&mid).await;
        assert_eq!(candidates.len(), params.total_shards);
    }

    #[tokio::test]
    async fn list_candidates_excludes_wrong_mid() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);
        let src = LocalShareSource::new(store.clone());

        let params = DissolutionParams::default();
        let (_, shares) = dissolve(b"content A", params).unwrap();
        let (other_mid, _) = dissolve(b"content B", params).unwrap();

        for s in &shares {
            store.put(s).unwrap();
        }

        // other_mid has a different prefix — should return no candidates.
        let candidates = src.list_candidates(&other_mid).await;
        assert!(candidates.is_empty());
    }

    #[tokio::test]
    async fn fetch_returns_none_for_missing_address() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);
        let src = LocalShareSource::new(store);
        let result = src.fetch("nonexistent_address").await.unwrap();
        assert!(result.is_none());
    }
}
