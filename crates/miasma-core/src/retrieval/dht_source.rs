/// DhtShareSource — resolves share locations via DHT and fetches via onion routing.
///
/// Used in Phase 2 when shares are distributed across the P2P network.
///
/// # How it works
/// 1. `list_candidates(mid)` queries the DHT (via `OnionAwareDhtExecutor`) for
///    a `DhtRecord` keyed by `mid`. The record contains `total_shards` (n) and
///    optional shard location hints.
/// 2. For each shard slot `0..total_shards` a synthetic locator is generated:
///    `"{mid_hex}:{slot_index}:{segment_index}"`.
/// 3. `fetch(locator)` decodes the locator and delegates to
///    `OnionShareFetcher::fetch_share`, which fetches the share over a fresh
///    ephemeral onion circuit.
///
/// # Phase 1 scope
/// The DHT record's `locations` field is currently unused (empty Vec). In Phase 1
/// we assume every shard is available and let `fetch_share` return `None` for
/// slots that are genuinely missing. The `RetrievalCoordinator` handles the
/// resulting `InsufficientShares` error.
use crate::{
    crypto::hash::ContentId, network::dht::OnionAwareDhtExecutor, onion::share::OnionShareFetcher,
    share::MiasmaShare, MiasmaError,
};

use super::source::ShareSource;

// ─── DhtShareSource ───────────────────────────────────────────────────────────

/// Phase 2 share source: resolves share addresses via DHT, fetches via onion routing.
pub struct DhtShareSource<D, F> {
    dht: D,
    fetcher: F,
}

impl<D: OnionAwareDhtExecutor, F: OnionShareFetcher> DhtShareSource<D, F> {
    pub fn new(dht: D, fetcher: F) -> Self {
        Self { dht, fetcher }
    }
}

#[async_trait::async_trait]
impl<D: OnionAwareDhtExecutor, F: OnionShareFetcher> ShareSource for DhtShareSource<D, F> {
    /// Query the DHT for a record matching `mid`, then enumerate shard locators.
    ///
    /// Returns locators of the form `"{mid_hex}:{slot_index}:{segment_index}"`.
    /// Returns an empty vec if no DHT record exists for this MID.
    async fn list_candidates(&self, mid: &ContentId) -> Vec<String> {
        match self.dht.get(mid).await {
            Ok(Some(record)) => {
                let mid_hex = hex::encode(record.mid_digest);
                (0..record.total_shards)
                    .map(|slot| format!("{mid_hex}:{slot}:0"))
                    .collect()
            }
            Ok(None) | Err(_) => vec![],
        }
    }

    /// Decode a locator and fetch the corresponding share via onion routing.
    ///
    /// Locator format: `"{mid_hex}:{slot_index}:{segment_index}"`.
    async fn fetch(&self, locator: &str) -> Result<Option<MiasmaShare>, MiasmaError> {
        let parts: Vec<&str> = locator.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(MiasmaError::InvalidMid(format!(
                "malformed DHT locator: '{locator}'"
            )));
        }

        let mid_bytes =
            hex::decode(parts[0]).map_err(|e| MiasmaError::InvalidMid(e.to_string()))?;
        let mid_digest: [u8; 32] = mid_bytes
            .try_into()
            .map_err(|_| MiasmaError::InvalidMid("locator mid_hex must be 32 bytes".into()))?;

        let slot_index: u16 = parts[1]
            .parse()
            .map_err(|e: std::num::ParseIntError| MiasmaError::InvalidMid(e.to_string()))?;

        let segment_index: u32 = parts[2]
            .parse()
            .map_err(|e: std::num::ParseIntError| MiasmaError::InvalidMid(e.to_string()))?;

        self.fetcher
            .fetch_share(mid_digest, slot_index, segment_index)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        network::dht::{BypassOnionDhtExecutor, OnionAwareDhtExecutor},
        network::types::DhtRecord,
        onion::share::OnionShareFetcher,
        pipeline::{dissolve, DissolutionParams},
        share::MiasmaShare,
        store::LocalShareStore,
        MiasmaError,
    };
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_store(dir: &TempDir) -> Arc<LocalShareStore> {
        Arc::new(LocalShareStore::open(dir.path(), 100).unwrap())
    }

    /// A simple in-memory OnionShareFetcher backed by a LocalShareStore (no onion routing).
    struct DirectShareFetcher {
        store: Arc<LocalShareStore>,
    }

    #[async_trait::async_trait]
    impl OnionShareFetcher for DirectShareFetcher {
        async fn fetch_share(
            &self,
            mid_digest: [u8; 32],
            slot_index: u16,
            segment_index: u32,
        ) -> Result<Option<MiasmaShare>, MiasmaError> {
            let prefix: [u8; 8] = mid_digest[..8].try_into().unwrap();
            let candidates = self.store.search_by_mid_prefix(&prefix);
            let share = candidates.iter().find_map(|addr| {
                self.store.get(addr).ok().and_then(|s| {
                    if s.slot_index == slot_index && s.segment_index == segment_index {
                        Some(s)
                    } else {
                        None
                    }
                })
            });
            Ok(share)
        }
    }

    #[tokio::test]
    async fn list_candidates_returns_locators_for_known_mid() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);

        let params = DissolutionParams::default(); // k=10, n=20
        let (mid, shares) = dissolve(b"dht source test content", params).unwrap();

        for s in &shares {
            store.put(s).unwrap();
        }

        let dht = BypassOnionDhtExecutor::new();
        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations: vec![],
            published_at: 0,
        };
        dht.put(record).await.unwrap();

        let fetcher = DirectShareFetcher { store };
        let source = DhtShareSource::new(dht, fetcher);

        let candidates = source.list_candidates(&mid).await;
        assert_eq!(candidates.len(), params.total_shards);
    }

    #[tokio::test]
    async fn list_candidates_empty_when_no_dht_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);
        let dht = BypassOnionDhtExecutor::new();
        let fetcher = DirectShareFetcher { store };
        let source = DhtShareSource::new(dht, fetcher);

        let mid = ContentId::compute(b"not in dht", b"k=10,n=20,v=1");
        let candidates = source.list_candidates(&mid).await;
        assert!(candidates.is_empty());
    }

    #[tokio::test]
    async fn fetch_decodes_locator_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);

        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(b"locator decode test", params).unwrap();
        for s in &shares {
            store.put(s).unwrap();
        }

        let dht = BypassOnionDhtExecutor::new();
        let fetcher = DirectShareFetcher { store };
        let source = DhtShareSource::new(dht, fetcher);

        // Build a locator for slot 0, segment 0.
        let mid_hex = hex::encode(mid.as_bytes());
        let locator = format!("{mid_hex}:0:0");

        let result = source.fetch(&locator).await.unwrap();
        assert!(result.is_some());
        let share = result.unwrap();
        assert_eq!(share.slot_index, 0);
        assert_eq!(share.segment_index, 0);
    }

    #[tokio::test]
    async fn fetch_malformed_locator_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);
        let dht = BypassOnionDhtExecutor::new();
        let fetcher = DirectShareFetcher { store };
        let source = DhtShareSource::new(dht, fetcher);

        let result = source.fetch("bad-locator").await;
        assert!(result.is_err());
    }
}
