/// DHT + Onion API boundary — ADR-002.
///
/// **All DHT I/O MUST go through `OnionAwareDhtExecutor`.**
/// Direct calls to `libp2p_kad::Behaviour::get_record` / `put_record` are forbidden.
///
/// See `docs/adr/002-dht-onion-boundary.md` for full rationale.
use std::sync::Arc;

use crate::{crypto::hash::ContentId, MiasmaError};

use super::types::DhtRecord;

// ─── Trait definition (ADR-002 output) ───────────────────────────────────────

/// The single entry point for all DHT I/O.
///
/// Implementations route queries through ≥2-hop onion circuits before
/// the query reaches the DHT layer. The caller never touches `libp2p_kad`
/// directly — this trait is the only interface.
///
/// # Contract
/// - `put` MUST route the publish request through ≥2 onion hops.
/// - `get` MUST route each query through an independent ephemeral circuit,
///   ensuring multiple queries for the same MID cannot be linked.
/// - Both methods abstract away who initiated the query (IP privacy).
#[async_trait::async_trait]
pub trait OnionAwareDhtExecutor: Send + Sync {
    /// Publish MID metadata to the DHT after dissolution completes.
    ///
    /// Routes through ≥2 onion hops. Returns when the record is confirmed
    /// stored by at least one DHT peer.
    async fn put(&self, record: DhtRecord) -> Result<(), MiasmaError>;

    /// Retrieve MID metadata from the DHT.
    ///
    /// Each call uses an independent ephemeral onion circuit so that
    /// multiple `get` calls for different MIDs cannot be correlated.
    async fn get(&self, mid: &ContentId) -> Result<Option<DhtRecord>, MiasmaError>;
}

// ─── Bypass executor (Phase 1 / testing) ─────────────────────────────────────

/// In-memory DHT executor — no network, no onion routing.
///
/// Used for:
/// - Phase 1 integration tests where a real network is not available.
/// - Unit tests of dissolution/retrieval pipelines.
///
/// **Do NOT use in production.** Provides zero anonymity guarantees.
pub struct BypassOnionDhtExecutor {
    store: Arc<tokio::sync::Mutex<std::collections::HashMap<[u8; 32], DhtRecord>>>,
}

impl BypassOnionDhtExecutor {
    pub fn new() -> Self {
        Self {
            store: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
}

impl Default for BypassOnionDhtExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl OnionAwareDhtExecutor for BypassOnionDhtExecutor {
    async fn put(&self, record: DhtRecord) -> Result<(), MiasmaError> {
        let mut store = self.store.lock().await;
        store.insert(record.mid_digest, record);
        Ok(())
    }

    async fn get(&self, mid: &ContentId) -> Result<Option<DhtRecord>, MiasmaError> {
        let store = self.store.lock().await;
        Ok(store.get(mid.as_bytes()).cloned())
    }
}

// ─── DirectDhtExecutor (Phase 2) ─────────────────────────────────────────────

/// Real-network DHT executor that drives Kademlia via `DhtHandle`.
///
/// Implements `OnionAwareDhtExecutor` without onion routing — privacy is
/// delegated to the transport layer. Suitable for bootstrap nodes and bridge
/// nodes where IP privacy is less critical than connectivity.
#[derive(Clone)]
pub struct DirectDhtExecutor {
    handle: super::node::DhtHandle,
}

impl DirectDhtExecutor {
    pub fn new(handle: super::node::DhtHandle) -> Self {
        Self { handle }
    }
}

#[async_trait::async_trait]
impl OnionAwareDhtExecutor for DirectDhtExecutor {
    async fn put(&self, record: DhtRecord) -> Result<(), MiasmaError> {
        self.handle.put(record).await
    }

    async fn get(&self, mid: &ContentId) -> Result<Option<DhtRecord>, MiasmaError> {
        self.handle.get_record(*mid.as_bytes()).await
    }
}

// ─── Live executor (Task 4 — implemented in onion::executor) ─────────────────

/// Phase 1 DHT executor with 2-hop in-process onion routing.
/// Re-exported from `onion::executor::LiveOnionDhtExecutor`.
pub use crate::onion::executor::LiveOnionDhtExecutor;

/// Phase 2 DHT executor — sends onion-wrapped queries through real relay peers.
/// Re-exported from `onion::executor::NetworkOnionDhtExecutor`.
pub use crate::onion::executor::NetworkOnionDhtExecutor;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::ContentId;

    fn dummy_record(mid: &ContentId) -> DhtRecord {
        DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: 10,
            total_shards: 20,
            version: 1,
            locations: vec![],
            published_at: 0,
        }
    }

    #[tokio::test]
    async fn bypass_put_get_roundtrip() {
        let exec = BypassOnionDhtExecutor::new();
        let mid = ContentId::compute(b"test content", b"k=10,n=20,v=1");
        let record = dummy_record(&mid);

        exec.put(record.clone()).await.unwrap();
        let retrieved = exec.get(&mid).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().mid_digest, *mid.as_bytes());
    }

    #[tokio::test]
    async fn bypass_get_missing_returns_none() {
        let exec = BypassOnionDhtExecutor::new();
        let mid = ContentId::compute(b"not stored", b"k=10,n=20,v=1");
        let result = exec.get(&mid).await.unwrap();
        assert!(result.is_none());
    }
}
