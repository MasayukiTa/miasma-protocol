/// Best-effort + repair share distribution protocol.
///
/// # Protocol overview
///
/// 1. **Best-effort phase** — `distribute_segment()`:
///    Attempt to store each share independently; failures are recorded but do
///    not halt the process. This tolerates transient unavailability of
///    individual storage nodes without blocking dissolution.
///
/// 2. **Success criterion**: `succeeded.len() >= data_shards`.
///    Content is recoverable as long as at least k shares were stored.
///    When this holds, `DistributionResult::needs_repair` is `false`.
///
/// 3. **Repair phase** — `redistribute_segment()`:
///    Triggered when `needs_repair == true` (too many stores failed).
///    Re-dissolves the segment (new K_enc, new shares) and retries all slots.
///    Re-dissolution rather than retry ensures forward secrecy for new shares.
///
/// # Why not distributed two-phase commit?
/// P2P 2PC requires a stable coordinator and all participants to remain online
/// during the commit window. This is incompatible with a mobile-first design
/// where nodes churn frequently. Best-effort + repair achieves equivalent
/// eventual durability without coordinator assumptions (PRD §10).
use crate::{
    crypto::hash::ContentId, pipeline::DissolutionParams, share::MiasmaShare, MiasmaError,
};

use super::segment::dissolve_segment;

/// Result of a best-effort distribution attempt for one segment.
///
/// Generic over `R`, the sink's `ShareSink::Receipt` type -- a local sink's
/// receipt might just be a storage address (`String`); a network sink's
/// receipt carries real placement metadata (peer ID, advertised addresses)
/// that a caller needs to build a `ShardLocation` others can actually dial.
#[derive(Debug)]
pub struct DistributionResult<R> {
    /// Segment index this result corresponds to.
    pub segment_index: u32,
    /// Slot indices that were stored successfully, paired with the sink's receipt.
    pub succeeded: Vec<(usize, R)>,
    /// Slot indices for which the store attempt failed.
    pub failed: Vec<usize>,
    /// True if `failed.len() > (total_shards - data_shards)`.
    ///
    /// When true, fewer than `data_shards` shares were stored, meaning the
    /// content is **not recoverable** from this distribution attempt alone.
    /// Call `redistribute_segment()` to repair.
    pub needs_repair: bool,
}

impl<R> DistributionResult<R> {
    /// Number of successfully stored shares.
    pub fn distributed_count(&self) -> usize {
        self.succeeded.len()
    }

    /// True if at least `data_shards` shares were stored (content recoverable).
    pub fn is_recoverable(&self, data_shards: usize) -> bool {
        self.succeeded.len() >= data_shards
    }
}

/// A sink that accepts one `MiasmaShare` and returns a receipt proving where
/// it landed.
///
/// # Implementations
/// - Phase 1: `LocalShareStore` (local encrypted on-disk store) -- receipt is
///   just the storage address, since there's no peer/network metadata to report.
/// - Phase 2.1: `network::NetworkShareSink` (stores on remote peers via
///   libp2p `/miasma/share-store/1.0.0`) -- receipt carries the real
///   `peer_id`/`advertised_addrs` the holder reported accepting the share,
///   which is what actually makes the resulting `ShardLocation` dialable by
///   someone who was never connected to the publisher.
///
/// `Receipt` is an associated type rather than a fixed `String` return so
/// each sink can report exactly the placement metadata its own callers need,
/// without every implementor being forced into the lowest common denominator
/// (or the distributor needing a side-channel to recover what `store()`
/// already knew and then discarded).
///
/// Failures are communicated as `MiasmaError`; the distributor records them
/// and continues to the next share rather than aborting.
#[async_trait::async_trait]
pub trait ShareSink: Send + Sync {
    type Receipt: Send;

    async fn store(&self, share: MiasmaShare) -> Result<Self::Receipt, MiasmaError>;
}

/// Best-effort + repair share distributor.
///
/// Generic over `S: ShareSink` so it works with both local and network sinks.
pub struct ShareDistributor<S> {
    sink: S,
    /// Minimum data shards — used to compute `needs_repair`.
    data_shards: usize,
}

impl<S: ShareSink> ShareDistributor<S> {
    pub fn new(sink: S, data_shards: usize) -> Self {
        Self { sink, data_shards }
    }

    /// Distribute shares for one segment using best-effort strategy.
    ///
    /// All stores are attempted regardless of individual failures.
    /// Returns a `DistributionResult` describing which slots succeeded.
    pub async fn distribute_segment(
        &self,
        shares: Vec<MiasmaShare>,
    ) -> DistributionResult<S::Receipt> {
        let total_shards = shares.len();
        let segment_index = shares.first().map(|s| s.segment_index).unwrap_or(0);

        let mut succeeded = Vec::with_capacity(total_shards);
        let mut failed = Vec::new();

        for share in shares {
            let slot = share.slot_index as usize;
            match self.sink.store(share).await {
                Ok(receipt) => succeeded.push((slot, receipt)),
                Err(_) => failed.push(slot),
            }
        }

        // needs_repair = fewer than data_shards stored.
        let needs_repair = succeeded.len() < self.data_shards;

        DistributionResult {
            segment_index,
            succeeded,
            failed,
            needs_repair,
        }
    }

    /// Re-dissolve a segment and redistribute all shares.
    ///
    /// Called when `DistributionResult::needs_repair` is true. Generates a
    /// fresh set of shares (new random K_enc) for the segment so that the
    /// previously failed shares cannot be combined with the new ones.
    ///
    /// # Parameters
    /// - `segment_data`: original plaintext bytes for this segment
    /// - `mid`: full-file content identifier
    /// - `segment_index`: segment position (0-based)
    /// - `offset_bytes`: byte offset of this segment in the original file
    /// - `params`: dissolution parameters
    pub async fn redistribute_segment(
        &self,
        segment_data: &[u8],
        mid: &ContentId,
        segment_index: u32,
        offset_bytes: u64,
        params: DissolutionParams,
    ) -> Result<DistributionResult<S::Receipt>, MiasmaError> {
        let (_, shares) = dissolve_segment(segment_data, mid, segment_index, offset_bytes, params)?;
        Ok(self.distribute_segment(shares).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::hash::ContentId, pipeline::DissolutionParams};
    use std::sync::{Arc, Mutex};

    /// A sink that always succeeds, recording stored shares.
    struct AlwaysOkSink {
        stored: Arc<Mutex<Vec<MiasmaShare>>>,
    }

    impl AlwaysOkSink {
        fn new() -> (Self, Arc<Mutex<Vec<MiasmaShare>>>) {
            let stored = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    stored: stored.clone(),
                },
                stored,
            )
        }
    }

    #[async_trait::async_trait]
    impl ShareSink for AlwaysOkSink {
        type Receipt = String;

        async fn store(&self, share: MiasmaShare) -> Result<String, MiasmaError> {
            let addr = format!("addr:{}", share.slot_index);
            self.stored.lock().unwrap().push(share);
            Ok(addr)
        }
    }

    /// A sink that fails for slot indices in a deny-list.
    struct SelectiveFailSink {
        fail_slots: Vec<u16>,
        stored: Arc<Mutex<Vec<MiasmaShare>>>,
    }

    impl SelectiveFailSink {
        fn new(fail_slots: Vec<u16>) -> (Self, Arc<Mutex<Vec<MiasmaShare>>>) {
            let stored = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    fail_slots,
                    stored: stored.clone(),
                },
                stored,
            )
        }
    }

    #[async_trait::async_trait]
    impl ShareSink for SelectiveFailSink {
        type Receipt = String;

        async fn store(&self, share: MiasmaShare) -> Result<String, MiasmaError> {
            if self.fail_slots.contains(&share.slot_index) {
                return Err(MiasmaError::Sss("simulated store failure".into()));
            }
            let addr = format!("addr:{}", share.slot_index);
            self.stored.lock().unwrap().push(share);
            Ok(addr)
        }
    }

    #[tokio::test]
    async fn distribute_all_succeed() {
        let data = b"test content for distribution";
        let mid = ContentId::compute(data, b"k=10,n=20,v=1");
        let params = DissolutionParams::default();
        let (_meta, shares) = super::dissolve_segment(data, &mid, 0, 0, params).unwrap();

        let (sink, stored) = AlwaysOkSink::new();
        let dist = ShareDistributor::new(sink, params.data_shards);
        let result = dist.distribute_segment(shares).await;

        assert_eq!(result.succeeded.len(), params.total_shards);
        assert!(result.failed.is_empty());
        assert!(!result.needs_repair);
        assert!(result.is_recoverable(params.data_shards));
        assert_eq!(stored.lock().unwrap().len(), params.total_shards);
    }

    #[tokio::test]
    async fn distribute_partial_failure_still_recoverable() {
        let data = b"partial failure test";
        let mid = ContentId::compute(data, b"k=10,n=20,v=1");
        let params = DissolutionParams::default(); // k=10, n=20

        let (_, shares) = super::dissolve_segment(data, &mid, 0, 0, params).unwrap();

        // Fail 9 slots (< 10 failures still leaves 11 ≥ k=10 distributed).
        let fail_slots: Vec<u16> = (0..9).collect();
        let (sink, _) = SelectiveFailSink::new(fail_slots);
        let dist = ShareDistributor::new(sink, params.data_shards);
        let result = dist.distribute_segment(shares).await;

        assert_eq!(result.failed.len(), 9);
        assert_eq!(result.succeeded.len(), 11);
        assert!(!result.needs_repair); // still recoverable
        assert!(result.is_recoverable(params.data_shards));
    }

    #[tokio::test]
    async fn distribute_too_many_failures_triggers_repair() {
        let data = b"repair trigger test";
        let mid = ContentId::compute(data, b"k=10,n=20,v=1");
        let params = DissolutionParams::default(); // k=10, n=20

        let (_, shares) = super::dissolve_segment(data, &mid, 0, 0, params).unwrap();

        // Fail 15 slots (only 5 distributed, < k=10).
        let fail_slots: Vec<u16> = (0..15).collect();
        let (sink, _) = SelectiveFailSink::new(fail_slots);
        let dist = ShareDistributor::new(sink, params.data_shards);
        let result = dist.distribute_segment(shares).await;

        assert_eq!(result.failed.len(), 15);
        assert_eq!(result.succeeded.len(), 5);
        assert!(result.needs_repair);
        assert!(!result.is_recoverable(params.data_shards));
    }

    #[tokio::test]
    async fn redistribute_segment_succeeds_after_repair() {
        let data = b"repair roundtrip test";
        let mid = ContentId::compute(data, b"k=10,n=20,v=1");
        let params = DissolutionParams::default();

        let (sink, stored) = AlwaysOkSink::new();
        let dist = ShareDistributor::new(sink, params.data_shards);
        let result = dist
            .redistribute_segment(data, &mid, 0, 0, params)
            .await
            .unwrap();

        assert!(!result.needs_repair);
        assert_eq!(stored.lock().unwrap().len(), params.total_shards);
    }
}
