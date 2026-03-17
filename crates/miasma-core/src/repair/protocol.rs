/// Repair coordinator — Phase 3 (Task 20).
///
/// Decides when to trigger a repair and orchestrates re-dissolution.
use crate::{
    crypto::hash::ContentId,
    pipeline::DissolutionParams,
    MiasmaError,
};

/// Configuration for the repair protocol.
#[derive(Debug, Clone)]
pub struct RepairConfig {
    /// Minimum number of reachable holders before repair is triggered.
    /// Default: data_shards + 2 = 12.
    pub replication_min: usize,
    /// How often to check replication health (seconds).
    pub check_interval_secs: u64,
}

impl Default for RepairConfig {
    fn default() -> Self {
        Self {
            replication_min: 12,
            check_interval_secs: 3600,
        }
    }
}

/// Coordinates proactive share repair across the network.
///
/// # Usage (Phase 3)
/// ```rust,ignore
/// let coord = RepairCoordinator::new(config, dht, store);
/// tokio::spawn(async move { coord.run().await });
/// ```
pub struct RepairCoordinator {
    pub config: RepairConfig,
}

impl RepairCoordinator {
    pub fn new(config: RepairConfig) -> Self {
        Self { config }
    }

    /// Check whether content identified by `mid` needs repair.
    ///
    /// Phase 3: query DHT for current holder list, compare to `replication_min`.
    pub async fn needs_repair(
        &self,
        _mid: &ContentId,
        reachable_holders: usize,
    ) -> bool {
        reachable_holders < self.config.replication_min
    }

    /// Trigger a repair for `mid`.
    ///
    /// Phase 3: reconstruct shares (via `RetrievalCoordinator`), then
    /// redistribute to new healthy peers via onion-routed puts.
    pub async fn repair(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
        _plaintext: &[u8],
    ) -> Result<usize, MiasmaError> {
        // Phase 3: re-dissolve and distribute to new peers.
        // Stub: return number of new shares that would be distributed.
        let extra = params.total_shards - params.data_shards;
        tracing::info!(
            mid = mid.to_string(),
            "Repair stub: would re-distribute {extra} replacement shares"
        );
        Ok(extra)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::DissolutionParams;

    #[tokio::test]
    async fn needs_repair_below_threshold() {
        let coord = RepairCoordinator::new(RepairConfig {
            replication_min: 12,
            ..Default::default()
        });
        let params = DissolutionParams::default();
        let mid = crate::ContentId::compute(b"test", &params.to_param_bytes());
        assert!(coord.needs_repair(&mid, 10).await);
        assert!(!coord.needs_repair(&mid, 15).await);
    }
}
