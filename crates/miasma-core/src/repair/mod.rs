/// Proactive share repair / re-distribution — Phase 3 (Task 20).
///
/// # Problem
/// Nodes churn: they go offline, change IPs, or run out of storage quota.
/// If the nodes that hold a share go offline permanently, retrieval will fail
/// once fewer than k distinct encoded slots remain reachable.
///
/// # Repair protocol design
/// 1. **Offline detection**: monitor holders and classify repeated failures.
/// 2. **Slot-preserving maintenance**: keep the original `(k, n)` parameters
///    and replicate already-verified encoded slots to additional independent
///    holders rather than changing `n` and therefore the content identity.
/// 3. **Failure-domain diversity**: when metadata is available, prefer a new
///    ASN/relay/operator/LAN domain instead of counting correlated copies as
///    equivalent durability.
/// 4. **Bounded work**: cooldown and per-tick action caps prevent churn or an
///    attacker from turning repair into an unbounded bandwidth loop.
/// 5. **Distributed responsibility (later integration)**: the daemon/network
///    executor decides which node owns an action and which admitted holder gets
///    the replica; the maintenance planner remains transport-independent.
///
/// The legacy `RepairCoordinator` remains for compatibility while
/// `PieceMaintenanceEngine` provides the deterministic planner used by the r18
/// durability work.
pub mod detector;
pub mod maintenance;
pub mod protocol;

pub use detector::{OfflineDetector, PeerHealth};
pub use maintenance::{
    PieceMaintenanceAction, PieceMaintenanceConfig, PieceMaintenanceEngine, PieceMaintenancePlan,
    ReplicaObservation,
};
pub use protocol::RepairCoordinator;
