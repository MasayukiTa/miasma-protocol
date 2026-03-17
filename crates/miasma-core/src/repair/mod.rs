/// Proactive share repair / re-distribution — Phase 3 (Task 20).
///
/// # Problem
/// Nodes churn: they go offline, change IPs, or run out of storage quota.
/// If the nodes that hold a share go offline permanently, retrieval will fail
/// once fewer than k shares remain reachable.
///
/// # Repair protocol design
/// 1. **Offline detection**: a node periodically pings the peers it knows hold
///    shares of content it *cares about* (i.e. content it dissolved).
///    If a peer does not respond within `probe_timeout`, it is marked *suspected offline*.
///
/// 2. **Replication threshold**: if the number of reachable holders of a share
///    drops below `replication_min` (default: k + 2), a repair is triggered.
///
/// 3. **Re-dissolution**: the original dissolver re-dissolves the content
///    (re-reads from its local store, or reconstructs from remaining shares)
///    and sends new shares to healthy peers.
///
/// 4. **Distributed responsibility (Phase 3.1)**: to avoid a single node
///    bearing all repair burden, the responsibility is assigned to the node
///    closest to the content's MID in the DHT keyspace.
///
/// # Churn model
/// - Expected monthly churn: 30% (typical P2P network).
/// - Default `replication_min = k + 2 = 12` provides headroom of 2 extra shares
///   before retrieval is at risk.
/// - Repair frequency: once/hour for content the local node tracks.
pub mod detector;
pub mod protocol;

pub use detector::{OfflineDetector, PeerHealth};
pub use protocol::RepairCoordinator;
