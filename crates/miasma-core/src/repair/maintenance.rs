//! Bounded, slot-preserving maintenance planner for durable Miasma content.
//!
//! The original `(k, n)` dissolution parameters are part of the content
//! identity and are never changed by maintenance. Durability is improved by
//! creating additional replicas of already-verified slot shares on independent
//! holders/failure domains instead of re-dissolving content with a different
//! `n`.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use crate::{crypto::hash::ContentId, pipeline::DissolutionParams};

/// One observed replica of an encoded slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaObservation {
    pub slot_index: u16,
    /// Stable holder identity (normally PeerId text).
    pub holder_id: String,
    /// Best available failure-domain label (ASN/relay/operator/LAN bucket).
    /// `None` means the domain is unknown and must not be treated as diverse.
    pub failure_domain: Option<String>,
    /// The holder answered the most recent liveness check.
    pub reachable: bool,
    /// The remotely advertised/stored share has been authenticated or otherwise
    /// verified strongly enough to count toward durability.
    pub verified: bool,
}

/// Maintenance policy. The defaults are deliberately conservative: one
/// additional replica per slot and only a few repairs per pass.
#[derive(Debug, Clone)]
pub struct PieceMaintenanceConfig {
    /// Desired number of independently reachable replicas per encoded slot.
    pub target_replicas_per_slot: usize,
    /// Number of actions that may be scheduled in one planning pass.
    pub max_actions_per_tick: usize,
    /// Minimum time before retrying maintenance for the same MID/slot after an
    /// attempted repair.
    pub repair_cooldown: Duration,
    /// When domain metadata exists, avoid considering same-domain replicas as
    /// sufficient diversity for the target.
    pub prefer_distinct_failure_domains: bool,
}

impl Default for PieceMaintenanceConfig {
    fn default() -> Self {
        Self {
            target_replicas_per_slot: 2,
            max_actions_per_tick: 4,
            repair_cooldown: Duration::from_secs(30 * 60),
            prefer_distinct_failure_domains: true,
        }
    }
}

/// A single bounded replication request. The executor should copy the verified
/// share for `slot_index` to a new holder while respecting the avoid lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceMaintenanceAction {
    pub slot_index: u16,
    pub avoid_holders: Vec<String>,
    pub avoid_failure_domains: Vec<String>,
    /// Number of verified, reachable holder identities seen by the planner.
    pub reachable_replicas: usize,
    /// Number of known distinct failure domains among those replicas.
    pub known_failure_domains: usize,
}

/// Result of one planning pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceMaintenancePlan {
    pub mid: String,
    pub expected_slots: usize,
    pub healthy_slots: usize,
    pub at_risk_slots: usize,
    pub cooldown_suppressed: usize,
    pub actions: Vec<PieceMaintenanceAction>,
}

/// Stateful planner that supplies hysteresis/cooldown for autonomous repair.
///
/// Network I/O is intentionally outside this type. A daemon executor can take
/// each [`PieceMaintenanceAction`], select a holder using its current routing
/// and admission policy, push the existing verified share, then call
/// [`record_attempt`](Self::record_attempt). This keeps the durability policy
/// deterministic and testable without teaching it transport details.
pub struct PieceMaintenanceEngine {
    config: PieceMaintenanceConfig,
    last_attempt: HashMap<(String, u16), Instant>,
}

impl PieceMaintenanceEngine {
    pub fn new(config: PieceMaintenanceConfig) -> Self {
        Self {
            config,
            last_attempt: HashMap::new(),
        }
    }

    pub fn config(&self) -> &PieceMaintenanceConfig {
        &self.config
    }

    /// Record a completed repair attempt, successful or not. Failed attempts are
    /// also cooled down so an unreachable/hostile network cannot create a tight
    /// retry loop.
    pub fn record_attempt(&mut self, mid: &ContentId, slot_index: u16) {
        self.last_attempt
            .insert((mid.to_string(), slot_index), Instant::now());
    }

    /// Forget expired cooldown entries. This bounds state for long-running
    /// nodes that have seen many MIDs.
    pub fn prune_cooldowns(&mut self) {
        let cooldown = self.config.repair_cooldown;
        self.last_attempt.retain(|_, at| at.elapsed() < cooldown);
    }

    fn in_cooldown(&self, mid: &str, slot_index: u16) -> bool {
        self.last_attempt
            .get(&(mid.to_owned(), slot_index))
            .is_some_and(|at| at.elapsed() < self.config.repair_cooldown)
    }

    /// Build a bounded plan for one content object.
    ///
    /// Only unique holder identities whose replica is both reachable and
    /// verified count. Duplicate advertisements from one holder never inflate
    /// durability. Unknown failure domains count as replicas but not as domain
    /// diversity evidence.
    pub fn plan(
        &self,
        mid: &ContentId,
        params: DissolutionParams,
        observations: &[ReplicaObservation],
    ) -> PieceMaintenancePlan {
        let expected_slots = params.total_shards;
        let target = self.config.target_replicas_per_slot.max(1);
        let mid_string = mid.to_string();
        let mut actions = Vec::new();
        let mut healthy_slots = 0usize;
        let mut at_risk_slots = 0usize;
        let mut cooldown_suppressed = 0usize;

        for slot in 0..expected_slots {
            let Ok(slot_index) = u16::try_from(slot) else {
                break;
            };
            let mut holders = HashSet::<String>::new();
            let mut domains = HashSet::<String>::new();

            for replica in observations
                .iter()
                .filter(|r| r.slot_index == slot_index && r.reachable && r.verified)
            {
                if holders.insert(replica.holder_id.clone()) {
                    if let Some(domain) = replica.failure_domain.as_ref() {
                        domains.insert(domain.clone());
                    }
                }
            }

            let enough_replicas = holders.len() >= target;
            let domain_diversity_needed = self.config.prefer_distinct_failure_domains
                && target > 1
                && !domains.is_empty()
                && domains.len() < target.min(holders.len());
            let needs_action = !enough_replicas || domain_diversity_needed;

            if !needs_action {
                healthy_slots += 1;
                continue;
            }

            at_risk_slots += 1;
            if self.in_cooldown(&mid_string, slot_index) {
                cooldown_suppressed += 1;
                continue;
            }
            if actions.len() >= self.config.max_actions_per_tick {
                continue;
            }

            let mut avoid_holders: Vec<_> = holders.into_iter().collect();
            avoid_holders.sort();
            let mut avoid_failure_domains: Vec<_> = domains.into_iter().collect();
            avoid_failure_domains.sort();
            actions.push(PieceMaintenanceAction {
                slot_index,
                reachable_replicas: avoid_holders.len(),
                known_failure_domains: avoid_failure_domains.len(),
                avoid_holders,
                avoid_failure_domains,
            });
        }

        PieceMaintenancePlan {
            mid: mid_string,
            expected_slots,
            healthy_slots,
            at_risk_slots,
            cooldown_suppressed,
            actions,
        }
    }
}

impl Default for PieceMaintenanceEngine {
    fn default() -> Self {
        Self::new(PieceMaintenanceConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_mid(params: DissolutionParams) -> ContentId {
        ContentId::compute(b"piece-maintenance-fixture", &params.to_param_bytes())
    }

    fn replica(slot: u16, holder: &str, domain: Option<&str>) -> ReplicaObservation {
        ReplicaObservation {
            slot_index: slot,
            holder_id: holder.into(),
            failure_domain: domain.map(str::to_owned),
            reachable: true,
            verified: true,
        }
    }

    #[test]
    fn missing_replica_schedules_slot_without_changing_n() {
        let params = DissolutionParams {
            data_shards: 2,
            total_shards: 3,
        };
        let mid = fixture_mid(params);
        let engine = PieceMaintenanceEngine::new(PieceMaintenanceConfig {
            target_replicas_per_slot: 2,
            max_actions_per_tick: 10,
            prefer_distinct_failure_domains: false,
            ..Default::default()
        });
        let observations = vec![
            replica(0, "a", Some("asn-a")),
            replica(0, "b", Some("asn-b")),
            replica(1, "a", Some("asn-a")),
            replica(2, "a", Some("asn-a")),
            replica(2, "b", Some("asn-b")),
        ];

        let plan = engine.plan(&mid, params, &observations);
        assert_eq!(plan.expected_slots, 3);
        assert_eq!(plan.healthy_slots, 2);
        assert_eq!(plan.at_risk_slots, 1);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].slot_index, 1);
        assert_eq!(plan.actions[0].reachable_replicas, 1);
    }

    #[test]
    fn duplicate_holder_and_unverified_replica_do_not_inflate_health() {
        let params = DissolutionParams {
            data_shards: 1,
            total_shards: 1,
        };
        let mid = fixture_mid(params);
        let engine = PieceMaintenanceEngine::default();
        let mut bad = replica(0, "b", Some("asn-b"));
        bad.verified = false;
        let observations = vec![
            replica(0, "a", Some("asn-a")),
            replica(0, "a", Some("asn-a")),
            bad,
        ];

        let plan = engine.plan(&mid, params, &observations);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].reachable_replicas, 1);
    }

    #[test]
    fn same_failure_domain_requests_diversification() {
        let params = DissolutionParams {
            data_shards: 1,
            total_shards: 1,
        };
        let mid = fixture_mid(params);
        let engine = PieceMaintenanceEngine::default();
        let observations = vec![
            replica(0, "a", Some("same-asn")),
            replica(0, "b", Some("same-asn")),
        ];

        let plan = engine.plan(&mid, params, &observations);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].reachable_replicas, 2);
        assert_eq!(plan.actions[0].known_failure_domains, 1);
        assert_eq!(plan.actions[0].avoid_failure_domains, vec!["same-asn"]);
    }

    #[test]
    fn action_budget_is_bounded() {
        let params = DissolutionParams {
            data_shards: 2,
            total_shards: 6,
        };
        let mid = fixture_mid(params);
        let engine = PieceMaintenanceEngine::new(PieceMaintenanceConfig {
            max_actions_per_tick: 2,
            ..Default::default()
        });

        let plan = engine.plan(&mid, params, &[]);
        assert_eq!(plan.at_risk_slots, 6);
        assert_eq!(plan.actions.len(), 2);
    }

    #[test]
    fn cooldown_suppresses_repeat_attempt() {
        let params = DissolutionParams {
            data_shards: 1,
            total_shards: 1,
        };
        let mid = fixture_mid(params);
        let mut engine = PieceMaintenanceEngine::default();
        engine.record_attempt(&mid, 0);

        let plan = engine.plan(&mid, params, &[]);
        assert!(plan.actions.is_empty());
        assert_eq!(plan.cooldown_suppressed, 1);
    }
}
