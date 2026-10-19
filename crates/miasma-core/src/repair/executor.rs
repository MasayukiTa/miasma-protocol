//! Autonomous piece-maintenance engine: evidence -> plan -> bounded repair.
//!
//! [`MaintenanceCore::tick`] performs one pass over the content a node
//! maintains. It is transport-independent: everything that touches the network
//! or the disk goes through [`MaintenanceBackend`], and every decision is a
//! function of the protocol time passed in, so the whole loop is testable with
//! a fake backend and a manual clock.
//!
//! One pass:
//!
//! 1. re-commit any record update that did not reach the backend last time;
//! 2. probe holders that are due (bounded count, charged to the traffic budget),
//!    feeding [`EvidenceBook`];
//! 3. ask the [`PieceMaintenanceEngine`] which slots need another replica;
//! 4. for each action, within the per-tick cap, the retry backoff and the
//!    traffic budget: pick a holder ([`select_holder`]), obtain a verified copy
//!    of the share, push it, and rewrite the record's locations.
//!
//! # Invariants (enforced by [`check_record_update`], tested)
//!
//! * `k`, `n` and the MID never change: maintenance copies existing slot
//!   shares and never re-dissolves content.
//! * Every slot that had a location keeps at least one.
//! * A location is only retired when its holder is confirmed lost, and only in
//!   the same update that adds its replacement.
//! * Replicas in the same (or an unknown) failure domain restore the copy
//!   count but are never counted as independent durability.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio::{sync::watch, task::JoinHandle};
use tracing::{debug, info, warn};

use super::{
    evidence::{holder_id_of, EvidenceBook, EvidenceConfig, HolderState, ProbeOutcome},
    maintenance::{PieceMaintenanceConfig, PieceMaintenanceEngine},
    schedule::{AttemptLedger, BackoffPolicy, MaintenanceClock, PieceKey, RateBudget},
    select::{select_holder, Candidate},
};
use crate::{
    crypto::hash::ContentId,
    network::types::{DhtRecord, ShardLocation},
    pipeline::DissolutionParams,
    share::{MiasmaShare, ShareVerification},
};

// ─── Backend ─────────────────────────────────────────────────────────────────

/// Outcome of probing one holder, with the traffic it cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResult {
    pub outcome: ProbeOutcome,
    /// Bytes moved by the probe, charged to the traffic budget.
    pub bytes: u64,
}

/// Everything the maintenance pass needs from the node.
#[async_trait]
pub trait MaintenanceBackend: Send + Sync {
    /// Records this node published and is responsible for keeping healthy.
    async fn tracked_records(&self) -> Vec<DhtRecord>;

    /// Ask `location`'s holder for the piece and verify what comes back.
    async fn probe(&self, location: &ShardLocation, mid_digest: &[u8; 32]) -> ProbeResult;

    /// A copy of the share for `(segment, slot)` to replicate: from the local
    /// store or from one of `live_holders`. The caller re-verifies it.
    async fn source_share(
        &self,
        record: &DhtRecord,
        segment: u32,
        slot: u16,
        live_holders: &[ShardLocation],
    ) -> Option<MiasmaShare>;

    /// Connected, admitted nodes that could host a replica, best first,
    /// excluding the PeerIds in `exclude`.
    async fn candidates(&self, exclude: &[String]) -> Vec<Candidate>;

    /// Push `share` to `candidate`; returns the location it is now served from.
    async fn push(
        &self,
        candidate: &Candidate,
        share: &MiasmaShare,
    ) -> Result<ShardLocation, String>;

    /// Persist and re-announce the updated record.
    async fn commit_record(&self, updated: DhtRecord) -> Result<(), String>;

    /// `false` while background traffic must not run (for example a metered
    /// link). The default is "always allowed".
    async fn link_allows_background(&self) -> bool {
        true
    }
}

// ─── Configuration and reporting ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    pub planner: PieceMaintenanceConfig,
    pub evidence: EvidenceConfig,
    pub backoff: BackoffPolicy,
    /// Delay before the first pass after start-up.
    pub initial_delay_secs: u64,
    /// Time between passes.
    pub tick_interval_secs: u64,
    /// Holders probed per pass.
    pub max_probes_per_tick: usize,
    /// Sustained background traffic ceiling.
    pub rate_bytes_per_sec: u64,
    /// Largest burst the pacing bucket allows.
    pub burst_bytes: u64,
    /// Rolling 24 h cap on background traffic (0 = unlimited).
    pub daily_budget_bytes: u64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            planner: PieceMaintenanceConfig::default(),
            evidence: EvidenceConfig::default(),
            backoff: BackoffPolicy::default(),
            initial_delay_secs: 600,
            tick_interval_secs: 300,
            max_probes_per_tick: 8,
            rate_bytes_per_sec: 64 * 1024,
            burst_bytes: 4 * 1024 * 1024,
            daily_budget_bytes: 256 * 1024 * 1024,
        }
    }
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// The link policy paused the pass.
    pub paused: bool,
    pub records_seen: usize,
    pub records_invalid: usize,
    pub probes: usize,
    pub probe_bytes: u64,
    /// Slots the planner found short of replicas or diversity.
    pub at_risk_slots: usize,
    /// Replicas successfully created.
    pub repaired: usize,
    pub failed: usize,
    pub deferred_backoff: usize,
    pub deferred_budget: usize,
    pub deferred_action_cap: usize,
    pub skipped_no_candidate: usize,
    pub skipped_no_source: usize,
    pub rejected_source: usize,
    pub records_committed: usize,
    pub commit_failures: usize,
    pub invariant_violations: usize,
}

// ─── Invariants ──────────────────────────────────────────────────────────────

/// Check that `updated` is a legal maintenance rewrite of `previous`.
pub fn check_record_update(previous: &DhtRecord, updated: &DhtRecord) -> Result<(), String> {
    if previous.mid_digest != updated.mid_digest {
        return Err("MID changed".into());
    }
    if previous.data_shards != updated.data_shards || previous.total_shards != updated.total_shards
    {
        return Err("k/n changed".into());
    }
    updated.validate().map_err(|e| e.to_string())?;

    let slots_after: HashSet<(u32, u16)> = updated
        .locations
        .iter()
        .map(|l| (l.segment_index, l.shard_index))
        .collect();
    for l in &previous.locations {
        if !slots_after.contains(&(l.segment_index, l.shard_index)) {
            return Err(format!(
                "slot {} of segment {} lost its last location",
                l.shard_index, l.segment_index
            ));
        }
    }
    let mut seen = HashSet::new();
    for l in &updated.locations {
        if !seen.insert((l.segment_index, l.shard_index, l.peer_id_bytes.clone())) {
            return Err("duplicate holder for one slot".into());
        }
    }
    Ok(())
}

fn record_params(record: &DhtRecord) -> Option<(ContentId, DissolutionParams)> {
    record.validate().ok()?;
    Some((
        ContentId::from_digest(record.mid_digest),
        DissolutionParams {
            data_shards: record.data_shards as usize,
            total_shards: record.total_shards as usize,
        },
    ))
}

// ─── Core ────────────────────────────────────────────────────────────────────

pub struct MaintenanceCore {
    cfg: MaintenanceConfig,
    engine: PieceMaintenanceEngine,
    evidence: EvidenceBook,
    ledger: AttemptLedger,
    budget: RateBudget,
    /// Record updates computed but not yet accepted by the backend, so a failed
    /// commit is retried instead of pushing the same share again.
    pending_commits: HashMap<[u8; 32], DhtRecord>,
    cursor: usize,
}

impl MaintenanceCore {
    pub fn new(cfg: MaintenanceConfig, start_secs: u64) -> Self {
        // The planner's own cooldown reads the platform clock; the executor's
        // protocol-time ledger replaces it.
        let mut planner = cfg.planner.clone();
        planner.repair_cooldown = Duration::ZERO;
        Self {
            engine: PieceMaintenanceEngine::new(planner),
            evidence: EvidenceBook::new(cfg.evidence.clone()),
            ledger: AttemptLedger::new(cfg.backoff),
            budget: RateBudget::new(
                cfg.rate_bytes_per_sec,
                cfg.burst_bytes,
                cfg.daily_budget_bytes,
                start_secs,
            ),
            pending_commits: HashMap::new(),
            cursor: 0,
            cfg,
        }
    }

    pub fn ledger(&self) -> &AttemptLedger {
        &self.ledger
    }

    pub fn evidence(&self) -> &EvidenceBook {
        &self.evidence
    }

    /// Run one maintenance pass at protocol time `now`.
    pub async fn tick(&mut self, backend: &dyn MaintenanceBackend, now: u64) -> TickReport {
        let mut report = TickReport::default();
        if !backend.link_allows_background().await {
            report.paused = true;
            return report;
        }

        // 1. Retry commits that failed before.
        let pending: Vec<[u8; 32]> = self.pending_commits.keys().copied().collect();
        for mid in pending {
            if let Some(update) = self.pending_commits.get(&mid).cloned() {
                match backend.commit_record(update).await {
                    Ok(()) => {
                        self.pending_commits.remove(&mid);
                        report.records_committed += 1;
                    }
                    Err(e) => {
                        report.commit_failures += 1;
                        debug!("maintenance: record commit still failing: {e}");
                    }
                }
            }
        }

        let mut records = backend.tracked_records().await;
        records.sort_by_key(|r| r.mid_digest);
        let live_mids: HashSet<[u8; 32]> = records.iter().map(|r| r.mid_digest).collect();
        self.pending_commits.retain(|m, _| live_mids.contains(m));
        for r in &mut records {
            if let Some(overlay) = self.pending_commits.get(&r.mid_digest) {
                *r = overlay.clone();
            }
        }
        report.records_seen = records.len();
        let advertised: HashSet<(String, PieceKey)> = records
            .iter()
            .flat_map(|r| {
                r.locations.iter().map(|l| {
                    (
                        holder_id_of(l),
                        (r.mid_digest, l.segment_index, l.shard_index),
                    )
                })
            })
            .collect();
        if !records.is_empty() {
            let start = self.cursor % records.len();
            records.rotate_left(start);
            self.cursor = self.cursor.wrapping_add(1);
        }

        let mut probes_left = self.cfg.max_probes_per_tick;
        let mut actions_left = self.cfg.planner.max_actions_per_tick;

        for record in records {
            let Some((mid, params)) = record_params(&record) else {
                report.records_invalid += 1;
                continue;
            };
            let mut working = record.clone();
            let segments: BTreeSet<u32> =
                record.locations.iter().map(|l| l.segment_index).collect();

            for segment in segments {
                self.probe_segment(
                    backend,
                    &working,
                    segment,
                    now,
                    &mut probes_left,
                    &mut report,
                )
                .await;

                let replicas = self.evidence.classify(&working, segment, now);
                let observations: Vec<_> = replicas.iter().map(|r| r.observation()).collect();
                let plan = self.engine.plan(&mid, params, &observations);
                report.at_risk_slots += plan.at_risk_slots;

                for action in plan.actions {
                    if actions_left == 0 {
                        report.deferred_action_cap += 1;
                        continue;
                    }
                    let key: PieceKey = (record.mid_digest, segment, action.slot_index);
                    if !self.ledger.allowed(&key, now) {
                        report.deferred_backoff += 1;
                        continue;
                    }
                    if !self.budget.can_spend(now, 1) {
                        report.deferred_budget += 1;
                        continue;
                    }
                    actions_left -= 1;
                    self.run_action(
                        backend,
                        &mut working,
                        &mid,
                        params,
                        segment,
                        &action,
                        key,
                        now,
                        &mut report,
                    )
                    .await;
                }
            }

            if working.locations != record.locations {
                if let Err(why) = check_record_update(&record, &working) {
                    warn!("maintenance: discarding illegal record update: {why}");
                    report.invariant_violations += 1;
                    continue;
                }
                // Strictly newer than what it replaces, whatever the clocks say.
                working.published_at = now.max(record.published_at.saturating_add(1));
                self.pending_commits
                    .insert(working.mid_digest, working.clone());
                match backend.commit_record(working.clone()).await {
                    Ok(()) => {
                        self.pending_commits.remove(&working.mid_digest);
                        report.records_committed += 1;
                    }
                    Err(e) => {
                        report.commit_failures += 1;
                        warn!("maintenance: record commit failed, will retry: {e}");
                    }
                }
            }
        }

        // Housekeeping keeps long-running state bounded.
        self.ledger.prune(now);
        self.evidence
            .retain_pieces(|h, p| advertised.contains(&(h.to_owned(), *p)));
        report
    }

    async fn probe_segment(
        &mut self,
        backend: &dyn MaintenanceBackend,
        record: &DhtRecord,
        segment: u32,
        now: u64,
        probes_left: &mut usize,
        report: &mut TickReport,
    ) {
        for replica in self.evidence.classify(record, segment, now) {
            if *probes_left == 0 {
                return;
            }
            let key = replica.piece_key(record.mid_digest);
            if !self.evidence.probe_due(&replica.holder_id, &key, now)
                || !self.budget.can_spend(now, 1)
            {
                continue;
            }
            *probes_left -= 1;
            let result = backend.probe(&replica.location, &record.mid_digest).await;
            self.budget.charge(now, result.bytes);
            self.evidence
                .record_probe(&replica.holder_id, key, result.outcome, now);
            report.probes += 1;
            report.probe_bytes = report.probe_bytes.saturating_add(result.bytes);
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_action(
        &mut self,
        backend: &dyn MaintenanceBackend,
        working: &mut DhtRecord,
        mid: &ContentId,
        params: DissolutionParams,
        segment: u32,
        action: &super::maintenance::PieceMaintenanceAction,
        key: PieceKey,
        now: u64,
        report: &mut TickReport,
    ) {
        let slot = action.slot_index;
        // Re-classify: earlier actions in this pass may have changed the record.
        let replicas = self.evidence.classify(working, segment, now);

        // Never offer the new copy to any current or former holder of this slot.
        let exclude: Vec<String> = replicas
            .iter()
            .filter(|r| r.location.shard_index == slot)
            .map(|r| r.holder_id.clone())
            .collect();
        let mut holder_load: HashMap<String, usize> = HashMap::new();
        for r in replicas.iter().filter(|r| r.state != HolderState::Lost) {
            *holder_load.entry(r.holder_id.clone()).or_insert(0) += 1;
        }
        let per_holder_cap = params
            .total_shards
            .saturating_sub(params.data_shards)
            .max(1);

        let candidates = backend.candidates(&exclude).await;
        let Some(selection) = select_holder(
            &candidates,
            action,
            self.cfg.planner.target_replicas_per_slot,
            &holder_load,
            per_holder_cap,
        ) else {
            report.skipped_no_candidate += 1;
            self.ledger.record(key, now, false);
            return;
        };
        let candidate = selection.candidate.clone();

        let live: Vec<ShardLocation> = replicas
            .iter()
            .filter(|r| r.location.shard_index == slot && r.state != HolderState::Lost)
            .map(|r| r.location.clone())
            .collect();
        let Some(share) = backend.source_share(working, segment, slot, &live).await else {
            report.skipped_no_source += 1;
            self.ledger.record(key, now, false);
            return;
        };
        // Never trust the backend: the share must be this exact piece.
        if share.slot_index != slot
            || share.segment_index != segment
            || !ShareVerification::coarse_verify(&share, mid)
        {
            report.rejected_source += 1;
            self.ledger.record(key, now, false);
            return;
        }

        let cost = (share.shard_data.len() + share.key_share.len()) as u64;
        if !self.budget.try_spend(now, cost) {
            report.deferred_budget += 1;
            return;
        }

        match backend.push(&candidate, &share).await {
            Ok(location) if location.shard_index == slot && location.segment_index == segment => {
                let lost: HashSet<String> = replicas
                    .iter()
                    .filter(|r| r.location.shard_index == slot && r.state == HolderState::Lost)
                    .map(|r| r.holder_id.clone())
                    .collect();
                working.locations.retain(|l| {
                    !(l.segment_index == segment
                        && l.shard_index == slot
                        && lost.contains(&holder_id_of(l)))
                });
                working.locations.push(location);
                self.ledger.record(key, now, true);
                report.repaired += 1;
                info!(
                    slot,
                    segment,
                    holder = %candidate.peer_id,
                    adds_diversity = selection.adds_domain_diversity,
                    "maintenance: replicated slot to a new holder"
                );
            }
            Ok(_) => {
                report.failed += 1;
                self.ledger.record(key, now, false);
                warn!("maintenance: holder reported a location for a different piece");
            }
            Err(e) => {
                report.failed += 1;
                self.ledger.record(key, now, false);
                debug!(slot, segment, "maintenance: push failed: {e}");
            }
        }
    }
}

// ─── Background task ─────────────────────────────────────────────────────────

/// Handle to a running maintenance task. Dropping it cancels the task.
pub struct ExecutorHandle {
    stop: watch::Sender<bool>,
    join: Option<JoinHandle<()>>,
}

impl ExecutorHandle {
    /// Ask the task to stop without waiting for it.
    pub fn cancel(&self) {
        let _ = self.stop.send(true);
    }

    /// Cancel the task, including a pass that is in the middle of network I/O,
    /// and wait for it to finish.
    pub async fn stop(mut self) {
        self.cancel();
        if let Some(mut join) = self.join.take() {
            if tokio::time::timeout(Duration::from_secs(5), &mut join)
                .await
                .is_err()
            {
                join.abort();
                let _ = join.await;
            }
        }
    }

    /// A cloneable cancel signal for lifecycle hooks (for example wipe).
    pub fn cancel_signal(&self) -> watch::Sender<bool> {
        self.stop.clone()
    }
}

impl Drop for ExecutorHandle {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

/// Sleep for `secs`, returning `true` if cancelled first.
async fn sleep_or_cancel(rx: &mut watch::Receiver<bool>, secs: u64) -> bool {
    if *rx.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(secs)) => *rx.borrow(),
        changed = rx.changed() => changed.is_err() || *rx.borrow(),
    }
}

/// Start the maintenance loop.
pub fn spawn_executor(
    backend: Arc<dyn MaintenanceBackend>,
    cfg: MaintenanceConfig,
    clock: Arc<dyn MaintenanceClock>,
) -> ExecutorHandle {
    let (stop, mut rx) = watch::channel(false);
    let join = tokio::spawn(async move {
        let mut core = MaintenanceCore::new(cfg.clone(), clock.now_secs());
        if sleep_or_cancel(&mut rx, cfg.initial_delay_secs).await {
            return;
        }
        loop {
            let pass = core.tick(backend.as_ref(), clock.now_secs());
            tokio::select! {
                report = pass => {
                    if report.repaired > 0 || report.failed > 0 {
                        info!(
                            repaired = report.repaired,
                            failed = report.failed,
                            at_risk = report.at_risk_slots,
                            "maintenance pass finished"
                        );
                    }
                }
                _ = rx.changed() => return,
            }
            if sleep_or_cancel(&mut rx, cfg.tick_interval_secs).await {
                return;
            }
        }
    });
    ExecutorHandle {
        stop,
        join: Some(join),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::repair::schedule::ManualClock;

    const MID: [u8; 32] = [9u8; 32];

    fn loc(slot: u16, holder: &str, addr: &str) -> ShardLocation {
        ShardLocation {
            peer_id_bytes: holder.as_bytes().to_vec(),
            shard_index: slot,
            segment_index: 0,
            addrs: vec![addr.to_string()],
        }
    }

    fn holder(h: &str) -> String {
        format!("raw:{}", hex::encode(h.as_bytes()))
    }

    fn record(k: u8, n: u8, locations: Vec<ShardLocation>) -> DhtRecord {
        DhtRecord {
            mid_digest: MID,
            data_shards: k,
            total_shards: n,
            version: 1,
            locations,
            published_at: 1,
        }
    }

    fn share(slot: u16) -> MiasmaShare {
        let mid = ContentId::from_digest(MID);
        MiasmaShare::new(
            &mid,
            0,
            slot,
            vec![slot as u8; 100],
            vec![7; 32],
            // The fake backend never decrypts: any nonce will do, and a random one keeps the
            // fixture from carrying a hard-coded cryptographic value.
            rand::random::<[u8; 12]>(),
            100,
            1,
        )
    }

    #[derive(Default)]
    struct State {
        record: Option<DhtRecord>,
        dead: HashSet<String>,
        candidates: Vec<Candidate>,
        pushes: Vec<(String, u16)>,
        fail_push: bool,
        fail_commit: usize,
        commits: usize,
        probes: usize,
        bad_source: bool,
        no_source: bool,
        paused: bool,
        probe_bytes: u64,
    }

    struct Fake(Mutex<State>);

    impl Fake {
        fn new(record: DhtRecord, candidates: Vec<Candidate>) -> Self {
            Self(Mutex::new(State {
                record: Some(record),
                candidates,
                ..State::default()
            }))
        }
        fn kill(&self, h: &str) {
            self.0.lock().unwrap().dead.insert(holder(h));
        }
        fn record(&self) -> DhtRecord {
            self.0.lock().unwrap().record.clone().unwrap()
        }
    }

    #[async_trait]
    impl MaintenanceBackend for Fake {
        async fn tracked_records(&self) -> Vec<DhtRecord> {
            self.0.lock().unwrap().record.clone().into_iter().collect()
        }
        async fn probe(&self, location: &ShardLocation, _mid: &[u8; 32]) -> ProbeResult {
            let mut s = self.0.lock().unwrap();
            s.probes += 1;
            let outcome = if s.dead.contains(&holder_id_of(location)) {
                ProbeOutcome::Unreachable
            } else {
                ProbeOutcome::Verified
            };
            ProbeResult {
                outcome,
                bytes: s.probe_bytes,
            }
        }
        async fn source_share(
            &self,
            _r: &DhtRecord,
            _seg: u32,
            slot: u16,
            _live: &[ShardLocation],
        ) -> Option<MiasmaShare> {
            let s = self.0.lock().unwrap();
            if s.no_source {
                return None;
            }
            Some(share(if s.bad_source { slot + 1 } else { slot }))
        }
        async fn candidates(&self, exclude: &[String]) -> Vec<Candidate> {
            let s = self.0.lock().unwrap();
            s.candidates
                .iter()
                .filter(|c| !exclude.contains(&c.peer_id))
                .cloned()
                .collect()
        }
        async fn push(&self, c: &Candidate, share: &MiasmaShare) -> Result<ShardLocation, String> {
            let mut s = self.0.lock().unwrap();
            if s.fail_push {
                return Err("refused".into());
            }
            s.pushes.push((c.peer_id.clone(), share.slot_index));
            let raw = c.peer_id.strip_prefix("raw:").unwrap();
            Ok(ShardLocation {
                peer_id_bytes: hex::decode(raw).unwrap(),
                shard_index: share.slot_index,
                segment_index: share.segment_index,
                addrs: vec![],
            })
        }
        async fn commit_record(&self, updated: DhtRecord) -> Result<(), String> {
            let mut s = self.0.lock().unwrap();
            if s.fail_commit > 0 {
                s.fail_commit -= 1;
                return Err("busy".into());
            }
            s.commits += 1;
            s.record = Some(updated);
            Ok(())
        }
        async fn link_allows_background(&self) -> bool {
            !self.0.lock().unwrap().paused
        }
    }

    fn cand(h: &str, domain: Option<&str>) -> Candidate {
        Candidate {
            peer_id: holder(h),
            failure_domain: domain.map(str::to_owned),
        }
    }

    fn cfg() -> MaintenanceConfig {
        MaintenanceConfig {
            planner: PieceMaintenanceConfig {
                target_replicas_per_slot: 1,
                max_actions_per_tick: 4,
                prefer_distinct_failure_domains: false,
                ..PieceMaintenanceConfig::default()
            },
            evidence: EvidenceConfig {
                max_failures: 1,
                ..EvidenceConfig::default()
            },
            backoff: BackoffPolicy {
                base_secs: 100,
                max_secs: 10_000,
                success_cooldown_secs: 500,
                jitter_percent: 0,
            },
            rate_bytes_per_sec: 1_000_000,
            burst_bytes: 10_000_000,
            daily_budget_bytes: 0,
            ..MaintenanceConfig::default()
        }
    }

    fn three_slot_record() -> DhtRecord {
        record(
            2,
            3,
            vec![
                loc(0, "h0", "/ip4/203.0.113.1/tcp/1"),
                loc(1, "h1", "/ip4/203.0.113.2/tcp/1"),
                loc(2, "h2", "/ip4/203.0.113.3/tcp/1"),
            ],
        )
    }

    #[tokio::test]
    async fn dead_holder_is_replaced_without_changing_k_n_mid_or_other_slots() {
        let backend = Fake::new(
            three_slot_record(),
            vec![cand("new", Some("ip4:198.51.100"))],
        );
        backend.kill("h1");
        let mut core = MaintenanceCore::new(cfg(), 0);
        let before = backend.record();

        let report = core.tick(&backend, 1_000).await;
        assert_eq!(report.repaired, 1, "{report:?}");
        assert_eq!(report.records_committed, 1);

        let after = backend.record();
        assert_eq!(after.mid_digest, before.mid_digest);
        assert!(after.published_at > before.published_at);
        assert_eq!((after.data_shards, after.total_shards), (2, 3));
        assert_eq!(after.locations.len(), 3);
        let slot1: Vec<_> = after
            .locations
            .iter()
            .filter(|l| l.shard_index == 1)
            .collect();
        assert_eq!(slot1.len(), 1);
        assert_eq!(holder_id_of(slot1[0]), holder("new"));
        for s in [0u16, 2] {
            let a = after.locations.iter().find(|l| l.shard_index == s).unwrap();
            let b = before
                .locations
                .iter()
                .find(|l| l.shard_index == s)
                .unwrap();
            assert_eq!(a, b, "untouched slots keep their holders");
        }
        assert_eq!(backend.0.lock().unwrap().pushes, vec![(holder("new"), 1)]);
    }

    #[tokio::test]
    async fn healthy_content_causes_no_traffic_beyond_probes() {
        let backend = Fake::new(three_slot_record(), vec![cand("new", None)]);
        backend.0.lock().unwrap().probe_bytes = 10;
        let mut core = MaintenanceCore::new(cfg(), 0);
        let report = core.tick(&backend, 1_000).await;
        assert_eq!(report.repaired, 0);
        assert_eq!(report.probes, 3);
        assert_eq!(report.probe_bytes, 30, "probe traffic is accounted for");
        assert!(backend.0.lock().unwrap().pushes.is_empty());
        // Verified holders are not re-probed until their interval passes.
        let again = core.tick(&backend, 1_100).await;
        assert_eq!(again.probes, 0);
    }

    #[tokio::test]
    async fn per_tick_action_cap_and_probe_cap_are_honoured() {
        let rec = record(
            1,
            6,
            (0..6)
                .map(|s| loc(s, &format!("h{s}"), "/ip4/203.0.113.1/tcp/1"))
                .collect(),
        );
        let cands: Vec<_> = (0..6).map(|i| cand(&format!("n{i}"), None)).collect();
        let backend = Fake::new(rec, cands);
        for s in 0..6 {
            backend.kill(&format!("h{s}"));
        }
        let mut c = cfg();
        c.planner.max_actions_per_tick = 2;
        c.max_probes_per_tick = 3;
        let mut core = MaintenanceCore::new(c, 0);

        let r1 = core.tick(&backend, 1_000).await;
        assert_eq!(r1.probes, 3);
        // Only probed holders are lost; the rest keep the benefit of the doubt.
        assert_eq!(r1.repaired, 2, "{r1:?}");
        let r2 = core.tick(&backend, 1_001).await;
        assert!(r2.repaired <= 2);
        assert!(backend.0.lock().unwrap().pushes.len() <= 4);
    }

    #[tokio::test]
    async fn failed_pushes_back_off_in_protocol_time() {
        let backend = Fake::new(three_slot_record(), vec![cand("new", None)]);
        backend.kill("h1");
        backend.0.lock().unwrap().fail_push = true;
        let mut core = MaintenanceCore::new(cfg(), 0);
        let key: PieceKey = (MID, 0, 1);

        let r = core.tick(&backend, 1_000).await;
        assert_eq!(r.failed, 1);
        assert_eq!(core.ledger().next_allowed(&key), Some(1_100));

        // Inside the backoff window nothing is attempted.
        let r = core.tick(&backend, 1_099).await;
        assert_eq!(r.failed, 0);
        assert_eq!(r.deferred_backoff, 1);

        // Second failure doubles the delay.
        let r = core.tick(&backend, 1_100).await;
        assert_eq!(r.failed, 1);
        assert_eq!(core.ledger().next_allowed(&key), Some(1_300));

        // The network recovers: the next allowed attempt repairs the slot.
        backend.0.lock().unwrap().fail_push = false;
        let r = core.tick(&backend, 1_300).await;
        assert_eq!(r.repaired, 1);
        assert_eq!(core.ledger().failures(&key), 0);
    }

    #[tokio::test]
    async fn no_candidate_or_no_source_backs_off_without_traffic() {
        let backend = Fake::new(three_slot_record(), vec![]);
        backend.kill("h1");
        let mut core = MaintenanceCore::new(cfg(), 0);
        let r = core.tick(&backend, 1_000).await;
        assert_eq!(r.skipped_no_candidate, 1);
        assert_eq!(r.repaired, 0);

        let backend = Fake::new(three_slot_record(), vec![cand("new", None)]);
        backend.kill("h1");
        backend.0.lock().unwrap().no_source = true;
        let mut core = MaintenanceCore::new(cfg(), 0);
        let r = core.tick(&backend, 1_000).await;
        assert_eq!(r.skipped_no_source, 1);
        assert!(backend.0.lock().unwrap().pushes.is_empty());
    }

    #[tokio::test]
    async fn a_source_share_for_the_wrong_piece_is_never_pushed() {
        let backend = Fake::new(three_slot_record(), vec![cand("new", None)]);
        backend.kill("h1");
        backend.0.lock().unwrap().bad_source = true;
        let mut core = MaintenanceCore::new(cfg(), 0);
        let r = core.tick(&backend, 1_000).await;
        assert_eq!(r.rejected_source, 1);
        assert!(backend.0.lock().unwrap().pushes.is_empty());
    }

    #[tokio::test]
    async fn traffic_budget_defers_repairs_and_paces_them() {
        let backend = Fake::new(
            three_slot_record(),
            vec![cand("n1", None), cand("n2", None)],
        );
        backend.kill("h0");
        backend.kill("h1");
        let mut c = cfg();
        // One 132-byte share per 10 s, bucket holds exactly one.
        c.rate_bytes_per_sec = 13;
        c.burst_bytes = 132;
        let mut core = MaintenanceCore::new(c, 1_000);

        let r = core.tick(&backend, 1_000).await;
        assert_eq!(r.repaired, 1, "{r:?}");
        assert!(r.deferred_budget >= 1);
        let r = core.tick(&backend, 1_001).await;
        assert_eq!(r.repaired, 0, "bucket is still empty");
        let r = core.tick(&backend, 1_020).await;
        assert_eq!(r.repaired, 1, "refilled: {r:?}");
    }

    #[tokio::test]
    async fn metered_link_pauses_everything() {
        let backend = Fake::new(three_slot_record(), vec![cand("new", None)]);
        backend.kill("h1");
        backend.0.lock().unwrap().paused = true;
        let mut core = MaintenanceCore::new(cfg(), 0);
        let r = core.tick(&backend, 1_000).await;
        assert!(r.paused);
        let s = backend.0.lock().unwrap();
        assert_eq!((s.probes, s.pushes.len()), (0, 0));
    }

    #[tokio::test]
    async fn suspected_holders_are_not_repaired_until_declared_lost() {
        let backend = Fake::new(three_slot_record(), vec![cand("new", None)]);
        backend.kill("h1");
        let mut c = cfg();
        c.evidence.max_failures = 3;
        c.evidence.suspect_interval_secs = 10;
        let mut core = MaintenanceCore::new(c, 0);
        let mut now = 1_000;
        for _ in 0..2 {
            let r = core.tick(&backend, now).await;
            assert_eq!(r.repaired, 0, "still only suspected: {r:?}");
            now += 10;
        }
        let r = core.tick(&backend, now).await;
        assert_eq!(r.repaired, 1, "third miss declares the holder lost: {r:?}");
    }

    #[tokio::test]
    async fn correlated_replicas_are_not_counted_as_independent_durability() {
        // Slot 0 has two copies, both in one failure domain.
        let rec = record(
            1,
            1,
            vec![
                loc(0, "a", "/ip4/203.0.113.1/tcp/1"),
                loc(0, "b", "/ip4/203.0.113.2/tcp/1"),
            ],
        );
        let mut c = cfg();
        c.planner.target_replicas_per_slot = 2;
        c.planner.prefer_distinct_failure_domains = true;

        // Only same-domain candidates: no useless extra copy is made.
        let backend = Fake::new(rec.clone(), vec![cand("c", Some("ip4:203.0.113"))]);
        let mut core = MaintenanceCore::new(c.clone(), 0);
        let r = core.tick(&backend, 1_000).await;
        assert_eq!(r.at_risk_slots, 1, "two copies in one domain are at risk");
        assert_eq!(r.repaired, 0);
        assert_eq!(r.skipped_no_candidate, 1);

        // A candidate in a new domain gets the copy; existing locations stay.
        let backend = Fake::new(rec, vec![cand("d", Some("ip4:198.51.100"))]);
        let mut core = MaintenanceCore::new(c, 0);
        let r = core.tick(&backend, 1_000).await;
        assert_eq!(r.repaired, 1, "{r:?}");
        let after = backend.record();
        assert_eq!(after.locations.len(), 3);
        assert!(after.locations.iter().all(|l| l.shard_index == 0));
    }

    #[tokio::test]
    async fn failed_commit_is_retried_without_pushing_again() {
        let backend = Fake::new(
            three_slot_record(),
            vec![cand("new", None), cand("other", None)],
        );
        backend.kill("h1");
        backend.0.lock().unwrap().fail_commit = 1;
        let mut core = MaintenanceCore::new(cfg(), 0);

        let r = core.tick(&backend, 1_000).await;
        assert_eq!((r.repaired, r.commit_failures), (1, 1));
        assert_eq!(backend.0.lock().unwrap().commits, 0);

        let r = core.tick(&backend, 1_001).await;
        assert_eq!(r.commit_failures, 0);
        assert_eq!(backend.0.lock().unwrap().commits, 1);
        assert_eq!(
            backend.0.lock().unwrap().pushes.len(),
            1,
            "the share must not be pushed a second time"
        );
        let after = backend.record();
        assert!(after
            .locations
            .iter()
            .any(|l| l.shard_index == 1 && holder_id_of(l) == holder("new")));
    }

    #[test]
    fn illegal_record_updates_are_rejected() {
        let before = three_slot_record();

        let mut other_mid = before.clone();
        other_mid.mid_digest = [1; 32];
        assert!(check_record_update(&before, &other_mid).is_err());

        let mut other_n = before.clone();
        other_n.total_shards = 4;
        assert!(check_record_update(&before, &other_n).is_err());

        let mut other_k = before.clone();
        other_k.data_shards = 1;
        assert!(check_record_update(&before, &other_k).is_err());

        let mut dropped = before.clone();
        dropped.locations.retain(|l| l.shard_index != 2);
        assert!(check_record_update(&before, &dropped).is_err());

        let mut dup = before.clone();
        dup.locations.push(dup.locations[0].clone());
        assert!(check_record_update(&before, &dup).is_err());

        let mut grown = before.clone();
        grown
            .locations
            .push(loc(0, "extra", "/ip4/203.0.113.9/tcp/1"));
        assert!(check_record_update(&before, &grown).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn stop_cancels_a_pass_that_is_blocked_on_the_network() {
        struct Stuck;
        #[async_trait]
        impl MaintenanceBackend for Stuck {
            async fn tracked_records(&self) -> Vec<DhtRecord> {
                std::future::pending().await
            }
            async fn probe(&self, _: &ShardLocation, _: &[u8; 32]) -> ProbeResult {
                unreachable!()
            }
            async fn source_share(
                &self,
                _: &DhtRecord,
                _: u32,
                _: u16,
                _: &[ShardLocation],
            ) -> Option<MiasmaShare> {
                None
            }
            async fn candidates(&self, _: &[String]) -> Vec<Candidate> {
                vec![]
            }
            async fn push(&self, _: &Candidate, _: &MiasmaShare) -> Result<ShardLocation, String> {
                Err("n/a".into())
            }
            async fn commit_record(&self, _: DhtRecord) -> Result<(), String> {
                Ok(())
            }
        }

        let mut c = cfg();
        c.initial_delay_secs = 1;
        let clock = Arc::new(ManualClock::new(0));
        let handle = spawn_executor(Arc::new(Stuck), c, clock);
        tokio::time::sleep(Duration::from_secs(5)).await; // the pass is now stuck
        tokio::time::timeout(Duration::from_secs(1), handle.stop())
            .await
            .expect("stop must not wait for the blocked pass");
    }

    #[tokio::test(start_paused = true)]
    async fn stop_during_the_initial_delay_returns_immediately() {
        let backend = Arc::new(Fake::new(three_slot_record(), vec![]));
        let clock = Arc::new(ManualClock::new(0));
        let handle = spawn_executor(backend.clone(), cfg(), clock);
        handle.stop().await;
        assert_eq!(backend.0.lock().unwrap().probes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_repairs_on_schedule_using_the_injected_clock() {
        let backend = Arc::new(Fake::new(three_slot_record(), vec![cand("new", None)]));
        backend.kill("h1");
        let mut c = cfg();
        c.initial_delay_secs = 10;
        c.tick_interval_secs = 10;
        let clock = Arc::new(ManualClock::new(5_000));
        let handle = spawn_executor(backend.clone(), c, clock.clone());
        tokio::time::sleep(Duration::from_secs(30)).await;
        handle.stop().await;
        assert_eq!(backend.0.lock().unwrap().pushes.len(), 1);
    }
}
