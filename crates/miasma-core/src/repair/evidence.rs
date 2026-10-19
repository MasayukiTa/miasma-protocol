//! Evidence feeding the maintenance planner.
//!
//! The planner counts a replica only when it is reachable *and* verified. This
//! module turns two sources into those facts:
//!
//! * holder liveness, tracked per peer by [`OfflineDetector`], and
//! * verified-share checks: a holder was asked for the piece and returned a
//!   copy that passed verification.
//!
//! All times are protocol-time seconds supplied by the caller.
//!
//! # Churn damping
//!
//! A holder that merely missed one probe ([`HolderState::Suspected`]), or that
//! has not been probed recently ([`HolderState::Unknown`]), is *not* reported
//! as lost: it keeps counting as a replica for the purpose of deciding whether
//! to act, so a transient outage or a fresh start never triggers a repair
//! storm. Only [`HolderState::Lost`] (offline after repeated failures, or a
//! holder that answered but no longer has a valid copy) removes a replica.

use std::collections::HashMap;

use libp2p::PeerId;

use super::{
    detector::{OfflineDetector, PeerHealth},
    maintenance::ReplicaObservation,
    schedule::PieceKey,
    select::failure_domain_for_addrs,
};
use crate::network::types::{DhtRecord, ShardLocation};

/// Result of asking one holder for one piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The holder returned a copy that passed verification.
    Verified,
    /// The holder answered but has no copy, or the copy failed verification.
    Unverifiable,
    /// No usable answer (dial failure, timeout, transport error).
    Unreachable,
}

/// What the book currently believes about one holder of one piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderState {
    /// Never probed, or the last verification is older than the evidence TTL.
    Unknown,
    /// Verified within the evidence TTL.
    Live,
    /// Missed a probe but is not yet declared offline.
    Suspected,
    /// Offline after repeated failures, or answered without a valid copy.
    Lost,
}

#[derive(Debug, Clone)]
pub struct EvidenceConfig {
    /// Re-verify each healthy holder this often.
    pub probe_interval_secs: u64,
    /// Re-probe a suspected holder this often.
    pub suspect_interval_secs: u64,
    /// A verification older than this no longer counts as `Live`.
    pub evidence_ttl_secs: u64,
    /// Consecutive failed probes before a peer is declared offline.
    pub max_failures: u32,
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        Self {
            probe_interval_secs: 6 * 3600,
            suspect_interval_secs: 600,
            evidence_ttl_secs: 24 * 3600,
            max_failures: 3,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PieceEvidence {
    last_probe: u64,
    last_ok: Option<u64>,
    lost: bool,
}

/// One advertised replica together with the book's current belief about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedReplica {
    pub location: ShardLocation,
    pub holder_id: String,
    pub failure_domain: Option<String>,
    pub state: HolderState,
}

impl LocatedReplica {
    pub fn piece_key(&self, mid_digest: [u8; 32]) -> PieceKey {
        (
            mid_digest,
            self.location.segment_index,
            self.location.shard_index,
        )
    }

    /// The planner's view of this replica. Suspected and unknown holders keep
    /// the benefit of the doubt (see the module documentation).
    pub fn observation(&self) -> ReplicaObservation {
        let counts = !matches!(self.state, HolderState::Lost);
        ReplicaObservation {
            slot_index: self.location.shard_index,
            holder_id: self.holder_id.clone(),
            failure_domain: self.failure_domain.clone(),
            reachable: counts,
            verified: counts,
        }
    }
}

/// Stable holder identity for a location: the PeerId text when the bytes parse
/// as a PeerId, otherwise `raw:<hex>` (which can never be reached).
pub fn holder_id_of(location: &ShardLocation) -> String {
    match PeerId::from_bytes(&location.peer_id_bytes) {
        Ok(p) => p.to_string(),
        Err(_) => format!("raw:{}", hex::encode(&location.peer_id_bytes)),
    }
}

/// Liveness plus per-piece verification state.
pub struct EvidenceBook {
    cfg: EvidenceConfig,
    detector: OfflineDetector,
    pieces: HashMap<(String, PieceKey), PieceEvidence>,
}

impl EvidenceBook {
    pub fn new(cfg: EvidenceConfig) -> Self {
        let mut detector = OfflineDetector::default();
        detector.max_failures = cfg.max_failures.max(1);
        Self {
            cfg,
            detector,
            pieces: HashMap::new(),
        }
    }

    pub fn config(&self) -> &EvidenceConfig {
        &self.cfg
    }

    /// Record the result of probing `holder` for `piece` at `now`.
    pub fn record_probe(&mut self, holder: &str, piece: PieceKey, outcome: ProbeOutcome, now: u64) {
        self.detector.track(holder);
        let entry = self
            .pieces
            .entry((holder.to_owned(), piece))
            .or_insert(PieceEvidence {
                last_probe: now,
                last_ok: None,
                lost: false,
            });
        entry.last_probe = now;
        match outcome {
            ProbeOutcome::Verified => {
                self.detector.record_success(holder);
                entry.last_ok = Some(now);
                entry.lost = false;
            }
            ProbeOutcome::Unverifiable => {
                // The peer is alive; this piece is not usable there.
                self.detector.record_success(holder);
                entry.lost = true;
            }
            ProbeOutcome::Unreachable => {
                self.detector.record_failure(holder);
            }
        }
    }

    pub fn state(&self, holder: &str, piece: &PieceKey, now: u64) -> HolderState {
        let evidence = self.pieces.get(&(holder.to_owned(), *piece));
        if evidence.is_some_and(|e| e.lost) {
            return HolderState::Lost;
        }
        match self.detector.health(holder) {
            Some(PeerHealth::Offline) => HolderState::Lost,
            Some(PeerHealth::Suspected) => HolderState::Suspected,
            Some(PeerHealth::Healthy) => match evidence.and_then(|e| e.last_ok) {
                Some(t) if now.saturating_sub(t) <= self.cfg.evidence_ttl_secs => HolderState::Live,
                _ => HolderState::Unknown,
            },
            None => HolderState::Unknown,
        }
    }

    /// Is a new probe of `holder` for `piece` due at `now`?
    pub fn probe_due(&self, holder: &str, piece: &PieceKey, now: u64) -> bool {
        let Some(e) = self.pieces.get(&(holder.to_owned(), *piece)) else {
            return true;
        };
        let interval = match self.state(holder, piece, now) {
            HolderState::Suspected => self.cfg.suspect_interval_secs,
            _ => self.cfg.probe_interval_secs,
        };
        now >= e.last_probe.saturating_add(interval)
    }

    /// Classify every advertised replica of `segment` in `record`.
    pub fn classify(&self, record: &DhtRecord, segment: u32, now: u64) -> Vec<LocatedReplica> {
        record
            .locations
            .iter()
            .filter(|l| l.segment_index == segment)
            .map(|l| {
                let holder_id = holder_id_of(l);
                let key = (record.mid_digest, l.segment_index, l.shard_index);
                LocatedReplica {
                    state: self.state(&holder_id, &key, now),
                    failure_domain: failure_domain_for_addrs(&l.addrs),
                    holder_id,
                    location: l.clone(),
                }
            })
            .collect()
    }

    /// Drop evidence about pieces and holders that are no longer advertised.
    pub fn retain_pieces(&mut self, keep: impl Fn(&str, &PieceKey) -> bool) {
        self.pieces.retain(|(holder, piece), _| keep(holder, piece));
    }

    pub fn tracked_pieces(&self) -> usize {
        self.pieces.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MID: [u8; 32] = [3u8; 32];

    fn piece(slot: u16) -> PieceKey {
        (MID, 0, slot)
    }

    fn book(max_failures: u32) -> EvidenceBook {
        EvidenceBook::new(EvidenceConfig {
            max_failures,
            ..EvidenceConfig::default()
        })
    }

    #[test]
    fn unprobed_holder_is_unknown_and_due() {
        let b = book(3);
        assert_eq!(b.state("h", &piece(0), 100), HolderState::Unknown);
        assert!(b.probe_due("h", &piece(0), 100));
    }

    #[test]
    fn verified_probe_is_live_until_the_ttl_expires() {
        let mut b = book(3);
        b.record_probe("h", piece(0), ProbeOutcome::Verified, 1_000);
        assert_eq!(b.state("h", &piece(0), 1_000), HolderState::Live);
        let ttl = b.config().evidence_ttl_secs;
        assert_eq!(b.state("h", &piece(0), 1_000 + ttl), HolderState::Live);
        assert_eq!(b.state("h", &piece(0), 1_001 + ttl), HolderState::Unknown);
    }

    #[test]
    fn probe_schedule_uses_protocol_time() {
        let mut b = book(3);
        b.record_probe("h", piece(0), ProbeOutcome::Verified, 1_000);
        let interval = b.config().probe_interval_secs;
        assert!(!b.probe_due("h", &piece(0), 1_000 + interval - 1));
        assert!(b.probe_due("h", &piece(0), 1_000 + interval));
        // A suspected holder is re-probed on the shorter interval.
        b.record_probe("h", piece(0), ProbeOutcome::Unreachable, 2_000);
        assert_eq!(b.state("h", &piece(0), 2_000), HolderState::Suspected);
        let suspect = b.config().suspect_interval_secs;
        assert!(!b.probe_due("h", &piece(0), 2_000 + suspect - 1));
        assert!(b.probe_due("h", &piece(0), 2_000 + suspect));
    }

    #[test]
    fn holder_is_lost_only_after_repeated_failures() {
        let mut b = book(3);
        b.record_probe("h", piece(0), ProbeOutcome::Verified, 0);
        b.record_probe("h", piece(0), ProbeOutcome::Unreachable, 10);
        assert_eq!(b.state("h", &piece(0), 10), HolderState::Suspected);
        b.record_probe("h", piece(0), ProbeOutcome::Unreachable, 20);
        assert_eq!(b.state("h", &piece(0), 20), HolderState::Suspected);
        b.record_probe("h", piece(0), ProbeOutcome::Unreachable, 30);
        assert_eq!(b.state("h", &piece(0), 30), HolderState::Lost);
        // A later success recovers it.
        b.record_probe("h", piece(0), ProbeOutcome::Verified, 40);
        assert_eq!(b.state("h", &piece(0), 40), HolderState::Live);
    }

    #[test]
    fn answering_without_a_valid_copy_loses_only_that_piece() {
        let mut b = book(3);
        b.record_probe("h", piece(0), ProbeOutcome::Verified, 0);
        b.record_probe("h", piece(1), ProbeOutcome::Verified, 0);
        b.record_probe("h", piece(0), ProbeOutcome::Unverifiable, 5);
        assert_eq!(b.state("h", &piece(0), 5), HolderState::Lost);
        assert_eq!(b.state("h", &piece(1), 5), HolderState::Live);
    }

    fn location(slot: u16, segment: u32, addr: &str) -> ShardLocation {
        ShardLocation {
            peer_id_bytes: vec![slot as u8, 1, 2],
            shard_index: slot,
            segment_index: segment,
            addrs: vec![addr.to_string()],
        }
    }

    #[test]
    fn classification_feeds_planner_observations() {
        let record = DhtRecord {
            mid_digest: MID,
            data_shards: 1,
            total_shards: 2,
            version: 1,
            locations: vec![
                location(0, 0, "/ip4/203.0.113.5/tcp/1"),
                location(1, 0, "/ip4/203.0.113.6/tcp/1"),
                location(0, 1, "/ip4/203.0.113.7/tcp/1"),
            ],
            published_at: 0,
        };
        let mut b = book(1);
        let h0 = holder_id_of(&record.locations[0]);
        let h1 = holder_id_of(&record.locations[1]);
        b.record_probe(&h0, piece(0), ProbeOutcome::Verified, 100);
        b.record_probe(&h1, piece(1), ProbeOutcome::Unreachable, 100);

        let replicas = b.classify(&record, 0, 100);
        assert_eq!(replicas.len(), 2, "other segments are not mixed in");
        assert_eq!(replicas[0].state, HolderState::Live);
        assert_eq!(replicas[1].state, HolderState::Lost);
        assert_eq!(replicas[0].failure_domain.as_deref(), Some("ip4:203.0.113"));

        let o0 = replicas[0].observation();
        let o1 = replicas[1].observation();
        assert!(o0.reachable && o0.verified);
        assert!(!o1.reachable && !o1.verified);
        assert_eq!(o1.slot_index, 1);
    }

    #[test]
    fn suspected_and_unknown_holders_keep_the_benefit_of_the_doubt() {
        let loc = location(0, 0, "/ip4/203.0.113.5/tcp/1");
        let mut r = LocatedReplica {
            holder_id: holder_id_of(&loc),
            failure_domain: None,
            location: loc,
            state: HolderState::Unknown,
        };
        assert!(r.observation().verified);
        r.state = HolderState::Suspected;
        assert!(r.observation().verified);
        r.state = HolderState::Lost;
        assert!(!r.observation().verified);
    }
}
