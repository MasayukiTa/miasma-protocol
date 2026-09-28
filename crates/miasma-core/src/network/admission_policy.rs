/// Hybrid admission policy ? first-contact Sybil resistance.
///
/// # Design
///
/// First-contact admission only consumes signals available before the
/// credential/descriptor exchange: verified PoW, observed IP-prefix diversity,
/// and externally probed reachability. Credential tier and self-declared device
/// class are deliberately absent. Credential tier is
/// deliberately absent: bootstrap peers can issue credentials to one another,
/// and those credentials are obtained only after admission. Reintroducing them
/// here would recreate circular/self-issued trust and lower Sybil cost.
///
/// # Scoring model
///
/// ```text
/// admission_score = pow_score + diversity_bonus + reachability_bonus
///
/// pow_score       = difficulty_bits ? 10
/// diversity_bonus = 50 if prefix is unique, 0 otherwise
/// reachability    = 30 only after an explicit external probe succeeds
///
/// admission_threshold = 100
/// ```
use serde::{Deserialize, Serialize};
use tracing::info;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Points per PoW difficulty bit.
const POW_POINTS_PER_BIT: u32 = 10;

/// Bonus for unique IP prefix (not already saturated).
const DIVERSITY_BONUS: u32 = 50;

/// Bonus for observed reachability (peer responded to probe).
const REACHABILITY_BONUS: u32 = 30;

/// Admission threshold for desktop peers.
const ADMISSION_THRESHOLD: u32 = 100;

/// Minimum PoW difficulty bits required regardless of other signals.
/// First-contact admission has no authenticated credential yet, so the floor
/// must match the work honest nodes actually mine rather than the old 4-bit
/// placeholder that only made sense for a future pre-authenticated credential path.
const MIN_POW_DIFFICULTY: u8 = super::sybil::DEFAULT_POW_DIFFICULTY;

// ─── Admission signals ──────────────────────────────────────────────────────

/// Individual admission signals that contribute to the final score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionSignals {
    /// PoW difficulty achieved by the peer.
    pub pow_difficulty: u8,
    /// Whether the peer's IP prefix is unique (not saturated in routing table).
    pub unique_prefix: bool,
    /// Whether the peer responded to a reachability probe.
    pub reachable: bool,
}

/// Result of admission evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionDecision {
    /// Whether the peer is admitted.
    pub admitted: bool,
    /// Total computed score.
    pub score: u32,
    /// Threshold that was applied.
    pub threshold: u32,
    /// Breakdown of how the score was computed.
    pub breakdown: ScoreBreakdown,
    /// If rejected, the reason.
    pub rejection_reason: Option<HybridRejection>,
}

/// Score breakdown for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub pow_score: u32,
    pub diversity_bonus: u32,
    pub reachability_bonus: u32,
}

/// Why a peer was rejected under the hybrid model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridRejection {
    /// PoW difficulty below absolute minimum.
    InsufficientMinPoW { required: u8, actual: u8 },
    /// Total score below threshold.
    ScoreBelowThreshold { score: u32, threshold: u32 },
}

impl std::fmt::Display for HybridRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HybridRejection::InsufficientMinPoW { required, actual } => {
                write!(f, "PoW too low: need {required} bits, have {actual}")
            }
            HybridRejection::ScoreBelowThreshold { score, threshold } => {
                write!(f, "score {score} below threshold {threshold}")
            }
        }
    }
}

// ─── Admission policy ───────────────────────────────────────────────────────

/// Configurable hybrid admission policy.
pub struct HybridAdmissionPolicy {
    /// Points per PoW difficulty bit.
    pub pow_weight: u32,
    /// Bonus for unique prefix.
    pub diversity_weight: u32,
    /// Bonus for observed reachability.
    pub reachability_weight: u32,
    /// First-contact admission threshold.
    pub threshold: u32,
    /// Minimum PoW bits regardless of other signals.
    pub min_pow: u8,
}

impl Default for HybridAdmissionPolicy {
    fn default() -> Self {
        Self {
            pow_weight: POW_POINTS_PER_BIT,
            diversity_weight: DIVERSITY_BONUS,
            reachability_weight: REACHABILITY_BONUS,
            threshold: ADMISSION_THRESHOLD,
            min_pow: MIN_POW_DIFFICULTY,
        }
    }
}

impl HybridAdmissionPolicy {
    /// Evaluate admission for a peer given their signals.
    pub fn evaluate(&self, signals: &AdmissionSignals) -> AdmissionDecision {
        // Hard check: minimum PoW.
        if signals.pow_difficulty < self.min_pow {
            return AdmissionDecision {
                admitted: false,
                score: 0,
                threshold: self.threshold,
                breakdown: ScoreBreakdown {
                    pow_score: 0,
                    diversity_bonus: 0,
                    reachability_bonus: 0,
                },
                rejection_reason: Some(HybridRejection::InsufficientMinPoW {
                    required: self.min_pow,
                    actual: signals.pow_difficulty,
                }),
            };
        }

        let pow_score = signals.pow_difficulty as u32 * self.pow_weight;
        let diversity_bonus = if signals.unique_prefix {
            self.diversity_weight
        } else {
            0
        };
        let reachability_bonus = if signals.reachable {
            self.reachability_weight
        } else {
            0
        };
        let total = pow_score + diversity_bonus + reachability_bonus;
        let threshold = self.threshold;

        let breakdown = ScoreBreakdown {
            pow_score,
            diversity_bonus,
            reachability_bonus,
        };

        if total >= threshold {
            info!(
                "admission.hybrid_admitted score={total} threshold={threshold} pow={} div={diversity_bonus} reach={reachability_bonus}",
                pow_score
            );
            AdmissionDecision {
                admitted: true,
                score: total,
                threshold,
                breakdown,
                rejection_reason: None,
            }
        } else {
            AdmissionDecision {
                admitted: false,
                score: total,
                threshold,
                breakdown,
                rejection_reason: Some(HybridRejection::ScoreBelowThreshold {
                    score: total,
                    threshold,
                }),
            }
        }
    }
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

/// Snapshot of admission policy state for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicyStats {
    pub min_pow_bits: u8,
    pub threshold: u32,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HybridAdmissionPolicy {
        HybridAdmissionPolicy::default()
    }

    #[test]
    fn default_pow_floor_matches_honest_mining_difficulty() {
        let p = policy();
        assert_eq!(p.min_pow, super::super::sybil::DEFAULT_POW_DIFFICULTY);
        assert_eq!(p.threshold, ADMISSION_THRESHOLD);
    }

    #[test]
    fn pow_only_admits_at_threshold() {
        let p = policy();
        let decision = p.evaluate(&AdmissionSignals {
            pow_difficulty: 10,
            unique_prefix: false,
            reachable: false,
        });
        assert!(decision.admitted);
        assert_eq!(decision.score, 100);
        assert_eq!(decision.threshold, 100);
    }

    #[test]
    fn default_pow_without_other_signal_rejects() {
        let p = policy();
        let decision = p.evaluate(&AdmissionSignals {
            pow_difficulty: super::super::sybil::DEFAULT_POW_DIFFICULTY,
            unique_prefix: false,
            reachable: false,
        });
        assert!(!decision.admitted);
        assert_eq!(decision.score, 80);
        assert!(matches!(
            decision.rejection_reason,
            Some(HybridRejection::ScoreBelowThreshold { .. })
        ));
    }

    #[test]
    fn default_pow_plus_diversity_admits() {
        let p = policy();
        let decision = p.evaluate(&AdmissionSignals {
            pow_difficulty: super::super::sybil::DEFAULT_POW_DIFFICULTY,
            unique_prefix: true,
            reachable: false,
        });
        assert!(decision.admitted);
        assert_eq!(decision.score, 130);
        assert_eq!(decision.breakdown.diversity_bonus, 50);
    }

    #[test]
    fn min_pow_enforced_before_other_signals() {
        let p = policy();
        let decision = p.evaluate(&AdmissionSignals {
            pow_difficulty: p.min_pow - 1,
            unique_prefix: true,
            reachable: true,
        });
        assert!(!decision.admitted);
        assert_eq!(decision.score, 0);
        assert!(matches!(
            decision.rejection_reason,
            Some(HybridRejection::InsufficientMinPoW { .. })
        ));
    }

    #[test]
    fn reachability_bonus_applied_only_when_signal_true() {
        let p = policy();
        let decision = p.evaluate(&AdmissionSignals {
            pow_difficulty: super::super::sybil::DEFAULT_POW_DIFFICULTY,
            unique_prefix: false,
            reachable: true,
        });
        assert!(decision.admitted);
        assert_eq!(decision.score, 110);
        assert_eq!(decision.breakdown.reachability_bonus, 30);
    }

    #[test]
    fn score_breakdown_contains_only_pre_admission_signals() {
        let p = policy();
        let decision = p.evaluate(&AdmissionSignals {
            pow_difficulty: super::super::sybil::DEFAULT_POW_DIFFICULTY,
            unique_prefix: true,
            reachable: true,
        });
        assert!(decision.admitted);
        assert_eq!(decision.score, 160);
        assert_eq!(decision.breakdown.pow_score, 80);
        assert_eq!(decision.breakdown.diversity_bonus, 50);
        assert_eq!(decision.breakdown.reachability_bonus, 30);
    }
}
