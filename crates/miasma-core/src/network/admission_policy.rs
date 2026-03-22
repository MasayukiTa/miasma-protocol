/// Hybrid admission policy — multi-signal Sybil resistance.
///
/// # Design
///
/// A pure PoW admission model penalises resource-constrained devices (mobile,
/// IoT) while providing only one axis of Sybil cost. This module implements
/// a hybrid admission model that combines multiple signals:
///
/// 1. **PoW cost** — required, but difficulty can be lower for vouched peers.
/// 2. **IP diversity** — enforced via the routing table's prefix limits.
/// 3. **Observed reachability** — bonus for peers that respond to liveness probes.
/// 4. **Trust credentials** — vouched peers can partially substitute PoW cost.
/// 5. **Resource profile** — mobile/constrained devices get adjusted thresholds.
///
/// # Mobile friendliness
///
/// The key insight: mobile devices can't cheaply produce high-difficulty PoW,
/// but they CAN be vouched for by desktop peers that have already been admitted.
/// A credential from a known issuer substitutes for part of the PoW cost,
/// keeping the total Sybil cost high without requiring every device to spend
/// CPU.
///
/// # Scoring model
///
/// ```text
/// admission_score = pow_score + diversity_bonus + reachability_bonus + credential_bonus
///
/// pow_score       = difficulty_bits × 10   (e.g., 8 bits = 80)
/// diversity_bonus = 50 if prefix is unique, 0 otherwise
/// reachability    = 30 if peer responded to probe within timeout
/// credential      = 100 if valid credential at Verified+ from known issuer
///
/// admission_threshold:
///   Desktop:      100  (PoW at 10 bits alone suffices)
///   Mobile:        80  (PoW at 4 bits + credential = 40+100 = 140, passes)
///   Constrained:   60  (PoW at 4 bits + credential + reachability = 170)
/// ```
use serde::{Deserialize, Serialize};
use tracing::info;

use super::credential::CredentialTier;
use super::descriptor::ResourceProfile;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Points per PoW difficulty bit.
const POW_POINTS_PER_BIT: u32 = 10;

/// Bonus for unique IP prefix (not already saturated).
const DIVERSITY_BONUS: u32 = 50;

/// Bonus for observed reachability (peer responded to probe).
const REACHABILITY_BONUS: u32 = 30;

/// Bonus for holding a valid credential from a known issuer.
const CREDENTIAL_BONUS: u32 = 100;

/// Extra bonus for Endorsed-tier credential.
const ENDORSED_BONUS: u32 = 50;

/// Admission threshold for desktop peers.
const THRESHOLD_DESKTOP: u32 = 100;

/// Admission threshold for mobile peers (lower to accommodate PoW cost).
const THRESHOLD_MOBILE: u32 = 80;

/// Admission threshold for constrained devices.
const THRESHOLD_CONSTRAINED: u32 = 60;

/// Minimum PoW difficulty bits required regardless of other signals.
/// Even with a credential, some PoW is required to prevent zero-cost Sybil.
const MIN_POW_DIFFICULTY: u8 = 4;

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
    /// Best credential tier presented, if any.
    pub credential_tier: Option<CredentialTier>,
    /// Resource profile declared by the peer.
    pub resource_profile: ResourceProfile,
}

/// Result of admission evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionDecision {
    /// Whether the peer is admitted.
    pub admitted: bool,
    /// Total computed score.
    pub score: u32,
    /// Threshold that was applied (depends on resource profile).
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
    pub credential_bonus: u32,
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
    /// Bonus for valid credential.
    pub credential_weight: u32,
    /// Extra bonus for Endorsed tier.
    pub endorsed_weight: u32,
    /// Threshold per resource profile.
    pub threshold_desktop: u32,
    pub threshold_mobile: u32,
    pub threshold_constrained: u32,
    /// Minimum PoW bits regardless of other signals.
    pub min_pow: u8,
}

impl Default for HybridAdmissionPolicy {
    fn default() -> Self {
        Self {
            pow_weight: POW_POINTS_PER_BIT,
            diversity_weight: DIVERSITY_BONUS,
            reachability_weight: REACHABILITY_BONUS,
            credential_weight: CREDENTIAL_BONUS,
            endorsed_weight: ENDORSED_BONUS,
            threshold_desktop: THRESHOLD_DESKTOP,
            threshold_mobile: THRESHOLD_MOBILE,
            threshold_constrained: THRESHOLD_CONSTRAINED,
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
                threshold: self.threshold_for(signals.resource_profile),
                breakdown: ScoreBreakdown {
                    pow_score: 0,
                    diversity_bonus: 0,
                    reachability_bonus: 0,
                    credential_bonus: 0,
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
        let credential_bonus = match signals.credential_tier {
            Some(CredentialTier::Endorsed) => self.credential_weight + self.endorsed_weight,
            Some(CredentialTier::Verified) => self.credential_weight,
            Some(CredentialTier::Observed) => self.credential_weight / 2,
            None => 0,
        };

        let total = pow_score + diversity_bonus + reachability_bonus + credential_bonus;
        let threshold = self.threshold_for(signals.resource_profile);

        let breakdown = ScoreBreakdown {
            pow_score,
            diversity_bonus,
            reachability_bonus,
            credential_bonus,
        };

        if total >= threshold {
            info!(
                "admission.hybrid_admitted score={total} threshold={threshold} pow={} div={diversity_bonus} reach={reachability_bonus} cred={credential_bonus}",
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

    fn threshold_for(&self, profile: ResourceProfile) -> u32 {
        match profile {
            ResourceProfile::Desktop => self.threshold_desktop,
            ResourceProfile::Mobile => self.threshold_mobile,
            ResourceProfile::Constrained => self.threshold_constrained,
        }
    }
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

/// Snapshot of admission policy state for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicyStats {
    pub min_pow_bits: u8,
    pub threshold_desktop: u32,
    pub threshold_mobile: u32,
    pub threshold_constrained: u32,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HybridAdmissionPolicy {
        HybridAdmissionPolicy::default()
    }

    #[test]
    fn desktop_pow_only_admits() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 10,
            unique_prefix: false,
            reachable: false,
            credential_tier: None,
            resource_profile: ResourceProfile::Desktop,
        };
        let decision = p.evaluate(&signals);
        // 10 * 10 = 100 >= 100
        assert!(decision.admitted);
        assert_eq!(decision.score, 100);
    }

    #[test]
    fn desktop_low_pow_rejects() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 8,
            unique_prefix: false,
            reachable: false,
            credential_tier: None,
            resource_profile: ResourceProfile::Desktop,
        };
        let decision = p.evaluate(&signals);
        // 8 * 10 = 80 < 100
        assert!(!decision.admitted);
    }

    #[test]
    fn desktop_pow_plus_diversity_admits() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 8,
            unique_prefix: true,
            reachable: false,
            credential_tier: None,
            resource_profile: ResourceProfile::Desktop,
        };
        let decision = p.evaluate(&signals);
        // 80 + 50 = 130 >= 100
        assert!(decision.admitted);
        assert_eq!(decision.breakdown.diversity_bonus, 50);
    }

    #[test]
    fn mobile_credential_compensates_low_pow() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 4,
            unique_prefix: false,
            reachable: false,
            credential_tier: Some(CredentialTier::Verified),
            resource_profile: ResourceProfile::Mobile,
        };
        let decision = p.evaluate(&signals);
        // 4*10 + 100 = 140 >= 80
        assert!(decision.admitted);
        assert_eq!(decision.breakdown.credential_bonus, 100);
    }

    #[test]
    fn min_pow_enforced_even_with_credential() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 2, // below MIN_POW_DIFFICULTY (4)
            unique_prefix: true,
            reachable: true,
            credential_tier: Some(CredentialTier::Endorsed),
            resource_profile: ResourceProfile::Mobile,
        };
        let decision = p.evaluate(&signals);
        assert!(!decision.admitted);
        assert!(matches!(
            decision.rejection_reason,
            Some(HybridRejection::InsufficientMinPoW { .. })
        ));
    }

    #[test]
    fn endorsed_gets_extra_bonus() {
        let p = policy();
        let signals_verified = AdmissionSignals {
            pow_difficulty: 4,
            unique_prefix: false,
            reachable: false,
            credential_tier: Some(CredentialTier::Verified),
            resource_profile: ResourceProfile::Desktop,
        };
        let signals_endorsed = AdmissionSignals {
            pow_difficulty: 4,
            unique_prefix: false,
            reachable: false,
            credential_tier: Some(CredentialTier::Endorsed),
            resource_profile: ResourceProfile::Desktop,
        };
        let d_verified = p.evaluate(&signals_verified);
        let d_endorsed = p.evaluate(&signals_endorsed);
        assert!(d_endorsed.score > d_verified.score);
        assert_eq!(d_endorsed.score - d_verified.score, ENDORSED_BONUS);
    }

    #[test]
    fn constrained_lower_threshold() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 4,
            unique_prefix: true,
            reachable: false,
            credential_tier: None,
            resource_profile: ResourceProfile::Constrained,
        };
        let decision = p.evaluate(&signals);
        // 40 + 50 = 90 >= 60 (constrained threshold)
        assert!(decision.admitted);
    }

    #[test]
    fn reachability_bonus_applied() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 8,
            unique_prefix: false,
            reachable: true,
            credential_tier: None,
            resource_profile: ResourceProfile::Desktop,
        };
        let decision = p.evaluate(&signals);
        // 80 + 30 = 110 >= 100
        assert!(decision.admitted);
        assert_eq!(decision.breakdown.reachability_bonus, 30);
    }

    #[test]
    fn all_signals_combined() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 8,
            unique_prefix: true,
            reachable: true,
            credential_tier: Some(CredentialTier::Endorsed),
            resource_profile: ResourceProfile::Desktop,
        };
        let decision = p.evaluate(&signals);
        // 80 + 50 + 30 + 150 = 310
        assert!(decision.admitted);
        assert_eq!(decision.score, 310);
    }

    #[test]
    fn score_breakdown_correct() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 8,
            unique_prefix: true,
            reachable: true,
            credential_tier: Some(CredentialTier::Verified),
            resource_profile: ResourceProfile::Desktop,
        };
        let decision = p.evaluate(&signals);
        assert_eq!(decision.breakdown.pow_score, 80);
        assert_eq!(decision.breakdown.diversity_bonus, 50);
        assert_eq!(decision.breakdown.reachability_bonus, 30);
        assert_eq!(decision.breakdown.credential_bonus, 100);
    }

    #[test]
    fn observed_credential_half_bonus() {
        let p = policy();
        let signals = AdmissionSignals {
            pow_difficulty: 8,
            unique_prefix: false,
            reachable: false,
            credential_tier: Some(CredentialTier::Observed),
            resource_profile: ResourceProfile::Desktop,
        };
        let decision = p.evaluate(&signals);
        assert_eq!(decision.breakdown.credential_bonus, CREDENTIAL_BONUS / 2);
    }
}
