/// First-contact admission policy.
///
/// Admission is intentionally not a weighted score. The network handler applies
/// independent hard constraints in order: Identify must have yielded routable
/// addresses, the routing prefix must pass the diversity limit, and the peer's
/// identity-bound PoW must meet this floor. Keeping these conditions independent
/// prevents one weak signal from compensating for a failed security boundary.
use serde::{Deserialize, Serialize};

/// The work honest nodes mine during bootstrap and the minimum accepted from a
/// first-contact peer. Dynamic routing-table difficulty is diagnostic only until
/// there is a network-wide negotiation/challenge protocol.
const MIN_POW_DIFFICULTY: u8 = super::sybil::DEFAULT_POW_DIFFICULTY;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    /// Minimum verified leading-zero bits required for admission.
    pub min_pow: u8,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            min_pow: MIN_POW_DIFFICULTY,
        }
    }
}

impl AdmissionPolicy {
    /// Whether an already recomputed PoW difficulty meets the hard floor.
    pub fn accepts_pow_difficulty(&self, actual: u8) -> bool {
        actual >= self.min_pow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_honest_mining_difficulty() {
        let p = AdmissionPolicy::default();
        assert_eq!(p.min_pow, super::super::sybil::DEFAULT_POW_DIFFICULTY);
    }

    #[test]
    fn floor_is_a_hard_boundary() {
        let p = AdmissionPolicy::default();
        assert!(!p.accepts_pow_difficulty(p.min_pow - 1));
        assert!(p.accepts_pow_difficulty(p.min_pow));
        assert!(p.accepts_pow_difficulty(p.min_pow.saturating_add(1)));
    }
}
