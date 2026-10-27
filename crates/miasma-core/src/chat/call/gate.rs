//! The call gate: map the hybrid PQC step result (a `Pass` from
//! `ChatCore::pq_step`) to a call-origination decision (PR2).
//! Design: design-call-security-v7e.md chapter 3, sections 3.4 and 3.7,
//! and the prohibitions in 3.11. The only sanctioned entry is pq_step;
//! this module never calls PqState::pass directly. It is pure: no I/O,
//! no key bytes, no peer id in any output.
//!
//! Mapping (section 3.4.2): Proceed sends the offer; Send holds while the
//! hybrid handshake is in flight (this is the normal first-call stage, not
//! a refusal); Hold waits to re-evaluate; Refuse means the call cannot be
//! placed. Collapsing Send into an error is the regression 3.11 forbids.

use super::super::pq::Pass;

/// Why the gate is holding the offer instead of sending it (section 3.4.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateHold {
    /// `Pass::Send`: the hybrid handshake is being sent first; wait for it
    /// to establish, then re-evaluate. The offer is not sent yet.
    HandshakeInFlight,
    /// `Pass::Hold`: the exchange is mid-flight; wait briefly and re-evaluate.
    Reevaluate,
}

/// The gate decision about originating a call, derived solely from a `Pass`.
/// Carries no peer id and no key material; the refusal reason is the stable,
/// secret-free string from `PqcRefusal::reason_str`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateDecision {
    /// Hybrid session established: send the offer and go to `calling`.
    Proceed,
    /// Do not send the offer; stay idle and hold. The variant says why.
    Hold(GateHold),
    /// The call cannot be placed (3.4.1 / 3.7.3). `reason` is the stable
    /// string shown to the person; it carries no peer id (3.11).
    Refuse { reason: &'static str },
}

impl GateDecision {
    /// True only for `Proceed`: the one case a `CALL_OFFER` may be sent.
    #[inline]
    pub fn may_send_offer(self) -> bool {
        matches!(self, GateDecision::Proceed)
    }
}

/// Map a `Pass` from `ChatCore::pq_step` to the call-origination decision.
#[inline]
pub fn decide_origination(pass: &Pass) -> GateDecision {
    match pass {
        Pass::Proceed => GateDecision::Proceed,
        Pass::Send(_) => GateDecision::Hold(GateHold::HandshakeInFlight),
        Pass::Hold => GateDecision::Hold(GateHold::Reevaluate),
        Pass::Refuse(refusal) => GateDecision::Refuse {
            reason: refusal.reason_str(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::pq::{PqcRefusal, FAIL_EXCHANGE, FAIL_NO_HYBRID};
    use super::*;

    #[test]
    fn proceed_sends_offer() {
        let d = decide_origination(&Pass::Proceed);
        assert_eq!(d, GateDecision::Proceed);
        assert!(d.may_send_offer());
    }

    #[test]
    fn hold_holds_for_reevaluation() {
        let d = decide_origination(&Pass::Hold);
        assert_eq!(d, GateDecision::Hold(GateHold::Reevaluate));
        assert!(!d.may_send_offer());
    }

    #[test]
    fn refuse_peer_lacks_pqc_is_stable_reason_without_peer_id() {
        let d = decide_origination(&Pass::Refuse(PqcRefusal::PeerLacksPqc { peer: [7u8; 32] }));
        assert_eq!(
            d,
            GateDecision::Refuse {
                reason: FAIL_NO_HYBRID
            }
        );
        assert!(!d.may_send_offer());
        if let GateDecision::Refuse { reason } = d {
            assert_eq!(reason, "pqc_peer_no_hybrid");
        }
    }

    #[test]
    fn refuse_downgrade_is_stable_reason() {
        let d = decide_origination(&Pass::Refuse(PqcRefusal::PqcDowngradeRefused {
            peer: [9u8; 32],
        }));
        assert_eq!(
            d,
            GateDecision::Refuse {
                reason: FAIL_EXCHANGE
            }
        );
    }
}
