//! Protocol-level building blocks that are independent of any one transport.
//!
//! * [`capability`]: versioned capability sets and degrade-to-common-level
//!   negotiation. A build never refuses to talk to an older or newer build
//!   only because of its version; it settles on the highest level both sides
//!   understand and reports (visibly) when that is below what it wanted.
//! * [`fragment`]: framing and bounded reassembly for handshake messages that
//!   are larger than one transport unit.
//!
//! * `hybrid` (only with the `pqc` cargo feature): X25519 + ML-KEM-768 key
//!   exchange with transcript binding and downgrade detection.
//!
//! `capability` and `fragment` are libraries; `hybrid` is used by exactly one
//! live path: the upgrade of private-conversation sessions
//! (`chat::pq`, default `prefer`, `pqc` feature). Nothing else uses them.

pub mod capability;
pub mod fragment;
#[cfg(feature = "pqc")]
pub mod hybrid;
#[cfg(all(test, feature = "pqc"))]
mod hybrid_kat_tests;

#[cfg(test)]
mod feature_gate_tests {
    /// With the feature off the module does not exist and the dependency is
    /// not compiled; with it on the module is present.
    #[test]
    fn hybrid_module_follows_the_feature() {
        #[cfg(not(feature = "pqc"))]
        {
            assert!(!cfg!(feature = "pqc"));
            // `super::hybrid` would not resolve here; the capability suite
            // bit stays reserved and negotiation is unaffected.
            let g = super::capability::negotiate(
                &super::capability::Capabilities::current(),
                &super::capability::Capabilities::current(),
                &super::capability::Requirements::default(),
            )
            .unwrap();
            assert!(!g.downgraded);
        }
        #[cfg(feature = "pqc")]
        {
            assert_eq!(super::hybrid::KEX_VERSION, 1);
        }
    }
}
