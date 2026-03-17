/// ZK Reputation system — Phase 3 (Task 18).
///
/// # Design overview
/// Miasma nodes earn *reputation* by reliably serving shares.  Reputation is
/// used as a Sybil-resistance mechanism: nodes that consistently answer
/// requests gain a "reputation token" that they can show to peers in order
/// to receive preferential routing.
///
/// **Privacy constraint**: reputation proofs must NOT reveal the node's
/// identity. We use BBS+ signatures for selective disclosure:
///   1. A reputation issuer (initially: bootstrap nodes) signs a credential
///      containing the node's anonymised contribution metrics.
///   2. The node generates a zero-knowledge proof of possession of a valid
///      credential — without revealing the credential itself.
///   3. Other nodes verify the ZK proof to decide whether to service a request.
///
/// # BBS+ baseline (< 10ms on mobile — Task 18 requirement)
/// - Credential: `{ uptime_score: u8, serves_per_hour: u16, version: u8 }`
/// - Proof: selective disclosure of `uptime_score ≥ threshold` without
///   revealing `serves_per_hour`.
///
/// # Groth16 optional path (Task 18 — high-value trustless verification)
/// For high-value DHT operations (publishing large content), a Groth16 proof
/// can be requested.  This provides stronger guarantees but costs ~200ms on
/// mobile.
///
/// # Phase 3 implementation plan
/// - Add `bbs` crate for BBS+ signatures.
/// - Implement `ReputationCredential`, `ReputationProof`, `ReputationVerifier`.
/// - Integrate with `OnionAwareDhtExecutor`: attach proof to DHT put/get.
pub mod bbs_credential;
pub mod verifier;

pub use bbs_credential::{ReputationCredential, ReputationProof};
pub use verifier::ReputationVerifier;
