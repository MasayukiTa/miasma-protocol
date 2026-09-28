/// Reputation proof verifier — Phase 3 (Task 18).
use super::bbs_credential::ReputationProof;

/// Verifies `ReputationProof` objects presented by remote peers.
///
/// Phase 3: replace stub verification with BBS+ proof-of-knowledge verification
/// using the issuer's public key (distributed via DHT genesis record).
pub struct ReputationVerifier {
    /// Issuer public key bytes (Phase 3: BBS+ public key).
    pub issuer_pubkey: Vec<u8>,
    /// Minimum uptime_score a peer must prove to receive service.
    pub min_uptime_threshold: u8,
}

impl ReputationVerifier {
    pub fn new(issuer_pubkey: Vec<u8>, min_uptime_threshold: u8) -> Self {
        Self {
            issuer_pubkey,
            min_uptime_threshold,
        }
    }

    /// Fail-closed until a real cryptographic verifier is implemented.
    ///
    /// The previous stub returned `true` for any non-empty `proof_bytes` once a
    /// prover-controlled disclosed value cleared the threshold. That makes this
    /// API unsafe to wire into authorization later by accident. Callers that
    /// intentionally bootstrap-trust a local configuration must use
    /// `allow_bypass()` explicitly instead.
    pub fn verify(&self, _proof: &ReputationProof, _nonce: &[u8]) -> bool {
        false
    }

    /// Convenience: bypass verification for nodes we bootstrap-trust.
    ///
    /// In Phase 1 all local nodes bypass reputation (no peers to verify).
    pub fn allow_bypass(&self) -> bool {
        self.min_uptime_threshold == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::bbs_credential::ReputationCredential;

    #[test]
    fn verifier_fails_closed_even_for_well_formed_stub_proof() {
        let cred = ReputationCredential::new(90, 100, 0, 0, 86400, b"key");
        let proof = ReputationProof::prove_uptime_threshold(&cred, 80, b"nonce").unwrap();
        let verifier = ReputationVerifier::new(b"key".to_vec(), 80);
        assert!(!verifier.verify(&proof, b"nonce"));
    }

    #[test]
    fn bootstrap_bypass_is_explicit_and_separate_from_verify() {
        let verifier = ReputationVerifier::new(Vec::new(), 0);
        assert!(verifier.allow_bypass());

        let fake_proof = ReputationProof {
            disclosed_fields: 0b0001,
            disclosed_values: vec![100],
            proof_bytes: vec![0xFF],
            claims_json: "{}".into(),
        };
        assert!(!verifier.verify(&fake_proof, b"nonce"));
    }

    #[test]
    fn verifier_rejects_low_uptime() {
        let _cred = ReputationCredential::new(50, 100, 0, 0, 86400, b"key");
        // Manually forge a proof with a low value.
        let fake_proof = ReputationProof {
            disclosed_fields: 0b0001,
            disclosed_values: vec![50],
            proof_bytes: vec![0xFF],
            claims_json: "{}".into(),
        };
        let verifier = ReputationVerifier::new(b"key".to_vec(), 80);
        assert!(!verifier.verify(&fake_proof, b"nonce"));
    }
}
