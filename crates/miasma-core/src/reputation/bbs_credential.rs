/// BBS+ reputation credential — Phase 3 (Task 18).
///
/// # Credential fields
/// ```text
/// uptime_score:    u8  — percentage of expected uptime in last 30 days (0-100)
/// serves_per_hour: u16 — average share-serve rate
/// tier:            u8  — 0=baseline, 1=trusted, 2=backbone
/// issued_at:       u64 — Unix timestamp of issuance
/// expires_at:      u64 — Unix timestamp of expiry
/// ```
///
/// # Selective disclosure
/// A node can prove `uptime_score ≥ 80` without revealing `serves_per_hour`
/// or its exact `uptime_score` value.
///
/// # Phase 3 integration plan
/// Replace the stub below with a real BBS+ implementation using the `bbs_plus`
/// crate (or `ark-bbs`). The verifier key is distributed via the DHT
/// (bootstrapped from hardcoded genesis keys).
use serde::{Deserialize, Serialize};

// ─── Credential ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationCredential {
    /// Node's contribution metrics.
    pub uptime_score: u8,
    pub serves_per_hour: u16,
    pub tier: u8,
    pub issued_at: u64,
    pub expires_at: u64,
    /// BBS+ signature bytes (Phase 3: replace stub with real BBS+ signature).
    pub signature: Vec<u8>,
}

impl ReputationCredential {
    /// Create a new credential (Phase 3: issuer signs with BBS+ key).
    pub fn new(
        uptime_score: u8,
        serves_per_hour: u16,
        tier: u8,
        issued_at: u64,
        ttl_secs: u64,
        issuer_signing_key: &[u8],
    ) -> Self {
        // Phase 3: compute real BBS+ signature over the credential fields.
        // Stub: BLAKE3 of concatenated fields as placeholder.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[uptime_score, tier]);
        hasher.update(&serves_per_hour.to_le_bytes());
        hasher.update(&issued_at.to_le_bytes());
        hasher.update(issuer_signing_key);
        let sig = hasher.finalize().as_bytes().to_vec();

        Self {
            uptime_score,
            serves_per_hour,
            tier,
            issued_at,
            expires_at: issued_at + ttl_secs,
            signature: sig,
        }
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }
}

// ─── Proof ────────────────────────────────────────────────────────────────────

/// A zero-knowledge proof derived from a `ReputationCredential`.
///
/// Proves one or more threshold claims without revealing the full credential.
///
/// Example claim: "uptime_score ≥ 80" disclosed; `serves_per_hour` hidden.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationProof {
    /// Which fields are disclosed (bit flags: bit 0 = uptime_score, bit 1 = tier, …).
    pub disclosed_fields: u8,
    /// Disclosed field values (in field order, only for disclosed fields).
    pub disclosed_values: Vec<u64>,
    /// ZK proof bytes (Phase 3: replace with real BBS+ proof-of-knowledge).
    pub proof_bytes: Vec<u8>,
    /// The threshold claims this proof satisfies (serialised as JSON for now).
    pub claims_json: String,
}

impl ReputationProof {
    /// Derive a proof from a credential, disclosing only `uptime_score ≥ threshold`.
    ///
    /// Phase 3: replace with a real BBS+ PoK proof.
    pub fn prove_uptime_threshold(
        cred: &ReputationCredential,
        threshold: u8,
        nonce: &[u8],
    ) -> Option<Self> {
        if cred.uptime_score < threshold {
            return None; // Cannot prove — credential doesn't satisfy claim.
        }

        // Phase 3: compute BBS+ proof-of-knowledge here.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&cred.signature);
        hasher.update(nonce);
        hasher.update(&[threshold]);
        let proof_bytes = hasher.finalize().as_bytes().to_vec();

        Some(Self {
            disclosed_fields: 0b0000_0001, // uptime_score disclosed
            disclosed_values: vec![cred.uptime_score as u64],
            proof_bytes,
            claims_json: format!("{{\"uptime_score_gte\":{threshold}}}"),
        })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_expiry() {
        let cred = ReputationCredential::new(90, 100, 1, 1000, 3600, b"issuer_key");
        assert!(!cred.is_expired(1000));
        assert!(!cred.is_expired(4599));
        assert!(cred.is_expired(4600));
    }

    #[test]
    fn proof_prove_threshold_pass() {
        let cred = ReputationCredential::new(85, 50, 0, 0, 86400, b"key");
        let proof = ReputationProof::prove_uptime_threshold(&cred, 80, b"nonce123");
        assert!(proof.is_some());
        let p = proof.unwrap();
        assert_eq!(p.disclosed_values[0], 85);
        assert!(p.claims_json.contains("80"));
    }

    #[test]
    fn proof_prove_threshold_fail() {
        let cred = ReputationCredential::new(50, 50, 0, 0, 86400, b"key");
        let proof = ReputationProof::prove_uptime_threshold(&cred, 80, b"nonce");
        assert!(proof.is_none());
    }
}
