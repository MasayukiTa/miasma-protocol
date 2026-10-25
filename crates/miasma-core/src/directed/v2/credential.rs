//! Credential binding a node's Ed25519 identity to its X25519 sharing key.
//!
//! The sharing key is derived from the master key and does not rotate, so the
//! binding carries no expiry (§3.2). The signature is over a domain-separated
//! BLAKE3 digest of the two public keys, matching the identity-key signing
//! convention used elsewhere in the crate.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Domain-separation label for the sharing-key binding digest.
const BINDING_LABEL: &str = "miasma sharing key binding v1";

/// Compute the digest that the binding signature covers.
///
/// `identity_pub ‖ sharing_pub`, folded through a keyed BLAKE3 derive.
fn binding_digest(identity_pub: &[u8; 32], sharing_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(BINDING_LABEL);
    h.update(identity_pub);
    h.update(sharing_pub);
    *h.finalize().as_bytes()
}

/// Sign the binding of `sharing_pub` to `identity_sk`'s public identity.
///
/// Returns the 64-byte Ed25519 signature. Signing is deterministic, so a node
/// computes this once at startup.
pub fn sign_binding(identity_sk: &SigningKey, sharing_pub: &[u8; 32]) -> [u8; 64] {
    let identity_pub = identity_sk.verifying_key().to_bytes();
    let digest = binding_digest(&identity_pub, sharing_pub);
    identity_sk.sign(&digest).to_bytes()
}

/// Verify that `sig` binds `sharing_pub` to `identity_pub`.
///
/// Returns `true` only when the identity key is well-formed and the signature
/// verifies strictly over the binding digest.
pub fn verify_binding(identity_pub: &[u8; 32], sharing_pub: &[u8; 32], sig: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_bytes(identity_pub) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let digest = binding_digest(identity_pub, sharing_pub);
    vk.verify_strict(&digest, &Signature::from_bytes(sig))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&rand::random())
    }

    #[test]
    fn a_binding_signed_by_an_identity_verifies_for_that_identity() {
        let sk = signing_key();
        let sharing: [u8; 32] = rand::random();
        let sig = sign_binding(&sk, &sharing);
        let id = sk.verifying_key().to_bytes();
        assert!(verify_binding(&id, &sharing, &sig));
    }

    #[test]
    fn a_binding_under_a_different_sharing_key_fails() {
        let sk = signing_key();
        let sharing: [u8; 32] = rand::random();
        let sig = sign_binding(&sk, &sharing);
        let id = sk.verifying_key().to_bytes();
        let other_sharing: [u8; 32] = rand::random();
        assert!(!verify_binding(&id, &other_sharing, &sig));
    }

    #[test]
    fn a_binding_checked_against_a_different_identity_fails() {
        let sk = signing_key();
        let sharing: [u8; 32] = rand::random();
        let sig = sign_binding(&sk, &sharing);
        let other_id = signing_key().verifying_key().to_bytes();
        assert!(!verify_binding(&other_id, &sharing, &sig));
    }

    #[test]
    fn flipping_one_byte_of_the_signature_fails() {
        let sk = signing_key();
        let sharing: [u8; 32] = rand::random();
        let mut sig = sign_binding(&sk, &sharing);
        let id = sk.verifying_key().to_bytes();
        sig[0] ^= 0x01;
        assert!(!verify_binding(&id, &sharing, &sig));
    }
}
