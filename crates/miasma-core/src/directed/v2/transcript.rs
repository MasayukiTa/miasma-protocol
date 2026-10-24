//! Header and transcript: the canonical bytes the sender signs (§3.3).
//!
//! All header fields are fixed length and little-endian, so no length prefixes
//! are needed. `H_hdr` folds the header; `sig_msg` folds `H_hdr` together with
//! the outer ciphertext hashes and the sharing-key binding; the signature and
//! the transcript hash follow from `sig_msg`.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Label for the header digest.
const HEADER_LABEL: &str = "miasma directed v2 header";
/// Label for the envelope signature digest.
const SIG_LABEL: &str = "miasma directed v2 envelope signature";

/// The header fields, in canonical order (§3.3 rows 1-13).
pub struct Header<'a> {
    /// Protocol version (= 2).
    pub version: u8,
    /// Suite selector (= 2).
    pub suite: u8,
    /// Envelope identifier.
    pub envelope_id: &'a [u8; 32],
    /// Sender's Ed25519 identity public key.
    pub sender_identity: &'a [u8; 32],
    /// Sender's X25519 sharing key.
    pub sender_pubkey: &'a [u8; 32],
    /// Recipient's Ed25519 identity public key.
    pub recipient_identity: &'a [u8; 32],
    /// Recipient's X25519 sharing key (`R_static`).
    pub recipient_pubkey: &'a [u8; 32],
    /// Sender ephemeral public key (`e_s`).
    pub ephemeral_pubkey: &'a [u8; 32],
    /// Recipient ephemeral public key (`r_eph`).
    pub recipient_ephemeral: &'a [u8; 32],
    /// Offer identifier.
    pub offer_id: &'a [u8; 16],
    /// Argon2id memory cost (KiB).
    pub kdf_m_kib: u32,
    /// Argon2id time cost.
    pub kdf_t_cost: u32,
    /// Argon2id parallelism.
    pub kdf_p_cost: u32,
    /// Argon2id salt.
    pub password_salt: &'a [u8; 32],
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Expiry timestamp (Unix seconds).
    pub expires_at: u64,
    /// Retention in seconds.
    pub retention_secs: u64,
}

/// Total length in bytes of the canonical header.
pub const HEADER_LEN: usize =
    1 + 1 + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 16 + (4 * 3) + 32 + (8 * 3);

impl Header<'_> {
    /// Serialise the header into its canonical byte string.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN);
        v.push(self.version);
        v.push(self.suite);
        v.extend_from_slice(self.envelope_id);
        v.extend_from_slice(self.sender_identity);
        v.extend_from_slice(self.sender_pubkey);
        v.extend_from_slice(self.recipient_identity);
        v.extend_from_slice(self.recipient_pubkey);
        v.extend_from_slice(self.ephemeral_pubkey);
        v.extend_from_slice(self.recipient_ephemeral);
        v.extend_from_slice(self.offer_id);
        v.extend_from_slice(&self.kdf_m_kib.to_le_bytes());
        v.extend_from_slice(&self.kdf_t_cost.to_le_bytes());
        v.extend_from_slice(&self.kdf_p_cost.to_le_bytes());
        v.extend_from_slice(self.password_salt);
        v.extend_from_slice(&self.created_at.to_le_bytes());
        v.extend_from_slice(&self.expires_at.to_le_bytes());
        v.extend_from_slice(&self.retention_secs.to_le_bytes());
        v
    }

    /// Compute `H_hdr`.
    pub fn h_hdr(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(HEADER_LABEL);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }
}

/// The outer values that bind the ciphertexts to the signature.
pub struct OuterRefs<'a> {
    /// Nonce of the payload AEAD.
    pub payload_nonce: &'a [u8; 24],
    /// Ciphertext of the payload AEAD.
    pub encrypted_payload: &'a [u8],
    /// Nonce of the DEK wrap.
    pub dek_nonce: &'a [u8; 24],
    /// Wrapped DEK.
    pub wrapped_dek: &'a [u8],
    /// Sender's sharing-key binding signature.
    pub sender_binding: &'a [u8; 64],
}

/// Compute `sig_msg` from `H_hdr` and the outer values (§3.3).
pub fn sig_msg(h_hdr: &[u8; 32], outer: &OuterRefs<'_>) -> [u8; 32] {
    let payload_hash = *blake3::hash(outer.encrypted_payload).as_bytes();
    let dek_hash = *blake3::hash(outer.wrapped_dek).as_bytes();
    let mut h = blake3::Hasher::new_derive_key(SIG_LABEL);
    h.update(h_hdr);
    h.update(outer.payload_nonce);
    h.update(&payload_hash);
    h.update(outer.dek_nonce);
    h.update(&dek_hash);
    h.update(outer.sender_binding);
    *h.finalize().as_bytes()
}

/// Sign `sig_msg` with the sender's identity key.
pub fn sign_transcript(sender_sk: &SigningKey, sig_msg: &[u8; 32]) -> [u8; 64] {
    sender_sk.sign(sig_msg).to_bytes()
}

/// Verify the transcript signature against `sender_identity`.
pub fn verify_transcript(
    sender_identity: &[u8; 32],
    sig_msg: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    let vk = match VerifyingKey::from_bytes(sender_identity) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    vk.verify_strict(sig_msg, &Signature::from_bytes(signature))
        .is_ok()
}

/// Compute `transcript_hash = BLAKE3(sig_msg ‖ signature)`.
pub fn transcript_hash(sig_msg: &[u8; 32], signature: &[u8; 64]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(sig_msg);
    h.update(signature);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Vals {
        envelope_id: [u8; 32],
        sender_identity: [u8; 32],
        sender_pubkey: [u8; 32],
        recipient_identity: [u8; 32],
        recipient_pubkey: [u8; 32],
        ephemeral_pubkey: [u8; 32],
        recipient_ephemeral: [u8; 32],
        offer_id: [u8; 16],
        password_salt: [u8; 32],
    }

    fn vals() -> Vals {
        Vals {
            envelope_id: rand::random(),
            sender_identity: rand::random(),
            sender_pubkey: rand::random(),
            recipient_identity: rand::random(),
            recipient_pubkey: rand::random(),
            ephemeral_pubkey: rand::random(),
            recipient_ephemeral: rand::random(),
            offer_id: rand::random(),
            password_salt: rand::random(),
        }
    }

    fn header(v: &Vals) -> Header<'_> {
        Header {
            version: 2,
            suite: 2,
            envelope_id: &v.envelope_id,
            sender_identity: &v.sender_identity,
            sender_pubkey: &v.sender_pubkey,
            recipient_identity: &v.recipient_identity,
            recipient_pubkey: &v.recipient_pubkey,
            ephemeral_pubkey: &v.ephemeral_pubkey,
            recipient_ephemeral: &v.recipient_ephemeral,
            offer_id: &v.offer_id,
            kdf_m_kib: 65536,
            kdf_t_cost: 3,
            kdf_p_cost: 1,
            password_salt: &v.password_salt,
            created_at: 1_700_000_000,
            expires_at: 1_700_003_600,
            retention_secs: 3600,
        }
    }

    #[test]
    fn the_header_has_the_declared_length() {
        let v = vals();
        assert_eq!(header(&v).canonical_bytes().len(), HEADER_LEN);
    }

    #[test]
    fn h_hdr_is_deterministic_for_the_same_header() {
        let v = vals();
        assert_eq!(header(&v).h_hdr(), header(&v).h_hdr());
    }

    #[test]
    fn changing_one_header_field_changes_h_hdr() {
        let v = vals();
        let base = header(&v).h_hdr();
        let mut v2 = vals();
        v2.envelope_id = v.envelope_id;
        v2.sender_identity = v.sender_identity;
        v2.sender_pubkey = v.sender_pubkey;
        v2.recipient_identity = v.recipient_identity;
        v2.recipient_pubkey = v.recipient_pubkey;
        v2.ephemeral_pubkey = v.ephemeral_pubkey;
        v2.recipient_ephemeral = v.recipient_ephemeral;
        v2.offer_id = v.offer_id;
        v2.password_salt = v.password_salt;
        // Only expires_at differs below.
        let mut h2 = header(&v2);
        h2.expires_at = header(&v).expires_at + 1;
        assert_ne!(base, h2.h_hdr());
    }

    fn outer_vals() -> ([u8; 24], Vec<u8>, [u8; 24], Vec<u8>, [u8; 64]) {
        (
            rand::random(),
            rand::random::<[u8; 40]>().to_vec(),
            rand::random(),
            rand::random::<[u8; 48]>().to_vec(),
            rand::random(),
        )
    }

    #[test]
    fn a_transcript_signature_verifies_and_rejects_tampering() {
        let sk = SigningKey::from_bytes(&rand::random());
        let sender_identity = sk.verifying_key().to_bytes();
        let v = vals();
        let h = header(&v).h_hdr();
        let (pn, ep, dn, wd, sb) = outer_vals();
        let outer = OuterRefs {
            payload_nonce: &pn,
            encrypted_payload: &ep,
            dek_nonce: &dn,
            wrapped_dek: &wd,
            sender_binding: &sb,
        };
        let sm = sig_msg(&h, &outer);
        let sig = sign_transcript(&sk, &sm);
        assert!(verify_transcript(&sender_identity, &sm, &sig));

        // Flip one byte of the payload ciphertext: sig_msg changes, verify fails.
        let mut ep2 = ep.clone();
        ep2[0] ^= 0x01;
        let outer2 = OuterRefs {
            encrypted_payload: &ep2,
            ..outer
        };
        let sm2 = sig_msg(&h, &outer2);
        assert_ne!(sm, sm2);
        assert!(!verify_transcript(&sender_identity, &sm2, &sig));
    }

    #[test]
    fn transcript_hash_is_deterministic() {
        let sk = SigningKey::from_bytes(&rand::random());
        let v = vals();
        let h = header(&v).h_hdr();
        let (pn, ep, dn, wd, sb) = outer_vals();
        let outer = OuterRefs {
            payload_nonce: &pn,
            encrypted_payload: &ep,
            dek_nonce: &dn,
            wrapped_dek: &wd,
            sender_binding: &sb,
        };
        let sm = sig_msg(&h, &outer);
        let sig = sign_transcript(&sk, &sm);
        assert_eq!(transcript_hash(&sm, &sig), transcript_hash(&sm, &sig));
    }
}
