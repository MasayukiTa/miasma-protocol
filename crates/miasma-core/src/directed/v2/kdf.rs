//! Key schedule and password hashing for v2 (§4.2, §4.3).
//!
//! Two Diffie-Hellman outputs are mixed with HKDF-SHA256. `dh1` ties the keys
//! to the recipient's static key; `dh2` ties them to the per-send ephemeral so
//! that, once `r_eph` is gone, past sends stay closed even if the static key
//! later leaks. The password hash enters only the wrap key, leaving the payload
//! preview password-free.

use zeroize::Zeroizing;

use crate::crypto::kdf_bounds::{MAX_M_KIB, MAX_P_COST, MAX_T_COST, MIN_M_KIB};
use crate::MiasmaError;

/// Extract salt for the key-exchange stage.
const SALT_KEX: &[u8] = b"miasma/directed/v2/kex";
/// Extract salt and info prefix for the wrap stage.
const SALT_WRAP: &[u8] = b"miasma/directed/v2/wrap";
/// Info prefix for the payload key.
const INFO_PAYLOAD: &[u8] = b"miasma/directed/v2/payload";
/// Info prefix for the content key.
const INFO_CONTENT: &[u8] = b"miasma/directed/v2/content";

/// Argon2id output length in bytes.
const PWH_LEN: usize = 32;

/// Compute `dh1 ‖ dh2` from the sender side (`e_s` secret, two public keys).
///
/// Both exchanges must be contributory.
pub fn dh_concat_sender(
    e_s_secret: &[u8; 32],
    r_static_pub: &[u8; 32],
    r_eph_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 64]>, MiasmaError> {
    let e_s = x25519_dalek::StaticSecret::from(*e_s_secret);
    dh_concat(&e_s, r_static_pub, r_eph_pub)
}

/// Compute `dh1 ‖ dh2` from the recipient side.
///
/// `dh1` uses the static secret; `dh2` uses the ephemeral secret; both pair with
/// the sender's ephemeral public key.
pub fn dh_concat_recipient(
    r_static_secret: &[u8; 32],
    r_eph_secret: &[u8; 32],
    e_s_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 64]>, MiasmaError> {
    let r_static = x25519_dalek::StaticSecret::from(*r_static_secret);
    let r_eph = x25519_dalek::StaticSecret::from(*r_eph_secret);
    let e_s_public = x25519_dalek::PublicKey::from(*e_s_pub);
    let dh1 = r_static.diffie_hellman(&e_s_public);
    if !dh1.was_contributory() {
        return Err(MiasmaError::KeyDerivation("non-contributory dh1".into()));
    }
    let dh2 = r_eph.diffie_hellman(&e_s_public);
    if !dh2.was_contributory() {
        return Err(MiasmaError::KeyDerivation("non-contributory dh2".into()));
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out[..32].copy_from_slice(dh1.as_bytes());
    out[32..].copy_from_slice(dh2.as_bytes());
    Ok(out)
}

fn dh_concat(
    e_s: &x25519_dalek::StaticSecret,
    r_static_pub: &[u8; 32],
    r_eph_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 64]>, MiasmaError> {
    let r_static = x25519_dalek::PublicKey::from(*r_static_pub);
    let r_eph = x25519_dalek::PublicKey::from(*r_eph_pub);
    let dh1 = e_s.diffie_hellman(&r_static);
    if !dh1.was_contributory() {
        return Err(MiasmaError::KeyDerivation("non-contributory dh1".into()));
    }
    let dh2 = e_s.diffie_hellman(&r_eph);
    if !dh2.was_contributory() {
        return Err(MiasmaError::KeyDerivation("non-contributory dh2".into()));
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out[..32].copy_from_slice(dh1.as_bytes());
    out[32..].copy_from_slice(dh2.as_bytes());
    Ok(out)
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new(rand::random::<[u8; 32]>());
    hk.expand(info, out.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

/// Derive `k_payload` from the key-exchange secret and `H_hdr` (§4.2).
pub fn derive_k_payload(
    dh_concat: &[u8; 64],
    h_hdr: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let mut info = Vec::with_capacity(INFO_PAYLOAD.len() + 32);
    info.extend_from_slice(INFO_PAYLOAD);
    info.extend_from_slice(h_hdr);
    hkdf_expand(SALT_KEX, dh_concat, &info)
}

/// Derive `k_wrap` from the key-exchange secret, the password hash and `H_hdr`.
pub fn derive_k_wrap(
    dh_concat: &[u8; 64],
    pwh: &[u8; 32],
    h_hdr: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64 + 32));
    ikm.extend_from_slice(dh_concat);
    ikm.extend_from_slice(pwh);
    let mut info = Vec::with_capacity(SALT_WRAP.len() + 32);
    info.extend_from_slice(SALT_WRAP);
    info.extend_from_slice(h_hdr);
    hkdf_expand(SALT_WRAP, &ikm, &info)
}

/// Derive `k_content` from the DEK (§4.2).
///
/// No salt; the info ties the key to the suite and envelope id.
pub fn derive_k_content(
    dek: &[u8; 32],
    suite: u8,
    envelope_id: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, dek);
    let mut info = Vec::with_capacity(INFO_CONTENT.len() + 1 + 32);
    info.extend_from_slice(INFO_CONTENT);
    info.push(suite);
    info.extend_from_slice(envelope_id);
    let mut out = Zeroizing::new(rand::random::<[u8; 32]>());
    hk.expand(&info, out.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

/// Check an Argon2id cost against the shared bounds before running any work.
///
/// Returns an error if the parameters fall outside the accepted window, so a
/// value from an untrusted sender is refused rather than executed.
pub fn check_kdf_bounds(m_kib: u32, t_cost: u32, p_cost: u32) -> Result<(), MiasmaError> {
    let oor = |what: &str| {
        Err(MiasmaError::KeyDerivation(format!(
            "kdf out of range: {what}"
        )))
    };
    if p_cost < 1 || p_cost > MAX_P_COST {
        return oor("p_cost");
    }
    if t_cost < 1 || t_cost > MAX_T_COST {
        return oor("t_cost");
    }
    if m_kib < MIN_M_KIB || m_kib > MAX_M_KIB {
        return oor("m_kib");
    }
    // Argon2 also requires m >= 8 * p.
    if m_kib < 8u32.saturating_mul(p_cost) {
        return oor("m_kib_vs_p");
    }
    Ok(())
}

/// Compute `pwh = Argon2id(password, salt, m, t, p, 32)` (§4.3).
///
/// The caller is expected to have run [`check_kdf_bounds`] first on any cost
/// that arrived from a peer.
pub fn password_hash(
    password: &str,
    salt: &[u8; 32],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; PWH_LEN]>, MiasmaError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_kib, t_cost, p_cost, Some(PWH_LEN))
        .map_err(|e| MiasmaError::KeyDerivation(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new(rand::random::<[u8; PWH_LEN]>());
    argon
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(format!("argon2 hash: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Party {
        r_static_secret: [u8; 32],
        r_static_pub: [u8; 32],
        r_eph_secret: [u8; 32],
        r_eph_pub: [u8; 32],
        e_s_secret: [u8; 32],
        e_s_pub: [u8; 32],
    }

    fn parties() -> Party {
        let r_static = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let r_eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let e_s = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        Party {
            r_static_secret: r_static.to_bytes(),
            r_static_pub: x25519_dalek::PublicKey::from(&r_static).to_bytes(),
            r_eph_secret: r_eph.to_bytes(),
            r_eph_pub: x25519_dalek::PublicKey::from(&r_eph).to_bytes(),
            e_s_secret: e_s.to_bytes(),
            e_s_pub: x25519_dalek::PublicKey::from(&e_s).to_bytes(),
        }
    }

    #[test]
    fn sender_and_recipient_reach_the_same_keys() {
        let p = parties();
        let h_hdr: [u8; 32] = rand::random();
        let dek: [u8; 32] = rand::random();
        let salt: [u8; 32] = rand::random();
        let pwh = password_hash("a correct horse", &salt, MIN_M_KIB.max(8), 1, 1).unwrap();

        let ds = dh_concat_sender(&p.e_s_secret, &p.r_static_pub, &p.r_eph_pub).unwrap();
        let dr = dh_concat_recipient(&p.r_static_secret, &p.r_eph_secret, &p.e_s_pub).unwrap();
        assert_eq!(&ds[..], &dr[..]);

        let kp_s = derive_k_payload(&ds, &h_hdr).unwrap();
        let kp_r = derive_k_payload(&dr, &h_hdr).unwrap();
        assert_eq!(&kp_s[..], &kp_r[..]);

        let kw_s = derive_k_wrap(&ds, &pwh, &h_hdr).unwrap();
        let kw_r = derive_k_wrap(&dr, &pwh, &h_hdr).unwrap();
        assert_eq!(&kw_s[..], &kw_r[..]);

        let kc_1 = derive_k_content(&dek, 2, &h_hdr).unwrap();
        let kc_2 = derive_k_content(&dek, 2, &h_hdr).unwrap();
        assert_eq!(&kc_1[..], &kc_2[..]);
    }

    #[test]
    fn changing_h_hdr_changes_the_derived_keys() {
        let p = parties();
        let h1: [u8; 32] = rand::random();
        let mut h2 = h1;
        h2[0] ^= 0x01;
        let ds = dh_concat_sender(&p.e_s_secret, &p.r_static_pub, &p.r_eph_pub).unwrap();
        assert_ne!(
            &derive_k_payload(&ds, &h1).unwrap()[..],
            &derive_k_payload(&ds, &h2).unwrap()[..]
        );
    }

    #[test]
    fn the_password_only_moves_the_wrap_key() {
        let p = parties();
        let h_hdr: [u8; 32] = rand::random();
        let salt: [u8; 32] = rand::random();
        let ds = dh_concat_sender(&p.e_s_secret, &p.r_static_pub, &p.r_eph_pub).unwrap();
        let pwh_a = password_hash("password one", &salt, MIN_M_KIB.max(8), 1, 1).unwrap();
        let pwh_b = password_hash("password two", &salt, MIN_M_KIB.max(8), 1, 1).unwrap();
        // payload key does not depend on the password.
        let kp = derive_k_payload(&ds, &h_hdr).unwrap();
        assert_eq!(&kp[..], &derive_k_payload(&ds, &h_hdr).unwrap()[..]);
        // wrap key moves with the password.
        let kw_a = derive_k_wrap(&ds, &pwh_a, &h_hdr).unwrap();
        let kw_b = derive_k_wrap(&ds, &pwh_b, &h_hdr).unwrap();
        assert_ne!(&kw_a[..], &kw_b[..]);
    }

    #[test]
    fn costs_outside_the_bounds_are_refused() {
        assert!(check_kdf_bounds(MAX_M_KIB, MAX_T_COST, MAX_P_COST).is_ok());
        assert!(check_kdf_bounds(MAX_M_KIB + 1, 3, 1).is_err());
        assert!(check_kdf_bounds(65536, MAX_T_COST + 1, 1).is_err());
        assert!(check_kdf_bounds(65536, 3, MAX_P_COST + 1).is_err());
        assert!(check_kdf_bounds(MIN_M_KIB - 1, 3, 1).is_err());
        assert!(check_kdf_bounds(65536, 3, 0).is_err());
        // m < 8*p.
        assert!(check_kdf_bounds(8, 3, 2).is_err());
    }

    #[test]
    fn a_non_contributory_public_key_is_rejected() {
        let p = parties();
        let zero = [0u8; 32];
        assert!(dh_concat_sender(&p.e_s_secret, &zero, &p.r_eph_pub).is_err());
    }
}
