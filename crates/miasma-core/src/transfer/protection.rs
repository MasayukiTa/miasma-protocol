//! Password protection for segmented transfers.
//!
//! The password is an *encryption factor*, not an access-control list: it is
//! mixed into the key that encrypts every segment, so holding the MID and every
//! shard is not enough to decrypt anything.
//!
//! ```text
//! pw_key = Argon2id(password, salt, m, t, p)
//! K_seg  = HKDF-SHA256(ikm = K_enc, salt = pw_key,
//!                      info = "miasma-seg-key-v1" || mid || segment_index)
//! ```
//!
//! `K_enc` is still a fresh random key per segment, Shamir-split across the
//! shards exactly as in the unprotected path, so nothing that operates on
//! shards changes. Binding `mid` and `segment_index` into the HKDF `info`
//! means a key for one segment can never decrypt another, and a different
//! transfer of the same file with the same password gets different keys.
//!
//! `key_check` lets a receiver reject a wrong password before downloading a
//! single piece. It reveals nothing an attacker holding ciphertext does not
//! already have (the AEAD tag on segment 0 is an offline password oracle
//! regardless); Argon2id is what bounds that.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{crypto::hash::ContentId, MiasmaError};

const LABEL_SEGMENT_KEY: &[u8] = b"miasma-seg-key-v1";
const LABEL_KEY_CHECK: &[u8] = b"miasma-pw-check-v1";

/// Length of the public Argon2id salt.
pub const SALT_LEN: usize = 16;
/// Length of the wrong-password check tag.
pub const KEY_CHECK_LEN: usize = 16;

/// Default Argon2id cost: the same as directed sharing (64 MiB, 3 passes).
pub const DEFAULT_M_KIB: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;

/// Upper bounds accepted from an *untrusted* manifest. Without them a hostile
/// sender could make a receiver allocate gigabytes just to check a password.
///
/// `create` uses 64 MiB / 3 passes / 1 lane (the defaults above) and nothing in
/// the CLI or desktop picks another cost, so the ceiling is twice the memory,
/// twice the passes and twice the lanes of what is actually produced: room to
/// raise the default later, far below what a hostile manifest could ask for.
/// A manifest above it is refused before any KDF work runs.
pub const MAX_M_KIB: u32 = 128 * 1024;
pub const MAX_T_COST: u32 = 6;
pub const MAX_P_COST: u32 = 2;
/// Argon2 itself requires `m >= 8 * p` KiB.
pub const MIN_M_KIB: u32 = 8;

/// How a transfer's segments are keyed on top of the per-segment random key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protection {
    /// `K_seg == K_enc` — identical to a plain (pre-transfer-manifest) dissolve.
    None,
    Password(PasswordProtection),
}

impl Protection {
    pub fn is_password(&self) -> bool {
        matches!(self, Protection::Password(_))
    }
}

/// Public parameters of a password-protected transfer. Contains no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordProtection {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
    pub key_check: [u8; KEY_CHECK_LEN],
}

/// Argon2id output for one password + salt. Never serialized; wiped on drop.
pub struct UnlockedKey {
    pw_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for UnlockedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockedKey(<redacted>)")
    }
}

impl PasswordProtection {
    /// Start a protected transfer with a fresh random salt and default cost.
    pub fn create(password: &str) -> Result<(Self, UnlockedKey), MiasmaError> {
        Self::create_with_cost(password, DEFAULT_M_KIB, DEFAULT_T_COST, DEFAULT_P_COST)
    }

    /// As [`create`](Self::create) with an explicit Argon2id cost (used by tests
    /// to avoid a 64 MiB derivation per case in a debug build).
    pub fn create_with_cost(
        password: &str,
        m_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<(Self, UnlockedKey), MiasmaError> {
        validate_cost(m_kib, t_cost, p_cost)?;
        let salt: [u8; SALT_LEN] = rand::rngs::OsRng.gen();
        let pw_key = argon2id(password, &salt, m_kib, t_cost, p_cost)?;
        let key_check = key_check_tag(&pw_key)?;
        Ok((
            Self {
                m_kib,
                t_cost,
                p_cost,
                salt,
                key_check,
            },
            UnlockedKey { pw_key },
        ))
    }

    /// Derive the key for `password` and confirm it against `key_check`.
    ///
    /// Returns [`MiasmaError::WrongPassword`] on mismatch, *before* any data has
    /// been fetched. The cost parameters come from an untrusted manifest, so
    /// they are bounds-checked first.
    pub fn unlock(&self, password: &str) -> Result<UnlockedKey, MiasmaError> {
        validate_cost(self.m_kib, self.t_cost, self.p_cost)?;
        let pw_key = argon2id(password, &self.salt, self.m_kib, self.t_cost, self.p_cost)?;
        let tag = key_check_tag(&pw_key)?;
        if bool::from(tag.ct_eq(&self.key_check)) {
            Ok(UnlockedKey { pw_key })
        } else {
            Err(MiasmaError::WrongPassword)
        }
    }

    /// Structural validity, for a manifest that has not been unlocked yet.
    pub fn validate(&self) -> Result<(), MiasmaError> {
        validate_cost(self.m_kib, self.t_cost, self.p_cost)
    }
}

impl UnlockedKey {
    /// Derive the AES-256-GCM key for one segment from its random `K_enc`.
    pub fn segment_key(
        &self,
        k_enc: &[u8],
        mid: &ContentId,
        segment_index: u32,
    ) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
        let mut info = Vec::with_capacity(LABEL_SEGMENT_KEY.len() + 32 + 4);
        info.extend_from_slice(LABEL_SEGMENT_KEY);
        info.extend_from_slice(mid.as_bytes());
        info.extend_from_slice(&segment_index.to_le_bytes());

        let hk = Hkdf::<Sha256>::new(Some(self.pw_key.as_ref()), k_enc);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(&info, out.as_mut())
            .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
        Ok(out)
    }
}

fn validate_cost(m_kib: u32, t_cost: u32, p_cost: u32) -> Result<(), MiasmaError> {
    if !(1..=MAX_P_COST).contains(&p_cost) {
        return Err(MiasmaError::InvalidManifest(format!(
            "argon2 p_cost {p_cost} outside 1..={MAX_P_COST}"
        )));
    }
    if !(1..=MAX_T_COST).contains(&t_cost) {
        return Err(MiasmaError::InvalidManifest(format!(
            "argon2 t_cost {t_cost} outside 1..={MAX_T_COST}"
        )));
    }
    let min_m = MIN_M_KIB.max(8 * p_cost);
    if !(min_m..=MAX_M_KIB).contains(&m_kib) {
        return Err(MiasmaError::InvalidManifest(format!(
            "argon2 m_kib {m_kib} outside {min_m}..={MAX_M_KIB}"
        )));
    }
    Ok(())
}

fn argon2id(
    password: &str,
    salt: &[u8; SALT_LEN],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let params = Params::new(m_kib, t_cost, p_cost, Some(32))
        .map_err(|e| MiasmaError::Encryption(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|e| MiasmaError::Encryption(format!("argon2 hash: {e}")))?;
    Ok(out)
}

fn key_check_tag(pw_key: &[u8; 32]) -> Result<[u8; KEY_CHECK_LEN], MiasmaError> {
    let hk = Hkdf::<Sha256>::new(None, pw_key);
    // Output buffer only: HKDF-Expand overwrites every byte of it.
    let mut tag = <[u8; KEY_CHECK_LEN]>::default();
    hk.expand(LABEL_KEY_CHECK, &mut tag)
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(tag)
}

/// A fresh random password, for tests: no test carries a fixed secret.
#[cfg(test)]
pub(crate) fn random_test_password() -> String {
    format!("pw-{:032x}", rand::random::<u128>())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap Argon2id for tests: 64 KiB, 1 pass. The default (64 MiB x 3) is far
    // too slow to run per case in a debug build.
    const M: u32 = 64;
    const T: u32 = 1;
    const P: u32 = 1;

    fn mid(tag: u8) -> ContentId {
        ContentId::compute(&[tag; 16], b"k=10,n=20,v=1")
    }

    #[test]
    fn unlock_with_the_right_password_succeeds() {
        let pw = random_test_password();
        let (prot, created) = PasswordProtection::create_with_cost(&pw, M, T, P).unwrap();
        let unlocked = prot.unlock(&pw).unwrap();
        // Both derivations must yield the same segment key.
        let k_enc = [7u8; 32];
        let a = created.segment_key(&k_enc, &mid(1), 0).unwrap();
        let b = unlocked.segment_key(&k_enc, &mid(1), 0).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn wrong_password_is_rejected_before_any_data_is_needed() {
        let pw = random_test_password();
        let other = random_test_password();
        let (prot, _) = PasswordProtection::create_with_cost(&pw, M, T, P).unwrap();
        assert!(matches!(
            prot.unlock(&other),
            Err(MiasmaError::WrongPassword)
        ));
        // Empty and near-miss passwords are wrong too.
        let empty = String::new();
        assert!(matches!(
            prot.unlock(&empty),
            Err(MiasmaError::WrongPassword)
        ));
        assert!(matches!(
            prot.unlock(&format!("{pw} ")),
            Err(MiasmaError::WrongPassword)
        ));
    }

    #[test]
    fn segment_key_is_bound_to_mid_segment_index_and_k_enc() {
        let pw = random_test_password();
        let (_, key) = PasswordProtection::create_with_cost(&pw, M, T, P).unwrap();
        let k_enc = [9u8; 32];
        let base = key.segment_key(&k_enc, &mid(1), 0).unwrap();

        let other_segment = key.segment_key(&k_enc, &mid(1), 1).unwrap();
        let other_mid = key.segment_key(&k_enc, &mid(2), 0).unwrap();
        let other_k_enc = key.segment_key(&[8u8; 32], &mid(1), 0).unwrap();

        assert_ne!(base.as_ref(), other_segment.as_ref());
        assert_ne!(base.as_ref(), other_mid.as_ref());
        assert_ne!(base.as_ref(), other_k_enc.as_ref());
    }

    #[test]
    fn same_password_different_transfer_gets_a_different_key() {
        // Fresh random salt per transfer: two protections of the same password
        // must not share key material.
        let pw = random_test_password();
        let (p1, k1) = PasswordProtection::create_with_cost(&pw, M, T, P).unwrap();
        let (p2, k2) = PasswordProtection::create_with_cost(&pw, M, T, P).unwrap();
        assert_ne!(p1.salt, p2.salt);
        let k_enc = [3u8; 32];
        assert_ne!(
            k1.segment_key(&k_enc, &mid(1), 0).unwrap().as_ref(),
            k2.segment_key(&k_enc, &mid(1), 0).unwrap().as_ref()
        );
    }

    #[test]
    fn the_password_never_appears_in_debug_output() {
        let pw = random_test_password();
        let (prot, key) = PasswordProtection::create_with_cost(&pw, M, T, P).unwrap();
        assert!(!format!("{prot:?}").contains(&pw));
        assert!(!format!("{key:?}").contains(&pw));
        assert_eq!(format!("{key:?}"), "UnlockedKey(<redacted>)");
    }

    #[test]
    fn hostile_argon2_parameters_from_a_manifest_are_refused_not_executed() {
        let pw = random_test_password();
        let (mut prot, _) = PasswordProtection::create_with_cost(&pw, M, T, P).unwrap();

        // 4 GiB of memory: must be rejected by validation, not attempted.
        prot.m_kib = 4 * 1024 * 1024;
        assert!(matches!(
            prot.unlock(&pw),
            Err(MiasmaError::InvalidManifest(_))
        ));
        prot.m_kib = M;

        prot.t_cost = 0;
        assert!(prot.unlock(&pw).is_err());
        prot.t_cost = 10_000;
        assert!(prot.unlock(&pw).is_err());
        prot.t_cost = T;

        prot.p_cost = 0;
        assert!(prot.unlock(&pw).is_err());
        prot.p_cost = 64;
        assert!(prot.unlock(&pw).is_err());
    }

    #[test]
    fn the_ceiling_is_close_to_what_create_produces() {
        // Not a free-for-all: at most 2x the default memory, passes and lanes.
        assert!(MAX_M_KIB <= 2 * DEFAULT_M_KIB);
        assert!(MAX_T_COST <= 2 * DEFAULT_T_COST);
        assert!(MAX_P_COST <= 2 * DEFAULT_P_COST);
        // What create() makes is always acceptable.
        assert!(validate_cost(DEFAULT_M_KIB, DEFAULT_T_COST, DEFAULT_P_COST).is_ok());
        // The old ceiling (256 MiB) is now refused.
        assert!(validate_cost(256 * 1024, 3, 1).is_err());
    }

    #[test]
    fn creating_with_out_of_range_cost_is_refused() {
        let pw = random_test_password();
        assert!(PasswordProtection::create_with_cost(&pw, 1, 1, 1).is_err());
        assert!(PasswordProtection::create_with_cost(&pw, MAX_M_KIB + 1, 1, 1).is_err());
    }

    /// Prints how long the *default* cost takes on this machine. Ignored: it is
    /// a measurement, not a correctness test, and slow in a debug build.
    #[test]
    #[ignore]
    fn measure_default_argon2id_cost() {
        let t0 = std::time::Instant::now();
        let pw = random_test_password();
        let (prot, _) = PasswordProtection::create(&pw).unwrap();
        let create = t0.elapsed();
        let t1 = std::time::Instant::now();
        prot.unlock(&pw).unwrap();
        println!(
            "argon2id default (m={} KiB, t={}, p={}): create {create:?}, unlock {:?}",
            DEFAULT_M_KIB,
            DEFAULT_T_COST,
            DEFAULT_P_COST,
            t1.elapsed()
        );
    }
}
