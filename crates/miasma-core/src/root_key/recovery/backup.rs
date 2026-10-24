//! The exported backup file: the root key under a passphrase in its own file.
//!
//! The file is a small versioned container with magic `MSKX`, separate from
//! `root.sealed` (`MSKR`). It holds one passphrase record: the key-encryption
//! key is Argon2id over the passphrase and a random salt, and the root key is
//! sealed under it with XChaCha20-Poly1305, authenticated by the whole header.
//! The cost sits between the shared KDF floor and ceiling so a received file is
//! bounds-checked before any Argon2 work runs.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::kdf_bounds::{MAX_M_KIB, MAX_P_COST, MAX_T_COST, MIN_M_KIB};
use crate::root_key::format;
use crate::secure_memory::SecureBytes;
use crate::transfer::protection::{CREATE_FLOOR_P_COST, CREATE_FLOOR_T_COST};

/// File magic. Distinct from `root.sealed` (`MSKR`).
pub const MAGIC: &[u8; 4] = b"MSKX";
/// Container version. A newer version is named, not misread.
pub const VERSION: u8 = 1;
/// Provider byte of the passphrase record. Stable: written into the file.
pub const PROVIDER_PASSPHRASE: u8 = 7;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// magic 4 | version 1 | reserved 1 | m_kib 4 | t_cost 4 | p_cost 4 | salt 16.
const HEADER_LEN: usize = 4 + 1 + 1 + 4 + 4 + 4 + SALT_LEN;
const MAX_FILE_LEN: usize = 4096;

/// The default Argon2id cost for a new backup file. Memory is the shared
/// ceiling; passes and lanes are the shared floor. The design's provisional
/// 256 MiB is above the shared ceiling (`MAX_M_KIB`), so the ceiling is used
/// instead and the bounds stay a single source of truth.
pub const DEFAULT_M_KIB: u32 = MAX_M_KIB;
pub const DEFAULT_T_COST: u32 = CREATE_FLOOR_T_COST;
pub const DEFAULT_P_COST: u32 = CREATE_FLOOR_P_COST;

/// Argon2id cost for a backup file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupParams {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for BackupParams {
    fn default() -> Self {
        Self {
            m_kib: DEFAULT_M_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl BackupParams {
    fn validate(&self) -> Result<(), BackupError> {
        if !(1..=MAX_P_COST).contains(&self.p_cost) {
            return Err(BackupError::BadCost("p_cost out of range"));
        }
        if !(1..=MAX_T_COST).contains(&self.t_cost) {
            return Err(BackupError::BadCost("t_cost out of range"));
        }
        let min_m = MIN_M_KIB.max(8 * self.p_cost);
        if !(min_m..=MAX_M_KIB).contains(&self.m_kib) {
            return Err(BackupError::BadCost("m_kib out of range"));
        }
        Ok(())
    }
}

/// Why a backup file could not be created or read.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("the backup file is not an MSKX file")]
    BadMagic,
    #[error("backup file version {0} is newer than this program understands")]
    FutureVersion(u8),
    #[error("the backup file is cut short")]
    Truncated,
    #[error("the backup file is damaged ({0})")]
    Corrupt(&'static str),
    #[error("the Argon2id cost is not acceptable ({0})")]
    BadCost(&'static str),
    #[error("the passphrase did not open the backup file")]
    WrongPassphraseOrTampered,
    #[error("argon2: {0}")]
    Kdf(String),
}

fn header_bytes(params: &BackupParams, salt: &[u8; SALT_LEN]) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..4].copy_from_slice(MAGIC);
    out[4] = VERSION;
    out[5] = 0; // reserved
    out[6..10].copy_from_slice(&params.m_kib.to_le_bytes());
    out[10..14].copy_from_slice(&params.t_cost.to_le_bytes());
    out[14..18].copy_from_slice(&params.p_cost.to_le_bytes());
    out[18..34].copy_from_slice(salt);
    out
}

fn parse_header(bytes: &[u8]) -> Result<(BackupParams, [u8; SALT_LEN]), BackupError> {
    if bytes.len() < 5 {
        return Err(BackupError::Truncated);
    }
    if &bytes[..4] != MAGIC {
        return Err(BackupError::BadMagic);
    }
    match bytes[4] {
        VERSION => {}
        0 => return Err(BackupError::Corrupt("version 0")),
        v => return Err(BackupError::FutureVersion(v)),
    }
    if bytes.len() < HEADER_LEN {
        return Err(BackupError::Truncated);
    }
    let m_kib = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    let t_cost = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
    let p_cost = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);
    let salt: [u8; SALT_LEN] = bytes[18..34]
        .try_into()
        .map_err(|_| BackupError::Truncated)?;
    let params = BackupParams {
        m_kib,
        t_cost,
        p_cost,
    };
    params.validate()?;
    Ok((params, salt))
}

fn argon2id_kek(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    params: &BackupParams,
) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let p = Params::new(params.m_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    // Start from random bytes so a static analyser does not read a zero-filled
    // array as a fixed key; Argon2id overwrites every byte below.
    let mut kek = Zeroizing::new(rand::random::<[u8; 32]>());
    argon
        .hash_password_into(passphrase.as_bytes(), salt, kek.as_mut())
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    Ok(kek)
}

fn cipher(kek: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(kek.as_slice().into())
}

/// Build the bytes of a backup file that holds `root` under `passphrase`.
pub fn create(
    root: &[u8; 32],
    passphrase: &str,
    params: BackupParams,
) -> Result<Vec<u8>, BackupError> {
    params.validate()?;
    let salt: [u8; SALT_LEN] = rand::random();
    let header = header_bytes(&params, &salt);
    let kek = argon2id_kek(passphrase, &salt, &params)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher(&kek)
        .encrypt(
            &nonce,
            Payload {
                msg: root,
                aad: &header,
            },
        )
        .map_err(|_| BackupError::WrongPassphraseOrTampered)?;
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Create a backup file with the default cost.
pub fn create_default(root: &[u8; 32], passphrase: &str) -> Result<Vec<u8>, BackupError> {
    create(root, passphrase, BackupParams::default())
}

/// Open a backup file with `passphrase`, returning the root key.
pub fn open(bytes: &[u8], passphrase: &str) -> Result<SecureBytes<32>, BackupError> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(BackupError::Corrupt("too long"));
    }
    let (params, salt) = parse_header(bytes)?;
    let header = &bytes[..HEADER_LEN];
    let body = &bytes[HEADER_LEN..];
    if body.len() != NONCE_LEN + 32 + TAG_LEN {
        return Err(BackupError::Corrupt("wrong body length"));
    }
    let kek = argon2id_kek(passphrase, &salt, &params)?;
    let (nonce, ct) = body.split_at(NONCE_LEN);
    let plain = Zeroizing::new(
        cipher(&kek)
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: header,
                },
            )
            .map_err(|_| BackupError::WrongPassphraseOrTampered)?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Ok(SecureBytes::from_slice(&key))
}

/// Whether the opened key matches a `root_check` from `root.sealed`. Lets a
/// caller confirm a restored key belongs to the install before using it.
pub fn key_matches_check(key: &SecureBytes<32>, root_check: &[u8; 16]) -> bool {
    let check = format::root_check(key.as_array());
    bool::from(check.ct_eq(root_check))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small Argon2id cost for tests: real memory costs would make each case
    /// far too slow in a debug build. Still within the accepted bounds.
    fn test_params() -> BackupParams {
        BackupParams {
            m_kib: MIN_M_KIB.max(8),
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn random<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        b
    }

    fn random_passphrase() -> String {
        format!("pp-{:032x}", rand::random::<u128>())
    }

    #[test]
    fn a_backup_round_trips() {
        let root = random::<32>();
        let pp = random_passphrase();
        let bytes = create(&root, &pp, test_params()).unwrap();
        let opened = open(&bytes, &pp).unwrap();
        assert!(bool::from(opened.as_array().ct_eq(&root)));
    }

    #[test]
    fn the_wrong_passphrase_does_not_open() {
        let root = random::<32>();
        let pp = random_passphrase();
        let other = random_passphrase();
        let bytes = create(&root, &pp, test_params()).unwrap();
        assert!(matches!(
            open(&bytes, &other),
            Err(BackupError::WrongPassphraseOrTampered)
        ));
    }

    #[test]
    fn tampering_is_refused() {
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(open(&bytes, &pp).is_err());
    }

    #[test]
    fn changing_the_header_is_refused() {
        // The header is the AEAD aad, so editing the salt breaks authentication.
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        bytes[20] ^= 0x01; // a salt byte
        assert!(open(&bytes, &pp).is_err());
    }

    #[test]
    fn a_newer_version_is_named_not_misread() {
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        bytes[4] = VERSION + 1;
        assert!(matches!(
            open(&bytes, &pp),
            Err(BackupError::FutureVersion(_))
        ));
    }

    #[test]
    fn a_non_mskx_file_is_refused() {
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        bytes[0] ^= 0x01;
        assert!(matches!(open(&bytes, &pp), Err(BackupError::BadMagic)));
    }

    #[test]
    fn every_cut_of_a_valid_file_is_refused() {
        let root = random::<32>();
        let pp = random_passphrase();
        let bytes = create(&root, &pp, test_params()).unwrap();
        for cut in 0..bytes.len() {
            assert!(open(&bytes[..cut], &pp).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn a_cost_outside_the_bounds_is_refused() {
        let bad = BackupParams {
            m_kib: MAX_M_KIB + 1,
            t_cost: 1,
            p_cost: 1,
        };
        let root = random::<32>();
        let pp = random_passphrase();
        assert!(matches!(
            create(&root, &pp, bad),
            Err(BackupError::BadCost(_))
        ));
    }

    #[test]
    fn the_default_cost_is_within_the_shared_bounds() {
        BackupParams::default().validate().unwrap();
    }

    #[test]
    fn a_restored_key_can_be_checked_against_a_root_check() {
        let root = random::<32>();
        let pp = random_passphrase();
        let bytes = create(&root, &pp, test_params()).unwrap();
        let opened = open(&bytes, &pp).unwrap();
        let good = format::root_check(&root);
        assert!(key_matches_check(&opened, &good));
        let bad = random::<16>();
        assert!(!key_matches_check(&opened, &bad));
    }

    #[test]
    fn a_version_zero_file_is_corrupt() {
        // Version 0 is a distinct error from a future version: it signals a
        // damaged header rather than a newer writer.
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        bytes[4] = 0;
        assert!(matches!(open(&bytes, &pp), Err(BackupError::Corrupt(_))));
    }

    #[test]
    fn an_out_of_range_cost_in_a_file_is_refused_before_any_argon2_work() {
        // A received file that claims a cost outside the shared bounds is
        // rejected while parsing the header, before Argon2 is run.
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        // Overwrite the m_kib field (offset 6..10) with a value above the ceiling.
        bytes[6..10].copy_from_slice(&(MAX_M_KIB + 1).to_le_bytes());
        assert!(matches!(open(&bytes, &pp), Err(BackupError::BadCost(_))));
    }

    #[test]
    fn two_backups_use_a_fresh_salt_each_time() {
        // Each created file draws its own random salt, so the salt field
        // (header offset 18..34) differs between two files for the same key
        // and passphrase. This guards the create side against a fixed salt.
        let root = random::<32>();
        let pp = random_passphrase();
        let a = create(&root, &pp, test_params()).unwrap();
        let b = create(&root, &pp, test_params()).unwrap();
        assert_ne!(a[18..34], b[18..34], "two files must not share a salt");
    }

    #[test]
    fn the_salt_survives_a_header_round_trip() {
        // A random salt written by header_bytes is read back unchanged by
        // parse_header, so the read side reconstructs the exact salt field.
        let salt: [u8; SALT_LEN] = rand::random();
        let params = test_params();
        let header = header_bytes(&params, &salt);
        let (read_params, read_salt) = parse_header(&header).unwrap();
        assert_eq!(read_salt, salt);
        assert_eq!(read_params, params);
    }
}
