//! The exported backup file: the root key under a passphrase in its own file.
//!
//! The file is a small self-describing container with magic `MSKX`, separate
//! from `root.sealed` (`MSKR`). It reuses the record frame of
//! [`crate::root_key::format`]: a short header followed by one record that
//! names its `provider`, `kdf_id`, and `kdf_params`, so a reader checks those
//! fields before it runs any Argon2id work. The single record is the passphrase
//! wrap (`provider = PROVIDER_PASSPHRASE`, `kdf_id = KDF_ARGON2ID`): its
//! `kdf_params` hold the Argon2id cost and salt, and its `wrapped` holds the
//! XChaCha20-Poly1305 nonce and ciphertext. The key-encryption key is Argon2id
//! over the passphrase and the salt; the whole header and the record head are
//! the AEAD aad.
//!
//! This format is pre-release: there is no compatibility with the earlier
//! simplified MSKX layout, and none is needed.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::kdf_bounds::{MAX_M_KIB, MAX_P_COST, MAX_T_COST, MIN_M_KIB};
use crate::root_key::format::{self, Record, KDF_ARGON2ID, RECORD_RECOVERY};
use crate::secure_memory::SecureBytes;
use crate::transfer::protection::{CREATE_FLOOR_P_COST, CREATE_FLOOR_T_COST};

/// File magic. Distinct from `root.sealed` (`MSKR`).
pub const MAGIC: &[u8; 4] = b"MSKX";
/// Container version. A newer version is named, not misread.
pub const VERSION: u8 = 1;
/// Provider byte of the passphrase record. Stable: written into the file.
pub const PROVIDER_PASSPHRASE: u8 = 7;

/// Header: magic 4 | version 1 | flags 1.
const HEADER_LEN: usize = 4 + 1 + 1;
/// kdf_params of the passphrase record: m_kib 4 | t_cost 4 | p_cost 4 | salt 16.
const SALT_LEN: usize = 16;
const KDF_PARAMS_LEN: usize = 4 + 4 + 4 + SALT_LEN;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// A whole MSKX file is far smaller than this; it bounds a received file.
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

    /// Encode the cost and `salt` as the record's `kdf_params`.
    fn to_kdf_params(self, salt: &[u8; SALT_LEN]) -> Vec<u8> {
        let mut out = Vec::with_capacity(KDF_PARAMS_LEN);
        out.extend_from_slice(&self.m_kib.to_le_bytes());
        out.extend_from_slice(&self.t_cost.to_le_bytes());
        out.extend_from_slice(&self.p_cost.to_le_bytes());
        out.extend_from_slice(salt);
        out
    }

    /// Read the cost and salt from a record's `kdf_params`, checking the cost
    /// against the shared bounds before any Argon2id work is done.
    fn from_kdf_params(params: &[u8]) -> Result<(Self, [u8; SALT_LEN]), BackupError> {
        if params.len() != KDF_PARAMS_LEN {
            return Err(BackupError::Corrupt("kdf_params length"));
        }
        let m_kib = u32::from_le_bytes([params[0], params[1], params[2], params[3]]);
        let t_cost = u32::from_le_bytes([params[4], params[5], params[6], params[7]]);
        let p_cost = u32::from_le_bytes([params[8], params[9], params[10], params[11]]);
        let salt: [u8; SALT_LEN] = params[12..12 + SALT_LEN]
            .try_into()
            .map_err(|_| BackupError::Corrupt("kdf_params salt"))?;
        let params = BackupParams {
            m_kib,
            t_cost,
            p_cost,
        };
        params.validate()?;
        Ok((params, salt))
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

/// The 6-byte header bytes for a backup file.
fn header_bytes() -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..4].copy_from_slice(MAGIC);
    out[4] = VERSION;
    out[5] = 0; // flags: reserved
    out
}

/// The aad for the passphrase wrap: the whole header and the record head.
fn backup_aad(record: &Record) -> Vec<u8> {
    let mut aad = header_bytes().to_vec();
    aad.extend_from_slice(&record.head());
    aad
}

/// Parse and check the header, returning the offset of the first record.
fn parse_header(bytes: &[u8]) -> Result<usize, BackupError> {
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
    Ok(HEADER_LEN)
}

/// Parse the one passphrase record that follows the header. Checks the record
/// frame, the provider, and the kdf before returning: a received file that is
/// not a passphrase wrap is refused here, before any Argon2id work.
fn parse_record(
    bytes: &[u8],
    pos: usize,
) -> Result<(Record, BackupParams, [u8; SALT_LEN]), BackupError> {
    // Fixed part: rtype 1 | provider 1 | kdf_id 1 | params_len 2.
    let fixed = bytes.get(pos..pos + 5).ok_or(BackupError::Truncated)?;
    let rtype = fixed[0];
    let provider = fixed[1];
    let kdf_id = fixed[2];
    let params_len = u16::from_le_bytes([fixed[3], fixed[4]]) as usize;
    if rtype != RECORD_RECOVERY {
        return Err(BackupError::Corrupt("unexpected record type"));
    }
    if provider != PROVIDER_PASSPHRASE {
        return Err(BackupError::Corrupt("unexpected provider"));
    }
    if kdf_id != KDF_ARGON2ID {
        return Err(BackupError::Corrupt("unexpected kdf"));
    }
    if params_len != KDF_PARAMS_LEN {
        return Err(BackupError::Corrupt("kdf_params length"));
    }
    let mut pos = pos + 5;
    let kdf_params = bytes
        .get(pos..pos + params_len)
        .ok_or(BackupError::Truncated)?
        .to_vec();
    pos += params_len;
    // Check the cost against the shared bounds before any Argon2id work.
    let (params, salt) = BackupParams::from_kdf_params(&kdf_params)?;
    let len_bytes = bytes.get(pos..pos + 4).ok_or(BackupError::Truncated)?;
    let wrapped_len =
        u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    pos += 4;
    if wrapped_len != NONCE_LEN + 32 + TAG_LEN {
        return Err(BackupError::Corrupt("wrong body length"));
    }
    let wrapped = bytes
        .get(pos..pos + wrapped_len)
        .ok_or(BackupError::Truncated)?
        .to_vec();
    pos += wrapped_len;
    if pos != bytes.len() {
        return Err(BackupError::Corrupt("trailing bytes"));
    }
    let record = Record {
        rtype,
        provider,
        kdf_id,
        kdf_params,
        wrapped,
    };
    Ok((record, params, salt))
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
///
/// The caller must normalise `passphrase` to Unicode NFKC before calling, so a
/// passphrase typed with differently composed but visually identical characters
/// still opens the file. This crate does not depend on a normalisation crate,
/// so normalisation is the caller's responsibility (see the module note).
pub fn create(
    root: &[u8; 32],
    passphrase: &str,
    params: BackupParams,
) -> Result<Vec<u8>, BackupError> {
    params.validate()?;
    let salt: [u8; SALT_LEN] = rand::random();
    let mut record = Record {
        rtype: RECORD_RECOVERY,
        provider: PROVIDER_PASSPHRASE,
        kdf_id: KDF_ARGON2ID,
        kdf_params: params.to_kdf_params(&salt),
        wrapped: Vec::new(),
    };
    let aad = backup_aad(&record);
    let kek = argon2id_kek(passphrase, &salt, &params)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher(&kek)
        .encrypt(
            &nonce,
            Payload {
                msg: root,
                aad: &aad,
            },
        )
        .map_err(|_| BackupError::WrongPassphraseOrTampered)?;
    let mut wrapped = Vec::with_capacity(NONCE_LEN + ct.len());
    wrapped.extend_from_slice(nonce.as_slice());
    wrapped.extend_from_slice(&ct);
    record.wrapped = wrapped;

    let mut out = Vec::with_capacity(HEADER_LEN + 5 + KDF_PARAMS_LEN + 4 + record.wrapped.len());
    out.extend_from_slice(&header_bytes());
    out.extend_from_slice(&record.head());
    out.extend_from_slice(&(record.wrapped.len() as u32).to_le_bytes());
    out.extend_from_slice(&record.wrapped);
    Ok(out)
}

/// Create a backup file with the default cost.
pub fn create_default(root: &[u8; 32], passphrase: &str) -> Result<Vec<u8>, BackupError> {
    create(root, passphrase, BackupParams::default())
}

/// Open a backup file with `passphrase`, returning the root key.
///
/// The caller must normalise `passphrase` to Unicode NFKC before calling, the
/// same form used when the file was created. This crate does not depend on a
/// normalisation crate, so normalisation is the caller's responsibility (see
/// the module note).
pub fn open(bytes: &[u8], passphrase: &str) -> Result<SecureBytes<32>, BackupError> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(BackupError::Corrupt("too long"));
    }
    let pos = parse_header(bytes)?;
    let (record, params, salt) = parse_record(bytes, pos)?;
    let aad = backup_aad(&record);
    // The record frame guarantees this length; split the stored nonce from the
    // ciphertext-and-tag.
    let kek = argon2id_kek(passphrase, &salt, &params)?;
    let (nonce, ct) = record.wrapped.split_at(NONCE_LEN);
    let plain = Zeroizing::new(
        cipher(&kek)
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| BackupError::WrongPassphraseOrTampered)?,
    );
    let mut key = Zeroizing::new(rand::random::<[u8; 32]>());
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

    /// The byte offset of the record's fixed part (rtype) in a file.
    const RECORD_START: usize = HEADER_LEN;
    /// The byte offset of the kdf_params within a file.
    const KDF_PARAMS_START: usize = HEADER_LEN + 5;

    #[test]
    fn a_backup_round_trips() {
        let root = random::<32>();
        let pp = random_passphrase();
        let bytes = create(&root, &pp, test_params()).unwrap();
        let opened = open(&bytes, &pp).unwrap();
        assert!(bool::from(opened.as_array().ct_eq(&root)));
    }

    #[test]
    fn the_file_is_self_describing_with_the_passphrase_record() {
        // The record frame names the passphrase provider and the Argon2id kdf,
        // so a reader can check them before doing any Argon2 work.
        let root = random::<32>();
        let pp = random_passphrase();
        let bytes = create(&root, &pp, test_params()).unwrap();
        assert_eq!(&bytes[..4], MAGIC);
        assert_eq!(bytes[4], VERSION);
        assert_eq!(bytes[RECORD_START], RECORD_RECOVERY);
        assert_eq!(bytes[RECORD_START + 1], PROVIDER_PASSPHRASE);
        assert_eq!(bytes[RECORD_START + 2], KDF_ARGON2ID);
        let params_len =
            u16::from_le_bytes([bytes[RECORD_START + 3], bytes[RECORD_START + 4]]) as usize;
        assert_eq!(params_len, KDF_PARAMS_LEN);
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
    fn changing_the_kdf_params_is_refused() {
        // The record head (which includes kdf_params) is the AEAD aad, so
        // editing a salt byte breaks authentication.
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        // A salt byte sits after m_kib|t_cost|p_cost (12 bytes) in kdf_params.
        bytes[KDF_PARAMS_START + 12] ^= 0x01;
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
    fn a_wrong_provider_is_refused() {
        // A record that is not the passphrase provider is refused while
        // parsing, before any Argon2 work. provider sits at RECORD_START + 1.
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        bytes[RECORD_START + 1] = PROVIDER_PASSPHRASE ^ 0x01;
        assert!(matches!(open(&bytes, &pp), Err(BackupError::Corrupt(_))));
    }

    #[test]
    fn a_wrong_kdf_is_refused() {
        // A record that does not name Argon2id is refused while parsing.
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        bytes[RECORD_START + 2] = KDF_ARGON2ID ^ 0x01;
        assert!(matches!(open(&bytes, &pp), Err(BackupError::Corrupt(_))));
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
        // rejected while parsing the record, before Argon2 is run. The m_kib
        // field is the first 4 bytes of kdf_params.
        let root = random::<32>();
        let pp = random_passphrase();
        let mut bytes = create(&root, &pp, test_params()).unwrap();
        bytes[KDF_PARAMS_START..KDF_PARAMS_START + 4]
            .copy_from_slice(&(MAX_M_KIB + 1).to_le_bytes());
        assert!(matches!(open(&bytes, &pp), Err(BackupError::BadCost(_))));
    }

    #[test]
    fn two_backups_use_a_fresh_salt_each_time() {
        // Each created file draws its own random salt, so the salt bytes within
        // kdf_params differ between two files for the same key and passphrase.
        let root = random::<32>();
        let pp = random_passphrase();
        let a = create(&root, &pp, test_params()).unwrap();
        let b = create(&root, &pp, test_params()).unwrap();
        let salt_a = &a[KDF_PARAMS_START + 12..KDF_PARAMS_START + 12 + SALT_LEN];
        let salt_b = &b[KDF_PARAMS_START + 12..KDF_PARAMS_START + 12 + SALT_LEN];
        assert_ne!(salt_a, salt_b, "two files must not share a salt");
    }
}
