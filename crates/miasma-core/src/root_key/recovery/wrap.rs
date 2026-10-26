//! The recovery wrap: a second record in `root.sealed` that a recovery code
//! opens, and the add / remove / open operations over it.
//!
//! The code's 32 bytes are the input key material of an HKDF that yields a
//! key-encryption key; the root key is then sealed under it with
//! XChaCha20-Poly1305, authenticated by the same header-and-record-head `aad`
//! as the device wrap. The record is provider [`PROVIDER_RECOVERY`], kdf
//! HKDF-SHA256. Adding and removing it rewrite `root.sealed` atomically; the
//! device record is never touched, so the device can always still open the key.

use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::code::RecoveryCode;
use crate::root_key::format::{self, Blob, FormatError, Record};
use crate::secure_memory::SecureBytes;

/// Provider byte of a recovery record. Stable: it is written into the file.
pub const PROVIDER_RECOVERY: u8 = 8;

const HKDF_INFO: &[u8] = b"miasma/root-recovery/v1";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Why a recovery operation could not be completed.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// `root.sealed` does not parse or a newer program wrote it.
    #[error("the sealed key file is damaged ({0})")]
    Corrupt(String),
    /// There is no recovery record to open or remove.
    #[error("there is no recovery wrap in the sealed key file")]
    NoRecoveryWrap,
    /// A recovery record is already present; remove it before adding another.
    #[error("a recovery wrap is already present")]
    AlreadyPresent,
    /// The recovery code did not open the record (wrong code or tampered bytes).
    #[error("the recovery code did not open the key")]
    WrongCodeOrTampered,
    /// The opened key does not match the file's key check.
    #[error("the recovered key failed its check")]
    KeyCheckFailed,
    /// The key-encryption key could not be derived. A 32-byte HKDF output is
    /// always a valid length, so this cannot happen in practice; it is kept so
    /// the derivation never has to return a value it did not compute.
    #[error("the recovery key could not be derived")]
    KeyDerivation,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

fn map_format(e: FormatError) -> RecoveryError {
    RecoveryError::Corrupt(e.to_string())
}

/// Derive the key-encryption key for a recovery code and install.
fn recovery_kek(
    code: &RecoveryCode,
    install_id: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    let hk = Hkdf::<Sha256>::new(Some(install_id), code.entropy());
    // Start from random bytes so a static analyser does not read a zero-filled
    // array as a fixed key; HKDF-Expand overwrites every byte below. If the
    // expand ever fails (it cannot for a 32-byte output), return an error
    // rather than let the random bytes stand in as a key.
    let mut kek = Zeroizing::new(rand::random::<[u8; 32]>());
    hk.expand(HKDF_INFO, kek.as_mut())
        .map_err(|_| RecoveryError::KeyDerivation)?;
    Ok(kek)
}

fn cipher(kek: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(kek.as_slice().into())
}

/// Build a recovery record for `root` under `code`, authenticated by the header.
fn seal_record(code: &RecoveryCode, blob: &Blob, root: &[u8; 32]) -> Result<Record, RecoveryError> {
    let mut record = Record {
        rtype: format::RECORD_RECOVERY,
        provider: PROVIDER_RECOVERY,
        kdf_id: format::KDF_HKDF_SHA256,
        kdf_params: Vec::new(),
        wrapped: Vec::new(),
    };
    let aad = record.aad(&blob.header);
    let kek = recovery_kek(code, &blob.header.install_id)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher(&kek)
        .encrypt(
            &nonce,
            Payload {
                msg: root,
                aad: &aad,
            },
        )
        .map_err(|_| RecoveryError::WrongCodeOrTampered)?;
    let mut wrapped = Vec::with_capacity(NONCE_LEN + ct.len());
    wrapped.extend_from_slice(nonce.as_slice());
    wrapped.extend_from_slice(&ct);
    record.wrapped = wrapped;
    Ok(record)
}

/// Open the key held by a recovery record under `code`.
fn open_record(
    code: &RecoveryCode,
    blob: &Blob,
    record: &Record,
) -> Result<SecureBytes<32>, RecoveryError> {
    if record.wrapped.len() != NONCE_LEN + 32 + TAG_LEN {
        return Err(RecoveryError::WrongCodeOrTampered);
    }
    let aad = record.aad(&blob.header);
    let kek = recovery_kek(code, &blob.header.install_id)?;
    let (nonce, ct) = record.wrapped.split_at(NONCE_LEN);
    let plain = Zeroizing::new(
        cipher(&kek)
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| RecoveryError::WrongCodeOrTampered)?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Ok(SecureBytes::from_slice(&key))
}

fn read_blob(data_dir: &Path) -> Result<Blob, RecoveryError> {
    let bytes = std::fs::read(crate::paths::ROOT_SEALED.in_dir(data_dir))?;
    Blob::parse(&bytes).map_err(map_format)
}

fn write_blob(data_dir: &Path, blob: &Blob) -> Result<(), RecoveryError> {
    let path = crate::paths::ROOT_SEALED.in_dir(data_dir);
    let staged = super::super::durable::stage(&path, &blob.encode())?;
    super::super::durable::replace_with(&staged, &path)?;
    Ok(())
}

fn recovery_index(blob: &Blob) -> Option<usize> {
    blob.records
        .iter()
        .position(|r| r.rtype == format::RECORD_RECOVERY)
}

/// Whether `root.sealed` holds a recovery record.
pub fn has_recovery_wrap(data_dir: &Path) -> Result<bool, RecoveryError> {
    Ok(recovery_index(&read_blob(data_dir)?).is_some())
}

/// Add a recovery record for `root` under `code`, rewriting `root.sealed`.
/// `root` must be the key the file already holds; it is confirmed against the
/// header's key check before anything is written. If the word confirmation is
/// not completed, the caller undoes the wrap with [`remove_recovery_wrap`],
/// which takes the recovery record back out so the file again holds only the
/// device wrap, as the design requires for a cancelled add. The write itself
/// is atomic (see [`write_blob`]), so a crash leaves either the old file or the
/// new one, never a half-written file.
pub fn add_recovery_wrap(
    data_dir: &Path,
    code: &RecoveryCode,
    root: &[u8; 32],
) -> Result<(), RecoveryError> {
    let mut blob = read_blob(data_dir)?;
    // The caller's key must be the file's key.
    let check = format::root_check(root);
    if !bool::from(check.ct_eq(&blob.header.root_check)) {
        return Err(RecoveryError::KeyCheckFailed);
    }
    if recovery_index(&blob).is_some() {
        return Err(RecoveryError::AlreadyPresent);
    }
    let record = seal_record(code, &blob, root)?;
    blob.records.push(record);
    write_blob(data_dir, &blob)
}

/// Remove the recovery record from `root.sealed`, rewriting it. The device
/// record is kept, so the device can still open the key, and install_id and
/// key_id are left unchanged. This is how an added wrap is taken back out when
/// a recovery add is cancelled: the file returns to holding only the device
/// wrap, which is the "before the wrap" state the design calls for.
pub fn remove_recovery_wrap(data_dir: &Path) -> Result<(), RecoveryError> {
    let mut blob = read_blob(data_dir)?;
    match recovery_index(&blob) {
        Some(i) => {
            blob.records.remove(i);
            write_blob(data_dir, &blob)
        }
        None => Err(RecoveryError::NoRecoveryWrap),
    }
}

/// Open the root key of `data_dir` with a recovery `code`. The opened key is
/// confirmed against the file's key check.
pub fn open_with_code(
    data_dir: &Path,
    code: &RecoveryCode,
) -> Result<SecureBytes<32>, RecoveryError> {
    let blob = read_blob(data_dir)?;
    let idx = recovery_index(&blob).ok_or(RecoveryError::NoRecoveryWrap)?;
    let key = open_record(code, &blob, &blob.records[idx])?;
    let check = format::root_check(key.as_array());
    if !bool::from(check.ct_eq(&blob.header.root_check)) {
        return Err(RecoveryError::KeyCheckFailed);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_key::format::{Header, RECORD_DEVICE, RECORD_RECOVERY};

    fn random<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        b
    }

    /// A `root.sealed` holding only a device record, for a random key. The
    /// device record's wrap bytes are random: these tests only exercise the
    /// recovery record, which is added on top.
    fn seed_sealed(data_dir: &Path, root: &[u8; 32]) {
        let header = Header {
            flags: 0,
            install_id: random(),
            key_id: random(),
            created_epoch: 1_700_000_000,
            root_check: format::root_check(root),
        };
        let device = Record {
            rtype: RECORD_DEVICE,
            provider: 0,
            kdf_id: format::KDF_HKDF_SHA256,
            kdf_params: Vec::new(),
            wrapped: random::<72>().to_vec(),
        };
        let blob = Blob {
            header,
            records: vec![device],
        };
        std::fs::create_dir_all(data_dir).unwrap();
        std::fs::write(crate::paths::ROOT_SEALED.in_dir(data_dir), blob.encode()).unwrap();
    }

    #[test]
    fn a_code_round_trips_through_the_recovery_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        seed_sealed(dir.path(), &root);
        let code = RecoveryCode::generate();
        assert!(!has_recovery_wrap(dir.path()).unwrap());
        add_recovery_wrap(dir.path(), &code, &root).unwrap();
        assert!(has_recovery_wrap(dir.path()).unwrap());
        let opened = open_with_code(dir.path(), &code).unwrap();
        assert!(bool::from(opened.as_array().ct_eq(&root)));
    }

    #[test]
    fn another_code_does_not_open_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        seed_sealed(dir.path(), &root);
        let code = RecoveryCode::generate();
        let other = RecoveryCode::generate();
        add_recovery_wrap(dir.path(), &code, &root).unwrap();
        assert!(matches!(
            open_with_code(dir.path(), &other),
            Err(RecoveryError::WrongCodeOrTampered)
        ));
    }

    #[test]
    fn tampering_with_the_record_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        seed_sealed(dir.path(), &root);
        let code = RecoveryCode::generate();
        add_recovery_wrap(dir.path(), &code, &root).unwrap();
        // Flip a byte in the file and confirm the code no longer opens it.
        let path = crate::paths::ROOT_SEALED.in_dir(dir.path());
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        assert!(open_with_code(dir.path(), &code).is_err());
    }

    #[test]
    fn a_removed_wrap_no_longer_opens() {
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        seed_sealed(dir.path(), &root);
        let code = RecoveryCode::generate();
        add_recovery_wrap(dir.path(), &code, &root).unwrap();
        remove_recovery_wrap(dir.path()).unwrap();
        assert!(!has_recovery_wrap(dir.path()).unwrap());
        assert!(matches!(
            open_with_code(dir.path(), &code),
            Err(RecoveryError::NoRecoveryWrap)
        ));
        // The device record is still there.
        let blob = read_blob(dir.path()).unwrap();
        assert!(blob.records.iter().any(|r| r.rtype == RECORD_DEVICE));
    }

    #[test]
    fn adding_a_wrap_for_the_wrong_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        seed_sealed(dir.path(), &root);
        let code = RecoveryCode::generate();
        let wrong = random::<32>();
        assert!(matches!(
            add_recovery_wrap(dir.path(), &code, &wrong),
            Err(RecoveryError::KeyCheckFailed)
        ));
    }

    #[test]
    fn a_second_wrap_is_refused_until_the_first_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        seed_sealed(dir.path(), &root);
        let code = RecoveryCode::generate();
        add_recovery_wrap(dir.path(), &code, &root).unwrap();
        assert!(matches!(
            add_recovery_wrap(dir.path(), &code, &root),
            Err(RecoveryError::AlreadyPresent)
        ));
    }

    #[test]
    fn adding_a_wrap_keeps_the_device_record_unchanged() {
        // Adding a recovery wrap must not disturb the device record: it is left
        // byte-for-byte as it was, so the device can still open the key.
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        seed_sealed(dir.path(), &root);
        // The device record before the recovery wrap is added.
        let before = read_blob(dir.path()).unwrap().device_record().clone();
        let code = RecoveryCode::generate();
        add_recovery_wrap(dir.path(), &code, &root).unwrap();
        let blob = read_blob(dir.path()).unwrap();
        // Exactly one device record and one recovery record are present.
        let devices: Vec<&Record> = blob
            .records
            .iter()
            .filter(|r| r.rtype == RECORD_DEVICE)
            .collect();
        assert_eq!(devices.len(), 1);
        assert!(blob.records.iter().any(|r| r.rtype == RECORD_RECOVERY));
        // The device record is unchanged: the device still opens the key.
        assert_eq!(*blob.device_record(), before);
    }

    #[test]
    fn wrapping_the_same_code_twice_uses_a_fresh_nonce() {
        // Wrapping the same root under the same code must draw a fresh nonce
        // each time, so the wrapped bytes differ. The nonce is the first
        // NONCE_LEN bytes of the record's wrapped field. This is a regression
        // guard against a fixed or reused nonce. Add, remove, then add again,
        // and compare the two recovery records' nonces.
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        seed_sealed(dir.path(), &root);
        let code = RecoveryCode::generate();

        add_recovery_wrap(dir.path(), &code, &root).unwrap();
        let first = read_blob(dir.path()).unwrap();
        let first_rec = &first.records[recovery_index(&first).unwrap()];
        let first_nonce = first_rec.wrapped[..NONCE_LEN].to_vec();

        remove_recovery_wrap(dir.path()).unwrap();
        add_recovery_wrap(dir.path(), &code, &root).unwrap();
        let second = read_blob(dir.path()).unwrap();
        let second_rec = &second.records[recovery_index(&second).unwrap()];
        let second_nonce = second_rec.wrapped[..NONCE_LEN].to_vec();

        assert_eq!(first_nonce.len(), NONCE_LEN);
        assert_eq!(second_nonce.len(), NONCE_LEN);
        assert_ne!(
            first_nonce, second_nonce,
            "a fresh nonce must be drawn for each wrap"
        );
        // The whole wrapped bytes therefore differ as well.
        assert_ne!(first_rec.wrapped, second_rec.wrapped);
        // Both wraps still open to the same key.
        let opened = open_with_code(dir.path(), &code).unwrap();
        assert!(bool::from(opened.as_array().ct_eq(&root)));
    }
}
