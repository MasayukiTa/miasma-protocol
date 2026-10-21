//! The file wrap: the root key is wrapped under a 32-byte wrapping secret that
//! is kept in a file of the data directory.
//!
//! This is the stand-in for an operating-system key store. It gives the sealed
//! form its full shape (header, record, authenticated wrap, atomic files) on
//! every platform, but it does not protect the key from someone who can read the
//! whole data directory. Providers backed by an OS key store replace it later
//! through the same [`DeviceWrap`] trait.
//!
//! `wrap` = XChaCha20-Poly1305 under `HKDF-SHA256(wrapping secret)`, with a
//! random 24-byte nonce, the record's `aad`, and the output laid out as
//! `nonce || ciphertext || tag`.

use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::provider::{Availability, DestroyOutcome, DeviceWrap, ProviderId, WrapError};
use crate::secure_memory::SecureBytes;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

pub struct FileWrap;

impl std::fmt::Debug for FileWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileWrap")
    }
}

fn secret_path(data_dir: &Path) -> std::path::PathBuf {
    crate::paths::WRAP_SECRET.in_dir(data_dir)
}

fn read_secret(data_dir: &Path) -> Result<Zeroizing<[u8; 32]>, WrapError> {
    let bytes = match std::fs::read(secret_path(data_dir)) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(WrapError::KeyGone),
        Err(e) => return Err(WrapError::Io(e)),
    };
    if bytes.len() != 32 {
        return Err(WrapError::Corrupt);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The wrapping secret, created on first use. Two processes that create it at
/// the same time end up with the same secret: the file is never replaced.
fn load_or_create_secret(data_dir: &Path) -> Result<Zeroizing<[u8; 32]>, WrapError> {
    match read_secret(data_dir) {
        Err(WrapError::KeyGone) => {}
        other => return other,
    }
    std::fs::create_dir_all(data_dir)?;
    let mut fresh = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, fresh.as_mut());
    super::durable::write_new(&secret_path(data_dir), fresh.as_ref())?;
    read_secret(data_dir)
}

fn cipher(secret: &[u8; 32]) -> XChaCha20Poly1305 {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"miasma/root-wrap/file/v1", kek.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    XChaCha20Poly1305::new(kek.as_ref().into())
}

impl DeviceWrap for FileWrap {
    fn id(&self) -> ProviderId {
        ProviderId::File
    }

    fn available(&self) -> Availability {
        Availability::Ready
    }

    fn wrap(&self, data_dir: &Path, aad: &[u8], root: &[u8; 32]) -> Result<Vec<u8>, WrapError> {
        let secret = load_or_create_secret(data_dir)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher(&secret)
            .encrypt(&nonce, Payload { msg: root, aad })
            .map_err(|_| WrapError::Corrupt)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap(
        &self,
        data_dir: &Path,
        aad: &[u8],
        wrapped: &[u8],
    ) -> Result<SecureBytes<32>, WrapError> {
        if wrapped.len() != NONCE_LEN + 32 + TAG_LEN {
            return Err(WrapError::Corrupt);
        }
        let secret = read_secret(data_dir)?;
        let (nonce, ct) = wrapped.split_at(NONCE_LEN);
        let plain = Zeroizing::new(
            cipher(&secret)
                .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
                .map_err(|_| WrapError::Corrupt)?,
        );
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&plain);
        Ok(SecureBytes::from_slice(&key))
    }

    /// The wrapping secret is a file of the data directory; the registry wipe
    /// removes it. Nothing lives outside.
    fn destroy(&self, _data_dir: &Path) -> Result<DestroyOutcome, WrapError> {
        Ok(DestroyOutcome::NothingToDestroy)
    }
}
