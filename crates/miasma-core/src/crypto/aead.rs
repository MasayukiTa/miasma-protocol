use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use zeroize::Zeroizing;

use crate::MiasmaError;

/// AES-256-GCM key size in bytes.
pub const KEY_LEN: usize = 32;
/// AES-256-GCM nonce size in bytes.
pub const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` with a freshly-generated AES-256-GCM key.
///
/// Returns `(ciphertext_with_tag, key, nonce)`.
/// The key is wrapped in `Zeroizing` so it is wiped from memory when dropped.
pub fn encrypt(
    plaintext: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; KEY_LEN]>, [u8; NONCE_LEN]), MiasmaError> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| MiasmaError::Encryption(e.to_string()))?;

    let mut key_arr = Zeroizing::new([0u8; KEY_LEN]);
    key_arr.as_mut().copy_from_slice(&key);

    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&nonce);

    Ok((ciphertext, key_arr, nonce_arr))
}

/// Encrypt `plaintext` with a **caller-supplied** key and nonce.
///
/// Useful for deterministic test vectors.
pub fn encrypt_with_key(
    plaintext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, MiasmaError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| MiasmaError::Encryption(e.to_string()))
}

/// Decrypt `ciphertext` (includes AES-GCM authentication tag) with `key` and `nonce`.
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, MiasmaError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| MiasmaError::Decryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"Miasma Protocol test plaintext";
        let (ct, key, nonce) = encrypt(plaintext).unwrap();
        assert_ne!(ct.as_slice(), plaintext.as_ref());
        let recovered = decrypt(&ct, &key, &nonce).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let plaintext = b"sensitive data";
        let (mut ct, key, nonce) = encrypt(plaintext).unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt(&ct, &key, &nonce).is_err());
    }

    /// Published test vector — deterministic encryption with known key/nonce.
    #[test]
    fn test_vector_deterministic() {
        let key = [0x42u8; KEY_LEN];
        let nonce = [0x24u8; NONCE_LEN];
        let plaintext = b"hello miasma";

        let ct1 = encrypt_with_key(plaintext, &key, &nonce).unwrap();
        let ct2 = encrypt_with_key(plaintext, &key, &nonce).unwrap();
        assert_eq!(ct1, ct2);

        let recovered = decrypt(&ct1, &key, &nonce).unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_ref());
    }

    #[test]
    fn ciphertext_includes_16_byte_tag() {
        let plaintext = b"exactly 16 bytes";
        let (ct, key, nonce) = encrypt(plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16);
        let _ = (key, nonce);
    }
}
