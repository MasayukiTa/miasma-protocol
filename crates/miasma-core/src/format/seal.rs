//! Suite2 segment sealing: the v2 key schedule and the AAD-bound AES-256-GCM.
//!
//! The AES key is not `K_enc` and not the v1 segment key. It is
//!
//! ```text
//! K_aes = HKDF-SHA256(salt = pw_key or empty, ikm = K_enc,
//!                     info = "miasma-seg-key-v2" || AAD)
//! ct    = AES-256-GCM(K_aes, nonce, plaintext, aad = AAD)
//! ```
//!
//! where `AAD` is the 49 bytes of [`super::aad`]. Deriving the key from the
//! AAD as well as binding it means a version-tag rewrite fails at the key
//! stage, not only at the tag: a v1 decryptor using `K_enc` directly, or a v2
//! decryptor built from a different AAD, never reaches a matching key.
//!
//! [`seal_segment`] takes `K_enc` by value and wipes it, so one `K_enc` cannot
//! be sealed twice (see the `compile_fail` doc-test on that function).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::aead::{KEY_LEN, NONCE_LEN};

use super::aad::AAD_LEN;

/// The HKDF `info` label prefix for the Suite2 segment key. The 49-byte AAD is
/// appended to it.
pub const LABEL_SEGMENT_KEY_V2: &[u8] = b"miasma-seg-key-v2";

/// Derive the Suite2 AES-256-GCM key from the per-segment random `K_enc`, the
/// optional password key and the segment's AAD.
///
/// `pw_key` is the Argon2id output of a password-protected transfer, or `None`
/// for an unprotected one (HKDF with an empty salt). The AAD is the same 49
/// bytes that are bound into the AEAD.
///
/// HKDF-SHA256 over these fixed-length inputs does not fail, so this returns
/// the key directly; the only `Err` HKDF can raise is an output longer than
/// 255 hash blocks, and 32 bytes is one block.
fn derive_segment_key_v2(
    k_enc: &[u8; KEY_LEN],
    pw_key: Option<&[u8; 32]>,
    aad: &[u8; AAD_LEN],
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut info = Vec::with_capacity(LABEL_SEGMENT_KEY_V2.len() + AAD_LEN);
    info.extend_from_slice(LABEL_SEGMENT_KEY_V2);
    info.extend_from_slice(aad);

    let hk = Hkdf::<Sha256>::new(pw_key.map(|k| k.as_slice()), k_enc);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&info, out.as_mut())
        .expect("HKDF-SHA256 output of 32 bytes is one block and cannot fail");
    out
}

/// Seal one Suite2 segment.
///
/// Derives `K_aes` from `k_enc`, `pw_key` and `aad` (see
/// [`derive_segment_key_v2`]), then encrypts `plaintext` with AES-256-GCM under
/// that key, the given `nonce` and `aad` as associated data. Returns
/// `ciphertext || 16-byte tag`; the nonce is kept outside, exactly as the v1
/// path stores it in every share.
///
/// `k_enc` is consumed by value and wiped: one random key seals one segment.
/// Reusing a key is a compile error, not a run-time one:
///
/// ```compile_fail
/// use zeroize::Zeroizing;
/// use miasma_core::format::seal_segment;
/// # fn demo(aad: [u8; 49], nonce: [u8; 12]) {
/// let k_enc = Zeroizing::new([0u8; 32]);
/// let _ = seal_segment(k_enc, &nonce, b"first", &aad, None);
/// // `k_enc` was moved into the first call; a second use does not compile.
/// let _ = seal_segment(k_enc, &nonce, b"second", &aad, None);
/// # }
/// ```
pub fn seal_segment(
    k_enc: Zeroizing<[u8; KEY_LEN]>,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8; AAD_LEN],
    pw_key: Option<&[u8; 32]>,
) -> Vec<u8> {
    let key = derive_segment_key_v2(&k_enc, pw_key, aad);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM encryption of a bounded segment does not fail")
}

/// Open one Suite2 segment: the reverse of [`seal_segment`].
///
/// Derives the same `K_aes` and decrypts `ciphertext` (which includes the
/// 16-byte tag) with `nonce` and `aad`. A wrong key, a tampered ciphertext or
/// any mismatch in the AAD returns `None`.
///
/// `k_enc` is taken by reference here: opening the same segment more than once
/// (a retry, a re-read) is legitimate, unlike sealing.
pub fn open_segment(
    k_enc: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8; AAD_LEN],
    pw_key: Option<&[u8; 32]>,
) -> Option<Vec<u8>> {
    let key = derive_segment_key_v2(k_enc, pw_key, aad);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}
