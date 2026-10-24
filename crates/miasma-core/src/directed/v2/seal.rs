//! Envelope sealing and opening for v2 (§4.4, §4.5).
//!
//! Three AEAD layers protect a send: the content key encrypts the body (bound
//! to suite and envelope id), the payload key encrypts the preview (bound to
//! the whole header through its AAD), and the wrap key wraps the DEK. The DEK
//! wrap needs `k_wrap`, which needs `r_eph`; without the recipient ephemeral
//! secret the wrap cannot be opened, so a past send stays closed once `r_eph`
//! is discarded.
//!
//! The `*_with` entry points take an RNG and a clock so tests are deterministic;
//! the shipping wrappers use `OsRng` and the system clock.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::MiasmaError;

use super::kdf;
use super::transcript::{self, Header, OuterRefs};

/// AAD prefixes (§4.4).
const AAD_PAYLOAD: &[u8] = b"miasma/directed/v2/payload-aad";
const AAD_WRAP: &[u8] = b"miasma/directed/v2/wrap-aad";
const AAD_CONTENT: &[u8] = b"miasma/directed/v2/content-aad";

/// Draw `N` random bytes from `rng` into a fresh array.
///
/// Used for AEAD nonces. The array is written from the RNG before it is read,
/// so no fixed value is assigned to a nonce.
fn random_array<const N: usize, R: RngCore + CryptoRng>(rng: &mut R) -> [u8; N] {
    let mut buf = [0u8; N];
    rng.fill_bytes(&mut buf);
    buf
}

fn xchacha_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MiasmaError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| MiasmaError::Encryption(e.to_string()))
}

fn xchacha_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MiasmaError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| MiasmaError::Decryption(e.to_string()))
}

/// Build `AAD_content` = prefix ‖ suite ‖ envelope_id.
fn content_aad(suite: u8, envelope_id: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(AAD_CONTENT.len() + 1 + 32);
    v.extend_from_slice(AAD_CONTENT);
    v.push(suite);
    v.extend_from_slice(envelope_id);
    v
}

fn header_aad(prefix: &[u8], h_hdr: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(prefix.len() + 32);
    v.extend_from_slice(prefix);
    v.extend_from_slice(h_hdr);
    v
}

/// Encrypt the body under a fresh content key derived from the DEK (§4.2, §4.4).
///
/// Returns `(content_nonce, ciphertext)`. The nonce comes from `rng`.
pub fn seal_content_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    dek: &[u8; 32],
    suite: u8,
    envelope_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; 24], Vec<u8>), MiasmaError> {
    let k_content = kdf::derive_k_content(dek, suite, envelope_id)?;
    let nonce: [u8; 24] = random_array(rng);
    let aad = content_aad(suite, envelope_id);
    let ct = xchacha_encrypt(&k_content, &nonce, plaintext, &aad)?;
    Ok((nonce, ct))
}

/// Open the body with the DEK (§4.2, §4.4).
pub fn open_content(
    dek: &[u8; 32],
    suite: u8,
    envelope_id: &[u8; 32],
    content_nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, MiasmaError> {
    let k_content = kdf::derive_k_content(dek, suite, envelope_id)?;
    let aad = content_aad(suite, envelope_id);
    xchacha_decrypt(&k_content, content_nonce, ciphertext, &aad)
}

/// The three outer ciphertexts a sealed v2 envelope carries.
pub struct SealedOuter {
    /// Nonce for the payload AEAD.
    pub payload_nonce: [u8; 24],
    /// Encrypted payload (preview, password-free).
    pub encrypted_payload: Vec<u8>,
    /// Nonce for the DEK wrap.
    pub dek_nonce: [u8; 24],
    /// Wrapped DEK (32 + 16 bytes).
    pub wrapped_dek: Vec<u8>,
}

/// Inputs needed to seal the payload and wrap the DEK against a header.
pub struct SealInput<'a> {
    /// `dh1 ‖ dh2` from the sender side.
    pub dh_concat: &'a [u8; 64],
    /// Argon2id password hash.
    pub pwh: &'a [u8; 32],
    /// The data-encryption key to wrap.
    pub dek: &'a [u8; 32],
    /// The serialized payload preview to encrypt.
    pub payload_plaintext: &'a [u8],
}

/// Seal the payload and wrap the DEK against `header` (§4.2, §4.4, §4.5).
///
/// Nonces come from `rng`. The header's `H_hdr` enters the AAD of both layers,
/// so any change to a header field makes both decryptions fail.
pub fn seal_outer_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    header: &Header<'_>,
    input: &SealInput<'_>,
) -> Result<SealedOuter, MiasmaError> {
    let h_hdr = header.h_hdr();

    let k_payload = kdf::derive_k_payload(input.dh_concat, &h_hdr)?;
    let payload_nonce: [u8; 24] = random_array(rng);
    let payload_aad = header_aad(AAD_PAYLOAD, &h_hdr);
    let encrypted_payload = xchacha_encrypt(
        &k_payload,
        &payload_nonce,
        input.payload_plaintext,
        &payload_aad,
    )?;

    let k_wrap = kdf::derive_k_wrap(input.dh_concat, input.pwh, &h_hdr)?;
    let dek_nonce: [u8; 24] = random_array(rng);
    let wrap_aad = header_aad(AAD_WRAP, &h_hdr);
    let wrapped_dek = xchacha_encrypt(&k_wrap, &dek_nonce, input.dek, &wrap_aad)?;

    Ok(SealedOuter {
        payload_nonce,
        encrypted_payload,
        dek_nonce,
        wrapped_dek,
    })
}

/// Open the DEK wrap with the key-exchange secret and the password hash.
///
/// Returns the recovered DEK. A wrong password, or a `dh_concat` computed
/// without `r_eph`, yields a wrap key that cannot open the DEK, so this fails
/// before the body is fetched.
pub fn open_wrapped_dek(
    dh_concat: &[u8; 64],
    pwh: &[u8; 32],
    h_hdr: &[u8; 32],
    dek_nonce: &[u8; 24],
    wrapped_dek: &[u8],
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let k_wrap = kdf::derive_k_wrap(dh_concat, pwh, h_hdr)?;
    let wrap_aad = header_aad(AAD_WRAP, h_hdr);
    let dek_bytes = xchacha_decrypt(&k_wrap, dek_nonce, wrapped_dek, &wrap_aad)?;
    let arr: [u8; 32] = dek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| MiasmaError::Decryption("wrapped DEK has the wrong length".into()))?;
    Ok(Zeroizing::new(arr))
}

/// Open the payload preview with the key-exchange secret (no password).
pub fn open_payload(
    dh_concat: &[u8; 64],
    h_hdr: &[u8; 32],
    payload_nonce: &[u8; 24],
    encrypted_payload: &[u8],
) -> Result<Vec<u8>, MiasmaError> {
    let k_payload = kdf::derive_k_payload(dh_concat, h_hdr)?;
    let payload_aad = header_aad(AAD_PAYLOAD, h_hdr);
    xchacha_decrypt(&k_payload, payload_nonce, encrypted_payload, &payload_aad)
}

/// Sign a sealed envelope's transcript (§3.3).
///
/// The caller passes the sender binding; the outer refs come from the sealed
/// layers. Returns `(signature, transcript_hash)`.
pub fn sign_sealed(
    sender_sk: &ed25519_dalek::SigningKey,
    header: &Header<'_>,
    outer: &OuterRefs<'_>,
) -> ([u8; 64], [u8; 32]) {
    let h_hdr = header.h_hdr();
    let sm = transcript::sig_msg(&h_hdr, outer);
    let signature = transcript::sign_transcript(sender_sk, &sm);
    let th = transcript::transcript_hash(&sm, &signature);
    (signature, th)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf_bounds::MIN_M_KIB;

    struct World {
        r_static_secret: [u8; 32],
        r_static_pub: [u8; 32],
        r_eph_secret: [u8; 32],
        r_eph_pub: [u8; 32],
        e_s_secret: [u8; 32],
        e_s_pub: [u8; 32],
        sender_identity: [u8; 32],
        recipient_identity: [u8; 32],
        envelope_id: [u8; 32],
        offer_id: [u8; 16],
        password_salt: [u8; 32],
        sender_binding: [u8; 64],
        dek: [u8; 32],
        password: String,
    }

    fn world() -> World {
        let r_static = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let r_eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let e_s = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        World {
            r_static_secret: r_static.to_bytes(),
            r_static_pub: x25519_dalek::PublicKey::from(&r_static).to_bytes(),
            r_eph_secret: r_eph.to_bytes(),
            r_eph_pub: x25519_dalek::PublicKey::from(&r_eph).to_bytes(),
            e_s_secret: e_s.to_bytes(),
            e_s_pub: x25519_dalek::PublicKey::from(&e_s).to_bytes(),
            sender_identity: rand::random(),
            recipient_identity: rand::random(),
            envelope_id: rand::random(),
            offer_id: rand::random(),
            password_salt: rand::random(),
            sender_binding: random_bytes_64(),
            dek: rand::random(),
            password: random_password(),
        }
    }

    /// 64 random bytes, built one byte at a time (no fixed array literal).
    ///
    /// `rand::random::<[u8; 64]>()` is not available, so the bytes are collected
    /// into a `Vec` and converted to the fixed-size array.
    fn random_bytes_64() -> [u8; 64] {
        let v: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();
        v.try_into().expect("collected 64 bytes")
    }

    /// A random password as ASCII hex of 16 random bytes, so no password literal
    /// appears in the test.
    fn random_password() -> String {
        let v: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn header<'a>(w: &'a World) -> Header<'a> {
        Header {
            version: 2,
            suite: 2,
            envelope_id: &w.envelope_id,
            sender_identity: &w.sender_identity,
            sender_pubkey: &w.r_static_pub, // any 32 bytes for the header test
            recipient_identity: &w.recipient_identity,
            recipient_pubkey: &w.r_static_pub,
            ephemeral_pubkey: &w.e_s_pub,
            recipient_ephemeral: &w.r_eph_pub,
            offer_id: &w.offer_id,
            kdf_m_kib: MIN_M_KIB.max(8),
            kdf_t_cost: 1,
            kdf_p_cost: 1,
            password_salt: &w.password_salt,
            created_at: 1_700_000_000,
            expires_at: 1_700_003_600,
            retention_secs: 3600,
        }
    }

    fn pwh(w: &World) -> Zeroizing<[u8; 32]> {
        kdf::password_hash(&w.password, &w.password_salt, MIN_M_KIB.max(8), 1, 1).unwrap()
    }

    #[test]
    fn a_sealed_envelope_opens_for_the_recipient() {
        let w = world();
        let mut rng = rand::rngs::OsRng;
        let body = b"the plaintext body of a directed share";
        let (cn, ct) = seal_content_with(&mut rng, &w.dek, 2, &w.envelope_id, body).unwrap();

        let ds = kdf::dh_concat_sender(&w.e_s_secret, &w.r_static_pub, &w.r_eph_pub).unwrap();
        let pwh = pwh(&w);
        let hdr = header(&w);
        let payload_plaintext = b"preview: mid, size, name";
        let sealed = seal_outer_with(
            &mut rng,
            &hdr,
            &SealInput {
                dh_concat: &ds,
                pwh: &pwh,
                dek: &w.dek,
                payload_plaintext,
            },
        )
        .unwrap();

        // Recipient side: recompute dh_concat and H_hdr, open the wrap, then body.
        let dr = kdf::dh_concat_recipient(&w.r_static_secret, &w.r_eph_secret, &w.e_s_pub).unwrap();
        let h_hdr = hdr.h_hdr();
        let dek =
            open_wrapped_dek(&dr, &pwh, &h_hdr, &sealed.dek_nonce, &sealed.wrapped_dek).unwrap();
        assert_eq!(&dek[..], &w.dek[..]);
        let recovered = open_content(&dek, 2, &w.envelope_id, &cn, &ct).unwrap();
        assert_eq!(recovered, body);

        // Payload preview opens without a password.
        let prev = open_payload(
            &dr,
            &h_hdr,
            &sealed.payload_nonce,
            &sealed.encrypted_payload,
        )
        .unwrap();
        assert_eq!(prev, payload_plaintext);
    }

    #[test]
    fn without_r_eph_the_dek_wrap_does_not_open() {
        let w = world();
        let mut rng = rand::rngs::OsRng;
        let ds = kdf::dh_concat_sender(&w.e_s_secret, &w.r_static_pub, &w.r_eph_pub).unwrap();
        let pwh = pwh(&w);
        let hdr = header(&w);
        let sealed = seal_outer_with(
            &mut rng,
            &hdr,
            &SealInput {
                dh_concat: &ds,
                pwh: &pwh,
                dek: &w.dek,
                payload_plaintext: b"preview",
            },
        )
        .unwrap();
        let h_hdr = hdr.h_hdr();

        // A fresh, unrelated ephemeral stands in for "r_eph discarded": the
        // recipient can no longer form dh2, so the wrap key is wrong.
        let other_eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes();
        let dr_wrong =
            kdf::dh_concat_recipient(&w.r_static_secret, &other_eph, &w.e_s_pub).unwrap();
        assert!(open_wrapped_dek(
            &dr_wrong,
            &pwh,
            &h_hdr,
            &sealed.dek_nonce,
            &sealed.wrapped_dek
        )
        .is_err());
    }

    #[test]
    fn a_wrong_password_does_not_open_the_dek_wrap() {
        let w = world();
        let mut rng = rand::rngs::OsRng;
        let ds = kdf::dh_concat_sender(&w.e_s_secret, &w.r_static_pub, &w.r_eph_pub).unwrap();
        let pwh_right = pwh(&w);
        let hdr = header(&w);
        let sealed = seal_outer_with(
            &mut rng,
            &hdr,
            &SealInput {
                dh_concat: &ds,
                pwh: &pwh_right,
                dek: &w.dek,
                payload_plaintext: b"preview",
            },
        )
        .unwrap();
        let h_hdr = hdr.h_hdr();
        let dr = kdf::dh_concat_recipient(&w.r_static_secret, &w.r_eph_secret, &w.e_s_pub).unwrap();
        // A wrong password that is simply the correct one with an extra char, so
        // it is derived from randomness and never equals the right password.
        let wrong_password = format!("{}!", w.password);
        let pwh_wrong =
            kdf::password_hash(&wrong_password, &w.password_salt, MIN_M_KIB.max(8), 1, 1).unwrap();
        assert!(open_wrapped_dek(
            &dr,
            &pwh_wrong,
            &h_hdr,
            &sealed.dek_nonce,
            &sealed.wrapped_dek
        )
        .is_err());
    }

    #[test]
    fn tampering_with_an_outer_field_fails_decryption() {
        let w = world();
        let mut rng = rand::rngs::OsRng;
        let ds = kdf::dh_concat_sender(&w.e_s_secret, &w.r_static_pub, &w.r_eph_pub).unwrap();
        let pwh = pwh(&w);
        let hdr = header(&w);
        let mut sealed = seal_outer_with(
            &mut rng,
            &hdr,
            &SealInput {
                dh_concat: &ds,
                pwh: &pwh,
                dek: &w.dek,
                payload_plaintext: b"preview",
            },
        )
        .unwrap();
        let h_hdr = hdr.h_hdr();
        let dr = kdf::dh_concat_recipient(&w.r_static_secret, &w.r_eph_secret, &w.e_s_pub).unwrap();

        // Flip one byte of wrapped_dek.
        sealed.wrapped_dek[0] ^= 0x01;
        assert!(
            open_wrapped_dek(&dr, &pwh, &h_hdr, &sealed.dek_nonce, &sealed.wrapped_dek).is_err()
        );
        sealed.wrapped_dek[0] ^= 0x01; // restore

        // Flip one byte of encrypted_payload.
        sealed.encrypted_payload[0] ^= 0x01;
        assert!(open_payload(
            &dr,
            &h_hdr,
            &sealed.payload_nonce,
            &sealed.encrypted_payload
        )
        .is_err());
    }

    #[test]
    fn a_changed_header_breaks_the_outer_aad() {
        let w = world();
        let mut rng = rand::rngs::OsRng;
        let ds = kdf::dh_concat_sender(&w.e_s_secret, &w.r_static_pub, &w.r_eph_pub).unwrap();
        let pwh = pwh(&w);
        let hdr = header(&w);
        let sealed = seal_outer_with(
            &mut rng,
            &hdr,
            &SealInput {
                dh_concat: &ds,
                pwh: &pwh,
                dek: &w.dek,
                payload_plaintext: b"preview",
            },
        )
        .unwrap();
        let dr = kdf::dh_concat_recipient(&w.r_static_secret, &w.r_eph_secret, &w.e_s_pub).unwrap();

        // Recompute H_hdr from a header with a different expires_at: the AAD no
        // longer matches, so the wrap does not open. Header holds only Copy
        // references, so functional update keeps the other fields.
        let hdr2 = Header {
            expires_at: hdr.expires_at + 1,
            ..header(&w)
        };
        let h_hdr2 = hdr2.h_hdr();
        assert_ne!(hdr.h_hdr(), h_hdr2);
        assert!(
            open_wrapped_dek(&dr, &pwh, &h_hdr2, &sealed.dek_nonce, &sealed.wrapped_dek).is_err()
        );
    }
}
