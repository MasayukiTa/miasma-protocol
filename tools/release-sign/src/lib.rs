//! Release signing for `SHA256SUMS.txt`.
//!
//! The update client (`miasma_core::update::verify`) accepts a detached
//! Ed25519 signature over the exact bytes of `SHA256SUMS.txt`, checked
//! strictly against the public keys pinned in `UPDATE_PUBKEYS`. This crate
//! creates those keys, signs, and verifies with the same rules. It is
//! offline: no network code, and secrets never touch arguments or the
//! environment.

pub mod safety;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The key file is not in the expected format.
    BadKeyFile(&'static str),
    /// Wrong passphrase, or the key file was modified.
    WrongPassphraseOrCorrupt,
    /// Key-derivation parameters in the file are outside the accepted range.
    KdfParams,
    /// `SHA256SUMS.txt` is empty or malformed.
    SumsMalformed(String),
    /// The signature is not 64 bytes in a recognised encoding.
    SignatureMalformed,
    /// No given key made a valid signature.
    SignatureInvalid,
    /// A public key is not 32 bytes of hex or not a valid point.
    BadPublicKey,
    /// `verify` was called without any key.
    NoKeys,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKeyFile(m) => write!(f, "not a valid key file: {m}"),
            Self::WrongPassphraseOrCorrupt => {
                f.write_str("wrong passphrase, or the key file has been modified")
            }
            Self::KdfParams => f.write_str("the key file has unacceptable key-derivation settings"),
            Self::SumsMalformed(m) => write!(f, "SHA256SUMS.txt is not valid: {m}"),
            Self::SignatureMalformed => f.write_str("the signature file is malformed"),
            Self::SignatureInvalid => f.write_str("the signature is not valid for any given key"),
            Self::BadPublicKey => f.write_str("the public key is not 64 hex characters of a valid key"),
            Self::NoKeys => f.write_str("at least one public key is required"),
        }
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// Encrypted key file
// ---------------------------------------------------------------------------

const MAGIC: &[u8; 8] = b"MRSIGKEY";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 8 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN + 32;
const CT_LEN: usize = 32 + 16;

/// Argon2id cost. The values are stored in the file and bounded on reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// For real keys: 256 MiB, 3 passes, 1 lane.
    pub const STRONG: KdfParams = KdfParams {
        m_kib: 256 * 1024,
        t: 3,
        p: 1,
    };

    fn check(&self) -> Result<(), Error> {
        let ok = (1..=16).contains(&self.p)
            && self.m_kib >= 8 * self.p
            && self.m_kib <= 1024 * 1024
            && (1..=64).contains(&self.t);
        if ok {
            Ok(())
        } else {
            Err(Error::KdfParams)
        }
    }
}

fn derive(
    passphrase: &[u8],
    salt: &[u8],
    k: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    k.check()?;
    let params = Params::new(k.m_kib, k.t, k.p, Some(32)).map_err(|_| Error::KdfParams)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| Error::KdfParams)?;
    Ok(out)
}

/// A new random signing key (seed from the operating system's RNG).
pub fn generate_key() -> SigningKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    SigningKey::from_bytes(&seed)
}

/// Encrypt the secret seed under `passphrase`. The public key is stored in the
/// (authenticated) header so it can be shown without the passphrase.
pub fn encrypt_key(key: &SigningKey, passphrase: &[u8], k: KdfParams) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let dk = derive(passphrase, &salt, k)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&k.m_kib.to_le_bytes());
    header.extend_from_slice(&k.t.to_le_bytes());
    header.extend_from_slice(&k.p.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(key.verifying_key().as_bytes());
    debug_assert_eq!(header.len(), HEADER_LEN);

    let seed = Zeroizing::new(key.to_bytes());
    let cipher = XChaCha20Poly1305::new(dk.as_ref().into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: seed.as_ref(),
                aad: &header,
            },
        )
        .map_err(|_| Error::WrongPassphraseOrCorrupt)?;
    let mut out = header;
    out.extend_from_slice(&ct);
    Ok(out)
}

struct Parsed<'a> {
    header: &'a [u8],
    k: KdfParams,
    salt: &'a [u8],
    nonce: &'a [u8],
    public: [u8; 32],
    ct: &'a [u8],
}

fn parse(file: &[u8]) -> Result<Parsed<'_>, Error> {
    if file.len() != HEADER_LEN + CT_LEN {
        return Err(Error::BadKeyFile("wrong size"));
    }
    if &file[..8] != MAGIC || file[8] != VERSION {
        return Err(Error::BadKeyFile("wrong magic or version"));
    }
    let u32at = |o: usize| u32::from_le_bytes(file[o..o + 4].try_into().unwrap());
    let k = KdfParams {
        m_kib: u32at(9),
        t: u32at(13),
        p: u32at(17),
    };
    let salt = &file[21..21 + SALT_LEN];
    let nonce = &file[21 + SALT_LEN..21 + SALT_LEN + NONCE_LEN];
    let public: [u8; 32] = file[HEADER_LEN - 32..HEADER_LEN].try_into().unwrap();
    Ok(Parsed {
        header: &file[..HEADER_LEN],
        k,
        salt,
        nonce,
        public,
        ct: &file[HEADER_LEN..],
    })
}

/// The public key stored in a key file. Not authenticated until the file is
/// decrypted; use [`decrypt_key`] to confirm.
pub fn key_file_public(file: &[u8]) -> Result<[u8; 32], Error> {
    Ok(parse(file)?.public)
}

/// Decrypt a key file.
pub fn decrypt_key(file: &[u8], passphrase: &[u8]) -> Result<SigningKey, Error> {
    let p = parse(file)?;
    let dk = derive(passphrase, p.salt, p.k)?;
    let cipher = XChaCha20Poly1305::new(dk.as_ref().into());
    let seed = cipher
        .decrypt(
            XNonce::from_slice(p.nonce),
            Payload {
                msg: p.ct,
                aad: p.header,
            },
        )
        .map_err(|_| Error::WrongPassphraseOrCorrupt)?;
    let seed = Zeroizing::new(seed);
    let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        <[u8; 32]>::try_from(seed.as_slice()).map_err(|_| Error::BadKeyFile("bad seed"))?,
    );
    let key = SigningKey::from_bytes(&arr);
    if key.verifying_key().as_bytes() != &p.public {
        return Err(Error::WrongPassphraseOrCorrupt);
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// SHA256SUMS.txt, signatures
// ---------------------------------------------------------------------------

/// Check that `sums` is a usable `SHA256SUMS.txt` (same rules as the update
/// client): UTF-8, optional BOM, lines `<64 hex> <name>` or `<64 hex> *<name>`,
/// blank lines and `#` comments ignored, at least one entry, no name listed
/// with two different hashes. Returns the number of distinct entries.
pub fn validate_sums(sums: &[u8]) -> Result<usize, Error> {
    let bad = |m: String| Error::SumsMalformed(m);
    let text = std::str::from_utf8(sums)
        .map_err(|_| bad("not UTF-8".into()))?
        .trim_start_matches('\u{feff}');
    let mut seen: Vec<(String, &str)> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, rest) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| bad(format!("line {}", n + 1)))?;
        let name = rest.trim_start().trim_start_matches('*').trim();
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) || name.is_empty() {
            return Err(bad(format!("line {}", n + 1)));
        }
        let hash = hash.to_ascii_lowercase();
        if let Some((h, _)) = seen.iter().find(|(_, nm)| *nm == name) {
            if *h != hash {
                return Err(bad(format!("{name} is listed with two different hashes")));
            }
            continue;
        }
        seen.push((hash, name));
    }
    if seen.is_empty() {
        return Err(bad("no entries".into()));
    }
    Ok(seen.len())
}

/// Output encodings of a signature file (the update client accepts both).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigFormat {
    Hex,
    Base64,
}

/// Sign the exact bytes of `sums`. Refuses an empty or malformed file, and
/// checks its own result before returning.
pub fn sign_sums(key: &SigningKey, sums: &[u8]) -> Result<[u8; 64], Error> {
    validate_sums(sums)?;
    let sig = key.sign(sums);
    key.verifying_key()
        .verify_strict(sums, &sig)
        .map_err(|_| Error::SignatureInvalid)?;
    Ok(sig.to_bytes())
}

/// The text written to `SHA256SUMS.txt.sig`.
pub fn encode_signature(sig: &[u8; 64], format: SigFormat) -> String {
    use base64::Engine as _;
    match format {
        SigFormat::Hex => format!("{}\n", hex::encode(sig)),
        SigFormat::Base64 => format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode(sig)
        ),
    }
}

/// Decode a signature file: 64 raw bytes, 128 hex characters, or base64
/// (the same three forms as the update client).
pub fn decode_signature(raw: &[u8]) -> Result<[u8; 64], Error> {
    use base64::Engine as _;
    if raw.len() == 64 {
        let mut out = [0u8; 64];
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| Error::SignatureMalformed)?
        .trim();
    let bytes = if text.len() == 128 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(text).map_err(|_| Error::SignatureMalformed)?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| Error::SignatureMalformed)?
    };
    <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| Error::SignatureMalformed)
}

/// Parse a public key given as 64 hex characters.
pub fn parse_public_key(s: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(s.trim()).map_err(|_| Error::BadPublicKey)?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::BadPublicKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| Error::BadPublicKey)?;
    Ok(arr)
}

/// Strict verification, as the update client does it: the signature must be
/// valid under at least one of `keys`. Returns the index of the key that
/// matched. Unlike the client, an empty key list is an error here.
pub fn verify_sums(sums: &[u8], sig_file: &[u8], keys: &[[u8; 32]]) -> Result<usize, Error> {
    if keys.is_empty() {
        return Err(Error::NoKeys);
    }
    let sig = Signature::from_bytes(&decode_signature(sig_file)?);
    for (i, k) in keys.iter().enumerate() {
        let Ok(vk) = VerifyingKey::from_bytes(k) else {
            continue;
        };
        if vk.verify_strict(sums, &sig).is_ok() {
            return Ok(i);
        }
    }
    Err(Error::SignatureInvalid)
}

/// A ready-to-paste `UPDATE_PUBKEYS` element for `key`.
pub fn rust_array(key: &[u8; 32]) -> String {
    let mut s = String::from("    [\n");
    for row in key.chunks(8) {
        s.push_str("        ");
        let items: Vec<String> = row.iter().map(|b| format!("0x{b:02x}")).collect();
        s.push_str(&items.join(", "));
        s.push_str(",\n");
    }
    s.push_str("    ],");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    fn sums() -> Vec<u8> {
        format!(
            "{}  Miasma-macOS.zip\n{} *miasma-macos.tar.gz\n",
            "a".repeat(64),
            "b".repeat(64)
        )
        .into_bytes()
    }

    #[test]
    fn sign_verify_round_trip_in_both_encodings() {
        let key = generate_key();
        let pk = *key.verifying_key().as_bytes();
        let sig = sign_sums(&key, &sums()).unwrap();
        for f in [SigFormat::Hex, SigFormat::Base64] {
            let text = encode_signature(&sig, f);
            assert_eq!(verify_sums(&sums(), text.as_bytes(), &[pk]), Ok(0));
        }
        // Raw 64 bytes too.
        assert_eq!(verify_sums(&sums(), &sig, &[pk]), Ok(0));
    }

    #[test]
    fn the_matching_key_index_is_reported() {
        let (a, b) = (generate_key(), generate_key());
        let sig = sign_sums(&b, &sums()).unwrap();
        let keys = [*a.verifying_key().as_bytes(), *b.verifying_key().as_bytes()];
        assert_eq!(verify_sums(&sums(), &sig, &keys), Ok(1));
    }

    #[test]
    fn wrong_key_fails() {
        let (a, other) = (generate_key(), generate_key());
        let sig = sign_sums(&a, &sums()).unwrap();
        let pk = *other.verifying_key().as_bytes();
        assert_eq!(verify_sums(&sums(), &sig, &[pk]), Err(Error::SignatureInvalid));
        assert_eq!(verify_sums(&sums(), &sig, &[]), Err(Error::NoKeys));
    }

    #[test]
    fn tampered_sums_fail() {
        let key = generate_key();
        let pk = *key.verifying_key().as_bytes();
        let sig = sign_sums(&key, &sums()).unwrap();
        let mut bad = sums();
        bad[0] = b'c';
        assert_eq!(verify_sums(&bad, &sig, &[pk]), Err(Error::SignatureInvalid));
        // A line-ending change is also a different file.
        let crlf = String::from_utf8(sums()).unwrap().replace('\n', "\r\n");
        assert_eq!(
            verify_sums(crlf.as_bytes(), &sig, &[pk]),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn malformed_signature_is_reported_as_such() {
        let pk = *generate_key().verifying_key().as_bytes();
        for bad in [&b""[..], b"zz", b"not base64 !!!"] {
            assert_eq!(
                verify_sums(&sums(), bad, &[pk]),
                Err(Error::SignatureMalformed)
            );
        }
    }

    #[test]
    fn empty_or_malformed_sums_are_not_signed() {
        let key = generate_key();
        let long = format!("{}  a.zip", "a".repeat(63));
        for bad in [
            "",
            "\n\n# only a comment\n",
            "not a hash  a.zip",
            long.as_str(),
        ] {
            assert!(
                matches!(
                    sign_sums(&key, bad.as_bytes()),
                    Err(Error::SumsMalformed(_))
                ),
                "{bad:?}"
            );
        }
        assert!(sign_sums(&key, &[0xff, 0xfe]).is_err());
        let dup = format!("{0}  a.zip\n{1}  a.zip\n", "a".repeat(64), "b".repeat(64));
        assert!(sign_sums(&key, dup.as_bytes()).is_err());
        assert_eq!(validate_sums(&sums()), Ok(2));
    }

    #[test]
    fn key_file_round_trip() {
        let key = generate_key();
        let file = encrypt_key(&key, b"correct horse battery", FAST).unwrap();
        assert_eq!(key_file_public(&file).unwrap(), *key.verifying_key().as_bytes());
        let back = decrypt_key(&file, b"correct horse battery").unwrap();
        assert_eq!(back.to_bytes(), key.to_bytes());
        // The seed is not present in clear text.
        assert!(!file
            .windows(32)
            .any(|w| w == key.to_bytes().as_slice()));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let key = generate_key();
        let file = encrypt_key(&key, b"correct horse battery", FAST).unwrap();
        assert_eq!(
            decrypt_key(&file, b"correct horse batterz").err(),
            Some(Error::WrongPassphraseOrCorrupt)
        );
        assert_eq!(
            decrypt_key(&file, b"").err(),
            Some(Error::WrongPassphraseOrCorrupt)
        );
    }

    #[test]
    fn modified_key_file_fails() {
        let key = generate_key();
        let file = encrypt_key(&key, b"correct horse battery", FAST).unwrap();
        // Flip one bit in each region: params, salt, nonce, public key, ciphertext.
        for pos in [9, 13, 25, 45, 80, HEADER_LEN + 3] {
            let mut bad = file.clone();
            bad[pos] ^= 1;
            assert!(
                decrypt_key(&bad, b"correct horse battery").is_err(),
                "byte {pos}"
            );
        }
        assert!(matches!(
            decrypt_key(&file[..file.len() - 1], b"x"),
            Err(Error::BadKeyFile(_))
        ));
    }

    #[test]
    fn absurd_kdf_settings_are_refused_before_any_work() {
        let key = generate_key();
        let mut file = encrypt_key(&key, b"correct horse battery", FAST).unwrap();
        file[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decrypt_key(&file, b"correct horse battery").err(),
            Some(Error::KdfParams)
        );
    }

    #[test]
    fn two_encryptions_of_one_key_differ() {
        let key = generate_key();
        let a = encrypt_key(&key, b"correct horse battery", FAST).unwrap();
        let b = encrypt_key(&key, b"correct horse battery", FAST).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn public_key_parsing() {
        let key = generate_key();
        let hex = hex::encode(key.verifying_key().as_bytes());
        assert_eq!(parse_public_key(&hex).unwrap(), *key.verifying_key().as_bytes());
        assert!(parse_public_key("abcd").is_err());
        assert!(parse_public_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn rust_array_has_32_bytes_in_four_rows() {
        let s = rust_array(&[7u8; 32]);
        assert_eq!(s.matches("0x07").count(), 32);
        assert_eq!(s.lines().count(), 6);
    }
}
