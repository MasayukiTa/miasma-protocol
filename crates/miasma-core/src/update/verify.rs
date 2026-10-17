//! Authenticity and integrity of a downloaded release.
//!
//! Two independent checks, both about the same small text file:
//!
//! 1. **Integrity (always mandatory).** The release must carry `SHA256SUMS.txt`
//!    and the archive's SHA-256 must match the line for its name. A release
//!    without that file is refused.
//! 2. **Authenticity (when keys are pinned).** `SHA256SUMS.txt.sig` is a
//!    detached Ed25519 signature over the exact bytes of `SHA256SUMS.txt`. The
//!    accepted public keys are compiled into the binary ([`UPDATE_PUBKEYS`]).
//!    While the list is empty the signature check is skipped (the SHA-256 check
//!    still applies, but a checksum that comes from the same place as the file
//!    proves integrity only, not who published it). Once the list has a key, a
//!    valid signature by one of the keys is mandatory. Several keys are allowed
//!    so a key can be rotated: ship a build that trusts old and new, then one
//!    that trusts only the new.

use std::io::Read;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Public keys (Ed25519, 32 bytes each) whose signature on `SHA256SUMS.txt`
/// makes a release acceptable. Empty for now: the signature check is skipped
/// until the maintainers decide who holds the signing key.
pub const UPDATE_PUBKEYS: &[[u8; 32]] = &[];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The release has no `SHA256SUMS.txt` (or it could not be fetched).
    SumsMissing,
    /// `SHA256SUMS.txt` could not be understood.
    SumsMalformed(String),
    /// `SHA256SUMS.txt` does not list the archive.
    NotListed(String),
    /// The archive's hash differs from the listed one.
    Mismatch {
        expected: String,
        actual: String,
    },
    /// Keys are pinned but the release has no signature.
    SignatureMissing,
    /// The signature file is not 64 bytes in a recognised encoding.
    SignatureMalformed,
    /// No pinned key made a valid signature.
    SignatureInvalid,
    Io(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SumsMissing => f.write_str("the release has no SHA256SUMS.txt"),
            Self::SumsMalformed(m) => write!(f, "SHA256SUMS.txt is not valid: {m}"),
            Self::NotListed(n) => write!(f, "SHA256SUMS.txt does not list {n}"),
            Self::Mismatch { .. } => f.write_str("the download does not match its SHA-256"),
            Self::SignatureMissing => f.write_str("the release is not signed"),
            Self::SignatureMalformed => f.write_str("the signature file is malformed"),
            Self::SignatureInvalid => f.write_str("the signature is not valid for any trusted key"),
            Self::Io(m) => write!(f, "cannot read the download: {m}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// What the signature step concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// No key is pinned in this build, so there was nothing to check against.
    Skipped,
    /// Valid under `UPDATE_PUBKEYS[index]`.
    Valid { key_index: usize },
}

/// SHA-256 of a file, read in 64 KiB pieces (never held in memory).
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// SHA-256 of a byte string.
pub fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The entries of a `SHA256SUMS.txt`: `(lowercase hex, file name)`.
///
/// Accepts the formats `sha256sum` (`<hex>  <name>`, `<hex> *<name>`) and
/// PowerShell scripts write, with LF or CRLF and an optional byte-order mark.
/// A name listed twice with different hashes is an error.
pub fn parse_sums(text: &[u8]) -> Result<Vec<(String, String)>, VerifyError> {
    let text = std::str::from_utf8(text)
        .map_err(|_| VerifyError::SumsMalformed("not UTF-8".into()))?
        .trim_start_matches('\u{feff}');
    let mut out: Vec<(String, String)> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, rest) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| VerifyError::SumsMalformed(format!("line {}", n + 1)))?;
        let name = rest.trim_start().trim_start_matches('*').trim();
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) || name.is_empty() {
            return Err(VerifyError::SumsMalformed(format!("line {}", n + 1)));
        }
        let hash = hash.to_ascii_lowercase();
        if let Some((h, _)) = out.iter().find(|(_, nm)| nm == name) {
            if *h != hash {
                return Err(VerifyError::SumsMalformed(format!(
                    "{name} is listed with two different hashes"
                )));
            }
            continue;
        }
        out.push((hash, name.to_owned()));
    }
    if out.is_empty() {
        return Err(VerifyError::SumsMalformed("no entries".into()));
    }
    Ok(out)
}

/// The listed hash of `name`.
pub fn expected_hash(sums: &[u8], name: &str) -> Result<String, VerifyError> {
    parse_sums(sums)?
        .into_iter()
        .find(|(_, n)| n == name)
        .map(|(h, _)| h)
        .ok_or_else(|| VerifyError::NotListed(name.to_owned()))
}

/// Compare a file against its line in `SHA256SUMS.txt`. Returns the hash.
pub fn verify_file_against_sums(
    path: &Path,
    name: &str,
    sums: &[u8],
) -> Result<String, VerifyError> {
    let expected = expected_hash(sums, name)?;
    let actual = sha256_file(path).map_err(|e| VerifyError::Io(e.to_string()))?;
    if constant_eq(expected.as_bytes(), actual.as_bytes()) {
        Ok(actual)
    } else {
        Err(VerifyError::Mismatch { expected, actual })
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Decode a detached signature: 64 raw bytes, 128 hex characters, or base64.
pub fn decode_signature(raw: &[u8]) -> Result<[u8; 64], VerifyError> {
    use base64::Engine as _;
    if raw.len() == 64 {
        let mut out = [0u8; 64];
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| VerifyError::SignatureMalformed)?
        .trim();
    let bytes = if text.len() == 128 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(text).map_err(|_| VerifyError::SignatureMalformed)?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| VerifyError::SignatureMalformed)?
    };
    <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| VerifyError::SignatureMalformed)
}

/// Check the detached signature over `sums` against `keys`.
///
/// `keys` empty: [`SignatureStatus::Skipped`] whatever `sig` is. `keys` not
/// empty: a signature is required and must verify (strictly) under one of them.
pub fn verify_sums_signature(
    sums: &[u8],
    sig: Option<&[u8]>,
    keys: &[[u8; 32]],
) -> Result<SignatureStatus, VerifyError> {
    if keys.is_empty() {
        return Ok(SignatureStatus::Skipped);
    }
    let sig = sig.ok_or(VerifyError::SignatureMissing)?;
    let sig = Signature::from_bytes(&decode_signature(sig)?);
    for (i, k) in keys.iter().enumerate() {
        let Ok(vk) = VerifyingKey::from_bytes(k) else {
            continue;
        };
        if vk.verify_strict(sums, &sig).is_ok() {
            return Ok(SignatureStatus::Valid { key_index: i });
        }
    }
    Err(VerifyError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    const SUMS_HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SUMS_HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sums() -> Vec<u8> {
        format!("{SUMS_HASH_A}  Miasma-macOS.zip\n{SUMS_HASH_B} *miasma-macos.tar.gz\n")
            .into_bytes()
    }

    #[test]
    fn sums_parse_in_both_dialects_with_crlf_and_bom() {
        let text = format!("\u{feff}{SUMS_HASH_A}  a.zip\r\n\r\n{SUMS_HASH_B} *b.zip\r\n");
        let v = parse_sums(text.as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], (SUMS_HASH_A.into(), "a.zip".into()));
        assert_eq!(v[1], (SUMS_HASH_B.into(), "b.zip".into()));
        // Upper-case hex is accepted and normalised.
        let up = format!("{}  a.zip", SUMS_HASH_A.to_uppercase());
        assert_eq!(parse_sums(up.as_bytes()).unwrap()[0].0, SUMS_HASH_A);
    }

    #[test]
    fn malformed_sums_are_refused() {
        for bad in [
            "".to_string(),
            "not a hash  a.zip".to_string(),
            format!("{SUMS_HASH_A}"),
            format!("{}  a.zip", &SUMS_HASH_A[..63]),
            format!("{SUMS_HASH_A}  a.zip\n{SUMS_HASH_B}  a.zip"),
        ] {
            assert!(
                matches!(
                    parse_sums(bad.as_bytes()),
                    Err(VerifyError::SumsMalformed(_))
                ),
                "{bad:?}"
            );
        }
        assert!(parse_sums(&[0xff, 0xfe, 0x00]).is_err());
    }

    #[test]
    fn a_file_is_checked_against_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.zip");
        std::fs::write(&p, b"hello").unwrap();
        let h = sha256_bytes(b"hello");
        assert_eq!(h, sha256_file(&p).unwrap());
        let good = format!("{h}  a.zip\n");
        assert_eq!(
            verify_file_against_sums(&p, "a.zip", good.as_bytes()).unwrap(),
            h
        );
        // Wrong content.
        let other = format!("{SUMS_HASH_A}  a.zip\n");
        assert!(matches!(
            verify_file_against_sums(&p, "a.zip", other.as_bytes()),
            Err(VerifyError::Mismatch { .. })
        ));
        // Not listed.
        assert_eq!(
            verify_file_against_sums(&p, "b.zip", good.as_bytes()),
            Err(VerifyError::NotListed("b.zip".into()))
        );
        // A one-bit change in the file is caught.
        std::fs::write(&p, b"hellp").unwrap();
        assert!(matches!(
            verify_file_against_sums(&p, "a.zip", good.as_bytes()),
            Err(VerifyError::Mismatch { .. })
        ));
    }

    #[test]
    fn with_no_pinned_key_the_signature_step_is_skipped() {
        assert_eq!(
            verify_sums_signature(&sums(), None, &[]),
            Ok(SignatureStatus::Skipped)
        );
        // A signature that is present but unchecked changes nothing.
        assert_eq!(
            verify_sums_signature(&sums(), Some(b"junk"), &[]),
            Ok(SignatureStatus::Skipped)
        );
    }

    #[test]
    fn a_good_signature_verifies_in_every_encoding() {
        use base64::Engine as _;
        let sk = key(7);
        let pk = sk.verifying_key().to_bytes();
        let sig = sk.sign(&sums()).to_bytes();
        let ok = Ok(SignatureStatus::Valid { key_index: 0 });
        assert_eq!(verify_sums_signature(&sums(), Some(&sig), &[pk]), ok);
        let hexed = hex::encode(sig);
        assert_eq!(
            verify_sums_signature(&sums(), Some(hexed.as_bytes()), &[pk]),
            ok
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        assert_eq!(
            verify_sums_signature(&sums(), Some(format!("{b64}\n").as_bytes()), &[pk]),
            ok
        );
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let sk = key(7);
        let pk = sk.verifying_key().to_bytes();
        let other = key(9).sign(&sums()).to_bytes();
        assert_eq!(
            verify_sums_signature(&sums(), Some(&other), &[pk]),
            Err(VerifyError::SignatureInvalid)
        );
        let mut flipped = sk.sign(&sums()).to_bytes();
        flipped[0] ^= 1;
        assert_eq!(
            verify_sums_signature(&sums(), Some(&flipped), &[pk]),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn a_tampered_sums_file_fails_the_signature() {
        let sk = key(7);
        let pk = sk.verifying_key().to_bytes();
        let sig = sk.sign(&sums()).to_bytes();
        let mut tampered = sums();
        tampered[3] = b'c';
        assert_eq!(
            verify_sums_signature(&tampered, Some(&sig), &[pk]),
            Err(VerifyError::SignatureInvalid)
        );
        // Appending a line also changes the signed bytes.
        let mut longer = sums();
        longer.extend_from_slice(b"\n");
        assert_eq!(
            verify_sums_signature(&longer, Some(&sig), &[pk]),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn a_missing_signature_is_refused_once_a_key_is_pinned() {
        let pk = key(7).verifying_key().to_bytes();
        assert_eq!(
            verify_sums_signature(&sums(), None, &[pk]),
            Err(VerifyError::SignatureMissing)
        );
    }

    #[test]
    fn a_malformed_signature_file_is_refused() {
        let pk = key(7).verifying_key().to_bytes();
        for junk in [&b"short"[..], &[0u8; 65][..], &b"zz".repeat(64)[..]] {
            assert_eq!(
                verify_sums_signature(&sums(), Some(junk), &[pk]),
                Err(VerifyError::SignatureMalformed),
                "{junk:?}"
            );
        }
    }

    #[test]
    fn several_keys_allow_rotation() {
        let old = key(1);
        let new = key(2);
        let keys = [
            old.verifying_key().to_bytes(),
            new.verifying_key().to_bytes(),
        ];
        let by_old = old.sign(&sums()).to_bytes();
        let by_new = new.sign(&sums()).to_bytes();
        assert_eq!(
            verify_sums_signature(&sums(), Some(&by_old), &keys),
            Ok(SignatureStatus::Valid { key_index: 0 })
        );
        assert_eq!(
            verify_sums_signature(&sums(), Some(&by_new), &keys),
            Ok(SignatureStatus::Valid { key_index: 1 })
        );
        // A key that is not in the list does not get in.
        let stranger = key(3).sign(&sums()).to_bytes();
        assert_eq!(
            verify_sums_signature(&sums(), Some(&stranger), &keys),
            Err(VerifyError::SignatureInvalid)
        );
        // After the rotation only the new key is pinned.
        assert_eq!(
            verify_sums_signature(&sums(), Some(&by_old), &keys[1..]),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn an_invalid_key_in_the_list_is_skipped_not_fatal() {
        let good = key(5);
        // 32 bytes that are not a valid curve point encoding for signing checks
        // still must not panic; the good key behind it is found.
        let bad = [0xffu8; 32];
        let keys = [bad, good.verifying_key().to_bytes()];
        let sig = good.sign(&sums()).to_bytes();
        assert_eq!(
            verify_sums_signature(&sums(), Some(&sig), &keys),
            Ok(SignatureStatus::Valid { key_index: 1 })
        );
    }
}
