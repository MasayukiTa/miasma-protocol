//! The share ID: what a sender hands to a receiver.
//!
//! A MID (`miasma:<base58>`) names *content* and stays the DHT key. It says
//! nothing about who published it or whether a password protects it, so on its
//! own it cannot authenticate a record (an attacker who knows the MID can sign a
//! record for it with any key, and an old unprotected record for the same
//! content can be replayed against a protected transfer).
//!
//! The share ID binds those facts in one typeable string:
//!
//! ```text
//! miasma-share:<base58( version:u8 = 2 || flags:u8 || MID:32 || publisher:32 || checksum:4 )>
//! ```
//!
//! * `flags` bit 0: the transfer is password-protected. All other bits are
//!   reserved and must be 0; an unknown bit is refused, not ignored.
//! * `publisher` is the Ed25519 verifying key that signs the DHT record (the
//!   node's persistent identity key). The receiver accepts only a record signed
//!   by exactly this key.
//! * `checksum` is the first four bytes of a domain-separated BLAKE3 over the
//!   preceding bytes. It catches a mistyped character before any network work;
//!   it is not a security boundary (the signature check is).

use std::{fmt, str::FromStr};

use crate::{crypto::hash::ContentId, MiasmaError};

/// Text prefix of a share ID.
pub const SHARE_ID_PREFIX: &str = "miasma-share:";
/// The only version this build reads and writes.
pub const SHARE_ID_VERSION: u8 = 2;
/// Flags bit 0: password-protected.
pub const FLAG_PROTECTED: u8 = 0b0000_0001;
const KNOWN_FLAGS: u8 = FLAG_PROTECTED;

const CHECKSUM_LEN: usize = 4;
const BODY_LEN: usize = 1 + 1 + 32 + 32;
/// Decoded length of a version-2 share ID.
pub const SHARE_ID_BYTES: usize = BODY_LEN + CHECKSUM_LEN;
const CHECKSUM_CONTEXT: &str = "miasma-share-id-v2 checksum";

/// Why a share ID string was refused. Every variant is distinct so a client can
/// say exactly what is wrong before touching the network.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareIdError {
    #[error("not a share ID: it must start with '{SHARE_ID_PREFIX}'")]
    BadPrefix,
    #[error("the share ID contains a character that is not base58")]
    BadBase58,
    #[error("the share ID has the wrong length ({got} bytes decoded, expected {SHARE_ID_BYTES})")]
    WrongLength { got: usize },
    #[error("the share ID checksum does not match: a character was probably mistyped")]
    BadChecksum,
    #[error("unsupported share ID version {0}; update Miasma")]
    UnsupportedVersion(u8),
    #[error("the share ID sets unknown flags (0x{0:02x}); update Miasma")]
    UnknownFlags(u8),
    #[error("the share ID carries an invalid publisher key")]
    InvalidPublisherKey,
}

/// Why a fetched record or manifest does not match the share ID the receiver
/// typed. Raised after the network fetch, before any piece is downloaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareMismatch {
    #[error(
        "the record was not signed by the publisher named in the share ID; \
         refusing it (forged or replayed record)"
    )]
    WrongSigner,
    #[error(
        "the share ID requires an authenticated transfer manifest but the record has none; \
         ask the sender to publish again"
    )]
    ManifestMissing,
    #[error("the manifest names a different publisher than the share ID")]
    ManifestPublisher,
    #[error(
        "the share ID says this transfer is password-protected but the record is not; \
         refusing (possible downgrade or replay of an old record)"
    )]
    ProtectionDowngrade,
    #[error(
        "the share ID says this transfer is not password-protected but the record is; \
         check the share ID"
    )]
    ProtectionUpgrade,
    #[error("the share ID and the record are for different content")]
    MidMismatch,
}

/// A parsed, checksum-verified share ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShareId {
    mid: [u8; 32],
    publisher: [u8; 32],
    protected: bool,
}

impl ShareId {
    pub fn new(mid: &ContentId, publisher: [u8; 32], protected: bool) -> Self {
        Self {
            mid: *mid.as_bytes(),
            publisher,
            protected,
        }
    }

    pub fn mid(&self) -> ContentId {
        ContentId::from_digest(self.mid)
    }

    pub fn mid_bytes(&self) -> &[u8; 32] {
        &self.mid
    }

    /// The Ed25519 key that must have signed the record.
    pub fn publisher(&self) -> &[u8; 32] {
        &self.publisher
    }

    /// Whether the ID says a password protects the transfer.
    pub fn protected(&self) -> bool {
        self.protected
    }

    fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
        let mut h = blake3::Hasher::new_derive_key(CHECKSUM_CONTEXT);
        h.update(body);
        let mut out = [0u8; CHECKSUM_LEN];
        out.copy_from_slice(&h.finalize().as_bytes()[..CHECKSUM_LEN]);
        out
    }

    /// The raw bytes that are base58-encoded.
    pub fn to_bytes(&self) -> [u8; SHARE_ID_BYTES] {
        let mut out = [0u8; SHARE_ID_BYTES];
        out[0] = SHARE_ID_VERSION;
        out[1] = if self.protected { FLAG_PROTECTED } else { 0 };
        out[2..34].copy_from_slice(&self.mid);
        out[34..66].copy_from_slice(&self.publisher);
        let sum = Self::checksum(&out[..BODY_LEN]);
        out[BODY_LEN..].copy_from_slice(&sum);
        out
    }

    /// Parse the text form. Surrounding whitespace is ignored.
    pub fn parse(text: &str) -> Result<Self, ShareIdError> {
        let rest = text
            .trim()
            .strip_prefix(SHARE_ID_PREFIX)
            .ok_or(ShareIdError::BadPrefix)?;
        let bytes = bs58::decode(rest)
            .into_vec()
            .map_err(|_| ShareIdError::BadBase58)?;
        if bytes.len() != SHARE_ID_BYTES {
            // A different version may simply have a different size: name the
            // version rather than calling it a length problem.
            return Err(match bytes.first() {
                Some(&v) if v != SHARE_ID_VERSION => ShareIdError::UnsupportedVersion(v),
                _ => ShareIdError::WrongLength { got: bytes.len() },
            });
        }
        if Self::checksum(&bytes[..BODY_LEN]) != bytes[BODY_LEN..] {
            return Err(ShareIdError::BadChecksum);
        }
        if bytes[0] != SHARE_ID_VERSION {
            return Err(ShareIdError::UnsupportedVersion(bytes[0]));
        }
        let flags = bytes[1];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(ShareIdError::UnknownFlags(flags & !KNOWN_FLAGS));
        }
        let mut mid = [0u8; 32];
        mid.copy_from_slice(&bytes[2..34]);
        let mut publisher = [0u8; 32];
        publisher.copy_from_slice(&bytes[34..66]);
        if ed25519_dalek::VerifyingKey::from_bytes(&publisher).is_err() {
            return Err(ShareIdError::InvalidPublisherKey);
        }
        Ok(Self {
            mid,
            publisher,
            protected: flags & FLAG_PROTECTED != 0,
        })
    }

    /// Check a record's MID and signer, and its manifest, against this ID.
    ///
    /// `record_signer` is the key that verifiably signed the record envelope (an
    /// envelope already verified with the signature check). `manifest` is what
    /// that record carried. Nothing here touches the network.
    pub fn check_record(
        &self,
        record_mid: &[u8; 32],
        record_signer: Option<&[u8; 32]>,
        manifest: Option<&super::TransferManifest>,
    ) -> Result<(), ShareMismatch> {
        if record_mid != &self.mid {
            return Err(ShareMismatch::MidMismatch);
        }
        if record_signer != Some(&self.publisher) {
            return Err(ShareMismatch::WrongSigner);
        }
        let Some(m) = manifest else {
            return Err(ShareMismatch::ManifestMissing);
        };
        if m.mid != self.mid {
            return Err(ShareMismatch::MidMismatch);
        }
        if m.publisher != self.publisher {
            return Err(ShareMismatch::ManifestPublisher);
        }
        match (self.protected, m.protection.is_password()) {
            (true, false) => Err(ShareMismatch::ProtectionDowngrade),
            (false, true) => Err(ShareMismatch::ProtectionUpgrade),
            _ => Ok(()),
        }
    }
}

impl fmt::Display for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{SHARE_ID_PREFIX}{}",
            bs58::encode(self.to_bytes()).into_string()
        )
    }
}

impl fmt::Debug for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShareId({self})")
    }
}

impl FromStr for ShareId {
    type Err = ShareIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// What a person typed to name a transfer: a share ID, or a bare MID (the older
/// form, which cannot authenticate the publisher).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferId {
    Mid(ContentId),
    Share(ShareId),
}

impl TransferId {
    pub fn mid(&self) -> ContentId {
        match self {
            Self::Mid(m) => m.clone(),
            Self::Share(s) => s.mid(),
        }
    }

    pub fn share_id(&self) -> Option<&ShareId> {
        match self {
            Self::Share(s) => Some(s),
            Self::Mid(_) => None,
        }
    }
}

/// The one place user input naming a transfer is parsed. Accepts
/// `miasma-share:…` or `miasma:…`; fails before any network work.
pub fn parse_transfer_id(text: &str) -> Result<TransferId, MiasmaError> {
    let t = text.trim();
    if t.starts_with(SHARE_ID_PREFIX) {
        ShareId::parse(t)
            .map(TransferId::Share)
            .map_err(MiasmaError::InvalidShareId)
    } else if t.starts_with("miasma:") {
        ContentId::from_str(t).map(TransferId::Mid)
    } else {
        Err(MiasmaError::InvalidMid(
            "expected a share ID (miasma-share:...) or a MID (miasma:...)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn mid(seed: u8) -> ContentId {
        ContentId::compute(&[seed; 16], b"k4n6")
    }

    fn sample(protected: bool) -> ShareId {
        ShareId::new(&mid(1), key(7).verifying_key().to_bytes(), protected)
    }

    #[test]
    fn round_trips_both_protection_states() {
        for protected in [false, true] {
            let id = sample(protected);
            let text = id.to_string();
            assert!(text.starts_with("miasma-share:"));
            let back: ShareId = text.parse().unwrap();
            assert_eq!(back, id);
            assert_eq!(back.protected(), protected);
            assert_eq!(back.mid(), mid(1));
            assert_eq!(back.publisher(), &key(7).verifying_key().to_bytes());
        }
    }

    #[test]
    fn protection_changes_the_id() {
        assert_ne!(sample(true).to_string(), sample(false).to_string());
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let id = sample(true);
        assert_eq!(ShareId::parse(&format!("  {id}\n")).unwrap(), id);
    }

    #[test]
    fn known_answer_vector() {
        // Pins the wire format: changing the layout, flags, domain string or
        // checksum changes this string.
        let id = ShareId::new(
            &ContentId::from_str(&format!(
                "miasma:{}",
                bs58::encode([0x11u8; 32]).into_string()
            ))
            .unwrap(),
            key(7).verifying_key().to_bytes(),
            true,
        );
        assert_eq!(id.to_string(), KAT);
        assert_eq!(ShareId::parse(KAT).unwrap(), id);
        assert_eq!(id.to_bytes().len(), 70);
        assert_eq!(id.to_bytes()[0], 2);
        assert_eq!(id.to_bytes()[1], 1);
    }

    const KAT: &str = "miasma-share:67Gg7UApFrDYASSKbFUoqeWbZmpGdmAuh1jHw2jncj98PBZtUD6EXRsazYMRDuQrJWgsbz3T6bSbRDFEZWj3FK4LRuJT42W";

    #[test]
    fn bad_prefix() {
        let t = sample(false).to_string();
        let body = t.strip_prefix("miasma-share:").unwrap();
        assert_eq!(
            ShareId::parse(&format!("miasma:{body}")),
            Err(ShareIdError::BadPrefix)
        );
        assert_eq!(ShareId::parse(body), Err(ShareIdError::BadPrefix));
        assert_eq!(ShareId::parse(""), Err(ShareIdError::BadPrefix));
    }

    #[test]
    fn bad_base58() {
        // '0', 'O', 'I' and 'l' are not in the base58 alphabet.
        assert_eq!(
            ShareId::parse("miasma-share:0OIl"),
            Err(ShareIdError::BadBase58)
        );
    }

    #[test]
    fn wrong_length() {
        let bytes = sample(false).to_bytes();
        let short = format!("miasma-share:{}", bs58::encode(&bytes[..60]).into_string());
        assert!(matches!(
            ShareId::parse(&short),
            Err(ShareIdError::WrongLength { got: 60 })
        ));
        let mut long = bytes.to_vec();
        long.push(9);
        let long = format!("miasma-share:{}", bs58::encode(&long).into_string());
        assert!(matches!(
            ShareId::parse(&long),
            Err(ShareIdError::WrongLength { got: 71 })
        ));
        assert!(matches!(
            ShareId::parse("miasma-share:"),
            Err(ShareIdError::WrongLength { got: 0 })
        ));
    }

    /// Re-encode `bytes` with a correct checksum over the (possibly altered) body.
    fn resealed(mut bytes: [u8; SHARE_ID_BYTES]) -> String {
        let sum = ShareId::checksum(&bytes[..BODY_LEN]);
        bytes[BODY_LEN..].copy_from_slice(&sum);
        format!("miasma-share:{}", bs58::encode(bytes).into_string())
    }

    #[test]
    fn bad_checksum() {
        let mut bytes = sample(true).to_bytes();
        bytes[SHARE_ID_BYTES - 1] ^= 1;
        let t = format!("miasma-share:{}", bs58::encode(bytes).into_string());
        assert_eq!(ShareId::parse(&t), Err(ShareIdError::BadChecksum));
    }

    #[test]
    fn unknown_version_and_flags() {
        let mut b = sample(false).to_bytes();
        b[0] = 3;
        assert_eq!(
            ShareId::parse(&resealed(b)),
            Err(ShareIdError::UnsupportedVersion(3))
        );
        let mut b = sample(false).to_bytes();
        b[1] = 0b0000_0011;
        assert_eq!(
            ShareId::parse(&resealed(b)),
            Err(ShareIdError::UnknownFlags(0b10))
        );
        let mut b = sample(false).to_bytes();
        b[1] = 0x80;
        assert_eq!(
            ShareId::parse(&resealed(b)),
            Err(ShareIdError::UnknownFlags(0x80))
        );
    }

    #[test]
    fn a_different_version_with_another_size_is_named_as_a_version() {
        let mut b = sample(false).to_bytes().to_vec();
        b[0] = 9;
        b.truncate(40);
        let t = format!("miasma-share:{}", bs58::encode(b).into_string());
        assert_eq!(ShareId::parse(&t), Err(ShareIdError::UnsupportedVersion(9)));
    }

    #[test]
    fn an_invalid_publisher_point_is_refused() {
        // y = 2 is not on the curve (checked: decompression fails for it).
        let mut bad = [0u8; 32];
        bad[0] = 2;
        if ed25519_dalek::VerifyingKey::from_bytes(&bad).is_ok() {
            // Find another invalid encoding deterministically.
            for b in 3u8..=255 {
                bad[0] = b;
                if ed25519_dalek::VerifyingKey::from_bytes(&bad).is_err() {
                    break;
                }
            }
        }
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&bad).is_err());
        let id = ShareId::new(&mid(1), bad, false);
        assert_eq!(
            ShareId::parse(&id.to_string()),
            Err(ShareIdError::InvalidPublisherKey)
        );
    }

    #[test]
    fn every_single_character_typo_is_rejected_before_any_network() {
        // Replace each character in turn by every other base58 character: the
        // result must never parse to an ID (it fails the checksum, the length or
        // the alphabet), let alone to the same one.
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for protected in [false, true] {
            let original = sample(protected).to_string();
            let body_start = SHARE_ID_PREFIX.len();
            let chars: Vec<char> = original.chars().collect();
            let mut tried = 0usize;
            for pos in body_start..chars.len() {
                for &c in ALPHABET {
                    let c = c as char;
                    if c == chars[pos] {
                        continue;
                    }
                    let mut t = chars.clone();
                    t[pos] = c;
                    let typo: String = t.into_iter().collect();
                    tried += 1;
                    assert!(
                        ShareId::parse(&typo).is_err(),
                        "typo at {pos} ({c}) parsed: {typo}"
                    );
                }
            }
            assert!(tried > 4000, "only {tried} typos tried");
        }
    }

    #[test]
    fn a_dropped_or_added_character_is_rejected() {
        let original = sample(true).to_string();
        for pos in SHARE_ID_PREFIX.len()..original.len() {
            let mut t = original.clone();
            t.remove(pos);
            assert!(ShareId::parse(&t).is_err(), "deleting {pos} parsed");
            let mut t = original.clone();
            t.insert(pos, '2');
            assert!(ShareId::parse(&t).is_err(), "inserting at {pos} parsed");
        }
    }

    #[test]
    fn parse_transfer_id_routes_both_forms() {
        let id = sample(true);
        match parse_transfer_id(&id.to_string()).unwrap() {
            TransferId::Share(s) => assert_eq!(s, id),
            other => panic!("{other:?}"),
        }
        let m = mid(3);
        match parse_transfer_id(&format!(" {} ", m.to_string())).unwrap() {
            TransferId::Mid(got) => assert_eq!(got, m),
            other => panic!("{other:?}"),
        }
        assert!(parse_transfer_id("hello").is_err());
        assert!(parse_transfer_id("").is_err());
        let mut typo = id.to_string();
        typo.pop();
        typo.push('1');
        assert!(matches!(
            parse_transfer_id(&typo),
            Err(MiasmaError::InvalidShareId(_))
        ));
    }
}
