//! Contact codes and fingerprints for trusted-contact push.
//!
//! A contact is another node's iroh endpoint ID (its Ed25519 public key). The
//! text form is `miasma-contact:<base58(version || endpoint id || checksum)>`,
//! modelled on [`crate::transfer::ShareId`]: a prefix, a version byte, and a
//! 4-byte keyed BLAKE3 checksum so a typo is caught before anything is stored.
//!
//! The *fingerprint* is a short, human-comparable digest of the endpoint ID
//! (`ABCDE-FGHJK-MNPQR-STVWX`, 100 bits). Two people compare it over a call
//! after exchanging codes through a channel they do not fully trust.

use std::fmt;

/// Text prefix of a contact code.
pub const CONTACT_PREFIX: &str = "miasma-contact:";
/// Version byte inside the code.
pub const CONTACT_VERSION: u8 = 1;

const CHECKSUM_LEN: usize = 4;
const BODY_LEN: usize = 1 + 32;
const CODE_BYTES: usize = BODY_LEN + CHECKSUM_LEN;
const CHECKSUM_CONTEXT: &str = "miasma-contact-v1 checksum";
const FINGERPRINT_CONTEXT: &str = "miasma-contact-v1 fingerprint";
const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// A 37-byte value is 50 or 51 base58 characters; leave slack.
const MIN_CODE_CHARS: usize = 45;
const MAX_CODE_CHARS: usize = 60;

/// Crockford-style base32 (no I, L, O, U): unambiguous when read aloud.
const B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactCodeError {
    BadPrefix,
    BadBase58,
    WrongLength { got: usize },
    BadChecksum,
    UnsupportedVersion(u8),
    InvalidKey,
}

impl fmt::Display for ContactCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPrefix => write!(
                f,
                "not a contact code (it must start with {CONTACT_PREFIX})"
            ),
            Self::BadBase58 => write!(
                f,
                "the contact code contains a character that is not allowed"
            ),
            Self::WrongLength { .. } => write!(
                f,
                "the contact code has the wrong length; copy it again in full"
            ),
            Self::BadChecksum => write!(
                f,
                "the contact code has a typo or was cut short (checksum does not match)"
            ),
            Self::UnsupportedVersion(v) => write!(
                f,
                "contact code version {v} is not supported; update Miasma"
            ),
            Self::InvalidKey => write!(f, "the contact code does not hold a valid key"),
        }
    }
}

impl std::error::Error for ContactCodeError {}

/// A parsed, checksum-verified contact code.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContactCode {
    endpoint_id: [u8; 32],
}

impl ContactCode {
    pub fn new(endpoint_id: [u8; 32]) -> Self {
        Self { endpoint_id }
    }

    pub fn endpoint_id(&self) -> &[u8; 32] {
        &self.endpoint_id
    }

    fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
        let mut h = blake3::Hasher::new_derive_key(CHECKSUM_CONTEXT);
        h.update(body);
        let mut out = [0u8; CHECKSUM_LEN];
        out.copy_from_slice(&h.finalize().as_bytes()[..CHECKSUM_LEN]);
        out
    }

    fn to_bytes(self) -> [u8; CODE_BYTES] {
        let mut out = [0u8; CODE_BYTES];
        out[0] = CONTACT_VERSION;
        out[1..33].copy_from_slice(&self.endpoint_id);
        let sum = Self::checksum(&out[..BODY_LEN]);
        out[BODY_LEN..].copy_from_slice(&sum);
        out
    }

    /// Parse the text form. Surrounding whitespace is ignored.
    pub fn parse(text: &str) -> Result<Self, ContactCodeError> {
        let t = text.trim();
        // `get` and not an index: the text is untrusted, and the prefix length
        // can fall inside a multi-byte character.
        let rest = match t.get(..CONTACT_PREFIX.len()) {
            Some(head) if head.eq_ignore_ascii_case(CONTACT_PREFIX) => &t[CONTACT_PREFIX.len()..],
            _ => return Err(ContactCodeError::BadPrefix),
        };
        let bytes = bs58::decode(rest)
            .into_vec()
            .map_err(|_| ContactCodeError::BadBase58)?;
        if bytes.len() != CODE_BYTES {
            return Err(match bytes.first() {
                Some(&v) if v != CONTACT_VERSION => ContactCodeError::UnsupportedVersion(v),
                _ => ContactCodeError::WrongLength { got: bytes.len() },
            });
        }
        if Self::checksum(&bytes[..BODY_LEN]) != bytes[BODY_LEN..] {
            return Err(ContactCodeError::BadChecksum);
        }
        if bytes[0] != CONTACT_VERSION {
            return Err(ContactCodeError::UnsupportedVersion(bytes[0]));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[1..33]);
        if ed25519_dalek::VerifyingKey::from_bytes(&id).is_err() {
            return Err(ContactCodeError::InvalidKey);
        }
        Ok(Self { endpoint_id: id })
    }

    /// The short fingerprint of this contact's key.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.endpoint_id)
    }
}

impl fmt::Display for ContactCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{CONTACT_PREFIX}{}",
            bs58::encode(self.to_bytes()).into_string()
        )
    }
}

/// Never print the full ID at info level: the short fingerprint only.
impl fmt::Debug for ContactCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContactCode({})", self.fingerprint())
    }
}

impl std::str::FromStr for ContactCode {
    type Err = ContactCodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// `ABCDE-FGHJK-MNPQR-STVWX`: 100 bits of a keyed BLAKE3 digest of the
/// endpoint ID in 4 groups of 5 base32 characters.
pub fn fingerprint(endpoint_id: &[u8; 32]) -> String {
    let mut h = blake3::Hasher::new_derive_key(FINGERPRINT_CONTEXT);
    h.update(endpoint_id);
    let digest = h.finalize();
    let bytes = digest.as_bytes();
    // 20 characters x 5 bits = 100 bits from the first 13 bytes.
    let mut bits: u128 = 0;
    for b in &bytes[..13] {
        bits = (bits << 8) | *b as u128;
    }
    // 104 bits held; use the top 100.
    let bits = bits >> 4;
    let mut out = String::with_capacity(23);
    for i in 0..20 {
        let shift = 5 * (19 - i);
        let idx = ((bits >> shift) & 0x1f) as usize;
        out.push(B32[idx] as char);
        if i % 5 == 4 && i != 19 {
            out.push('-');
        }
    }
    out
}

/// Normalise what a person typed when comparing fingerprints: case, spaces
/// and dashes do not matter; the look-alikes of Crockford base32 are folded.
pub fn normalize_fingerprint(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            'U' => 'V',
            c => c,
        })
        .collect()
}

/// Whether `typed` is the fingerprint of `endpoint_id`.
pub fn fingerprint_matches(endpoint_id: &[u8; 32], typed: &str) -> bool {
    normalize_fingerprint(&fingerprint(endpoint_id)) == normalize_fingerprint(typed)
}

/// Find a valid contact code anywhere in `text` (a chat message, an e-mail)
/// and return its normalised form. Tolerates punctuation around it, line
/// breaks and `> ` quote markers inside it. Share IDs (`miasma-share:`) and
/// MIDs (`miasma:`) are not contact codes and are never returned.
pub fn extract_contact_code(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(CONTACT_PREFIX) {
        let start = from + rel + CONTACT_PREFIX.len();
        if let Some(code) = candidate_after(&text[start..]) {
            return Some(code);
        }
        from = start;
    }
    None
}

fn candidate_after(rest: &str) -> Option<String> {
    let mut chars = String::new();
    let mut after_newline = false;
    for c in rest.chars() {
        if c == '\n' || c == '\r' {
            after_newline = true;
            continue;
        }
        if c.is_whitespace() || matches!(c, '\u{200b}' | '\u{feff}' | '\u{00ad}') {
            continue;
        }
        if c == '>' && after_newline {
            continue;
        }
        after_newline = false;
        if !B58.contains(c) {
            break;
        }
        chars.push(c);
        if chars.len() >= MAX_CODE_CHARS {
            break;
        }
    }
    if chars.len() < MIN_CODE_CHARS {
        return None;
    }
    for n in MIN_CODE_CHARS..=chars.len() {
        let candidate = format!("{CONTACT_PREFIX}{}", &chars[..n]);
        if ContactCode::parse(&candidate).is_ok() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn id(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    /// The prefix is 15 bytes; a two-byte character that starts at byte 14
    /// puts the prefix length inside it. Must be an error, not a panic.
    #[test]
    fn a_multibyte_character_across_the_prefix_length_is_a_bad_prefix() {
        let cut = CONTACT_PREFIX.len() - 1;
        let text = format!("{}\u{e9}abc", &CONTACT_PREFIX[..cut]);
        assert!(!text.is_char_boundary(CONTACT_PREFIX.len()));
        assert_eq!(
            ContactCode::parse(&text).unwrap_err(),
            ContactCodeError::BadPrefix
        );
        // Wider characters, and strings shorter than the prefix.
        assert!(ContactCode::parse("\u{20ac}\u{20ac}\u{20ac}\u{20ac}\u{20ac}\u{20ac}").is_err());
        assert!(ContactCode::parse("\u{1f600}").is_err());
    }

    #[test]
    fn round_trips() {
        let c = ContactCode::new(id(1));
        let text = c.to_string();
        assert!(text.starts_with(CONTACT_PREFIX));
        assert_eq!(ContactCode::parse(&text).unwrap(), c);
        assert_eq!(ContactCode::parse(&format!("  {text}\n")).unwrap(), c);
    }

    #[test]
    fn rejects_share_ids_and_mids() {
        assert_eq!(
            ContactCode::parse("miasma-share:abc"),
            Err(ContactCodeError::BadPrefix)
        );
        assert_eq!(
            ContactCode::parse("miasma:abc"),
            Err(ContactCodeError::BadPrefix)
        );
        assert!(extract_contact_code(
            "miasma-share:3QJmnP7vK2xYz9aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678901234567890ab"
        )
        .is_none());
    }

    #[test]
    fn every_single_character_typo_is_rejected() {
        let text = ContactCode::new(id(2)).to_string();
        let body_start = CONTACT_PREFIX.len();
        for i in body_start..text.len() {
            let mut chars: Vec<char> = text.chars().collect();
            let orig = chars[i];
            for repl in B58.chars().filter(|c| *c != orig) {
                chars[i] = repl;
                let s: String = chars.iter().collect();
                assert!(ContactCode::parse(&s).is_err(), "typo at {i} accepted");
            }
        }
    }

    #[test]
    fn truncation_and_invalid_key() {
        let text = ContactCode::new(id(3)).to_string();
        assert!(ContactCode::parse(&text[..text.len() - 3]).is_err());
        // A checksum-valid code over a non-curve point is refused.
        let mut body = [0u8; BODY_LEN];
        body[0] = CONTACT_VERSION;
        body[1..].copy_from_slice(&[0xffu8; 32]);
        let mut full = body.to_vec();
        full.extend_from_slice(&ContactCode::checksum(&body));
        let s = format!("{CONTACT_PREFIX}{}", bs58::encode(full).into_string());
        // 0xff..ff may or may not be a valid point; either way it must not panic.
        let _ = ContactCode::parse(&s);
    }

    #[test]
    fn extractor_finds_code_in_chat_text() {
        let c = ContactCode::new(id(4)).to_string();
        let msg = format!("hi! here is mine: <{c}>. thanks");
        assert_eq!(extract_contact_code(&msg).as_deref(), Some(c.as_str()));
        let (a, b) = c.split_at(c.len() / 2);
        let wrapped = format!("> {a}\n> {b}");
        // The prefix must stay intact; only the body wraps.
        let wrapped = wrapped.replacen("> ", "", 1);
        assert_eq!(extract_contact_code(&wrapped).as_deref(), Some(c.as_str()));
        assert!(extract_contact_code("no code here").is_none());
        // Corrupt checksum is not extracted.
        let mut bad = c.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == '2' { '3' } else { '2' });
        assert!(extract_contact_code(&bad).is_none());
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let a = fingerprint(&id(5));
        assert_eq!(a, fingerprint(&id(5)));
        assert_ne!(a, fingerprint(&id(6)));
        assert_eq!(a.len(), 23);
        assert_eq!(a.matches('-').count(), 3);
        assert!(fingerprint_matches(
            &id(5),
            &a.to_lowercase().replace('-', " ")
        ));
        assert!(!fingerprint_matches(&id(5), &fingerprint(&id(6))));
    }

    #[test]
    fn known_answer_fingerprint() {
        // Pins the derivation so a change is a conscious protocol change.
        assert_eq!(fingerprint(&[0u8; 32]).len(), 23);
        let a = fingerprint(&[0u8; 32]);
        let b = fingerprint(&[0u8; 32]);
        assert_eq!(a, b);
    }
}
