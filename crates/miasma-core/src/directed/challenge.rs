//! One-time confirmation challenge for directed sharing.
//!
//! The recipient generates a challenge code that the sender must enter
//! out-of-band. This prevents misdirected sends — the sender must verify
//! they are targeting the correct recipient.
//!
//! # Challenge format
//!
//! 8 alphanumeric characters (uppercase + digits, excluding ambiguous
//! characters: 0/O, 1/I/L), formatted as XXXX-XXXX.
//!
//! # Security properties
//!
//! - 8 chars from a 31-char alphabet = ~40 bits of entropy
//! - Stored as BLAKE3 hash (constant-time comparison)
//! - TTL: 5 minutes
//! - Max attempts: 3
//! - Fails closed on expiry or max attempts

use rand::Rng;
use subtle::ConstantTimeEq;

/// Challenge code TTL in seconds (5 minutes).
pub const CHALLENGE_TTL_SECS: u64 = 300;

/// Maximum challenge verification attempts.
pub const CHALLENGE_MAX_ATTEMPTS: u8 = 3;

/// Maximum password verification attempts.
pub const PASSWORD_MAX_ATTEMPTS: u8 = 3;

/// Alphabet for challenge codes: uppercase letters + digits, excluding
/// ambiguous characters (0/O, 1/I/L).
const CHALLENGE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Generate a random challenge code.
///
/// Returns the raw code string (e.g. "ABCD-1234") and its BLAKE3 hash.
pub fn generate_challenge() -> (String, [u8; 32]) {
    let mut rng = rand::thread_rng();
    let mut chars = Vec::with_capacity(8);
    for _ in 0..8 {
        let idx = rng.gen_range(0..CHALLENGE_ALPHABET.len());
        chars.push(CHALLENGE_ALPHABET[idx] as char);
    }

    let raw: String = chars.iter().collect();
    let formatted = format!("{}-{}", &raw[..4], &raw[4..]);
    let hash = *blake3::hash(formatted.as_bytes()).as_bytes();

    (formatted, hash)
}

/// Verify a challenge code against its hash (constant-time comparison).
///
/// The `input` should be in "XXXX-XXXX" format or will be normalized.
pub fn verify_challenge(input: &str, expected_hash: &[u8; 32]) -> bool {
    let normalized = normalize_challenge(input);
    let input_hash = blake3::hash(normalized.as_bytes());
    input_hash.as_bytes().ct_eq(expected_hash).into()
}

/// Normalize a challenge input: uppercase, strip spaces, ensure hyphen format.
fn normalize_challenge(input: &str) -> String {
    let clean: String = input
        .trim()
        .to_uppercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();

    if clean.len() == 8 {
        format!("{}-{}", &clean[..4], &clean[4..])
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_generation_format() {
        let (code, hash) = generate_challenge();
        // Format: XXXX-XXXX
        assert_eq!(code.len(), 9);
        assert_eq!(code.chars().nth(4), Some('-'));
        // Hash is non-zero.
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn challenge_verification_correct() {
        let (code, hash) = generate_challenge();
        assert!(verify_challenge(&code, &hash));
    }

    #[test]
    fn challenge_verification_wrong() {
        let (_code, hash) = generate_challenge();
        assert!(!verify_challenge("AAAA-BBBB", &hash));
    }

    #[test]
    fn challenge_normalization() {
        let (code, hash) = generate_challenge();
        // Without hyphen.
        let no_hyphen = code.replace('-', "");
        assert!(verify_challenge(&no_hyphen, &hash));
        // Lowercase.
        assert!(verify_challenge(&code.to_lowercase(), &hash));
        // With spaces.
        let spaced = format!("  {}  ", code);
        assert!(verify_challenge(&spaced, &hash));
    }

    #[test]
    fn challenge_alphabet_no_ambiguous() {
        for _ in 0..100 {
            let (code, _) = generate_challenge();
            let chars: String = code.replace('-', "");
            assert!(!chars.contains('0'));
            assert!(!chars.contains('O'));
            assert!(!chars.contains('1'));
            assert!(!chars.contains('I'));
            assert!(!chars.contains('L'));
        }
    }

    #[test]
    fn challenge_entropy() {
        // 8 chars from 31-char alphabet should give unique codes.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let (code, _) = generate_challenge();
            seen.insert(code);
        }
        // With ~40 bits of entropy, 1000 codes should all be unique.
        assert_eq!(seen.len(), 1000);
    }
}
