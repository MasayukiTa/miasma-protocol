//! Password policy for *protected transfers*, and a strong-password generator.
//!
//! The policy applies where key material is created (the publish side,
//! [`PasswordProtection::create`](super::protection::PasswordProtection::create)).
//! It is never applied when a password is *used* to receive: a transfer that
//! was published with an older, weaker password must stay receivable.
//!
//! Rules (all must hold):
//!
//! * at least [`MIN_LEN`] characters (Unicode scalar values) and at most
//!   [`MAX_LEN`];
//! * at least one ASCII digit `0-9`;
//! * at least one ASCII letter `a-z` or `A-Z` (upper *or* lower case);
//! * at least one symbol: an ASCII punctuation/symbol character, i.e.
//!   ``!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~``.
//!
//! Space is **not** a symbol, and neither is any non-ASCII character. Non-ASCII
//! characters are allowed in a password (they count towards the length) but
//! never satisfy the letter, digit or symbol requirement. The vectors in
//! `tests/password_policy_vectors.json` pin this, and the web client's JS port
//! reads the same file.
//!
//! Honest note: a policy-compliant 6-character password is still weak. Random
//! over the 94 printable ASCII characters it is about 38 bits (roughly 5 years
//! on average at 1,000 guesses per second), and a human-chosen one is far
//! weaker. The manifest's `key_check` tag is an offline verifier, so anyone
//! holding the manifest can brute-force offline; Argon2id only slows that. The
//! generator ([`generate`]) is the recommended path, and [`strength_hint`]
//! drives a soft "short" warning below [`RECOMMENDED_LEN`].

use rand::Rng as _;
use zeroize::Zeroizing;

/// Shortest password the policy accepts.
pub const MIN_LEN: usize = 6;
/// Longest password the policy accepts (the daemon's field cap is 1024).
pub const MAX_LEN: usize = 1024;
/// Below this a compliant password still gets a soft warning.
pub const RECOMMENDED_LEN: usize = 12;

/// Generator bounds and default.
pub const GENERATE_MIN_LEN: usize = 12;
pub const GENERATE_MAX_LEN: usize = 64;
pub const GENERATE_DEFAULT_LEN: usize = 16;

/// Symbols the generator draws from: ASCII punctuation that survives a shell,
/// a URL fragment and a copy/paste without quoting. All of them count as
/// symbols for [`check`].
#[cfg(test)]
const GEN_SYMBOLS: &[u8] = b"!#$%&*+-=?@^_~";
const GEN_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-=?@^_~";

/// One way a password fails the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyViolation {
    TooShort { min: usize, len: usize },
    TooLong { max: usize, len: usize },
    NoDigit,
    NoLetter,
    NoSymbol,
}

impl PolicyViolation {
    /// Stable machine-readable code. Clients match on this, never on prose.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "too_short",
            Self::TooLong { .. } => "too_long",
            Self::NoDigit => "no_digit",
            Self::NoLetter => "no_letter",
            Self::NoSymbol => "no_symbol",
        }
    }
}

/// `too_short,no_symbol`: the codes of `violations`, comma-separated.
pub fn codes(violations: &[PolicyViolation]) -> String {
    violations
        .iter()
        .map(PolicyViolation::code)
        .collect::<Vec<_>>()
        .join(",")
}

/// Prefix of the error text that carries the codes (`weak password: a,b`).
pub const ERROR_PREFIX: &str = "weak password: ";

/// Parse the codes out of an error string produced by
/// [`MiasmaError::WeakPassword`](crate::MiasmaError::WeakPassword)'s `Display`
/// (possibly wrapped by a client). Unknown codes are kept out; `None` when the
/// text carries no `weak password:` list.
pub fn parse_codes(error_text: &str) -> Option<Vec<&'static str>> {
    let rest = error_text.split_once(ERROR_PREFIX)?.1;
    let list: &str = rest
        .split(|c: char| c.is_whitespace() || c == '"' || c == ')')
        .next()
        .unwrap_or("");
    let known = [
        "too_short",
        "too_long",
        "no_digit",
        "no_letter",
        "no_symbol",
    ];
    let out: Vec<&'static str> = list
        .split(',')
        .filter_map(|c| known.iter().copied().find(|k| *k == c))
        .collect();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Check `password` against the policy. `Ok(())` when it complies, otherwise
/// every violation, in a stable order (length, digit, letter, symbol).
pub fn check(password: &str) -> Result<(), Vec<PolicyViolation>> {
    let mut v = Vec::new();
    let len = password.chars().count();
    if len < MIN_LEN {
        v.push(PolicyViolation::TooShort { min: MIN_LEN, len });
    }
    if len > MAX_LEN {
        v.push(PolicyViolation::TooLong { max: MAX_LEN, len });
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        v.push(PolicyViolation::NoDigit);
    }
    if !password.chars().any(|c| c.is_ascii_alphabetic()) {
        v.push(PolicyViolation::NoLetter);
    }
    if !password.chars().any(|c| c.is_ascii_punctuation()) {
        v.push(PolicyViolation::NoSymbol);
    }
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

/// Soft strength verdict for a password that already passes [`check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// Compliant but shorter than [`RECOMMENDED_LEN`]: warn, do not block.
    Short,
    Ok,
}

pub fn strength_hint(password: &str) -> Strength {
    if password.chars().count() < RECOMMENDED_LEN {
        Strength::Short
    } else {
        Strength::Ok
    }
}

/// A random password of `len` characters (clamped to 12..=64) that always
/// contains a digit, a letter and a symbol.
///
/// Characters come from the OS RNG, uniformly over a 76-character alphabet
/// (letters, digits and `!#$%&*+-=?@^_~`); a draw that happens to miss a class
/// is discarded and redrawn, so the result is uniform among compliant strings.
/// 16 characters is about 100 bits.
pub fn generate(len: usize) -> Zeroizing<String> {
    let len = len.clamp(GENERATE_MIN_LEN, GENERATE_MAX_LEN);
    let mut rng = rand::rngs::OsRng;
    loop {
        let mut s = Zeroizing::new(String::with_capacity(len));
        for _ in 0..len {
            let i = rng.gen_range(0..GEN_ALPHABET.len());
            s.push(GEN_ALPHABET[i] as char);
        }
        if check(&s).is_ok() {
            return s;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        password: String,
        violations: Vec<String>,
    }

    fn codes_of(pw: &str) -> Vec<&'static str> {
        match check(pw) {
            Ok(()) => vec![],
            Err(v) => v.iter().map(PolicyViolation::code).collect(),
        }
    }

    /// The same file is read by `web/tests/password_policy.test.mjs`.
    #[test]
    fn shared_vectors_match() {
        let raw = include_str!("../../tests/password_policy_vectors.json");
        let vectors: Vec<Vector> = serde_json::from_str(raw).unwrap();
        assert!(vectors.len() >= 20);
        for v in vectors {
            assert_eq!(
                codes_of(&v.password),
                v.violations.iter().map(String::as_str).collect::<Vec<_>>(),
                "password {:?}",
                v.password
            );
        }
    }

    #[test]
    fn boundaries_five_versus_six() {
        assert_eq!(codes_of("a1!bc"), vec!["too_short"]);
        assert!(check("a1!bcd").is_ok());
        assert_eq!(
            codes_of(""),
            vec!["too_short", "no_digit", "no_letter", "no_symbol"]
        );
    }

    #[test]
    fn each_missing_class_is_reported_alone() {
        assert_eq!(codes_of("abcdef!"), vec!["no_digit"]);
        assert_eq!(codes_of("123456!"), vec!["no_letter"]);
        assert_eq!(codes_of("abc1234"), vec!["no_symbol"]);
        assert!(check("Abc123!").is_ok());
        assert!(check("ABC123!").is_ok());
        assert!(check("abc123!").is_ok());
    }

    #[test]
    fn space_is_not_a_symbol() {
        assert_eq!(codes_of("abc 123 "), vec!["no_symbol"]);
        assert_eq!(
            codes_of("      "),
            vec!["no_digit", "no_letter", "no_symbol"]
        );
    }

    #[test]
    fn non_ascii_counts_for_length_only() {
        // Full-width letters, digits and punctuation satisfy nothing.
        assert_eq!(
            codes_of("ａｂｃ１２３！"),
            vec!["no_digit", "no_letter", "no_symbol"]
        );
        // Accented letters are not ASCII letters.
        assert_eq!(codes_of("éèà12!"), vec!["no_letter"]);
        // Length is in characters, not bytes: 5 multi-byte chars is too short.
        assert_eq!(codes_of("あいう1!"), vec!["too_short", "no_letter"]);
        // Non-ASCII alongside a compliant ASCII core is fine.
        assert!(check("pässw0rd!あ").is_ok());
    }

    #[test]
    fn every_ascii_punctuation_is_a_symbol() {
        for c in (0x21u8..=0x7e).filter(|b| b.is_ascii_punctuation()) {
            let pw = format!("a1{}bcd", c as char);
            assert!(check(&pw).is_ok(), "{pw:?}");
        }
        // 32 symbols in total, and space is not one of them.
        assert_eq!((0x00u8..=0x7f).filter(u8::is_ascii_punctuation).count(), 32);
        assert!(!b' '.is_ascii_punctuation());
    }

    #[test]
    fn too_long_is_refused() {
        let ok = format!("a1!{}", "x".repeat(MAX_LEN - 3));
        assert!(check(&ok).is_ok());
        let long = format!("{ok}x");
        assert_eq!(codes_of(&long), vec!["too_long"]);
    }

    #[test]
    fn strength_hint_warns_below_twelve() {
        assert_eq!(strength_hint("a1!bcd"), Strength::Short);
        assert_eq!(strength_hint("a1!bcdefghi"), Strength::Short); // 11
        assert_eq!(strength_hint("a1!bcdefghij"), Strength::Ok); // 12
    }

    #[test]
    fn codes_round_trip_through_the_error_text() {
        let e = crate::MiasmaError::WeakPassword(check("abc").unwrap_err()).to_string();
        assert_eq!(e, "weak password: too_short,no_digit,no_symbol");
        assert_eq!(
            parse_codes(&e).unwrap(),
            vec!["too_short", "no_digit", "no_symbol"]
        );
        // Wrapped by a client or the daemon's job-status text.
        let wrapped = format!("daemon error: {e}");
        assert_eq!(parse_codes(&wrapped).unwrap().len(), 3);
        assert!(parse_codes("wrong password").is_none());
    }

    #[test]
    fn generated_passwords_are_always_compliant() {
        for i in 0..10_000 {
            let len = GENERATE_MIN_LEN + (i % (GENERATE_MAX_LEN - GENERATE_MIN_LEN + 1));
            let pw = generate(len);
            assert_eq!(pw.chars().count(), len);
            assert!(check(&pw).is_ok(), "{pw:?}");
            assert_eq!(strength_hint(&pw), Strength::Ok);
            assert!(pw.bytes().all(|b| GEN_ALPHABET.contains(&b)));
        }
    }

    #[test]
    fn generator_bounds_and_default() {
        assert_eq!(generate(12).len(), 12);
        assert_eq!(generate(64).len(), 64);
        assert_eq!(generate(0).len(), GENERATE_MIN_LEN);
        assert_eq!(generate(1000).len(), GENERATE_MAX_LEN);
        assert_eq!(generate(GENERATE_DEFAULT_LEN).len(), 16);
        assert!(GEN_SYMBOLS.iter().all(|b| b.is_ascii_punctuation()));
    }

    #[test]
    fn generated_passwords_differ() {
        let a = generate(16);
        let b = generate(16);
        assert_ne!(a.as_str(), b.as_str());
    }
}
