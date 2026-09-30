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

/// Run-time password construction for tests: no test carries a literal
/// password, and no failure message prints one.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use rand::{rngs::OsRng, seq::SliceRandom};

    /// A character class that never satisfies the letter/digit/symbol rules.
    #[derive(Clone, Copy, Debug)]
    pub enum Other {
        /// ASCII space (not a symbol).
        Space,
        /// A non-ASCII character from a randomly chosen range (accented
        /// letters, kana, full-width forms, emoji).
        NonAscii,
    }

    fn non_ascii(rng: &mut OsRng) -> char {
        const RANGES: [(u32, u32); 5] = [
            (0xC0, 0xD6),
            (0x3041, 0x3096),
            (0xFF10, 0xFF19),
            (0xFF21, 0xFF3A),
            (0x1F600, 0x1F64F),
        ];
        let (lo, hi) = RANGES[rng.gen_range(0..RANGES.len())];
        char::from_u32(rng.gen_range(lo..=hi)).expect("scalar value")
    }

    /// A shuffled string of `letters` ASCII letters, `digits` digits,
    /// `symbols` ASCII punctuation characters and one character per entry of
    /// `others`, every character drawn from the OS RNG.
    pub fn compose(letters: usize, digits: usize, symbols: usize, others: &[Other]) -> String {
        let mut rng = OsRng;
        let mut chars: Vec<char> = Vec::new();
        for _ in 0..letters {
            let base = if rng.gen_bool(0.5) { b'a' } else { b'A' };
            chars.push((base + rng.gen_range(0..26u8)) as char);
        }
        for _ in 0..digits {
            chars.push((b'0' + rng.gen_range(0..10u8)) as char);
        }
        for _ in 0..symbols {
            loop {
                let b = rng.gen_range(0x21u8..=0x7e);
                if b.is_ascii_punctuation() {
                    chars.push(b as char);
                    break;
                }
            }
        }
        for o in others {
            chars.push(match o {
                Other::Space => ' ',
                Other::NonAscii => non_ascii(&mut rng),
            });
        }
        chars.shuffle(&mut rng);
        chars.into_iter().collect()
    }

    /// The violation codes a composition must produce, derived from its
    /// counts (never from a literal list), in `check`'s stable order.
    pub fn expected_codes(
        letters: usize,
        digits: usize,
        symbols: usize,
        others: &[Other],
    ) -> Vec<&'static str> {
        let len = letters + digits + symbols + others.len();
        let mut v = Vec::new();
        if len < MIN_LEN {
            v.push("too_short");
        }
        if len > MAX_LEN {
            v.push("too_long");
        }
        if digits == 0 {
            v.push("no_digit");
        }
        if letters == 0 {
            v.push("no_letter");
        }
        if symbols == 0 {
            v.push("no_symbol");
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{compose, expected_codes, Other};
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

    /// Checks a composition against `check`; the failure message carries the
    /// counts only, never the password.
    fn assert_composition(letters: usize, digits: usize, symbols: usize, others: &[Other]) {
        let pw = compose(letters, digits, symbols, others);
        assert_eq!(
            pw.chars().count(),
            letters + digits + symbols + others.len()
        );
        let ok = codes_of(&pw) == expected_codes(letters, digits, symbols, others);
        assert!(
            ok,
            "composition l={letters} d={digits} s={symbols} o={} mismatched",
            others.len()
        );
    }

    /// The same file is read by `web/tests/password_policy.test.mjs`. The
    /// failure message names the case index only.
    #[test]
    fn shared_vectors_match() {
        let raw = include_str!("../../tests/password_policy_vectors.json");
        let vectors: Vec<Vector> = serde_json::from_str(raw).unwrap();
        assert!(vectors.len() >= 20);
        for (i, v) in vectors.iter().enumerate() {
            let want: Vec<&str> = v.violations.iter().map(String::as_str).collect();
            let matches = codes_of(&v.password) == want;
            assert!(matches, "shared vector #{i} disagrees with check()");
        }
    }

    #[test]
    fn boundaries_five_versus_six() {
        // Five characters in every class: too short and nothing else.
        assert_composition(3, 1, 1, &[]);
        assert!(check(&compose(4, 1, 1, &[])).is_ok());
        // Empty: every rule fails.
        assert_composition(0, 0, 0, &[]);
    }

    #[test]
    fn each_missing_class_is_reported_alone() {
        assert_composition(5, 0, 2, &[]);
        assert_composition(0, 5, 2, &[]);
        assert_composition(4, 3, 0, &[]);
        assert!(check(&compose(4, 2, 1, &[])).is_ok());
        assert!(check(&compose(1, 3, 3, &[])).is_ok());
        assert!(check(&compose(6, 1, 1, &[])).is_ok());
    }

    #[test]
    fn space_is_not_a_symbol() {
        assert_composition(3, 3, 0, &[Other::Space, Other::Space]);
        assert_composition(0, 0, 0, &[Other::Space; 6]);
    }

    #[test]
    fn non_ascii_counts_for_length_only() {
        // Non-ASCII stand-ins for letters, digits and symbols satisfy nothing.
        assert_composition(0, 0, 0, &[Other::NonAscii; 7]);
        // Non-ASCII letters are not ASCII letters.
        assert_composition(0, 2, 1, &[Other::NonAscii; 3]);
        // Length is in characters, not bytes: 5 multi-byte chars is too short.
        assert_composition(0, 1, 1, &[Other::NonAscii; 3]);
        // Non-ASCII alongside a compliant ASCII core is fine.
        let pw = compose(4, 2, 1, &[Other::NonAscii]);
        assert!(check(&pw).is_ok());
        assert!(pw.len() > pw.chars().count());
    }

    #[test]
    fn every_ascii_punctuation_is_a_symbol() {
        for c in (0x21u8..=0x7e).filter(|b| b.is_ascii_punctuation()) {
            let mut pw = compose(5, 1, 0, &[]);
            pw.push(c as char);
            assert!(check(&pw).is_ok(), "symbol byte {c:#04x} refused");
        }
        // 32 symbols in total, and space is not one of them.
        assert_eq!((0x00u8..=0x7f).filter(u8::is_ascii_punctuation).count(), 32);
        assert!(!b' '.is_ascii_punctuation());
    }

    #[test]
    fn too_long_is_refused() {
        let ok = compose(MAX_LEN - 2, 1, 1, &[]);
        assert_eq!(ok.chars().count(), MAX_LEN);
        assert!(check(&ok).is_ok());
        assert_composition(MAX_LEN - 1, 1, 1, &[]);
    }

    #[test]
    fn strength_hint_warns_below_twelve() {
        assert_eq!(strength_hint(&compose(4, 1, 1, &[])), Strength::Short); // 6
        assert_eq!(strength_hint(&compose(9, 1, 1, &[])), Strength::Short); // 11
        assert_eq!(strength_hint(&compose(10, 1, 1, &[])), Strength::Ok); // 12
    }

    #[test]
    fn codes_round_trip_through_the_error_text() {
        let pw = compose(3, 0, 0, &[]);
        let e = crate::MiasmaError::WeakPassword(check(&pw).unwrap_err()).to_string();
        let want = expected_codes(3, 0, 0, &[]);
        assert!(e == format!("{ERROR_PREFIX}{}", want.join(",")));
        assert!(parse_codes(&e).unwrap() == want);
        // Wrapped by a client or the daemon's job-status text.
        let wrapped = format!("daemon error: {e}");
        assert_eq!(parse_codes(&wrapped).unwrap().len(), want.len());
        assert!(parse_codes("wrong password").is_none());
    }

    #[test]
    fn generated_passwords_are_always_compliant() {
        for i in 0..10_000 {
            let len = GENERATE_MIN_LEN + (i % (GENERATE_MAX_LEN - GENERATE_MIN_LEN + 1));
            let pw = generate(len);
            assert_eq!(pw.chars().count(), len);
            assert!(
                check(&pw).is_ok(),
                "generated password of length {len} refused"
            );
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
        assert!(a.as_str() != b.as_str());
    }
}
