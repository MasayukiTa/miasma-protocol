// Password policy for a NEW protected transfer, and a strong-password generator.
//
// A JS port of crates/miasma-core/src/transfer/password_policy.rs. The two are kept in
// step by one shared list of vectors, crates/miasma-core/tests/password_policy_vectors.json,
// which the Rust unit test and web/tests/password_policy.test.mjs both read.
//
// Rules (all must hold), applied where key material is created (the publish side), never
// when a password is used to receive:
//   - at least MIN_LEN characters (Unicode code points) and at most MAX_LEN;
//   - an ASCII digit 0-9, an ASCII letter a-z / A-Z, and an ASCII symbol (punctuation);
//   - a space is NOT a symbol, and non-ASCII characters count towards the length only.
//
// Honest note: a compliant 6-character password is still weak (about 38 bits if truly random
// over 94 characters). The manifest's key check is an offline verifier, so anyone holding the
// manifest can guess offline; Argon2id only slows that. Prefer generatePassword().
//
// The web app cannot start a protected publish today (a browser has no file path to give the
// daemon), so this module is used to show the daemon's refusal in the page language; it is
// also what a future web send form would call.

export const MIN_LEN = 6;
export const MAX_LEN = 1024;
export const RECOMMENDED_LEN = 12;
export const GENERATE_MIN_LEN = 12;
export const GENERATE_MAX_LEN = 64;
export const GENERATE_DEFAULT_LEN = 16;

export const CODES = ['too_short', 'too_long', 'no_digit', 'no_letter', 'no_symbol'];

// ASCII punctuation: ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
const isDigit = (c) => c >= '0' && c <= '9';
const isLetter = (c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
const isSymbol = (c) => {
  const n = c.charCodeAt(0);
  return c.length === 1 && n >= 0x21 && n <= 0x7e && !isDigit(c) && !isLetter(c);
};

/** The violation codes of `password`, in the order the Rust side reports them. [] = compliant. */
export function checkPassword(password) {
  const chars = Array.from(String(password ?? ''));
  const v = [];
  if (chars.length < MIN_LEN) v.push('too_short');
  if (chars.length > MAX_LEN) v.push('too_long');
  if (!chars.some(isDigit)) v.push('no_digit');
  if (!chars.some(isLetter)) v.push('no_letter');
  if (!chars.some(isSymbol)) v.push('no_symbol');
  return v;
}

/** 'short' for a compliant password under 12 characters (warn, do not block), else 'ok'. */
export function strengthHint(password) {
  return Array.from(String(password ?? '')).length < RECOMMENDED_LEN ? 'short' : 'ok';
}

/** The codes carried by a daemon error text `weak password: too_short,no_symbol`, or null. */
export function parseWeakPasswordCodes(errorText) {
  const m = /weak password: ([a-z_,]+)/.exec(String(errorText || ''));
  if (!m) return null;
  const codes = m[1].split(',').filter((c) => CODES.includes(c));
  return codes.length ? codes : null;
}

const ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-=?@^_~';

/** A uniform random integer in [0, n) from the crypto RNG, without modulo bias. */
function randomBelow(n, rng) {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    rng.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

/**
 * A random password of `length` characters (clamped to 12..64) with a digit, a letter and a
 * symbol. `rng` is a WebCrypto object (default: globalThis.crypto); there is no Math.random
 * fallback, so a page without crypto throws rather than producing a weak password.
 */
export function generatePassword(length = GENERATE_DEFAULT_LEN, rng = globalThis.crypto) {
  if (!rng || typeof rng.getRandomValues !== 'function') {
    throw new Error('no secure random source available');
  }
  const n = Math.min(GENERATE_MAX_LEN, Math.max(GENERATE_MIN_LEN, Math.trunc(Number(length)) || GENERATE_DEFAULT_LEN));
  for (;;) {
    let s = '';
    for (let i = 0; i < n; i++) s += ALPHABET[randomBelow(ALPHABET.length, rng)];
    if (checkPassword(s).length === 0) return s;
  }
}
