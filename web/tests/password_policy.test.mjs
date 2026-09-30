// The password policy and generator. Run: node --test web/tests/
//
// The vectors are shared with the Rust implementation: the same JSON file is read by the
// unit test in crates/miasma-core/src/transfer/password_policy.rs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import {
  checkPassword, strengthHint, parseWeakPasswordCodes, generatePassword,
  GENERATE_MIN_LEN, GENERATE_MAX_LEN, MAX_LEN,
} from '../js/password_policy.js';

const vectors = JSON.parse(
  readFileSync(new URL('../../crates/miasma-core/tests/password_policy_vectors.json', import.meta.url), 'utf8'),
);

test('the shared vectors give the same violations as the Rust implementation', () => {
  assert.ok(vectors.length >= 20);
  for (const { password, violations } of vectors) {
    assert.deepEqual(checkPassword(password), violations, JSON.stringify(password));
  }
});

test('boundaries: length counts characters, not UTF-16 units or bytes', () => {
  assert.deepEqual(checkPassword('a1!bc'), ['too_short']);
  assert.deepEqual(checkPassword('a1!bcd'), []);
  // Five characters where two are outside the BMP: still too short (code points, not units).
  assert.deepEqual(checkPassword('a1!😀😀'), ['too_short']);
  assert.deepEqual(checkPassword('a1!😀😀😀'), []);
  const ok = 'a1!' + 'x'.repeat(MAX_LEN - 3);
  assert.deepEqual(checkPassword(ok), []);
  assert.deepEqual(checkPassword(ok + 'x'), ['too_long']);
});

test('a space and non-ASCII characters satisfy no class', () => {
  assert.deepEqual(checkPassword('abc 123 '), ['no_symbol']);
  assert.deepEqual(checkPassword('éèà12!'), ['no_letter']);
  assert.deepEqual(checkPassword('ａｂｃ１２３！'), ['no_digit', 'no_letter', 'no_symbol']);
  assert.deepEqual(checkPassword(undefined), ['too_short', 'no_digit', 'no_letter', 'no_symbol']);
});

test('every ASCII punctuation character is a symbol; there are 32', () => {
  let n = 0;
  for (let c = 0x21; c <= 0x7e; c++) {
    const ch = String.fromCharCode(c);
    if (/[0-9A-Za-z]/.test(ch)) continue;
    n++;
    assert.deepEqual(checkPassword(`a1${ch}bcd`), [], ch);
  }
  assert.equal(n, 32);
});

test('strengthHint warns below 12 characters', () => {
  assert.equal(strengthHint('a1!bcd'), 'short');
  assert.equal(strengthHint('a1!bcdefghi'), 'short'); // 11
  assert.equal(strengthHint('a1!bcdefghij'), 'ok'); // 12
});

test('the daemon error text is parsed into codes', () => {
  assert.deepEqual(parseWeakPasswordCodes('weak password: too_short,no_symbol'), ['too_short', 'no_symbol']);
  assert.deepEqual(parseWeakPasswordCodes('daemon error: weak password: no_digit'), ['no_digit']);
  assert.equal(parseWeakPasswordCodes('wrong password'), null);
  assert.equal(parseWeakPasswordCodes('weak password: bogus'), null);
});

test('generated passwords are always compliant, of the asked length, and differ', () => {
  const seen = new Set();
  for (let i = 0; i < 3000; i++) {
    const len = GENERATE_MIN_LEN + (i % (GENERATE_MAX_LEN - GENERATE_MIN_LEN + 1));
    const pw = generatePassword(len, webcrypto);
    assert.equal(Array.from(pw).length, len);
    assert.deepEqual(checkPassword(pw), [], pw);
    assert.equal(strengthHint(pw), 'ok');
    seen.add(pw);
  }
  assert.equal(seen.size, 3000);
  assert.equal(generatePassword(undefined, webcrypto).length, 16);
  assert.equal(generatePassword(1, webcrypto).length, GENERATE_MIN_LEN);
  assert.equal(generatePassword(1000, webcrypto).length, GENERATE_MAX_LEN);
});

test('no secure random source means no password, never a weak fallback', () => {
  assert.throws(() => generatePassword(16, {}), /secure random/);
  assert.throws(() => generatePassword(16, null), /secure random/);
});
