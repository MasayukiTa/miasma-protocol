// Pure helper behind the Retrieve screen's error toast. Run: node --test web/tests/
//
// The WASM reader refuses a newer share with an explicit message (crates/
// miasma-wasm/src/lib.rs retrieve_inner). The web UI used to flatten every
// retrieve error into the generic "retrieval failed" toast, hiding that text.
// webUnsupportedShareMessage picks the version-refusal message out so the UI can
// show it verbatim.

import test from 'node:test';
import assert from 'node:assert/strict';
import { webUnsupportedShareMessage } from '../js/format.js';

// The message the WASM reader returns for a version-2 share, as produced by
// retrieve_inner in crates/miasma-wasm/src/lib.rs.
const WASM_V2 =
  'この形式は Web 版では読めません (share version 2). デスクトップ版をご利用ください。 / '
  + 'this format cannot be read in the web version (share version 2); use the desktop app';

test('the version-refusal message is returned verbatim, from a string or an Error', () => {
  assert.equal(webUnsupportedShareMessage(WASM_V2), WASM_V2);
  assert.equal(webUnsupportedShareMessage(new Error(WASM_V2)), WASM_V2);
  assert.equal(webUnsupportedShareMessage({ message: WASM_V2 }), WASM_V2);
});

test('any other version is still recognised (locale-independent clause)', () => {
  const v5 = 'この形式は Web 版では読めません (share version 5). ... (share version 5); use the desktop app';
  assert.equal(webUnsupportedShareMessage(v5), v5);
});

test('surrounding whitespace is trimmed', () => {
  assert.equal(webUnsupportedShareMessage(`  ${WASM_V2}  `), WASM_V2);
});

test('an unrelated retrieve error is not claimed, so the generic toast stands', () => {
  for (const other of [
    'too many shares: 9 (max 8)',
    'insufficient shares',
    'trailing bytes in share bundle',
    'wrong password',
    '',
  ]) {
    assert.equal(webUnsupportedShareMessage(other), '');
    assert.equal(webUnsupportedShareMessage(new Error(other)), '');
  }
});

test('non-string, non-Error inputs never throw and yield the empty string', () => {
  for (const bad of [null, undefined, 42, {}, { message: 99 }, [], { code: 'auth' }]) {
    assert.equal(webUnsupportedShareMessage(bad), '');
  }
});
