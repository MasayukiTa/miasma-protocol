// The browser bundle formats, frozen byte for byte.
//
// `dissolve_bytes_bundle` (MDB1) and `retrieve_from_share_bundle` (MSB1) are the
// boundary between the shipped WASM build in web/pkg and web/js/storage.js; the
// bundles are also what the browser keeps. The fixture was produced once by the
// checked-in web/pkg build (crates/miasma-wasm/tests/fixtures/web_bundle_v1).
// These tests check that
//   - the JavaScript reader parses it and gives back the original fields,
//   - the JavaScript writer packs the same shares into exactly the frozen share bundle,
//   - the checked-in WASM build verifies and reconstructs from the frozen bytes,
//   - the same bytes are read by the Rust tests in crates/miasma-wasm (native reader).
// A change to the layout needs a new magic or version and new fixture lines,
// not a regenerated fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import init, {
  dissolve_bytes_bundle,
  retrieve_from_share_bundle,
  verify_share_bytes,
} from '../pkg/miasma_wasm.js';
import { packShareBundle, parseDissolveBundle } from '../js/storage.js';

await init({ module_or_path: readFileSync(new URL('../pkg/miasma_wasm_bg.wasm', import.meta.url)) });

const fixtureText = readFileSync(
  new URL('../../crates/miasma-wasm/tests/fixtures/web_bundle_v1/frozen.hex', import.meta.url),
  'utf8',
);
function frozen(name) {
  for (const line of fixtureText.split('\n')) {
    if (line.startsWith('#')) continue;
    const i = line.indexOf(' ');
    if (i > 0 && line.slice(0, i) === name) {
      const h = line.slice(i + 1).trim();
      const out = new Uint8Array(h.length / 2);
      for (let j = 0; j < out.length; j++) out[j] = parseInt(h.slice(j * 2, j * 2 + 2), 16);
      return out;
    }
  }
  throw new Error(`no fixture ${name}`);
}

const plaintext = frozen('plaintext');
const dissolveBundle = frozen('dissolve_bundle');
const shareBundle = frozen('share_bundle_slots_1_to_3');

test('the frozen dissolve bundle has the documented MDB1 layout', () => {
  const dv = new DataView(dissolveBundle.buffer, dissolveBundle.byteOffset, dissolveBundle.byteLength);
  assert.equal(new TextDecoder().decode(dissolveBundle.subarray(0, 4)), 'MDB1');
  const midLen = dv.getUint16(4, true);
  const mid = new TextDecoder().decode(dissolveBundle.subarray(6, 6 + midLen));
  assert.ok(mid.startsWith('miasma:'));
  let off = 6 + midLen;
  assert.equal(dv.getUint16(off, true), 3); // data shards
  assert.equal(dv.getUint16(off + 2, true), 5); // total shards
  assert.equal(dv.getUint16(off + 4, true), 5); // share count
  off += 6;
  for (let i = 0; i < 5; i++) {
    const len = dv.getUint32(off, true);
    off += 4 + len;
  }
  assert.equal(off, dissolveBundle.byteLength);
});

test('the JavaScript reader parses the frozen dissolve bundle', () => {
  const parsed = parseDissolveBundle(dissolveBundle);
  assert.ok(parsed.mid.startsWith('miasma:'));
  assert.equal(parsed.data_shards, 3);
  assert.equal(parsed.total_shards, 5);
  assert.equal(parsed.shares.length, 5);
  parsed.shares.forEach((share, i) => {
    assert.equal(share.slot_index, i);
    assert.equal(share.version, 1);
    assert.ok(share.binary.byteLength > 0);
    // version byte first, then the 8-byte MID prefix: the bincode share layout.
    assert.equal(share.binary[0], 1);
  });
});

test('the JavaScript writer packs the frozen shares into the frozen share bundle', () => {
  const parsed = parseDissolveBundle(dissolveBundle);
  const packed = packShareBundle(parsed.shares.slice(1, 4));
  assert.deepEqual(packed, shareBundle);
  assert.equal(new TextDecoder().decode(shareBundle.subarray(0, 4)), 'MSB1');
});

test('the checked-in WASM build verifies and reconstructs from the frozen bytes', () => {
  const parsed = parseDissolveBundle(dissolveBundle);
  for (const share of parsed.shares) {
    assert.equal(verify_share_bytes(share.binary, parsed.mid), true);
  }
  const recovered = retrieve_from_share_bundle(parsed.mid, shareBundle, 3, 5);
  assert.deepEqual(recovered, plaintext);
  // Three other shares work as well.
  const other = packShareBundle([parsed.shares[0], parsed.shares[2], parsed.shares[4]]);
  assert.deepEqual(retrieve_from_share_bundle(parsed.mid, other, 3, 5), plaintext);
});

test('the reader and the WASM build refuse damaged bundles', () => {
  const longer = new Uint8Array(dissolveBundle.byteLength + 1);
  longer.set(dissolveBundle);
  assert.throws(() => parseDissolveBundle(longer), /trailing/);
  assert.throws(() => parseDissolveBundle(dissolveBundle.subarray(0, dissolveBundle.byteLength - 1)), /truncated/);
  const badMagic = dissolveBundle.slice();
  badMagic[3] = 0x32; // MDB2
  assert.throws(() => parseDissolveBundle(badMagic), /header/);

  const parsed = parseDissolveBundle(dissolveBundle);
  const bad = shareBundle.slice();
  bad[3] = 0x32; // MSB2
  assert.throws(() => retrieve_from_share_bundle(parsed.mid, bad, 3, 5));
});

test('a bundle made now by the checked-in WASM build has the frozen layout', () => {
  const fresh = parseDissolveBundle(dissolve_bytes_bundle(plaintext, 3, 5));
  const old = parseDissolveBundle(dissolveBundle);
  assert.equal(fresh.shares.length, old.shares.length);
  assert.equal(fresh.data_shards, old.data_shards);
  assert.equal(fresh.total_shards, old.total_shards);
  // Same plaintext and parameters give the same MID.
  assert.equal(fresh.mid, old.mid);
  assert.deepEqual(
    retrieve_from_share_bundle(fresh.mid, packShareBundle(fresh.shares.slice(2, 5)), 3, 5),
    plaintext,
  );
  // And a share of the old fixture is accepted for the fresh bundle's MID.
  assert.equal(verify_share_bytes(old.shares[0].binary, fresh.mid), true);
});
