import test from 'node:test';
import assert from 'node:assert/strict';
import {
  midPrefixHexFromMid, packShareBundle, parseDissolveBundle,
  shareBinaryBytes, shareSerializedSize, shareToPortableJson,
} from '../js/storage.js';

function b58encode(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry) { digits.push(carry % 58); carry = Math.floor(carry / 58); }
  }
  for (let i = 0; i < bytes.length - 1 && bytes[i] === 0; i++) digits.push(0);
  return digits.reverse().map((d) => alphabet[d]).join('');
}

function dissolveBundle(mid, k, n, shares) {
  const midBytes = new TextEncoder().encode(mid);
  let total = 12 + midBytes.length;
  for (const s of shares) total += 4 + s.length;
  const out = new Uint8Array(total);
  out.set([0x4d, 0x44, 0x42, 0x31], 0);
  const view = new DataView(out.buffer);
  view.setUint16(4, midBytes.length, true);
  let off = 6;
  out.set(midBytes, off); off += midBytes.length;
  view.setUint16(off, k, true); off += 2;
  view.setUint16(off, n, true); off += 2;
  view.setUint16(off, shares.length, true); off += 2;
  for (const share of shares) {
    view.setUint32(off, share.length, true); off += 4;
    out.set(share, off); off += share.length;
  }
  return out;
}

test('MID prefix helper decodes the first eight digest bytes', () => {
  const digest = Uint8Array.from({ length: 32 }, (_, i) => i);
  const mid = 'miasma:' + b58encode(digest);
  assert.equal(midPrefixHexFromMid(mid), '0001020304050607');
});

test('binary shares stay binary until a portable export is requested', () => {
  const share = { slot_index: 3, mid_prefix: '0011223344556677', binary: new Uint8Array([1, 2, 3, 4]) };
  assert.deepEqual(Array.from(shareBinaryBytes(share)), [1, 2, 3, 4]);
  assert.equal(shareSerializedSize(share), 4);
  const portable = shareToPortableJson(share);
  assert.equal(portable.slot_index, 3);
  assert.equal(portable.bincode, 'AQIDBA==');
  assert.equal('binary' in portable, false);
});

test('retrieval bundle is length-prefixed and contains no base64', () => {
  const bundle = packShareBundle([
    { binary: new Uint8Array([10, 11]) },
    { bincode: 'DA0O' },
  ]);
  assert.deepEqual(Array.from(bundle.slice(0, 6)), [0x4d, 0x53, 0x42, 0x31, 2, 0]);
  const view = new DataView(bundle.buffer, bundle.byteOffset, bundle.byteLength);
  assert.equal(view.getUint32(6, true), 2);
  assert.deepEqual(Array.from(bundle.slice(10, 12)), [10, 11]);
  assert.equal(view.getUint32(12, true), 3);
  assert.deepEqual(Array.from(bundle.slice(16)), [12, 13, 14]);
});

test('dissolve bundle parser returns binary shares and rejects trailing data', () => {
  const digest = Uint8Array.from({ length: 32 }, (_, i) => 31 - i);
  const mid = 'miasma:' + b58encode(digest);
  const source = dissolveBundle(mid, 2, 3, [new Uint8Array([1]), new Uint8Array([2, 3]), new Uint8Array([4, 5, 6])]);
  const parsed = parseDissolveBundle(source);
  assert.equal(parsed.mid, mid);
  assert.equal(parsed.data_shards, 2);
  assert.equal(parsed.total_shards, 3);
  assert.equal(parsed.shares.length, 3);
  assert.deepEqual(Array.from(parsed.shares[2].binary), [4, 5, 6]);
  assert.equal(parsed.shares[2].slot_index, 2);

  const bad = new Uint8Array(source.length + 1);
  bad.set(source);
  assert.throws(() => parseDissolveBundle(bad), /trailing/);
});
