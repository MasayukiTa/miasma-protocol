import assert from 'node:assert/strict';
import test from 'node:test';
import {
  authorizationHeader, b64urlDecode, b64urlEncode, b64urlLength, canonicalRequest, isBootToken,
  parseAuthorizationHeader, pathAndQuery, registrationProof, toHex,
  HEADER_MAX_BYTES, REQUEST_PREFIX, REGISTER_PREFIX,
} from '../js/websig.js';
import { specCanonical, specRegisterProof, b64u, sha256Hex } from './fakes.mjs';

// All values are made up per run; nothing here is a key or a secret.
const rnd = (n) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const sample = () => ({
  method: 'POST',
  pathAndQuery: '/api/retrieve?x=1',
  origin: 'http://127.0.0.1:17842',
  sid: rnd(16),
  ts: 1792999999123,
  nonce: rnd(16),
  bodyHashHex: 'ab'.repeat(32),
});

test('canonical request has eight LF-separated lines, no trailing LF', () => {
  const v = sample();
  const text = canonicalRequest(v);
  const lines = text.split('\n');
  assert.equal(lines.length, 8);
  assert.deepEqual(lines, [REQUEST_PREFIX, 'POST', '/api/retrieve?x=1', 'http://127.0.0.1:17842', v.sid, '1792999999123', v.nonce, 'ab'.repeat(32)]);
  assert.ok(!text.endsWith('\n'));
  assert.ok(!text.includes('\r'));
  assert.equal(text, specCanonical({ method: v.method, target: v.pathAndQuery, origin: v.origin, sid: v.sid, ts: v.ts, nonce: v.nonce, bodyHash: v.bodyHashHex }));
});

test('canonical request: every field changes the string', () => {
  const base = sample();
  const baseText = canonicalRequest(base);
  const variants = {
    method: 'GET',
    pathAndQuery: '/api/status',
    origin: 'http://localhost:17842',
    sid: rnd(16),
    ts: base.ts + 1,
    nonce: rnd(16),
    bodyHashHex: 'cd'.repeat(32),
  };
  for (const [field, value] of Object.entries(variants)) {
    assert.notEqual(canonicalRequest({ ...base, [field]: value }), baseText, field);
  }
});

test('canonical request accepts ts as a number or a digit string, identically', () => {
  const v = sample();
  assert.equal(canonicalRequest({ ...v, ts: 1792999999123 }), canonicalRequest({ ...v, ts: '1792999999123' }));
});

test('canonical request rejects values that could blur two requests into one', () => {
  const v = sample();
  const bad = [
    { method: 'post' }, { method: 'PO ST' }, { method: '' }, { method: 'GET\nX' },
    { pathAndQuery: 'api/x' }, { pathAndQuery: '/a\nb' }, { pathAndQuery: '/a\rb' }, { pathAndQuery: '' },
    { origin: '' }, { origin: 'http://a\nhttp://b' },
    { sid: 'short' }, { sid: rnd(17) }, { sid: `${rnd(16).slice(0, 21)}=` }, { sid: `${rnd(16).slice(0, 21)}\n` },
    { nonce: 'x' }, { nonce: rnd(32) },
    { ts: -1 }, { ts: 1.5 }, { ts: '12a' }, { ts: '' }, { ts: NaN }, { ts: 'x\n1' },
    { bodyHashHex: 'AB'.repeat(32) }, { bodyHashHex: 'ab'.repeat(31) }, { bodyHashHex: `${'ab'.repeat(32)}\n` },
  ];
  for (const patch of bad) {
    assert.throws(() => canonicalRequest({ ...v, ...patch }), Error, JSON.stringify(patch));
  }
});

test('empty body hashes to the SHA-256 of zero bytes and is accepted', async () => {
  const empty = await sha256Hex(new Uint8Array(0));
  assert.equal(empty, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.doesNotThrow(() => canonicalRequest({ ...sample(), bodyHashHex: empty }));
});

test('registration proof has five lines in the documented order', () => {
  const boot = rnd(32);
  const pub = rnd(65);
  const text = registrationProof({ origin: 'http://127.0.0.1:17842', boot, pub, ts: 1792999999123 });
  assert.deepEqual(text.split('\n'), [REGISTER_PREFIX, 'http://127.0.0.1:17842', boot, pub, '1792999999123']);
  assert.equal(text, specRegisterProof({ origin: 'http://127.0.0.1:17842', boot, pub, ts: 1792999999123 }));
  assert.throws(() => registrationProof({ origin: 'o', boot: rnd(31), pub, ts: 1 }));
  assert.throws(() => registrationProof({ origin: 'o', boot, pub: rnd(64), ts: 1 }));
  assert.throws(() => registrationProof({ origin: 'o\n', boot, pub, ts: 1 }));
});

test('request and registration strings can never be mistaken for each other', () => {
  assert.notEqual(REQUEST_PREFIX, REGISTER_PREFIX);
  const req = canonicalRequest(sample());
  const reg = registrationProof({ origin: 'o', boot: rnd(32), pub: rnd(65), ts: 1 });
  assert.ok(!req.startsWith(REGISTER_PREFIX));
  assert.ok(!reg.startsWith(REQUEST_PREFIX));
});

test('Authorization header: exact shape, round trip, size limit', () => {
  const sid = rnd(16); const nonce = rnd(16); const sig = rnd(64);
  const header = authorizationHeader({ sid, ts: 1792999999123, nonce, sig });
  assert.equal(header, `MiasmaSig v=1, sid=${sid}, ts=1792999999123, n=${nonce}, sig=${sig}`);
  assert.ok(header.length <= HEADER_MAX_BYTES);
  assert.deepEqual(parseAuthorizationHeader(header), { sid, ts: '1792999999123', nonce, sig });
  assert.ok(!header.startsWith('Bearer '));
});

test('Authorization header parser is strict', () => {
  const sid = rnd(16); const nonce = rnd(16); const sig = rnd(64);
  const good = `MiasmaSig v=1, sid=${sid}, ts=1, n=${nonce}, sig=${sig}`;
  assert.ok(parseAuthorizationHeader(good));
  const bad = [
    good.replace('v=1', 'v=2'),
    good.replace(', sid=', ',sid='),
    good.replace('MiasmaSig', 'miasmasig'),
    `${good} `,
    ` ${good}`,
    good.replace(`sid=${sid}, ts=1, n=${nonce}`, `ts=1, sid=${sid}, n=${nonce}`),
    good.replace(`sig=${sig}`, `sig=${sig}=`),
    good.replace(`sig=${sig}`, `sig=${rnd(63)}`),
    `${good}, extra=1`,
    `Bearer ${sid}`,
    `${good}${'a'.repeat(HEADER_MAX_BYTES)}`,
    '', null, undefined, 5,
  ];
  for (const text of bad) assert.equal(parseAuthorizationHeader(text), null, String(text));
});

test('header builder refuses parts of the wrong size', () => {
  const sid = rnd(16); const nonce = rnd(16); const sig = rnd(64);
  assert.throws(() => authorizationHeader({ sid, ts: 1, nonce, sig: rnd(63) }));
  assert.throws(() => authorizationHeader({ sid: rnd(15), ts: 1, nonce, sig }));
  assert.throws(() => authorizationHeader({ sid, ts: 'x', nonce, sig }));
});

test('base64url: unpadded, URL-safe, strict on decode', () => {
  const bytes = new Uint8Array([0xfb, 0xff, 0xfe, 0x00, 0x01]);
  const text = b64urlEncode(bytes);
  assert.equal(text, Buffer.from(bytes).toString('base64url'));
  assert.ok(!/[+/=]/.test(text));
  assert.deepEqual([...b64urlDecode(text)], [...bytes]);
  assert.equal(b64urlEncode(new ArrayBuffer(0)), '');
  for (const n of [0, 1, 2, 3, 16, 32, 64, 65]) {
    const b = crypto.getRandomValues(new Uint8Array(n));
    assert.equal(b64urlEncode(b).length, b64urlLength(n));
    assert.deepEqual([...b64urlDecode(b64urlEncode(b))], [...b]);
  }
  for (const bad of ['a', 'ab=', 'a+b/', 'a b', 'AB\n', '=', 5, null]) {
    assert.throws(() => b64urlDecode(bad), Error, String(bad));
  }
  // "AB" and "AC" decode to the same byte; only one spelling is accepted.
  assert.throws(() => b64urlDecode('AC'));
});

test('hex is lower-case and fixed width', () => {
  assert.equal(toHex(new Uint8Array([0, 1, 15, 16, 255])), '00010f10ff');
  assert.equal(toHex(new Uint8Array([1, 2]).buffer), '0102');
});

test('boot token shape: 32 bytes as unpadded base64url', () => {
  assert.ok(isBootToken(rnd(32)));
  for (const bad of [rnd(31), rnd(33), `${rnd(32)}=`, `${rnd(32).slice(0, 42)}+`, '', null, undefined, 5]) {
    assert.equal(isBootToken(bad), false, String(bad));
  }
});

test('path-and-query is the request line target, with no re-encoding of what fetch will send', () => {
  const base = 'http://127.0.0.1:17842';
  assert.equal(pathAndQuery(`${base}/api/status`, base), '/api/status');
  assert.equal(pathAndQuery(`${base}/api/transfers/abc%2Fdef`, base), '/api/transfers/abc%2Fdef');
  assert.equal(pathAndQuery(`${base}/api/x?a=1&b=%E3%81%82`, base), '/api/x?a=1&b=%E3%81%82');
  assert.equal(pathAndQuery(`${base}/api/x#frag`, base), '/api/x');
  assert.equal(pathAndQuery('/api/y?z=1', base), '/api/y?z=1');
  // The id a page puts in a path goes through encodeURIComponent first (bridge.js).
  const id = 'a b/c?d';
  assert.equal(pathAndQuery(`${base}/api/transfers/${encodeURIComponent(id)}`, base), `/api/transfers/${encodeURIComponent(id)}`);
});
