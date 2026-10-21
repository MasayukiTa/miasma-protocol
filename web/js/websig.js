// Miasma Web — wire format of the signed-request scheme ("sig-v1").
//
// This is the only place that builds the strings that get signed. It has no
// dependencies and no side effects, so the daemon's tests can be fed the same
// vectors (see web/tests/websig.test.mjs). Every field is validated before it
// is joined: a value with a line break or the wrong shape would let two
// different requests produce the same string.

export const SIG_VERSION = 1;
export const REQUEST_PREFIX = 'miasma-web-sig-v1';
export const REGISTER_PREFIX = 'miasma-web-register-v1';
export const HEADER_SCHEME = 'MiasmaSig';
export const HEADER_MAX_BYTES = 256;

export const SID_BYTES = 16;
export const NONCE_BYTES = 16;
export const BOOT_BYTES = 32;
export const SIG_BYTES = 64;
export const PUB_BYTES = 65;

const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const METHOD_RE = /^[A-Z]+$/;
const DIGITS_RE = /^[0-9]{1,16}$/;

/** Encoded length of `bytes` bytes in unpadded base64url. */
export function b64urlLength(bytes) {
  return Math.ceil((bytes * 4) / 3);
}

export function b64urlEncode(bytes) {
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let binary = '';
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Strict decoder: unpadded base64url only. Throws on anything else. */
export function b64urlDecode(text) {
  if (typeof text !== 'string' || !B64URL_RE.test(text) || text.length % 4 === 1) {
    throw new Error('not unpadded base64url');
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  // Reject non-canonical encodings (stray trailing bits) so one value has one spelling.
  if (b64urlEncode(out) !== text) throw new Error('non-canonical base64url');
  return out;
}

export function toHex(bytes) {
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let out = '';
  for (let i = 0; i < view.length; i++) out += view[i].toString(16).padStart(2, '0');
  return out;
}

function fixedB64(name, value, bytes) {
  if (typeof value !== 'string' || value.length !== b64urlLength(bytes) || !B64URL_RE.test(value)) {
    throw new Error(`${name}: expected ${bytes} bytes as unpadded base64url`);
  }
  return value;
}

function oneLine(name, value) {
  if (typeof value !== 'string' || value.length === 0 || /[\r\n]/.test(value)) {
    throw new Error(`${name}: must be a non-empty single line`);
  }
  return value;
}

function timestamp(value) {
  const text = typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? String(value) : value;
  if (typeof text !== 'string' || !DIGITS_RE.test(text)) throw new Error('ts: expected unix milliseconds');
  return text;
}

/** `path?query` exactly as the request line will carry it (no re-encoding). */
export function pathAndQuery(url, base) {
  const u = new URL(url, base);
  return u.pathname + u.search;
}

/**
 * The string a request signature covers. Eight lines, LF-separated, no trailing LF:
 * prefix, METHOD, path-and-query, registered origin, sid, ts, nonce, hex SHA-256 of the body.
 */
export function canonicalRequest({ method, pathAndQuery: target, origin, sid, ts, nonce, bodyHashHex }) {
  if (typeof method !== 'string' || !METHOD_RE.test(method)) throw new Error('method: expected upper-case letters');
  if (typeof target !== 'string' || !target.startsWith('/') || /[\r\n]/.test(target)) {
    throw new Error('pathAndQuery: must start with "/" and hold no line break');
  }
  if (typeof bodyHashHex !== 'string' || !SHA256_HEX_RE.test(bodyHashHex)) {
    throw new Error('bodyHashHex: expected 64 lower-case hex digits');
  }
  return [
    REQUEST_PREFIX,
    method,
    target,
    oneLine('origin', origin),
    fixedB64('sid', sid, SID_BYTES),
    timestamp(ts),
    fixedB64('nonce', nonce, NONCE_BYTES),
    bodyHashHex,
  ].join('\n');
}

/**
 * The string signed to prove the registering page holds the private key.
 * Five lines: prefix, origin, boot, pub, ts.
 */
export function registrationProof({ origin, boot, pub, ts }) {
  return [
    REGISTER_PREFIX,
    oneLine('origin', origin),
    fixedB64('boot', boot, BOOT_BYTES),
    fixedB64('pub', pub, PUB_BYTES),
    timestamp(ts),
  ].join('\n');
}

/** `Authorization` header value. Fixed field order and separators; at most 256 bytes. */
export function authorizationHeader({ sid, ts, nonce, sig }) {
  const value = `${HEADER_SCHEME} v=${SIG_VERSION}, sid=${fixedB64('sid', sid, SID_BYTES)}, ts=${timestamp(ts)}, `
    + `n=${fixedB64('nonce', nonce, NONCE_BYTES)}, sig=${fixedB64('sig', sig, SIG_BYTES)}`;
  if (value.length > HEADER_MAX_BYTES) throw new Error('Authorization header too long');
  return value;
}

/** Inverse of authorizationHeader, as strict as the daemon's parser. Returns null when malformed. */
export function parseAuthorizationHeader(value) {
  if (typeof value !== 'string' || value.length > HEADER_MAX_BYTES) return null;
  const m = /^MiasmaSig v=1, sid=([A-Za-z0-9_-]+), ts=([0-9]+), n=([A-Za-z0-9_-]+), sig=([A-Za-z0-9_-]+)$/.exec(value);
  if (!m) return null;
  try {
    const [, sid, ts, nonce, sig] = m;
    return { sid: fixedB64('sid', sid, SID_BYTES), ts: timestamp(ts), nonce: fixedB64('nonce', nonce, NONCE_BYTES), sig: fixedB64('sig', sig, SIG_BYTES) };
  } catch (_) { return null; }
}

/** True for a launch-link `boot` value (32 bytes, unpadded base64url). */
export function isBootToken(value) {
  return typeof value === 'string' && value.length === b64urlLength(BOOT_BYTES) && B64URL_RE.test(value);
}
