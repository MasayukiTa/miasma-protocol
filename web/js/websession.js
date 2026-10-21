// Miasma Web — request-signing session for the daemon's HTTP bridge.
//
// A launch link carries a one-time `boot` value. The page makes an ECDSA P-256
// key that cannot be exported, registers its public half together with a
// signature proving it holds the private half, and from then on signs every
// request. The daemon never sees a reusable secret and the page never holds one.
//
// The strings that get signed are built in websig.js; this file does the work
// around them (key, registration, storage, retries). Every dependency (crypto,
// indexedDB, fetch, clock, origin) can be passed in, so it runs under node.

import {
  NONCE_BYTES, SIG_BYTES, SID_BYTES, SIG_VERSION,
  authorizationHeader, b64urlDecode, b64urlEncode, b64urlLength, canonicalRequest,
  isBootToken, pathAndQuery, registrationProof, toHex,
} from './websig.js';

export const SESSION_DB = 'miasma-session';
const STORE = 'session';
const RECORD_KEY = 'current';
const RECORD_VERSION = 1;
const KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' };

/** A failed registration or an unusable session. `definitive` means the daemon answered. */
export class SessionError extends Error {
  constructor(code, message, extra = {}) {
    super(message || code);
    this.name = 'SessionError';
    this.code = code;
    this.status = extra.status || 0;
    this.definitive = extra.definitive === true;
  }
}

/**
 * Which way to authenticate, from the body of GET /api/ping.
 *  - "sig-v1": the daemon lists it in `web_auth`.
 *  - "legacy-bearer": the daemon does not know the field at all (an older daemon).
 *  - "unsupported": the daemon names schemes this page does not speak.
 * A daemon that advertises `web_auth` never gets a Bearer token from this page.
 */
export function chooseAuthMode(ping) {
  const advertised = ping ? ping.web_auth : undefined;
  if (advertised === undefined || advertised === null) return 'legacy-bearer';
  if (Array.isArray(advertised) && advertised.includes('sig-v1')) return 'sig-v1';
  return 'unsupported';
}

const SESSION_GONE = new Set(['session_unknown', 'session_expired']);
const MISSING = new Set(['session_required']);

/** What the page should tell the user for a refusal code from the daemon. */
export function authStateForCode(code) {
  if (SESSION_GONE.has(code) || (typeof code === 'string' && code.startsWith('boot_'))) return 'expired';
  if (MISSING.has(code)) return 'missing';
  return 'rejected';
}

/** True when the session itself is finished (as opposed to one request being refused). */
export function isSessionGone(code) {
  return SESSION_GONE.has(code);
}

async function readError(resp) {
  let body = null;
  try { body = await resp.clone().json(); } catch (_) { /* not JSON */ }
  const code = body && typeof body.code === 'string' ? body.code : '';
  const serverTime = body && typeof body.server_time_ms === 'number' ? body.server_time_ms : NaN;
  const message = body && typeof body.error === 'string' ? body.error : `HTTP ${resp.status}`;
  return { code, serverTime, message };
}

function toBytes(body) {
  if (body === undefined || body === null) return new Uint8Array(0);
  if (typeof body === 'string') return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  throw new SessionError('unsupported_body', 'Signed requests need a string or bytes as the body.');
}

function headerObject(headers) {
  if (!headers) return {};
  if (typeof Headers !== 'undefined' && headers instanceof Headers) return Object.fromEntries(headers.entries());
  return Object.assign({}, headers);
}

// ── IndexedDB (own database, separate from the shares) ───────────────────────

function openStore(idb) {
  return new Promise((resolve, reject) => {
    const req = idb.open(SESSION_DB, 1);
    req.onupgradeneeded = (e) => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains(STORE)) d.createObjectStore(STORE);
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = (e) => reject((e && e.target && e.target.error) || new Error('indexedDB open failed'));
  });
}

async function withStore(idb, mode, fn) {
  const db = await openStore(idb);
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      let result;
      tx.oncomplete = () => resolve(result);
      tx.onerror = (e) => reject((e && e.target && e.target.error) || new Error('indexedDB transaction failed'));
      tx.onabort = (e) => reject((e && e.target && e.target.error) || new Error('indexedDB transaction aborted'));
      const req = fn(tx.objectStore(STORE));
      req.onsuccess = () => { result = req.result; };
      req.onerror = (e) => reject((e && e.target && e.target.error) || new Error('indexedDB request failed'));
    });
  } finally {
    try { db.close(); } catch (_) { /* already closed */ }
  }
}

function deleteStore(idb, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let timer = null;
    const req = idb.deleteDatabase(SESSION_DB);
    req.onsuccess = () => { clearTimeout(timer); resolve(); };
    req.onerror = (e) => { clearTimeout(timer); reject((e && e.target && e.target.error) || new Error('deleteDatabase failed')); };
    req.onblocked = () => {
      timer = setTimeout(() => reject(new Error('session database delete is blocked by another tab')), timeoutMs);
    };
  });
}

// ── The client ───────────────────────────────────────────────────────────────

/**
 * @param {object} [deps] crypto, indexedDB, fetch, now (ms), origin: each defaults to the page's own,
 *   looked up at call time.
 */
export function createSessionClient(deps = {}) {
  const getCrypto = () => deps.crypto || globalThis.crypto;
  const getIdb = () => ('indexedDB' in deps ? deps.indexedDB : globalThis.indexedDB);
  const getFetch = () => deps.fetch || globalThis.fetch;
  const getNow = () => (typeof deps.now === 'function' ? deps.now() : Date.now());
  const getOrigin = () => deps.origin || (globalThis.location && globalThis.location.origin) || '';

  let session = null;         // { sid, privateKey, pub, origin, bridge, offsetMs, scopes, expiresAt, persisted }
  let noSessionState = 'missing';
  let pendingBoot = '';
  let locked = false;

  function subtle() {
    const c = getCrypto();
    // crypto.subtle only exists in a secure context (https, or http on localhost).
    if (!c || !c.subtle || typeof c.subtle.generateKey !== 'function' || typeof c.getRandomValues !== 'function') return null;
    return c.subtle;
  }

  async function persist() {
    const idb = getIdb();
    if (!idb || !session) return false;
    try {
      const record = {
        v: RECORD_VERSION, sid: session.sid, privateKey: session.privateKey, pub: session.pub,
        origin: session.origin, bridge: session.bridge, offsetMs: session.offsetMs,
        scopes: session.scopes, expiresAt: session.expiresAt,
      };
      await withStore(idb, 'readwrite', (s) => s.put(record, RECORD_KEY));
      return true;
    } catch (_) {
      return false; // private mode and the like: the key then lives for this page load only
    }
  }

  async function eraseStore() {
    const idb = getIdb();
    if (!idb) return;
    await deleteStore(idb);
  }

  async function register(bridge, boot) {
    const sub = subtle();
    if (!sub) throw new SessionError('crypto_unavailable', 'WebCrypto is not available in this page.');
    if (locked) throw new SessionError('locked', 'The page was erased.');
    const origin = getOrigin();
    if (!origin) throw new SessionError('no_origin', 'The page has no origin to register.');
    // extractable:false — the private key can be used to sign but never read out.
    const pair = await sub.generateKey(KEY_ALGORITHM, false, ['sign', 'verify']);
    const pub = b64urlEncode(new Uint8Array(await sub.exportKey('raw', pair.publicKey)));
    let offsetMs = 0;
    for (let attempt = 0; attempt < 2; attempt++) {
      const ts = getNow() + offsetMs;
      const proof = new TextEncoder().encode(registrationProof({ origin, boot, pub, ts }));
      const pop = b64urlEncode(new Uint8Array(await sub.sign(SIGN_ALGORITHM, pair.privateKey, proof)));
      let resp;
      try {
        resp = await getFetch()(`${bridge}/api/session/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ v: SIG_VERSION, boot, pub, ts, pop }),
        });
      } catch (e) {
        throw new SessionError('network', e && e.message ? e.message : 'request failed');
      }
      if (!resp.ok) {
        const err = await readError(resp);
        // The daemon refused before using the boot value, so one retry with its clock is safe.
        if (attempt === 0 && err.code === 'stale_timestamp' && Number.isFinite(err.serverTime)) {
          offsetMs = err.serverTime - getNow();
          continue;
        }
        const definitive = resp.status >= 400 && resp.status < 500 && resp.status !== 429;
        throw new SessionError(err.code || 'register_failed', err.message, { status: resp.status, definitive });
      }
      let info;
      try { info = await resp.json(); } catch (_) { info = null; }
      if (!info || info.v !== SIG_VERSION || info.alg !== 'ES256'
          || typeof info.sid !== 'string' || info.sid.length !== b64urlLength(SID_BYTES)) {
        throw new SessionError('bad_register_response', 'The daemon sent an unexpected registration reply.', { status: resp.status, definitive: true });
      }
      b64urlDecode(info.sid);
      const now = getNow();
      session = {
        sid: info.sid,
        privateKey: pair.privateKey,
        pub,
        origin,
        bridge,
        offsetMs: typeof info.server_time_ms === 'number' ? info.server_time_ms - now : offsetMs,
        scopes: Array.isArray(info.scopes) ? info.scopes.filter((s) => typeof s === 'string') : [],
        expiresAt: typeof info.expires_in_s === 'number' ? now + info.expires_in_s * 1000 : 0,
        persisted: false,
      };
      session.persisted = await persist();
      noSessionState = 'missing';
      return session;
    }
    throw new SessionError('register_failed', 'registration did not complete');
  }

  async function restore(bridge) {
    const idb = getIdb();
    if (!idb || locked) return null;
    let record;
    try {
      record = await withStore(idb, 'readonly', (s) => s.get(RECORD_KEY));
    } catch (_) { return null; }
    if (!record) return null;
    const key = record.privateKey;
    const sane = record.v === RECORD_VERSION && key && key.type === 'private'
      && typeof record.sid === 'string' && typeof record.pub === 'string';
    // A key that could be read out is not one to keep using.
    if (!sane || key.extractable !== false) {
      try { await eraseStore(); } catch (_) { /* best effort */ }
      return null;
    }
    // Only the daemon and page this session was registered for.
    if (record.origin !== getOrigin() || record.bridge !== bridge) return null;
    session = {
      sid: record.sid, privateKey: key, pub: record.pub, origin: record.origin, bridge: record.bridge,
      offsetMs: Number.isFinite(record.offsetMs) ? record.offsetMs : 0,
      scopes: Array.isArray(record.scopes) ? record.scopes : [],
      expiresAt: Number.isFinite(record.expiresAt) ? record.expiresAt : 0,
      persisted: true,
    };
    return session;
  }

  const client = {
    /** Whether this page can create and use a signing key at all. */
    isSupported() { return subtle() !== null; },

    hasSession() { return session !== null; },

    /** 'missing' | 'expired' | 'unsupported': why there is no session (valid while hasSession() is false). */
    noSessionState() { return noSessionState; },

    /** What is known about the current session, for display. Never includes key material. */
    info() {
      if (!session) return null;
      return { sid: session.sid, origin: session.origin, bridge: session.bridge, scopes: session.scopes.slice(), expiresAt: session.expiresAt, persisted: session.persisted };
    },

    /** Remember the one-time boot value from the launch link until the daemon has answered it. */
    setBoot(boot) { pendingBoot = isBootToken(boot) ? boot : ''; },

    hasBoot() { return pendingBoot !== ''; },

    /**
     * Get a session for the daemon at `bridge`: register with the boot value when there is one,
     * otherwise reuse the one stored by an earlier load of this page.
     * @returns {Promise<'ready'|'missing'|'expired'|'unsupported'>}
     */
    async establish(bridge) {
      if (!client.isSupported()) { noSessionState = 'unsupported'; return 'unsupported'; }
      if (session && session.bridge === bridge) return 'ready';
      if (pendingBoot) {
        try {
          await register(bridge, pendingBoot);
          pendingBoot = '';
          return 'ready';
        } catch (e) {
          if (e instanceof SessionError && e.definitive) {
            // The link was refused (used, expired, wrong page): it can never work.
            pendingBoot = '';
            noSessionState = 'expired';
            return 'expired';
          }
          // The daemon could not be reached: the link may still be good, keep it for another try.
          noSessionState = 'missing';
          return 'missing';
        }
      }
      if (await restore(bridge)) return 'ready';
      noSessionState = 'missing';
      return 'missing';
    },

    /** fetch() with the request signed. Retries once, with a new nonce, if only the clock was wrong. */
    async signedFetch(url, opts = {}) {
      if (!session) throw new SessionError('session_required', 'There is no session to sign with.');
      const sub = subtle();
      if (!sub) throw new SessionError('crypto_unavailable', 'WebCrypto is not available in this page.');
      const target = new URL(url, session.bridge);
      if (target.origin !== new URL(session.bridge).origin) {
        throw new SessionError('wrong_host', 'Refusing to sign a request for another host.');
      }
      const method = String(opts.method || 'GET').toUpperCase();
      const bytes = toBytes(opts.body);
      const bodyHashHex = toHex(new Uint8Array(await sub.digest('SHA-256', bytes)));
      const where = pathAndQuery(url, session.bridge);
      let resp;
      for (let attempt = 0; attempt < 2; attempt++) {
        const ts = getNow() + session.offsetMs;
        const nonce = b64urlEncode(getCrypto().getRandomValues(new Uint8Array(NONCE_BYTES)));
        const canonical = canonicalRequest({ method, pathAndQuery: where, origin: session.origin, sid: session.sid, ts, nonce, bodyHashHex });
        const sigBytes = new Uint8Array(await sub.sign(SIGN_ALGORITHM, session.privateKey, new TextEncoder().encode(canonical)));
        if (sigBytes.length !== SIG_BYTES) throw new SessionError('bad_signature_length', 'Unexpected signature size.');
        const headers = headerObject(opts.headers);
        for (const name of Object.keys(headers)) if (name.toLowerCase() === 'authorization') delete headers[name];
        headers.Authorization = authorizationHeader({ sid: session.sid, ts, nonce, sig: b64urlEncode(sigBytes) });
        const init = Object.assign({}, opts, { method, headers });
        if (bytes.length > 0) init.body = bytes; else delete init.body;
        resp = await getFetch()(url, init);
        if (resp.status === 401 && attempt === 0) {
          const err = await readError(resp);
          if (err.code === 'stale_timestamp' && Number.isFinite(err.serverTime)) {
            session.offsetMs = err.serverTime - getNow();
            continue;
          }
        }
        break;
      }
      return resp;
    },

    /** The daemon said the session is over (restart, expiry): forget it here too. */
    async invalidate(reason) {
      session = null;
      noSessionState = reason === 'expired' ? 'expired' : 'missing';
      try { await eraseStore(); } catch (_) { /* best effort */ }
    },

    /** End the session on the daemon, then forget it. */
    async end() {
      if (session) {
        try { await client.signedFetch(`${session.bridge}/api/session/end`, { method: 'POST' }); } catch (_) { /* forget it anyway */ }
      }
      await client.clear();
    },

    /** Drop the in-memory key reference only. */
    dropMemory() {
      session = null;
      pendingBoot = '';
      noSessionState = 'missing';
    },

    /** Drop the key everywhere (memory and IndexedDB). With `lock`, refuse to make a new one (after an erase). */
    async clear({ lock = false } = {}) {
      client.dropMemory();
      if (lock) locked = true;
      await eraseStore();
    },
  };
  return client;
}

/** The page's own client. */
export const sessionClient = createSessionClient();

/** Delete the stored key and forget the session; used by the erase routine. */
export function clearSession() {
  return sessionClient.clear({ lock: true });
}

/** A 401 the page makes up itself when it has nothing to sign with, so no request leaves it. */
export function noSessionResponse(state) {
  const text = state === 'unsupported'
    ? 'This browser cannot create the signing key the daemon requires.'
    : 'No session with the daemon. Run `miasma web` and open the link it prints.';
  return new Response(JSON.stringify({ error: text, code: 'session_required' }), {
    status: 401,
    headers: { 'Content-Type': 'application/json' },
  });
}
