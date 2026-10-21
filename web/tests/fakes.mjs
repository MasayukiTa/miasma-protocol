// Test doubles for the signed-session tests (not itself a test file).
//
// FakeDaemon answers like the daemon's HTTP bridge would for ping, registration
// and signed requests. Its check of a signature is written out from the wire
// format on purpose, without importing web/js/websig.js, so a mistake in the
// client's string builder cannot also hide in the checker.

const enc = new TextEncoder();
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN = { name: 'ECDSA', hash: 'SHA-256' };

export function b64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function unb64u(text) {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

export async function sha256Hex(bytes) {
  return Buffer.from(await crypto.subtle.digest('SHA-256', bytes)).toString('hex');
}

/** Spec-literal canonical request string (design: eight lines, LF, no trailing LF). */
export function specCanonical({ method, target, origin, sid, ts, nonce, bodyHash }) {
  return ['miasma-web-sig-v1', method, target, origin, sid, String(ts), nonce, bodyHash].join('\n');
}

export function specRegisterProof({ origin, boot, pub, ts }) {
  return ['miasma-web-register-v1', origin, boot, pub, String(ts)].join('\n');
}

export async function verifyP1363(pubB64, message, sigB64) {
  const key = await crypto.subtle.importKey('raw', unb64u(pubB64), ECDSA, true, ['verify']);
  return crypto.subtle.verify(SIGN, key, unb64u(sigB64), enc.encode(message));
}

export function newBoot() {
  return b64u(crypto.getRandomValues(new Uint8Array(32)));
}

/** A small IndexedDB: open / upgrade / get / put / delete / deleteDatabase. Values are structured-cloned. */
export function fakeIndexedDb() {
  const dbs = new Map(); // name -> Map(storeName -> Map(key -> value))
  const stats = { opened: 0, closed: 0, deleted: [] };
  function request(run) {
    const req = {};
    queueMicrotask(() => {
      try {
        req.result = run();
        if (req.onsuccess) req.onsuccess({ target: req });
      } catch (e) {
        req.error = e;
        if (req.onerror) req.onerror({ target: req });
      }
    });
    return req;
  }
  return {
    dbs,
    stats,
    open(name) {
      const req = {};
      queueMicrotask(() => {
        stats.opened++;
        const fresh = !dbs.has(name);
        if (fresh) dbs.set(name, new Map());
        const stores = dbs.get(name);
        req.result = {
          objectStoreNames: { contains: (n) => stores.has(n) },
          createObjectStore(n) { stores.set(n, new Map()); return {}; },
          transaction(n) {
            const tx = {};
            const store = stores.get(n);
            tx.objectStore = () => ({
              put: (value, key) => request(() => { store.set(key, structuredClone(value)); }),
              get: (key) => request(() => (store.has(key) ? structuredClone(store.get(key)) : undefined)),
              delete: (key) => request(() => { store.delete(key); }),
            });
            setTimeout(() => { if (tx.oncomplete) tx.oncomplete({ target: tx }); }, 0);
            return tx;
          },
          close() { stats.closed++; },
        };
        if (fresh && req.onupgradeneeded) req.onupgradeneeded({ target: req });
        req.onsuccess({ target: req });
      });
      return req;
    },
    deleteDatabase(name) {
      return request(() => { dbs.delete(name); stats.deleted.push(name); });
    },
  };
}

export function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export class FakeDaemon {
  /**
   * @param {object} [o]
   * @param {string[]|undefined} [o.webAuth] value of ping.web_auth (undefined: an old daemon, field absent)
   * @param {string} [o.pageOrigin] the Origin the browser would attach to page requests
   * @param {() => number} [o.now] the daemon's clock (ms)
   */
  constructor({ webAuth = ['bearer', 'sig-v1'], pageOrigin = 'http://127.0.0.1:17842', now = () => Date.now() } = {}) {
    this.webAuth = webAuth;
    this.pageOrigin = pageOrigin;
    this.now = now;
    this.boots = new Set();
    this.usedBoots = new Set();
    this.sessions = new Map(); // sid -> { pub, origin, nonces:Set }
    this.token = null;         // legacy Bearer token the daemon accepts, if any
    this.log = [];             // every request: { method, path, headers, body(Uint8Array) }
    this.failNext = [];        // queued responses/errors for the next non-ping requests
  }

  issueBoot() {
    const boot = newBoot();
    this.boots.add(boot);
    return boot;
  }

  forgetSessions() { this.sessions.clear(); }

  requests(pred = () => true) { return this.log.filter(pred); }

  fetch = async (url, init = {}) => {
    const u = new URL(url);
    const method = String(init.method || 'GET').toUpperCase();
    const headers = {};
    for (const [k, v] of Object.entries(init.headers || {})) headers[k.toLowerCase()] = v;
    let body = new Uint8Array(0);
    if (typeof init.body === 'string') body = enc.encode(init.body);
    else if (init.body) body = new Uint8Array(init.body);
    const target = u.pathname + u.search;
    this.log.push({ method, path: u.pathname, target, headers, body });

    if (u.pathname === '/api/ping') {
      const out = { ok: true };
      if (this.webAuth !== undefined) out.web_auth = this.webAuth;
      return jsonResponse(200, out);
    }
    if (this.failNext.length) {
      const next = this.failNext.shift();
      if (next instanceof Error) throw next;
      return next;
    }
    if (u.pathname === '/api/session/register' && method === 'POST') return this.#register(body);

    const auth = headers.authorization || '';
    if (auth.startsWith('Bearer ')) {
      if (this.token && auth === `Bearer ${this.token}`) return jsonResponse(200, { ok: true, legacy: true });
      return jsonResponse(401, { error: 'bad token', code: 'bad_token' });
    }
    if (!auth.startsWith('MiasmaSig ')) return jsonResponse(401, { error: 'session required', code: 'session_required' });
    return this.#signed(method, target, auth, body);
  };

  async #register(body) {
    let req;
    try { req = JSON.parse(new TextDecoder().decode(body)); } catch (_) { return jsonResponse(400, { error: 'bad json', code: 'bad_request' }); }
    const { boot, pub, ts, pop } = req;
    if (Object.keys(req).join(',') !== 'v,boot,pub,ts,pop' || req.v !== 1) return jsonResponse(400, { error: 'shape', code: 'bad_request' });
    if (this.usedBoots.has(boot)) return jsonResponse(401, { error: 'link already used', code: 'boot_already_used' });
    if (!this.boots.has(boot)) return jsonResponse(401, { error: 'unknown link', code: 'boot_invalid' });
    const now = this.now();
    if (!(ts >= now - 60000 && ts <= now + 10000)) {
      return jsonResponse(401, { error: 'clock', code: 'stale_timestamp', server_time_ms: now });
    }
    if (unb64u(pub).length !== 65 || unb64u(pub)[0] !== 4) return jsonResponse(400, { error: 'pub', code: 'bad_request' });
    const message = specRegisterProof({ origin: this.pageOrigin, boot, pub, ts });
    if (!(await verifyP1363(pub, message, pop))) return jsonResponse(401, { error: 'proof', code: 'bad_signature' });
    this.boots.delete(boot);
    this.usedBoots.add(boot);
    const sid = b64u(crypto.getRandomValues(new Uint8Array(16)));
    this.sessions.set(sid, { pub, origin: this.pageOrigin, nonces: new Set() });
    return jsonResponse(200, {
      sid, v: 1, alg: 'ES256', scopes: ['status', 'transfer', 'directed'],
      idle_timeout_s: 900, expires_in_s: 43200, server_time_ms: now,
    });
  }

  async #signed(method, target, auth, body) {
    const m = /^MiasmaSig v=1, sid=([A-Za-z0-9_-]{22}), ts=([0-9]+), n=([A-Za-z0-9_-]{22}), sig=([A-Za-z0-9_-]{86})$/.exec(auth);
    if (!m) return jsonResponse(401, { error: 'bad header', code: 'bad_auth_header' });
    const [, sid, tsText, nonce, sig] = m;
    const session = this.sessions.get(sid);
    if (!session) return jsonResponse(401, { error: 'unknown session', code: 'session_unknown' });
    const now = this.now();
    const ts = Number(tsText);
    if (!(ts >= now - 60000 && ts <= now + 10000)) {
      return jsonResponse(401, { error: 'clock', code: 'stale_timestamp', server_time_ms: now });
    }
    if (session.nonces.has(nonce)) return jsonResponse(401, { error: 'replay', code: 'replayed_nonce' });
    const canonical = specCanonical({
      method, target, origin: session.origin, sid, ts: tsText, nonce, bodyHash: await sha256Hex(body),
    });
    if (!(await verifyP1363(session.pub, canonical, sig))) return jsonResponse(401, { error: 'signature', code: 'bad_signature' });
    session.nonces.add(nonce);
    return jsonResponse(200, { ok: true });
  }
}
