// Miasma Web — Bridge Abstraction Layer
//
// Detects the runtime environment and routes API calls accordingly:
//   1. WebView bridge (Android/iOS) — window.miasma injected by native host
//   2. HTTP bridge (Desktop) — the daemon's HTTP API on 127.0.0.1. Found, in
//      this order, at: the address a launch link named, the page's own origin
//      (the daemon serves this client itself), the default port 17842.
//   3. Local-only (Standalone browser) — WASM-only, no network
//
// The bridge provides a unified async API regardless of backend.

const MODE_WEBVIEW = 'webview';
const MODE_HTTP = 'http';
const MODE_LOCAL = 'local';

const HTTP_BRIDGE_PORT = 17842;
const DEFAULT_BRIDGE_URL = `http://127.0.0.1:${HTTP_BRIDGE_PORT}`;
const PING_TIMEOUT_MS = 2000;
const STATUS_POLL_MS = 30000;

export class MiasmaBridge {
  constructor() {
    this._mode = MODE_LOCAL;
    this._wasm = null;
    this._connected = false;
    this._lastStatus = null;
    this._pollTimer = null;
    this._onStateChange = null;
  }

  /** Detect environment and initialize. */
  async init(wasmModule) {
    this._wasm = wasmModule;

    // 1. Check for native WebView bridge
    if (typeof window.miasma !== 'undefined' && typeof window.miasma.ping === 'function') {
      try {
        const result = await Promise.resolve(window.miasma.ping());
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        if (parsed && parsed.ok) {
          this._mode = MODE_WEBVIEW;
          this._connected = true;
          this._startPolling();
          return;
        }
      } catch (_) { /* fall through */ }
    }

    // 2. Check for desktop HTTP bridge
    const found = await findBridge();
    if (found) {
      bridgeBase = found;
      this._mode = MODE_HTTP;
      // Reachable is not the same as allowed in: /api/ping needs no token, the
      // rest does. status() records whether the token was accepted.
      this._connected = false;
      await this.status();
      this._startPolling();
      return;
    }

    // 3. Fallback to local-only WASM
    this._mode = MODE_LOCAL;
    this._connected = false;
  }

  /** Current connection mode. */
  get mode() { return this._mode; }

  /** Whether a network backend is available. */
  get connected() { return this._connected; }

  /** Last status snapshot (null if unavailable). */
  get lastStatus() { return this._lastStatus; }

  /** Register a state-change callback: fn(mode, connected, status). */
  set onStateChange(fn) { this._onStateChange = fn; }

  /** Get daemon status. Returns null in local-only mode. */
  async status() {
    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(window.miasma.status());
        this._lastStatus = typeof result === 'string' ? JSON.parse(result) : result;
        this._setConnected(true);
        return this._lastStatus;
      } catch (e) {
        this._setConnected(false);
        return null;
      }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await fetchWithTimeout(`${bridgeBase}/api/status`, {
          method: 'GET',
        }, 5000);
        if (resp.ok) {
          this._lastStatus = await resp.json();
          this._setConnected(true);
          return this._lastStatus;
        }
      } catch (_) { /* fall through */ }
      this._setConnected(false);
      return null;
    }

    return null;
  }

  /**
   * Dissolve content.
   *
   * In connected mode: publishes to the P2P network via daemon.
   * In local mode: uses WASM (returns shares for manual handling).
   *
   * @param {Uint8Array|string} data - Content to dissolve
   * @param {number} k - Minimum shares to reconstruct
   * @param {number} n - Total shares to generate
   * @returns {{ mid: string, shares?: Array, networkPublished?: boolean }}
   */
  async dissolve(data, k, n) {
    if (this._mode === MODE_LOCAL) {
      return this._dissolveLocal(data, k, n);
    }

    // Connected mode: publish through backend
    const bytes = typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data;
    const b64 = arrayBufferToBase64(bytes);

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(
          window.miasma.dissolve(b64, k, n)
        );
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        if (parsed.error) throw new Error(parsed.error);
        return { mid: parsed.mid, networkPublished: true };
      } catch (e) {
        // Fall back to local WASM on bridge error
        console.warn('WebView dissolve failed, falling back to WASM:', e);
        return this._dissolveLocal(data, k, n);
      }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/publish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data: b64, data_shards: k, total_shards: n }),
        });
        if (resp.status === 401) throw new BridgeAuthError(authState);
        const result = await resp.json();
        if (result.error) throw new Error(result.error);
        return { mid: result.mid, networkPublished: true };
      } catch (e) {
        // A refused token is not a reason to quietly produce local-only shares.
        if (e && e.code === 'auth') throw e;
        console.warn('HTTP publish failed, falling back to WASM:', e);
        return this._dissolveLocal(data, k, n);
      }
    }
  }

  /**
   * Retrieve content by MID.
   *
   * In connected mode: retrieves from P2P network via daemon.
   * In local mode: requires manual share collection (returns null).
   *
   * @param {string} mid - Miasma Content ID
   * @param {number} k - data_shards parameter
   * @param {number} n - total_shards parameter
   * @returns {Uint8Array|null} Retrieved plaintext, or null if local-only
   */
  async retrieve(mid, k, n) {
    if (this._mode === MODE_LOCAL) {
      return null; // Caller must use manual share collection
    }

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(
          window.miasma.retrieve(mid, k, n)
        );
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        if (parsed.error) throw new Error(parsed.error);
        return base64ToArrayBuffer(parsed.data);
      } catch (e) {
        throw new Error(`Network retrieval failed: ${e.message}`);
      }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/retrieve`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mid, data_shards: k, total_shards: n }),
        });
        if (resp.status === 401) throw new BridgeAuthError(authState);
        const result = await resp.json();
        if (result.error) throw new Error(result.error);
        return base64ToArrayBuffer(result.data);
      } catch (e) {
        if (e && e.code === 'auth') throw e;
        throw new Error(`Network retrieval failed: ${e.message}`);
      }
    }
  }

  /** Distress wipe. Returns true on success. */
  async wipe() {
    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(window.miasma.wipe());
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        return parsed.ok === true;
      } catch (_) { return false; }
    }

    if (this._mode === MODE_HTTP) {
      try {
        // Two steps: the first call returns a challenge, the second echoes it.
        const first = await bridgeFetch(`${bridgeBase}/api/wipe`, {
          method: 'POST',
        });
        const challenge = (await first.json()).challenge;
        if (!challenge) return false;
        const resp = await bridgeFetch(`${bridgeBase}/api/wipe`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ confirm: challenge }),
        });
        const result = await resp.json();
        return result.ok === true;
      } catch (_) { return false; }
    }

    return false;
  }

  /** Get this node's sharing key and contact string. Returns { key, contact } or null. */
  async sharingKey() {
    if (this._mode === MODE_LOCAL) return null;

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(window.miasma.sharingKey());
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        if (parsed.error) return null;
        return { key: parsed.key, contact: parsed.contact };
      } catch (_) { return null; }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/sharing-key`, {
          method: 'GET',
        });
        if (!resp.ok) return null;
        const data = await resp.json();
        return { key: data.key, contact: data.contact };
      } catch (_) { return null; }
    }

    return null;
  }

  /**
   * Send a directed share.
   * @param {string} recipientContact - msk:... contact
   * @param {Uint8Array} data - file content
   * @param {string} password
   * @param {number} retentionSecs
   * @param {string|null} filename
   * @returns {{ envelope_id: string }}
   */
  async directedSend(recipientContact, data, password, retentionSecs, filename) {
    if (this._mode === MODE_LOCAL) {
      throw new Error('Not available in local mode');
    }

    const b64 = arrayBufferToBase64(data);

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(
          window.miasma.directedSend(recipientContact, b64, password, retentionSecs, filename)
        );
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        if (parsed.error) throw new Error(parsed.error);
        return { envelope_id: parsed.envelope_id };
      } catch (e) {
        throw new Error(`Directed send failed: ${e.message}`);
      }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/directed/send`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            recipient_contact: recipientContact,
            data: b64,
            password,
            retention_secs: retentionSecs,
            filename,
          }),
        });
        const result = await resp.json();
        if (result.error) throw new Error(result.error);
        return { envelope_id: result.envelope_id };
      } catch (e) {
        throw new Error(`Directed send failed: ${e.message}`);
      }
    }
  }

  /**
   * Confirm a directed share with challenge code.
   * @param {string} envelopeId
   * @param {string} challengeCode
   * @returns {boolean}
   */
  async directedConfirm(envelopeId, challengeCode) {
    if (this._mode === MODE_LOCAL) return false;

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(
          window.miasma.directedConfirm(envelopeId, challengeCode)
        );
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        return parsed.ok === true;
      } catch (_) { return false; }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/directed/confirm`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ envelope_id: envelopeId, challenge_code: challengeCode }),
        });
        const result = await resp.json();
        return result.ok === true;
      } catch (_) { return false; }
    }

    return false;
  }

  /**
   * Retrieve directed share content.
   * @param {string} envelopeId
   * @param {string} password
   * @returns {{ data: Uint8Array, filename: string }}
   */
  async directedRetrieve(envelopeId, password) {
    if (this._mode === MODE_LOCAL) {
      throw new Error('Not available in local mode');
    }

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(
          window.miasma.directedRetrieve(envelopeId, password)
        );
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        if (parsed.error) throw new Error(parsed.error);
        return { data: base64ToArrayBuffer(parsed.data), filename: parsed.filename };
      } catch (e) {
        throw new Error(`Directed retrieve failed: ${e.message}`);
      }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/directed/retrieve`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ envelope_id: envelopeId, password }),
        });
        const result = await resp.json();
        if (result.error) throw new Error(result.error);
        return { data: base64ToArrayBuffer(result.data), filename: result.filename };
      } catch (e) {
        throw new Error(`Directed retrieve failed: ${e.message}`);
      }
    }
  }

  /**
   * Revoke a directed share.
   * @param {string} envelopeId
   * @returns {boolean}
   */
  async directedRevoke(envelopeId) {
    if (this._mode === MODE_LOCAL) return false;

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(window.miasma.directedRevoke(envelopeId));
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        return parsed.ok === true;
      } catch (_) { return false; }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/directed/revoke`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ envelope_id: envelopeId }),
        });
        const result = await resp.json();
        return result.ok === true;
      } catch (_) { return false; }
    }

    return false;
  }

  /** List inbox items. Returns array of envelope objects. */
  async directedInbox() {
    if (this._mode === MODE_LOCAL) return [];

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(window.miasma.directedInbox());
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        return Array.isArray(parsed) ? parsed : [];
      } catch (_) { return []; }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/directed/inbox`, {
          method: 'GET',
        });
        if (!resp.ok) return [];
        return await resp.json();
      } catch (_) { return []; }
    }

    return [];
  }

  /** List outbox items. Returns array of envelope objects. */
  async directedOutbox() {
    if (this._mode === MODE_LOCAL) return [];

    if (this._mode === MODE_WEBVIEW) {
      try {
        const result = await Promise.resolve(window.miasma.directedOutbox());
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        return Array.isArray(parsed) ? parsed : [];
      } catch (_) { return []; }
    }

    if (this._mode === MODE_HTTP) {
      try {
        const resp = await bridgeFetch(`${bridgeBase}/api/directed/outbox`, {
          method: 'GET',
        });
        if (!resp.ok) return [];
        return await resp.json();
      } catch (_) { return []; }
    }

    return [];
  }

  // ── Transfers (daemon over HTTP only) ─────────────────────────────

  /** Whether this backend can list and start transfers at all. */
  get supportsTransfers() { return this._mode === MODE_HTTP; }

  /**
   * Every transfer the daemon knows (running, paused, finished), each with an `id`.
   * Throws an Error whose `code` is 'unsupported', 'offline', 'auth' or 'http'.
   */
  async transfers() {
    if (this._mode !== MODE_HTTP) throw transferError('unsupported');
    let resp;
    try {
      resp = await bridgeFetch(`${bridgeBase}/api/transfers`, { method: 'GET' });
    } catch (_) {
      this._setConnected(false);
      throw transferError('offline');
    }
    if (resp.status === 401) throw new BridgeAuthError(authState);
    if (!resp.ok) throw transferError('http', await errorText(resp));
    const list = await resp.json();
    return Array.isArray(list) ? list : [];
  }

  /**
   * Start (or resume: the same request again) a receive. `outputPath` is a path on the
   * DAEMON's computer. The password goes in the request body only: never in the URL,
   * never stored here. Returns the transfer id.
   */
  async transferReceive({ mid, outputPath, password, restart, via }) {
    if (this._mode !== MODE_HTTP) throw transferError('unsupported');
    const body = { mid, output_path: outputPath, restart: !!restart };
    if (password) body.password = password;
    // Direct receive: fetch from the sender's tunnel URL(s) instead of the DHT.
    if (Array.isArray(via) && via.length) body.via = via;
    let resp;
    try {
      resp = await bridgeFetch(`${bridgeBase}/api/transfers/receive`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (_) {
      throw transferError('offline');
    }
    if (resp.status === 401) throw new BridgeAuthError(authState);
    if (!resp.ok) throw transferError('http', await errorText(resp));
    return (await resp.json()).id;
  }

  /** Ask a running transfer to stop at its next safe point (progress is kept). */
  async transferCancel(id) {
    if (this._mode !== MODE_HTTP) throw transferError('unsupported');
    let resp;
    try {
      resp = await bridgeFetch(`${bridgeBase}/api/transfers/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
    } catch (_) {
      throw transferError('offline');
    }
    if (resp.status === 401) throw new BridgeAuthError(authState);
    if (!resp.ok) throw transferError('http', await errorText(resp));
    return true;
  }

  /** Try to reconnect if currently disconnected. */
  async reconnect() {
    await this.init(this._wasm);
    this._notifyStateChange();
  }

  // ── Private ──────────────────────────────────────────────────────

  _dissolveLocal(data, k, n) {
    let jsonStr;
    if (typeof data === 'string') {
      jsonStr = this._wasm.dissolve_text(data, k, n);
    } else {
      jsonStr = this._wasm.dissolve_bytes(data, k, n);
    }
    const result = JSON.parse(jsonStr);
    return { mid: result.mid, shares: result.shares, networkPublished: false };
  }

  _startPolling() {
    if (this._pollTimer) clearInterval(this._pollTimer);
    this._pollTimer = setInterval(() => this._poll(), STATUS_POLL_MS);
  }

  async _poll() {
    const status = await this.status();
    if (!status && this._connected) {
      this._setConnected(false);
    }
  }

  _setConnected(value) {
    if (this._connected !== value) {
      this._connected = value;
      this._notifyStateChange();
    }
  }

  _notifyStateChange() {
    if (this._onStateChange) {
      this._onStateChange(this._mode, this._connected, this._lastStatus);
    }
  }
}

// ── Utility ──────────────────────────────────────────────────────────────────

// The daemon's HTTP bridge requires its control token (contents of
// <data_dir>/daemon.token) as a Bearer credential on everything except
// /api/ping. A page cannot read that file, so `miasma web` prints a launch
// link with the token in its URL fragment:
//
//   http://127.0.0.1:<port>/#token=<hex>[&bridge=http://127.0.0.1:<port>]
//
// A fragment is never sent to any server. The page reads it once at load, keeps
// it in sessionStorage (gone when the tab closes; unlike localStorage it is not
// shared with other tabs or kept on disk) and removes it from the address bar.
// `bridge=` is honoured only for a loopback address: the token must never be
// sent to a remote host because a link said so.
const TOKEN_KEY = 'miasma_control_token';
const BRIDGE_KEY = 'miasma_bridge_url';
const TOKEN_SHAPE = /^[0-9a-fA-F]{16,128}$/;

let bridgeBase = DEFAULT_BRIDGE_URL;

function sessionGet(key) {
  try { return sessionStorage.getItem(key) || ''; } catch (_) { return ''; }
}

function sessionSet(key, value) {
  try {
    if (value) sessionStorage.setItem(key, value);
    else sessionStorage.removeItem(key);
  } catch (_) { /* storage unavailable: the token then lives for this page load only */ }
}

// Held in memory too, so a browser that refuses sessionStorage still works until reload.
let memoryToken = '';

/** True for http(s) URLs whose host is this computer. */
export function isLoopbackUrl(value) {
  let u;
  try { u = new URL(value); } catch (_) { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  if (u.username || u.password) return false;
  return u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
}

/**
 * Take the token (and optional bridge address) out of a launch-link fragment.
 * Returns what was found; the caller stores it and clears the address bar.
 */
export function parseLaunchFragment(hash) {
  const out = { token: '', bridge: '' };
  if (!hash || hash.length < 2) return out;
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const token = (params.get('token') || '').trim();
  if (TOKEN_SHAPE.test(token)) out.token = token;
  const bridge = (params.get('bridge') || '').trim();
  if (bridge && isLoopbackUrl(bridge)) out.bridge = bridge.replace(/\/+$/, '');
  return out;
}

function consumeLaunchFragment() {
  // The old build kept the token in localStorage, which outlives the tab and is
  // shared by every tab of this origin. Do not leave a secret behind there.
  try { localStorage.removeItem(TOKEN_KEY); } catch (_) { /* ignore */ }

  let hash = '';
  try { hash = window.location.hash; } catch (_) { return; }
  const found = parseLaunchFragment(hash);
  if (found.token) { memoryToken = found.token; sessionSet(TOKEN_KEY, found.token); }
  if (found.bridge) sessionSet(BRIDGE_KEY, found.bridge);
  if (found.token || found.bridge || /token=/.test(hash)) {
    try {
      window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search);
    } catch (_) { /* ignore */ }
  }
}

consumeLaunchFragment();

/** Set the token by hand (for example from a console); kept for this tab only. */
export function setControlToken(token) {
  const t = token ? String(token).trim() : '';
  memoryToken = t;
  sessionSet(TOKEN_KEY, t);
}

function controlToken() {
  return memoryToken || sessionGet(TOKEN_KEY);
}

// ── Auth state ───────────────────────────────────────────────────────────────
// 'unknown' until a request needing the token has been answered.
//   ok        the daemon accepted the token
//   missing   no token in this tab (the page was not opened from a launch link)
//   rejected  a token is present but the daemon refused it (it changes at every
//             daemon start, so a link from an earlier run stops working)
let authState = 'unknown';
const authListeners = new Set();

export function getAuthState() { return authState; }

export function onAuthChange(fn) {
  authListeners.add(fn);
  return () => authListeners.delete(fn);
}

function setAuthState(next) {
  if (next === authState) return;
  authState = next;
  for (const fn of authListeners) {
    try { fn(next); } catch (_) { /* a listener must not break requests */ }
  }
}

/** Thrown where a silent fallback would hide that the token is the problem. */
export class BridgeAuthError extends Error {
  constructor(state) {
    super(state === 'rejected' ? 'control token rejected' : 'control token missing');
    this.name = 'BridgeAuthError';
    this.code = 'auth';
    this.state = state;
  }
}

async function findBridge() {
  const candidates = [];
  const stored = sessionGet(BRIDGE_KEY);
  if (stored && isLoopbackUrl(stored)) candidates.push(stored);
  // The daemon serves this client itself: the page's own origin is the bridge.
  if (window.location.protocol === 'http:' || window.location.protocol === 'https:') {
    if (isLoopbackUrl(window.location.origin)) candidates.push(window.location.origin);
  }
  candidates.push(DEFAULT_BRIDGE_URL);
  for (const base of [...new Set(candidates)]) {
    try {
      const resp = await fetchWithTimeout(`${base}/api/ping`, { method: 'GET' }, PING_TIMEOUT_MS);
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.ok === true) return base;
      }
    } catch (_) { /* try the next one */ }
  }
  return '';
}

async function bridgeFetch(url, options) {
  const opts = Object.assign({}, options);
  const isPing = url.endsWith('/api/ping');
  const token = controlToken();
  if (token && !isPing) {
    opts.headers = Object.assign({}, opts.headers, { Authorization: `Bearer ${token}` });
  }
  const resp = await fetch(url, opts);
  if (!isPing) {
    if (resp.status === 401) setAuthState(token ? 'rejected' : 'missing');
    else if (resp.ok) setAuthState('ok');
  }
  return resp;
}

function transferError(code, message) {
  const e = new Error(message || code);
  e.code = code;
  return e;
}

async function errorText(resp) {
  try {
    const j = await resp.json();
    if (j && typeof j.error === 'string') return j.error;
  } catch (_) { /* not JSON */ }
  return `HTTP ${resp.status}`;
}

function fetchWithTimeout(url, options, timeoutMs) {
  return Promise.race([
    bridgeFetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), timeoutMs)
    ),
  ]);
}

function arrayBufferToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
