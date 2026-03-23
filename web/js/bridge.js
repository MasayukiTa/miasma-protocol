// Miasma Web — Bridge Abstraction Layer
//
// Detects the runtime environment and routes API calls accordingly:
//   1. WebView bridge (Android/iOS) — window.miasma injected by native host
//   2. HTTP bridge (Desktop) — daemon's HTTP API on localhost:17842
//   3. Local-only (Standalone browser) — WASM-only, no network
//
// The bridge provides a unified async API regardless of backend.

const MODE_WEBVIEW = 'webview';
const MODE_HTTP = 'http';
const MODE_LOCAL = 'local';

const HTTP_BRIDGE_PORT = 17842;
const HTTP_BRIDGE_URL = `http://127.0.0.1:${HTTP_BRIDGE_PORT}`;
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
    try {
      const resp = await fetchWithTimeout(`${HTTP_BRIDGE_URL}/api/ping`, {
        method: 'GET',
      }, PING_TIMEOUT_MS);
      if (resp.ok) {
        const data = await resp.json();
        if (data.ok) {
          this._mode = MODE_HTTP;
          this._connected = true;
          this._startPolling();
          return;
        }
      }
    } catch (_) { /* fall through */ }

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
        const resp = await fetchWithTimeout(`${HTTP_BRIDGE_URL}/api/status`, {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/publish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data: b64, data_shards: k, total_shards: n }),
        });
        const result = await resp.json();
        if (result.error) throw new Error(result.error);
        return { mid: result.mid, networkPublished: true };
      } catch (e) {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/retrieve`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mid, data_shards: k, total_shards: n }),
        });
        const result = await resp.json();
        if (result.error) throw new Error(result.error);
        return base64ToArrayBuffer(result.data);
      } catch (e) {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/wipe`, {
          method: 'POST',
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/sharing-key`, {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/directed/send`, {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/directed/confirm`, {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/directed/retrieve`, {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/directed/revoke`, {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/directed/inbox`, {
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
        const resp = await fetch(`${HTTP_BRIDGE_URL}/api/directed/outbox`, {
          method: 'GET',
        });
        if (!resp.ok) return [];
        return await resp.json();
      } catch (_) { return []; }
    }

    return [];
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

function fetchWithTimeout(url, options, timeoutMs) {
  return Promise.race([
    fetch(url, options),
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
