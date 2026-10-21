// Miasma Web — erase everything this browser holds for the app.
//
// wipeEverything() runs every step even if an earlier one fails, then puts the
// page into a locked "erased" state that only a reload leaves. Each dependency
// is passed in (and defaults to the page's own), so the steps can be tested.

import { clearControlState } from './bridge.js';
import { lockStorage, deleteDatabase } from './storage.js';
import { clearSession } from './websession.js';

const CACHE_PREFIX = 'miasma';

/** Best-effort zero-fill of byte buffers reachable from `value` (shallow walk, bounded depth). */
export function zeroFill(value, depth = 0, seen = new Set()) {
  if (!value || typeof value !== 'object' || depth > 4 || seen.has(value)) return;
  seen.add(value);
  try {
    if (value instanceof ArrayBuffer) { new Uint8Array(value).fill(0); return; }
    if (ArrayBuffer.isView(value)) {
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength).fill(0);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) zeroFill(item, depth + 1, seen);
      return;
    }
    for (const key of Object.keys(value)) zeroFill(value[key], depth + 1, seen);
  } catch (_) { /* frozen or detached: nothing more to do */ }
}

let erased = false;
export function isErased() { return erased; }

function defaultLockScreen(doc, message, buttonLabel) {
  if (!doc || !doc.body) return;
  doc.body.replaceChildren();
  const box = doc.createElement('div');
  box.setAttribute('role', 'alert');
  box.style.cssText = 'padding:48px 24px;text-align:center;font-family:sans-serif';
  const p = doc.createElement('p');
  p.textContent = message;
  const b = doc.createElement('button');
  b.textContent = buttonLabel;
  b.addEventListener('click', () => doc.defaultView && doc.defaultView.location.reload());
  box.append(p, b);
  doc.body.append(box);
}

/**
 * @param {object} opts
 * @param {Function[]} [opts.dropBuffers] callbacks that zero and release the app's in-memory data
 * @param {string} [opts.message] text of the locked screen
 * @param {string} [opts.reloadLabel] label of its reload button
 * @param {object} [opts.env] globals to use (sessionStorage, localStorage, caches, navigator, document)
 * @param {Function} [opts.clearToken] defaults to bridge.js clearControlState
 * @param {Function} [opts.clearSession] defaults to websession.js clearSession (deletes the stored signing key)
 * @param {Function} [opts.removeDatabase] defaults to storage.js deleteDatabase
 * @param {Function} [opts.lockDb] defaults to storage.js lockStorage
 * @returns {Promise<{ok: boolean, errors: string[]}>}
 */
export async function wipeEverything(opts = {}) {
  const env = opts.env || globalThis;
  const errors = [];
  const step = async (name, fn) => {
    try { await fn(); } catch (e) { errors.push(`${name}: ${e && e.message ? e.message : e}`); }
  };

  // 1. In-memory data first, while nothing else has changed.
  await step('buffers', async () => { for (const drop of opts.dropBuffers || []) await drop(); });
  // 2. Control token (memory + sessionStorage keys).
  await step('token', () => (opts.clearToken || clearControlState)());
  // 2b. The request-signing key: forget it in memory and delete its database.
  await step('session', () => (opts.clearSession || clearSession)());
  // 3. Everything else in sessionStorage / localStorage.
  await step('sessionStorage', () => env.sessionStorage && env.sessionStorage.clear());
  await step('localStorage', () => env.localStorage && env.localStorage.clear());
  // 4. IndexedDB: close this tab's handle and delete the database; refuse re-creation.
  await step('lockDb', () => (opts.lockDb || lockStorage)());
  await step('indexedDB', () => (opts.removeDatabase || deleteDatabase)());
  // 5. CacheStorage: every Miasma cache.
  await step('caches', async () => {
    if (!env.caches) return;
    const names = await env.caches.keys();
    await Promise.all(names.filter((n) => n.toLowerCase().startsWith(CACHE_PREFIX)).map((n) => env.caches.delete(n)));
  });
  // 6. Service worker registrations.
  await step('serviceWorker', async () => {
    const sw = env.navigator && env.navigator.serviceWorker;
    if (!sw || typeof sw.getRegistrations !== 'function') return;
    const regs = await sw.getRegistrations();
    await Promise.all(regs.map((r) => r.unregister()));
  });
  // 7. Dead state: the page no longer works until it is reloaded.
  erased = true;
  await step('lockScreen', () => defaultLockScreen(
    env.document,
    opts.message || 'Data in this browser was erased. Reload to start again.',
    opts.reloadLabel || 'Reload',
  ));
  return { ok: errors.length === 0, errors };
}
