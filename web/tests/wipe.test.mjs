import assert from 'node:assert/strict';
import test from 'node:test';
import { wipeEverything, zeroFill, isErased } from '../js/wipe.js';
import { clearAll, deleteDatabase, initDB, saveShares, setConnectedProbe } from '../js/storage.js';
import { MiasmaBridge, setAfterWipeHandler } from '../js/bridge.js';

function fakeStorage(entries = {}) {
  const m = new Map(Object.entries(entries));
  return { m, clear: () => m.clear(), get length() { return m.size; } };
}

function fakeEnv({ cacheNames = ['miasma-web-abc', 'miasma-web-v10', 'other-app'], regs = 2 } = {}) {
  const deleted = [];
  const unregistered = [];
  const body = { children: [], replaceChildren() { this.children = []; }, append(...c) { this.children.push(...c); } };
  const doc = {
    body,
    defaultView: { location: { reload() {} } },
    createElement: () => ({ setAttribute() {}, style: {}, append() {}, addEventListener() {} }),
  };
  return {
    deleted, unregistered, body,
    env: {
      sessionStorage: fakeStorage({ miasma_control_token: 'aa' }),
      localStorage: fakeStorage({ lang: 'ja' }),
      caches: { keys: async () => cacheNames, delete: async (n) => { deleted.push(n); return true; } },
      navigator: { serviceWorker: { getRegistrations: async () => Array.from({ length: regs }, () => ({ unregister: async () => { unregistered.push(1); return true; } })) } },
      document: doc,
    },
  };
}

test('zeroFill clears typed arrays, buffers and nested holders', () => {
  const a = new Uint8Array([1, 2, 3]);
  const buf = new Uint8Array([4, 5]).buffer;
  const holder = { shares: [{ binary: a }], raw: buf };
  zeroFill(holder);
  assert.deepEqual([...a], [0, 0, 0]);
  assert.deepEqual([...new Uint8Array(buf)], [0, 0]);
  zeroFill(null); zeroFill('text'); zeroFill(5);
});

test('wipeEverything runs every step and locks the page', async () => {
  const { env, deleted, unregistered, body } = fakeEnv();
  const secret = new Uint8Array([9, 9, 9]);
  const calls = [];
  const result = await wipeEverything({
    env,
    dropBuffers: [() => { zeroFill(secret); calls.push('buffers'); }],
    clearToken: () => calls.push('token'),
    clearSession: () => calls.push('session'),
    lockDb: () => calls.push('lock'),
    removeDatabase: async () => calls.push('deleteDatabase'),
  });
  assert.deepEqual(result, { ok: true, errors: [] });
  assert.deepEqual(calls, ['buffers', 'token', 'session', 'lock', 'deleteDatabase']);
  assert.deepEqual([...secret], [0, 0, 0]);
  assert.equal(env.sessionStorage.m.size, 0);
  assert.equal(env.localStorage.m.size, 0);
  assert.deepEqual(deleted.sort(), ['miasma-web-abc', 'miasma-web-v10']);
  assert.equal(unregistered.length, 2);
  assert.equal(body.children.length, 1, 'locked screen shown');
  assert.ok(isErased());
});

test('a failing step does not stop the others and is reported', async () => {
  const { env, deleted, unregistered } = fakeEnv();
  const result = await wipeEverything({
    env,
    clearToken: () => {},
    clearSession: () => {},
    lockDb: () => {},
    removeDatabase: async () => { throw new Error('blocked'); },
    dropBuffers: [() => { throw new Error('boom'); }],
  });
  assert.equal(result.ok, false);
  assert.equal(result.errors.length, 2);
  assert.equal(deleted.length, 2);
  assert.equal(unregistered.length, 2);
  assert.equal(env.sessionStorage.m.size, 0);
});

// Minimal IndexedDB: only what deleteDatabase / initDB need.
function installFakeIndexedDb({ block = false } = {}) {
  const log = [];
  let closed = 0;
  globalThis.indexedDB = {
    open() {
      const req = {};
      queueMicrotask(() => {
        const dbObj = { close() { closed++; }, objectStoreNames: { contains: () => true }, transaction() { throw new Error('unused'); } };
        req.onsuccess({ target: { result: dbObj } });
      });
      return req;
    },
    deleteDatabase(name) {
      log.push(name);
      const req = {};
      queueMicrotask(() => { if (block) req.onblocked(); else req.onsuccess(); });
      return req;
    },
  };
  return { log, closed: () => closed };
}

test('clearAll deletes the database (after closing the handle)', async () => {
  const idb = installFakeIndexedDb();
  await initDB();
  await clearAll();
  assert.deepEqual(idb.log, ['miasma-web']);
  assert.equal(idb.closed(), 1);
});

test('a blocked delete is reported instead of hanging', async () => {
  installFakeIndexedDb({ block: true });
  await assert.rejects(deleteDatabase(20), /blocked/);
});

test('saveShares refuses in connected mode and does not touch IndexedDB', async () => {
  const idb = installFakeIndexedDb();
  setConnectedProbe(() => true);
  await assert.rejects(saveShares('miasma:x', [], { k: 1, n: 1 }), /connected/);
  assert.equal(idb.log.length, 0);
  setConnectedProbe(null);
});

test('bridge.wipe runs the after-wipe handler only when the remote wipe succeeded', async () => {
  let ran = 0;
  setAfterWipeHandler(() => { ran++; });
  const b = new MiasmaBridge();
  b._wipeRemote = async () => false;
  assert.equal(await b.wipe(), false);
  assert.equal(ran, 0);
  b._wipeRemote = async () => true;
  assert.equal(await b.wipe(), true);
  assert.equal(ran, 1);
  setAfterWipeHandler(null);
});

test('wipeEverything deletes the stored signing key by default', async () => {
  const idb = installFakeIndexedDb();
  const { env } = fakeEnv();
  const result = await wipeEverything({
    env, clearToken: () => {}, lockDb: () => {}, removeDatabase: async () => {},
  });
  assert.equal(result.ok, true);
  assert.ok(idb.log.includes('miasma-session'));
});
