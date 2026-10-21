import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { WEB_ROOT, computeManifest, normalise } from '../../scripts/web-asset-manifest.mjs';

const ORIGIN = 'https://app.test';
const SCOPE = `${ORIGIN}/`;

function makeCaches() {
  const stores = new Map();
  const mk = () => ({
    map: new Map(),
    async put(key, res) { this.map.set(typeof key === 'string' ? key : key.url, res); },
    async match(key) {
      const res = this.map.get(typeof key === 'string' ? key : key.url);
      return res ? res.clone() : undefined;
    },
  });
  return {
    stores,
    async open(name) { if (!stores.has(name)) stores.set(name, mk()); return stores.get(name); },
    async delete(name) { return stores.delete(name); },
    async keys() { return [...stores.keys()]; },
  };
}

// Load sw.js with a sandbox standing in for the service worker global scope.
function loadSw({ files, manifestText, swSource, online = true }) {
  const listeners = {};
  const caches = makeCaches();
  const net = { online, requests: [] };
  const served = { has: (k) => k in files, get: (k) => files[k] };
  async function fakeFetch(input, init) {
    const req = typeof input === 'string' ? { url: input } : input;
    net.requests.push({ url: req.url, cache: (init && init.cache) || req.cache });
    if (!net.online) throw new TypeError('network down');
    const rel = req.url.slice(SCOPE.length);
    if (rel === 'asset-manifest.json') return new Response(manifestText);
    if (!served.has(rel)) return new Response('nope', { status: 404 });
    return new Response(served.get(rel));
  }
  const clientsClaimed = [];
  const self = {
    location: new URL(SCOPE),
    registration: { scope: SCOPE },
    clients: { claim: async () => { clientsClaimed.push(true); } },
    skipWaiting: async () => { net.skipped = true; },
    addEventListener: (type, fn) => { listeners[type] = fn; },
  };
  class FakeRequest {
    constructor(input, init = {}) {
      this.url = typeof input === 'string' ? input : input.url;
      this.method = (init && init.method) || input.method || 'GET';
      this.mode = (init && init.mode) || input.mode || 'cors';
      this.cache = (init && init.cache) || 'default';
    }
  }
  const sandbox = {
    self, caches, fetch: fakeFetch, Request: FakeRequest, Response, URL, crypto: globalThis.crypto,
    Promise, Uint8Array, Array, Object, JSON, Error,
  };
  vm.createContext(sandbox);
  vm.runInContext(swSource, sandbox);
  const run = async (type, extra = {}) => {
    let pending;
    const event = { waitUntil: (p) => { pending = p; }, ...extra };
    listeners[type](event);
    if (pending) await pending;
    return event;
  };
  return { caches, net, run, listeners, clientsClaimed };
}

function currentBuild() {
  const swSource = fs.readFileSync(path.join(WEB_ROOT, 'sw.js'), 'utf8');
  const manifest = computeManifest();
  const files = {};
  for (const rel of Object.keys(manifest.files)) files[rel] = fs.readFileSync(path.join(WEB_ROOT, rel));
  return { swSource, manifest, manifestText: JSON.stringify(manifest), files };
}

const cacheName = (m) => `miasma-web-${m.version}`;

test('install stores every manifest file in one versioned cache, then skips waiting', async () => {
  const b = currentBuild();
  const sw = loadSw(b);
  await sw.run('install');
  const cache = sw.caches.stores.get(cacheName(b.manifest));
  assert.ok(cache, 'cache named after the manifest version');
  for (const rel of Object.keys(b.manifest.files)) {
    if (rel === 'sw.js') continue;
    assert.ok(cache.map.has(SCOPE + rel), `${rel} cached`);
  }
  assert.ok(cache.map.has(`${SCOPE}__complete`));
  assert.ok(sw.net.skipped);
  assert.ok(sw.net.requests.every((r) => r.cache === 'reload' || r.cache === 'no-store'));
});

test('a file that does not match the manifest fails the install and leaves no cache', async () => {
  const b = currentBuild();
  b.files['js/bridge.js'] = Buffer.from('// tampered or from another build');
  const sw = loadSw(b);
  await assert.rejects(sw.run('install'));
  assert.equal(sw.caches.stores.size, 0);
  assert.ok(!sw.net.skipped);
});

test('a missing file fails the install', async () => {
  const b = currentBuild();
  delete b.files['pkg/miasma_wasm_bg.wasm'];
  const sw = loadSw(b);
  await assert.rejects(sw.run('install'));
  assert.equal(sw.caches.stores.size, 0);
});

test('a manifest from another build than the worker fails the install', async () => {
  const b = currentBuild();
  b.manifestText = JSON.stringify({ ...b.manifest, version: 'ffffffffffffffff' });
  const sw = loadSw(b);
  await assert.rejects(sw.run('install'));
  assert.equal(sw.caches.stores.size, 0);
});

test('activate deletes other Miasma caches only after this one is complete, then claims clients', async () => {
  const b = currentBuild();
  const sw = loadSw(b);
  await sw.caches.open('miasma-web-v10');
  await sw.caches.open('miasma-web-0123456789abcdef');
  // Not installed yet: nothing usable, so old caches stay.
  await sw.run('activate');
  assert.ok(sw.caches.stores.has('miasma-web-v10'));
  await sw.run('install');
  await sw.run('activate');
  assert.deepEqual([...sw.caches.stores.keys()], [cacheName(b.manifest)]);
  assert.equal(sw.clientsClaimed.length, 2);
});

function fetchEvent(url, extra = {}) {
  let responded;
  const event = {
    request: { url, method: 'GET', mode: 'cors', ...extra },
    respondWith: (p) => { responded = Promise.resolve(p); },
  };
  return { event, response: () => responded };
}

test('online: network first with revalidation, never the cache', async () => {
  const b = currentBuild();
  const sw = loadSw(b);
  await sw.run('install');
  // The server now serves newer bridge.js than the cached build.
  b.files['js/bridge.js'] = Buffer.from('// newer');
  const { event, response } = fetchEvent(`${SCOPE}js/bridge.js`);
  sw.listeners.fetch(event);
  assert.equal(await (await response()).text(), '// newer');
  const last = sw.net.requests.at(-1);
  assert.equal(last.cache, 'no-cache');
});

test('offline: the cache of this build answers, navigation falls back to index.html', async () => {
  const b = currentBuild();
  const sw = loadSw(b);
  await sw.run('install');
  sw.net.online = false;
  const asset = fetchEvent(`${SCOPE}js/bridge.js`);
  sw.listeners.fetch(asset.event);
  assert.equal(await (await asset.response()).text(), b.files['js/bridge.js'].toString());
  const nav = fetchEvent(SCOPE, { mode: 'navigate' });
  sw.listeners.fetch(nav.event);
  assert.equal(await (await nav.response()).text(), b.files['index.html'].toString());
});

test('offline without a complete cache gives an error, not a partial answer', async () => {
  const b = currentBuild();
  const sw = loadSw({ ...b, online: false });
  const cache = await sw.caches.open(cacheName(b.manifest));
  await cache.put(`${SCOPE}js/bridge.js`, new Response('partial'));
  const { event, response } = fetchEvent(`${SCOPE}js/bridge.js`);
  sw.listeners.fetch(event);
  assert.equal((await response()).type, 'error');
});

test('/api/*, other origins and non-GET are not handled', async () => {
  const b = currentBuild();
  const sw = loadSw(b);
  for (const [url, extra] of [
    [`${SCOPE}api/status`, {}],
    [`${ORIGIN}/api/wipe`, {}],
    ['https://other.test/x.js', {}],
    [`${SCOPE}js/app.js`, { method: 'POST' }],
  ]) {
    const { event, response } = fetchEvent(url, extra);
    sw.listeners.fetch(event);
    assert.equal(response(), undefined, `${url} must pass through`);
  }
});

test('the sw hash helper agrees with the manifest script', () => {
  const crlf = Buffer.from('a\r\nb\r\n');
  assert.equal(
    createHash('sha256').update(normalise('x.js', crlf)).digest('hex'),
    createHash('sha256').update(Buffer.from('a\nb\n')).digest('hex'),
  );
});
