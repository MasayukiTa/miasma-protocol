// Miasma Web — Service Worker
//
// One cache holds exactly one build of the app shell and the crypto assets.
// The build is named by ASSET_VERSION, which scripts/web-asset-manifest.mjs
// derives from the hashes in asset-manifest.json and writes into this file (so
// every shipped change also changes this file and the browser installs it).
//
//  - install: fetch every file listed in the manifest, check its SHA-256 against
//    the manifest, store all of them in the cache for this version, and only
//    then finish. Any failure discards the partial cache and the install fails,
//    leaving the previous worker and cache in place.
//  - activate: delete every other Miasma cache, take over open pages.
//  - fetch: network first for everything same-origin (never serve an older copy
//    while online); the cache of this exact version is the offline fallback.
//  - /api/* is never touched or cached.

const ASSET_VERSION = 'c56b7ab5c8bcbf8e';
const CACHE_PREFIX = 'miasma-web-';
const CACHE_NAME = CACHE_PREFIX + ASSET_VERSION;
const MANIFEST_PATH = 'asset-manifest.json';
const COMPLETE_MARKER = '__complete';
// Listed in the manifest (it is part of the version) but not stored in the cache.
const NOT_CACHED = new Set(['sw.js']);
const TEXT_EXT = /\.(js|html|css|json)$/;

function scopeUrl(rel) {
  return new URL(rel, self.registration.scope).href;
}

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Same normalisation as the manifest script: line endings do not change a hash.
function normalise(rel, buffer) {
  const bytes = new Uint8Array(buffer);
  if (!TEXT_EXT.test(rel)) return bytes;
  return bytes.filter((b) => b !== 0x0d);
}

async function fetchChecked(rel, expectedHash) {
  const response = await fetch(new Request(scopeUrl(rel), { cache: 'reload' }));
  if (!response.ok) throw new Error(`${rel}: HTTP ${response.status}`);
  const actual = await sha256Hex(normalise(rel, await response.clone().arrayBuffer()));
  if (actual !== expectedHash) throw new Error(`${rel}: content does not match the manifest`);
  return response;
}

async function installVersion() {
  const res = await fetch(new Request(scopeUrl(MANIFEST_PATH), { cache: 'no-store' }));
  if (!res.ok) throw new Error(`${MANIFEST_PATH}: HTTP ${res.status}`);
  const manifestText = await res.text();
  const manifest = JSON.parse(manifestText);
  if (manifest.version !== ASSET_VERSION) {
    throw new Error('asset manifest and service worker are from different builds');
  }
  await caches.delete(CACHE_NAME); // a partial cache from an earlier attempt
  const cache = await caches.open(CACHE_NAME);
  try {
    const entries = Object.entries(manifest.files).filter(([rel]) => !NOT_CACHED.has(rel));
    const responses = await Promise.all(entries.map(([rel, hash]) => fetchChecked(rel, hash)));
    for (let i = 0; i < entries.length; i++) await cache.put(scopeUrl(entries[i][0]), responses[i]);
    await cache.put(scopeUrl(MANIFEST_PATH), new Response(manifestText, {
      headers: { 'Content-Type': 'application/json' },
    }));
    // Written last: a cache without it is never used.
    await cache.put(scopeUrl(COMPLETE_MARKER), new Response(ASSET_VERSION));
  } catch (err) {
    await caches.delete(CACHE_NAME);
    throw err;
  }
}

async function activateVersion() {
  const cache = await caches.open(CACHE_NAME);
  if (!(await cache.match(scopeUrl(COMPLETE_MARKER)))) return; // nothing usable: keep what exists
  const keys = await caches.keys();
  await Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)));
}

async function cachedResponse(request) {
  const cache = await caches.open(CACHE_NAME);
  if (!(await cache.match(scopeUrl(COMPLETE_MARKER)))) return undefined;
  if (request.mode === 'navigate') {
    return (await cache.match(request)) || cache.match(scopeUrl('index.html'));
  }
  return cache.match(request);
}

self.addEventListener('install', (event) => {
  event.waitUntil(installVersion().then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(activateVersion().then(() => self.clients.claim()));
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // Never touch the daemon's API (it carries the control token) or any other origin.
  // The second form also covers deployments where the whole PWA is hosted below a subpath.
  const scopePath = new URL(self.registration.scope).pathname;
  const scopedApiPath = `${scopePath}${scopePath.endsWith('/') ? '' : '/'}api/`;
  if (
    url.origin !== self.location.origin ||
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith(scopedApiPath)
  ) return;

  // Network first: while online the page always gets the server's current build.
  // Offline (the fetch itself fails) it gets the cache of this worker's build.
  const request = event.request;
  event.respondWith(
    (request.mode === 'navigate' ? fetch(request) : fetch(request, { cache: 'no-cache' })).catch(async () => {
      const cached = await cachedResponse(request);
      if (cached) return cached;
      return Response.error();
    })
  );
});
