// Miasma Web — Service Worker
// Provides offline support via Cache API

const CACHE_NAME = 'miasma-web-v2';
const PRECACHE_ASSETS = [
  '/index.html',
  '/css/style.css',
  '/js/app.js',
  '/js/i18n.js',
  '/js/storage.js',
  '/manifest.json',
];

// Critical assets use stale-while-revalidate to prevent serving tampered caches
const REVALIDATE_ASSETS = [
  '/pkg/miasma_wasm.js',
  '/pkg/miasma_wasm_bg.wasm',
];

// Install: precache all assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll([...PRECACHE_ASSETS, ...REVALIDATE_ASSETS]);
    })
  );
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      );
    })
  );
  self.clients.claim();
});

// Fetch handler
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // WASM/JS assets: stale-while-revalidate (serve cached, update in background)
  if (REVALIDATE_ASSETS.some(a => url.pathname.endsWith(a))) {
    event.respondWith(
      caches.open(CACHE_NAME).then((cache) => {
        return cache.match(event.request).then((cached) => {
          const fetchPromise = fetch(event.request).then((response) => {
            if (response.ok) {
              cache.put(event.request, response.clone());
            }
            return response;
          }).catch(() => cached); // Network failure: fall back to cache

          return cached || fetchPromise;
        });
      })
    );
    return;
  }

  // Other assets: cache-first with network fallback
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((response) => {
        // Only cache same-origin successful responses from the precache list
        if (response.ok && PRECACHE_ASSETS.some(a => url.pathname.endsWith(a))) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, clone);
          });
        }
        return response;
      });
    })
  );
});
