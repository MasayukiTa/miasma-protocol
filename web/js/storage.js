// Miasma Web — IndexedDB Storage Layer

const DB_NAME = 'miasma-web';
const DB_VERSION = 1;

let db = null;

export async function initDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains('shares')) {
        const store = d.createObjectStore('shares', { keyPath: ['midPrefixHex', 'slotIndex'] });
        store.createIndex('midPrefixHex', 'midPrefixHex', { unique: false });
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
      if (!d.objectStoreNames.contains('metadata')) {
        d.createObjectStore('metadata', { keyPath: 'mid' });
      }
    };
    req.onsuccess = (e) => {
      db = e.target.result;
      resolve(db);
    };
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function saveShares(mid, shares, params) {
  if (!db) await initDB();
  const tx = db.transaction(['shares', 'metadata'], 'readwrite');
  const shareStore = tx.objectStore('shares');
  const metaStore = tx.objectStore('metadata');

  for (const share of shares) {
    await putAsync(shareStore, {
      midPrefixHex: share.mid_prefix,
      slotIndex: share.slot_index,
      data: share,
      timestamp: share.timestamp,
    });
  }

  await putAsync(metaStore, {
    mid,
    createdAt: Date.now(),
    originalLen: shares[0]?.original_len || 0,
    dataShards: params.k,
    totalShards: params.n,
  });

  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = (e) => reject(e.target.error);
  });
}

export async function getSharesByMidPrefix(midPrefixHex) {
  if (!db) await initDB();
  const tx = db.transaction('shares', 'readonly');
  const store = tx.objectStore('shares');
  const idx = store.index('midPrefixHex');
  return getAllAsync(idx, IDBKeyRange.only(midPrefixHex));
}

export async function getShareCount() {
  if (!db) await initDB();
  const tx = db.transaction('shares', 'readonly');
  const store = tx.objectStore('shares');
  return countAsync(store);
}

export async function getMidCount() {
  if (!db) await initDB();
  const tx = db.transaction('metadata', 'readonly');
  const store = tx.objectStore('metadata');
  return countAsync(store);
}

export async function getStorageEstimate() {
  if (navigator.storage && navigator.storage.estimate) {
    const est = await navigator.storage.estimate();
    return est.usage || 0;
  }
  return 0;
}

export async function clearAll() {
  if (!db) await initDB();
  const tx = db.transaction(['shares', 'metadata'], 'readwrite');
  tx.objectStore('shares').clear();
  tx.objectStore('metadata').clear();
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = (e) => reject(e.target.error);
  });
}

// IDB helpers
function putAsync(store, val) {
  return new Promise((resolve, reject) => {
    const req = store.put(val);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e.target.error);
  });
}

function getAllAsync(storeOrIndex, query) {
  return new Promise((resolve, reject) => {
    const req = query ? storeOrIndex.getAll(query) : storeOrIndex.getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e.target.error);
  });
}

function countAsync(store) {
  return new Promise((resolve, reject) => {
    const req = store.count();
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e.target.error);
  });
}
