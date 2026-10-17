// Miasma Web — IndexedDB Storage Layer

const DB_NAME = 'miasma-web';
const DB_VERSION = 2;

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
    // New local writes persist a single binary representation. Old object records remain readable
    // after the v1 -> v2 database upgrade and are replaced naturally when the same slot is saved.
    const binary = share.bincode ? base64ToBytes(share.bincode).buffer : null;
    shareStore.put({
      midPrefixHex: share.mid_prefix,
      slotIndex: share.slot_index,
      segmentIndex: share.segment_index || 0,
      version: share.version || 1,
      originalLen: share.original_len || 0,
      data: binary || share,
      encoding: binary ? 'bincode-v1' : 'legacy-json-v1',
      timestamp: share.timestamp || 0,
    });
  }

  metaStore.put({
    mid,
    createdAt: Date.now(),
    originalLen: shares[0]?.original_len || 0,
    dataShards: params.k,
    totalShards: params.n,
  });

  return transactionDone(tx);
}

// Cursor-based lookup. `accept` is deliberately synchronous so callers can validate each share
// in WASM and stop as soon as k valid shares have been found without materializing the whole set.
export async function getSharesByMidPrefix(midPrefixHex, limit = Infinity, accept = null) {
  if (!db) await initDB();
  const tx = db.transaction('shares', 'readonly');
  const idx = tx.objectStore('shares').index('midPrefixHex');
  return cursorCollect(idx, IDBKeyRange.only(midPrefixHex), limit, accept);
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
function transactionDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = (e) => reject(e.target.error);
    tx.onabort = (e) => reject(e.target.error || new Error('IndexedDB transaction aborted'));
  });
}

function cursorCollect(index, query, limit, accept) {
  return new Promise((resolve, reject) => {
    const result = [];
    const req = index.openCursor(query);
    req.onerror = (e) => reject(e.target.error);
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor || result.length >= limit) {
        resolve(result);
        return;
      }
      const row = hydrateShareRecord(cursor.value);
      let keep = true;
      if (accept) {
        try { keep = !!accept(row); } catch (_) { keep = false; }
      }
      if (keep) result.push(row);
      if (result.length >= limit) resolve(result);
      else cursor.continue();
    };
  });
}

function hydrateShareRecord(row) {
  if (row && row.encoding === 'bincode-v1' && isBinary(row.data)) {
    const bytes = row.data instanceof ArrayBuffer
      ? new Uint8Array(row.data)
      : new Uint8Array(row.data.buffer, row.data.byteOffset, row.data.byteLength);
    return {
      ...row,
      data: {
        version: row.version || 1,
        mid_prefix: row.midPrefixHex,
        segment_index: row.segmentIndex || 0,
        slot_index: row.slotIndex,
        original_len: row.originalLen || 0,
        timestamp: row.timestamp || 0,
        bincode: bytesToBase64(bytes),
      },
    };
  }
  return row;
}

function isBinary(value) {
  return value instanceof ArrayBuffer || ArrayBuffer.isView(value);
}

function base64ToBytes(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes) {
  // Avoid spreading a large typed array onto the JS stack.
  const chunk = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunk) {
    const end = Math.min(bytes.length, i + chunk);
    let part = '';
    for (let j = i; j < end; j++) part += String.fromCharCode(bytes[j]);
    binary += part;
  }
  return btoa(binary);
}

function countAsync(store) {
  return new Promise((resolve, reject) => {
    const req = store.count();
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e.target.error);
  });
}
