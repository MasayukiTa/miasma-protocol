// Miasma Web — IndexedDB Storage Layer

const DB_NAME = 'miasma-web';
const DB_VERSION = 2;

let db = null;
let locked = false;
let connectedProbe = null;

/** Tell the storage layer how to ask "is the page in daemon (connected) mode?". */
export function setConnectedProbe(fn) {
  connectedProbe = typeof fn === 'function' ? fn : null;
}

/** After an erase the database must not be re-created by a stray call. */
export function lockStorage() {
  locked = true;
  closeDB();
}

export function closeDB() {
  if (db) {
    try { db.close(); } catch (_) { /* already closed */ }
    db = null;
  }
}

export async function initDB() {
  if (locked) throw new Error('storage is locked after erase');
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
      // v1 stored a full JSON object that itself contained another base64 bincode copy.
      // Convert those rows in-place during the schema upgrade so existing users reclaim the
      // duplicate representation without needing to re-save every item manually.
      if (e.oldVersion < 2 && d.objectStoreNames.contains('shares')) {
        const store = e.target.transaction.objectStore('shares');
        const cursorReq = store.openCursor();
        cursorReq.onsuccess = () => {
          const cursor = cursorReq.result;
          if (!cursor) return;
          const row = cursor.value;
          const share = row && row.data;
          if (share && typeof share.bincode === 'string' && share.bincode.length > 0) {
            try {
              const binary = base64ToBytes(share.bincode);
              cursor.update({
                ...row,
                segmentIndex: share.segment_index || 0,
                version: share.version || 1,
                originalLen: share.original_len || 0,
                data: exactArrayBuffer(binary),
                encoding: 'bincode-v1',
                timestamp: share.timestamp || row.timestamp || 0,
              });
            } catch (_) { /* Keep a malformed legacy row readable through the old path. */ }
          }
          cursor.continue();
        };
      }
    };
    req.onsuccess = (e) => {
      db = e.target.result;
      // Another tab asking to delete or upgrade the database must not be blocked by us.
      db.onversionchange = () => closeDB();
      resolve(db);
    };
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function saveShares(mid, shares, params) {
  // Shares published through the daemon are not kept in this browser.
  if (connectedProbe && connectedProbe()) {
    throw new Error('saving shares in the browser is not available while connected to the daemon');
  }
  if (!db) await initDB();
  const tx = db.transaction(['shares', 'metadata'], 'readwrite');
  const shareStore = tx.objectStore('shares');
  const metaStore = tx.objectStore('metadata');

  const fallbackPrefix = midPrefixHexFromMid(mid);
  for (let i = 0; i < shares.length; i++) {
    const share = shares[i];
    // Prefer direct Uint8Array output from the binary WASM API. Compatibility JSON is decoded
    // only when an older generated WASM package is still in use.
    const binary = shareBinaryBytes(share);
    shareStore.put({
      midPrefixHex: share.mid_prefix || fallbackPrefix,
      slotIndex: Number.isInteger(share.slot_index) ? share.slot_index : i,
      segmentIndex: share.segment_index || 0,
      version: share.version || 1,
      originalLen: share.original_len || 0,
      data: binary ? exactArrayBuffer(binary) : share,
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

/** Close this tab's handle and delete the whole database (not just its rows). */
export function deleteDatabase(timeoutMs = 5000) {
  closeDB();
  return new Promise((resolve, reject) => {
    let timer = null;
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => { clearTimeout(timer); resolve(); };
    req.onerror = (e) => { clearTimeout(timer); reject(e.target.error || new Error('deleteDatabase failed')); };
    // Another tab still holds the database; the delete completes once it closes.
    req.onblocked = () => {
      timer = setTimeout(() => reject(new Error('database delete is blocked by another tab')), timeoutMs);
    };
  });
}

export async function clearAll() {
  await deleteDatabase();
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
        binary: bytes,
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

export function shareBinaryBytes(share) {
  if (!share || typeof share !== 'object') return null;
  if (share.binary instanceof Uint8Array) return share.binary;
  if (share.binary instanceof ArrayBuffer) return new Uint8Array(share.binary);
  if (ArrayBuffer.isView(share.binary)) {
    return new Uint8Array(share.binary.buffer, share.binary.byteOffset, share.binary.byteLength);
  }
  if (typeof share.bincode === 'string' && share.bincode.length > 0) {
    try { return base64ToBytes(share.bincode); } catch (_) { return null; }
  }
  return null;
}

export function shareToPortableJson(share) {
  if (!share || typeof share !== 'object') return share;
  const binary = shareBinaryBytes(share);
  if (!binary) return share;
  return {
    version: share.version || 1,
    mid_prefix: share.mid_prefix || '',
    segment_index: share.segment_index || 0,
    slot_index: Number.isInteger(share.slot_index) ? share.slot_index : 0,
    original_len: share.original_len || 0,
    timestamp: share.timestamp || 0,
    bincode: bytesToBase64(binary),
  };
}

export function shareSerializedSize(share) {
  const binary = shareBinaryBytes(share);
  return binary ? binary.byteLength : JSON.stringify(share || {}).length;
}

export function packShareBundle(shares) {
  if (!Array.isArray(shares) || shares.length === 0 || shares.length > 512) {
    throw new Error('invalid share bundle count');
  }
  const parts = shares.map(shareBinaryBytes);
  if (parts.some((p) => !p || p.byteLength === 0)) {
    throw new Error('share bundle needs binary shares');
  }
  let total = 6;
  for (const p of parts) total += 4 + p.byteLength;
  const out = new Uint8Array(total);
  out.set([0x4d, 0x53, 0x42, 0x31], 0); // MSB1
  const view = new DataView(out.buffer);
  view.setUint16(4, parts.length, true);
  let off = 6;
  for (const p of parts) {
    view.setUint32(off, p.byteLength, true);
    off += 4;
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

export function parseDissolveBundle(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.byteLength < 12 || bytes[0] !== 0x4d || bytes[1] !== 0x44 || bytes[2] !== 0x42 || bytes[3] !== 0x31) {
    throw new Error('invalid dissolve bundle header');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const midLen = view.getUint16(4, true);
  let off = 6;
  if (off + midLen + 6 > bytes.byteLength) throw new Error('truncated dissolve bundle');
  const mid = new TextDecoder().decode(bytes.subarray(off, off + midLen));
  off += midLen;
  const dataShards = view.getUint16(off, true); off += 2;
  const totalShards = view.getUint16(off, true); off += 2;
  const count = view.getUint16(off, true); off += 2;
  if (!mid.startsWith('miasma:') || count === 0 || count > 512 || count !== totalShards) {
    throw new Error('invalid dissolve bundle metadata');
  }
  const prefix = midPrefixHexFromMid(mid);
  const shares = [];
  for (let i = 0; i < count; i++) {
    if (off + 4 > bytes.byteLength) throw new Error('truncated dissolve share length');
    const len = view.getUint32(off, true); off += 4;
    if (len === 0 || off + len > bytes.byteLength) throw new Error('truncated dissolve share');
    shares.push({
      version: 1,
      mid_prefix: prefix,
      segment_index: 0,
      slot_index: i,
      original_len: 0,
      timestamp: 0,
      binary: bytes.slice(off, off + len),
    });
    off += len;
  }
  if (off !== bytes.byteLength) throw new Error('trailing dissolve bundle bytes');
  return { mid, shares, data_shards: dataShards, total_shards: totalShards };
}

export function midPrefixHexFromMid(mid) {
  if (typeof mid !== 'string' || !mid.startsWith('miasma:')) throw new Error('invalid MID');
  const bytes = decodeBase58(mid.slice(7));
  if (bytes.length < 8) throw new Error('MID digest too short');
  return Array.from(bytes.slice(0, 8)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function exactArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function decodeBase58(str) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let bytes = [0];
  for (const ch of str) {
    const value = alphabet.indexOf(ch);
    if (value < 0) throw new Error('invalid base58');
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < str.length - 1 && str[i] === '1'; i++) bytes.push(0);
  return new Uint8Array(bytes.reverse());
}

function countAsync(store) {
  return new Promise((resolve, reject) => {
    const req = store.count();
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e.target.error);
  });
}
