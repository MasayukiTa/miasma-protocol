import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import init, {
  dissolve_bytes_bundle,
  retrieve_from_share_bundle,
  verify_share_bytes,
} from '../pkg/miasma_wasm.js';
import { packShareBundle, parseDissolveBundle } from '../js/storage.js';

const wasmBytes = readFileSync(new URL('../pkg/miasma_wasm_bg.wasm', import.meta.url));
await init({ module_or_path: wasmBytes });

test('binary WASM boundary dissolves, verifies, and retrieves without JSON/base64', () => {
  const source = new TextEncoder().encode('Miasma binary browser boundary');
  const dissolved = parseDissolveBundle(dissolve_bytes_bundle(source, 3, 5));

  assert.ok(dissolved.mid.startsWith('miasma:'));
  assert.equal(dissolved.data_shards, 3);
  assert.equal(dissolved.total_shards, 5);
  assert.equal(dissolved.shares.length, 5);
  for (const share of dissolved.shares) {
    assert.ok(share.binary instanceof Uint8Array);
    assert.equal(verify_share_bytes(share.binary, dissolved.mid), true);
  }

  const bundle = packShareBundle(dissolved.shares.slice(1, 4));
  const recovered = retrieve_from_share_bundle(dissolved.mid, bundle, 3, 5);
  assert.deepEqual(recovered, source);
});
