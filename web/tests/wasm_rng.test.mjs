// The committed WebAssembly package must stop when no secure random source is
// available: no key, no nonce, no shares, and no weaker generator behind it.
//
// Each case runs in its own node process, because the package reads the random
// source once and keeps it. The first case is the control: with the normal
// source the same call works. The others remove or break the source before the
// package starts.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const PKG_JS = pathToFileURL(fileURLToPath(new URL('../pkg/miasma_wasm.js', import.meta.url))).href;
const PKG_WASM = fileURLToPath(new URL('../pkg/miasma_wasm_bg.wasm', import.meta.url));

// Runs in the child. SETUP is placed before the package is loaded.
function childProgram(setup) {
  return `
${setup}
import { readFileSync } from 'node:fs';
const mod = await import(process.env.PKG_JS);
await mod.default({ module_or_path: readFileSync(process.env.PKG_WASM) });
const data = new TextEncoder().encode('fail closed check');
const outcomes = [];
for (const call of [
  () => mod.dissolve_bytes_bundle(data, 3, 5),
  () => mod.dissolve_bytes(data, 3, 5),
  () => mod.dissolve_text('fail closed check', 3, 5),
]) {
  try {
    const out = call();
    outcomes.push({ ok: true, size: out.length });
  } catch (e) {
    outcomes.push({ ok: false });
  }
}
console.log('RESULT ' + JSON.stringify(outcomes));
`;
}

function run(setup) {
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', childProgram(setup)], {
    env: { ...process.env, PKG_JS, PKG_WASM },
    encoding: 'utf8',
    timeout: 60_000,
  });
  const line = (r.stdout || '').split('\n').find((l) => l.startsWith('RESULT '));
  return { status: r.status, outcomes: line ? JSON.parse(line.slice(7)) : null, stderr: r.stderr };
}

test('control: with the normal random source every dissolve call works', () => {
  const r = run('');
  assert.deepEqual(
    r.outcomes?.map((o) => o.ok),
    [true, true, true],
    r.stderr,
  );
});

test('no crypto object at all: every dissolve call fails and returns nothing', () => {
  const r = run("Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });");
  assert.deepEqual(
    r.outcomes?.map((o) => o.ok),
    [false, false, false],
    r.stderr,
  );
});

test('getRandomValues throws: every dissolve call fails and returns nothing', () => {
  const r = run(
    "Object.defineProperty(globalThis, 'crypto', { value: { getRandomValues() { throw new Error('no entropy'); } }, configurable: true });",
  );
  assert.deepEqual(
    r.outcomes?.map((o) => o.ok),
    [false, false, false],
    r.stderr,
  );
});
