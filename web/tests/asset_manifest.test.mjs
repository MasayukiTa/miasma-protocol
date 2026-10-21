import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { check, computeManifest, swWithVersion, WEB_ROOT } from '../../scripts/web-asset-manifest.mjs';

test('committed asset manifest and sw.js version match web/', () => {
  assert.deepEqual(check(), [], 'run: node scripts/web-asset-manifest.mjs');
});

function copyWeb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'miasma-web-'));
  fs.cpSync(WEB_ROOT, dir, { recursive: true });
  return dir;
}

test('changing any shipped file changes the version and is reported', () => {
  const dir = copyWeb();
  try {
    const before = computeManifest(dir);
    fs.appendFileSync(path.join(dir, 'js/bridge.js'), '\n// changed\n');
    const after = computeManifest(dir);
    assert.notEqual(after.version, before.version);
    assert.notEqual(after.files['js/bridge.js'], before.files['js/bridge.js']);
    assert.ok(check(dir).some((p) => p.includes('js/bridge.js')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('line endings and tests/ do not affect the version', () => {
  const dir = copyWeb();
  try {
    const before = computeManifest(dir);
    const file = path.join(dir, 'js/format.js');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace(/\r/g, '').replace(/\n/g, '\r\n'));
    fs.writeFileSync(path.join(dir, 'tests/extra.test.mjs'), 'x');
    assert.equal(computeManifest(dir).version, before.version);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the sw.js version line is part of the check and is rewritable', () => {
  const sw = fs.readFileSync(path.join(WEB_ROOT, 'sw.js'), 'utf8');
  const out = swWithVersion(sw, 'abcdef0123456789');
  assert.match(out, /const ASSET_VERSION = 'abcdef0123456789';/);
  assert.throws(() => swWithVersion('nothing here', 'abcdef0123456789'));
  const manifest = computeManifest();
  assert.ok(!('asset-manifest.json' in manifest.files));
  assert.ok(!Object.keys(manifest.files).some((p) => p.startsWith('tests/') || p.endsWith('.d.ts')));
});
