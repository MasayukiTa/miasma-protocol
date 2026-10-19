import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(here, '..');
const manifestPath = path.join(webRoot, 'manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

function pngSize(filePath) {
  const data = fs.readFileSync(filePath);
  assert.equal(data.subarray(1, 4).toString('ascii'), 'PNG');
  assert.equal(data.subarray(12, 16).toString('ascii'), 'IHDR');
  return [data.readUInt32BE(16), data.readUInt32BE(20)];
}

test('PWA manifest is installable and subpath-safe', () => {
  assert.ok(manifest.name || manifest.short_name);
  assert.equal(manifest.id, './');
  assert.equal(manifest.start_url, './');
  assert.equal(manifest.scope, './');
  assert.equal(manifest.display, 'standalone');
  assert.equal(manifest.orientation, 'any');

  const sizes = new Set(manifest.icons.filter(i => i.purpose?.includes('any')).map(i => i.sizes));
  assert.ok(sizes.has('192x192'), '192x192 any-purpose icon is required');
  assert.ok(sizes.has('512x512'), '512x512 any-purpose icon is required');
  assert.ok(manifest.icons.some(i => i.sizes === '512x512' && i.purpose?.includes('maskable')));

  for (const icon of manifest.icons) {
    assert.match(icon.src, /^icons\//, 'manifest icons must be real same-origin files');
    assert.equal(icon.type, 'image/png');
    const iconPath = path.join(webRoot, icon.src);
    assert.ok(fs.existsSync(iconPath), `missing icon: ${icon.src}`);
    const expected = icon.sizes.split('x').map(Number);
    assert.deepEqual(pngSize(iconPath), expected);
  }
});

test('HTML exposes manifest and iOS touch icon', () => {
  const html = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');
  assert.match(html, /<link rel="manifest" href="manifest\.json">/);
  assert.match(html, /<link rel="apple-touch-icon" sizes="180x180" href="icons\/apple-touch-icon\.png">/);
  assert.deepEqual(pngSize(path.join(webRoot, 'icons/apple-touch-icon.png')), [180, 180]);
});

test('service worker precaches install assets and has offline navigation fallback', () => {
  const sw = fs.readFileSync(path.join(webRoot, 'sw.js'), 'utf8');
  for (const icon of [...manifest.icons.map(i => i.src), 'icons/apple-touch-icon.png', 'manifest.json']) {
    assert.ok(sw.includes(`'${icon}'`), `service worker does not precache ${icon}`);
  }
  assert.match(sw, /event\.request\.mode === 'navigate'/);
  assert.match(sw, /cache\.match\(new URL\('\.\/index\.html', self\.registration\.scope\)\.href\)/);
  assert.match(sw, /url\.pathname\.startsWith\('\/api\/'\)/);
});
