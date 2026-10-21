#!/usr/bin/env node
// Build manifest for the web client.
//
//   node scripts/web-asset-manifest.mjs           write web/asset-manifest.json and
//                                                 the version constant in web/sw.js
//   node scripts/web-asset-manifest.mjs --check   fail if either is out of date
//
// The manifest lists every shipped file under web/ with its SHA-256. `version`
// is a hash over that list, and the service worker derives its cache name from
// it, so any change to a shipped file gives a new cache. No dependencies.

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const WEB_ROOT = path.resolve(here, '..', 'web');
export const MANIFEST_NAME = 'asset-manifest.json';

// Not shipped to the browser: node tests and wasm-pack by-products.
const SKIP_DIRS = new Set(['tests']);
const SKIP_FILES = new Set([MANIFEST_NAME, 'pkg/.gitignore', 'pkg/package.json']);
const TEXT_EXT = new Set(['.js', '.html', '.css', '.json']);
const VERSION_RE = /const ASSET_VERSION = '([0-9a-f]{16})';/;
const ZERO_VERSION = '0'.repeat(16);

/** Line endings must not change a hash (a Windows checkout may rewrite them). */
export function normalise(relPath, bytes) {
  if (!TEXT_EXT.has(path.extname(relPath))) return bytes;
  return Buffer.from(bytes.filter((b) => b !== 0x0d));
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function listFiles(dir, base = '') {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) || base) out.push(...listFiles(path.join(dir, entry.name), rel));
      continue;
    }
    if (SKIP_FILES.has(rel) || rel.endsWith('.d.ts')) continue;
    out.push(rel);
  }
  return out.sort();
}

export function computeManifest(webRoot = WEB_ROOT) {
  const files = {};
  for (const rel of listFiles(webRoot)) {
    let bytes = fs.readFileSync(path.join(webRoot, rel));
    if (rel === 'sw.js') {
      // The version constant is derived from this hash: hash with it blanked.
      bytes = Buffer.from(bytes.toString('utf8').replace(VERSION_RE, `const ASSET_VERSION = '${ZERO_VERSION}';`));
    }
    files[rel] = sha256(normalise(rel, bytes));
  }
  const listing = Object.entries(files).map(([p, h]) => `${p}\0${h}\n`).join('');
  return { schema: 1, version: sha256(Buffer.from(listing)).slice(0, 16), files };
}

export function renderManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

export function swWithVersion(swSource, version) {
  if (!VERSION_RE.test(swSource)) throw new Error("sw.js has no `const ASSET_VERSION = '<16 hex>';` line");
  return swSource.replace(VERSION_RE, `const ASSET_VERSION = '${version}';`);
}

/** Returns a list of problems; empty when the committed files match web/. */
export function check(webRoot = WEB_ROOT) {
  const problems = [];
  const expected = computeManifest(webRoot);
  const manifestPath = path.join(webRoot, MANIFEST_NAME);
  const swPath = path.join(webRoot, 'sw.js');
  let committed = null;
  try { committed = fs.readFileSync(manifestPath, 'utf8').replace(/\r/g, ''); } catch (_) { /* reported below */ }
  if (committed === null) {
    problems.push(`web/${MANIFEST_NAME} is missing`);
  } else if (committed !== renderManifest(expected)) {
    let old = {};
    try { old = JSON.parse(committed).files || {}; } catch (_) { /* malformed */ }
    for (const p of new Set([...Object.keys(old), ...Object.keys(expected.files)])) {
      if (old[p] !== expected.files[p]) problems.push(`web/${p} differs from ${MANIFEST_NAME}`);
    }
    if (problems.length === 0) problems.push(`web/${MANIFEST_NAME} is out of date`);
  }
  const m = VERSION_RE.exec(fs.readFileSync(swPath, 'utf8'));
  if (!m) problems.push('web/sw.js has no ASSET_VERSION line');
  else if (m[1] !== expected.version) problems.push(`web/sw.js ASSET_VERSION ${m[1]} != ${expected.version}`);
  return problems;
}

function write(webRoot = WEB_ROOT) {
  const swPath = path.join(webRoot, 'sw.js');
  const manifest = computeManifest(webRoot);
  fs.writeFileSync(swPath, swWithVersion(fs.readFileSync(swPath, 'utf8'), manifest.version));
  fs.writeFileSync(path.join(webRoot, MANIFEST_NAME), renderManifest(manifest));
  return manifest;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--check')) {
    const problems = check();
    if (problems.length) {
      console.error(problems.join('\n'));
      console.error('Run: node scripts/web-asset-manifest.mjs   (then commit web/asset-manifest.json and web/sw.js)');
      process.exit(1);
    }
    console.log('web asset manifest is up to date');
  } else {
    const m = write();
    console.log(`wrote web/${MANIFEST_NAME}: ${Object.keys(m.files).length} files, version ${m.version}`);
  }
}
