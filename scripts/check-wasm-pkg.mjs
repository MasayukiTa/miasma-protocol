#!/usr/bin/env node
// Checks that the committed browser package (web/pkg) matches its source.
//
//   node scripts/check-wasm-pkg.mjs --check            committed web/pkg and the
//                                                      source still match the
//                                                      record in
//                                                      crates/miasma-wasm/pkg-build.json
//   node scripts/check-wasm-pkg.mjs --compare <dir>    a package rebuilt from the
//                                                      source (see
//                                                      scripts/build-wasm-pkg.sh)
//                                                      agrees with web/pkg
//   node scripts/check-wasm-pkg.mjs --write            rewrite the record from the
//                                                      source and the current web/pkg
//
// Why not compare the .wasm bytes: a wasm-bindgen release build embeds the
// absolute build paths of the compiler, the cargo registry and the source tree
// (panic locations), so two machines never give the same bytes. The committed
// file was built on Windows; CI builds on Linux. What can be compared exactly
// is the JS glue and the type files (wasm-bindgen output, no paths), and the
// interface of the wasm module (imports, exports with their signatures,
// memories, tables). The source itself is covered by a digest of
// crates/miasma-wasm (Cargo.toml and src/) plus the locked dependency set.
// No dependencies.

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { abiOf } from './wasm-abi.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, '..');
const CRATE = path.join(ROOT, 'crates', 'miasma-wasm');
const RECORD = path.join(CRATE, 'pkg-build.json');
const PKG = path.join(ROOT, 'web', 'pkg');
const GLUE_FILES = ['miasma_wasm.js', 'miasma_wasm.d.ts', 'miasma_wasm_bg.wasm.d.ts'];
const WASM_FILE = 'miasma_wasm_bg.wasm';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const noCr = (bytes) => Buffer.from(bytes.filter((b) => b !== 0x0d));
const textHash = (file) => sha256(noCr(fs.readFileSync(file)));

function listSrc(dir, base = '') {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = base ? `${base}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...listSrc(path.join(dir, e.name), rel));
    else out.push(rel);
  }
  return out.sort();
}

/** Digest of everything in the crate that is compiled into the package. */
export function sourceDigest() {
  const lines = [`Cargo.toml ${textHash(path.join(CRATE, 'Cargo.toml'))}`];
  for (const rel of listSrc(path.join(CRATE, 'src'))) {
    lines.push(`src/${rel} ${textHash(path.join(CRATE, 'src', rel))}`);
  }
  return sha256(Buffer.from(lines.join('\n')));
}

// ---- locked dependency set -------------------------------------------------

function parseLock(text) {
  const packages = [];
  for (const block of text.split(/\n\[\[package\]\]\n/).slice(1)) {
    const name = /^name = "([^"]+)"/m.exec(block)?.[1];
    const version = /^version = "([^"]+)"/m.exec(block)?.[1];
    const checksum = /^checksum = "([^"]+)"/m.exec(block)?.[1] ?? '';
    const deps = [];
    const depBlock = /^dependencies = \[\n([\s\S]*?)\n\]/m.exec(block)?.[1] ?? '';
    for (const m of depBlock.matchAll(/"([^"]+)"/g)) deps.push(m[1]);
    packages.push({ name, version, checksum, deps });
  }
  return packages;
}

/** Names the crate lists under [dependencies] and target-specific dependencies. */
function directDependencyNames() {
  const names = [];
  let on = false;
  for (const raw of fs.readFileSync(path.join(CRATE, 'Cargo.toml'), 'utf8').split('\n')) {
    const line = raw.trim();
    if (line.startsWith('[')) {
      on = line === '[dependencies]' || /^\[target\..*\.dependencies\]$/.test(line);
      continue;
    }
    const m = on && /^([A-Za-z0-9_-]+)\s*=/.exec(line);
    if (m) names.push(m[1]);
  }
  return names;
}

/** Name, version and registry checksum of every package the crate depends on. */
export function dependencyClosure() {
  const pkgs = parseLock(fs.readFileSync(path.join(ROOT, 'Cargo.lock'), 'utf8').replace(/\r/g, ''));
  const byName = new Map();
  for (const p of pkgs) {
    if (!byName.has(p.name)) byName.set(p.name, []);
    byName.get(p.name).push(p);
  }
  const find = (ref) => {
    const [name, version] = ref.split(' ');
    const list = byName.get(name) ?? [];
    return version ? list.find((p) => p.version === version) : list[0];
  };
  const seen = new Map();
  const todo = directDependencyNames().map((n) => find(n)).filter(Boolean);
  while (todo.length) {
    const p = todo.pop();
    const key = `${p.name} ${p.version}`;
    if (seen.has(key)) continue;
    seen.set(key, p);
    for (const d of p.deps) {
      const q = find(d);
      if (q) todo.push(q);
    }
  }
  return [...seen.values()]
    .map((p) => `${p.name} ${p.version} ${p.checksum}`)
    .sort();
}

const lockDigest = () => sha256(Buffer.from(dependencyClosure().join('\n')));

// ---- record ----------------------------------------------------------------

function wasmBindgenVersion() {
  const lock = fs.readFileSync(path.join(ROOT, 'Cargo.lock'), 'utf8');
  return /name = "wasm-bindgen"\r?\nversion = "([^"]+)"/.exec(lock)?.[1] ?? 'unknown';
}

function artifactOf(dir) {
  const files = {};
  for (const f of GLUE_FILES) files[f] = textHash(path.join(dir, f));
  const wasm = fs.readFileSync(path.join(dir, WASM_FILE));
  files[WASM_FILE] = sha256(wasm);
  return { files, abiSha256: sha256(Buffer.from(JSON.stringify(abiOf(wasm)))) };
}

function buildRecord() {
  return {
    schema: 1,
    note:
      'Generated by scripts/check-wasm-pkg.mjs --write (run through scripts/build-wasm-pkg.sh --update). ' +
      'sourceSha256 covers crates/miasma-wasm Cargo.toml and src/; dependenciesSha256 covers the locked ' +
      'dependency set; artifact describes the committed web/pkg built from them.',
    wasmBindgen: wasmBindgenVersion(),
    sourceSha256: sourceDigest(),
    dependenciesSha256: lockDigest(),
    artifact: artifactOf(PKG),
  };
}

function fail(messages) {
  for (const m of messages) console.error(`FAIL: ${m}`);
  process.exit(1);
}

const [mode, arg] = process.argv.slice(2);

if (mode === '--write') {
  fs.writeFileSync(RECORD, `${JSON.stringify(buildRecord(), null, 2)}\n`);
  console.log(`wrote ${path.relative(ROOT, RECORD)}`);
} else if (mode === '--check') {
  const rec = JSON.parse(fs.readFileSync(RECORD, 'utf8'));
  const now = buildRecord();
  const problems = [];
  if (rec.sourceSha256 !== now.sourceSha256) {
    problems.push(
      'crates/miasma-wasm (Cargo.toml or src/) changed since web/pkg was built: rebuild with ' +
        'scripts/build-wasm-pkg.sh --update and commit web/pkg, crates/miasma-wasm/pkg-build.json and web/asset-manifest.json',
    );
  }
  if (rec.dependenciesSha256 !== now.dependenciesSha256) {
    problems.push(
      'the locked dependencies of miasma-wasm changed since web/pkg was built: rebuild with scripts/build-wasm-pkg.sh --update',
    );
  }
  if (rec.wasmBindgen !== now.wasmBindgen) {
    problems.push(`wasm-bindgen is ${now.wasmBindgen} in Cargo.lock but web/pkg was built with ${rec.wasmBindgen}`);
  }
  for (const [f, h] of Object.entries(now.artifact.files)) {
    if (rec.artifact.files[f] !== h) problems.push(`web/pkg/${f} differs from the recorded build`);
  }
  if (rec.artifact.abiSha256 !== now.artifact.abiSha256) problems.push('the wasm interface differs from the recorded build');
  if (problems.length) fail(problems);
  console.log('web/pkg matches the recorded build of crates/miasma-wasm');
} else if (mode === '--compare' && arg) {
  const dir = path.resolve(arg);
  const committed = artifactOf(PKG);
  const rebuilt = artifactOf(dir);
  const problems = [];
  for (const f of GLUE_FILES) {
    if (committed.files[f] !== rebuilt.files[f]) problems.push(`rebuilt ${f} differs from web/pkg/${f}`);
  }
  if (committed.abiSha256 !== rebuilt.abiSha256) {
    const a = JSON.stringify(abiOf(fs.readFileSync(path.join(PKG, WASM_FILE))), null, 1).split('\n');
    const b = JSON.stringify(abiOf(fs.readFileSync(path.join(dir, WASM_FILE))), null, 1).split('\n');
    const first = a.findIndex((l, i) => l !== b[i]);
    problems.push(`rebuilt wasm interface differs from web/pkg (first difference near line ${first}: '${a[first]}' vs '${b[first]}')`);
  }
  // The build script remaps the machine's own paths; a home directory in the
  // rebuilt module means that stopped working.
  const HOME_PATH = /(?:[A-Za-z]:\\Users\\|\/home\/|\/Users\/|\/runner\/)[A-Za-z0-9_.-]+/g;
  const homePaths = (file) => new Set(fs.readFileSync(file).toString('latin1').match(HOME_PATH) ?? []).size;
  const rebuiltHomes = homePaths(path.join(dir, WASM_FILE));
  if (rebuiltHomes) problems.push(`the rebuilt wasm embeds ${rebuiltHomes} home-directory path(s); the build script's path remapping did not apply`);
  const committedHomes = homePaths(path.join(PKG, WASM_FILE));
  if (committedHomes) console.log(`note: web/pkg/${WASM_FILE} embeds ${committedHomes} distinct home-directory path(s) from the machine that built it`);
  if (problems.length) fail(problems);
  const same =committed.files[WASM_FILE] === rebuilt.files[WASM_FILE];
  console.log(
    `rebuilt package agrees with web/pkg: glue, type files and wasm interface identical; wasm bytes ${
      same ? 'identical' : 'differ (expected: the code embeds absolute build paths)'
    }`,
  );
} else {
  console.error('usage: check-wasm-pkg.mjs --check | --write | --compare <dir>');
  process.exit(2);
}
