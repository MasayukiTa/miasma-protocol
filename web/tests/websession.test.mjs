import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {
  createSessionClient, chooseAuthMode, authStateForCode, SessionError, SESSION_DB, noSessionResponse,
} from '../js/websession.js';
import { wipeEverything } from '../js/wipe.js';
import {
  FakeDaemon, fakeIndexedDb, jsonResponse, b64u, unb64u, sha256Hex, specCanonical, specRegisterProof, verifyP1363,
} from './fakes.mjs';

const ORIGIN = 'http://127.0.0.1:17842';
const BRIDGE = ORIGIN;

/** A client wired to a fake daemon, a fake IndexedDB and a clock the test controls. */
function setup({ webAuth, clock = { t: 1792999999000 }, idb = fakeIndexedDb(), daemonSkew = 0 } = {}) {
  const daemon = new FakeDaemon({ webAuth, now: () => clock.t + daemonSkew, pageOrigin: ORIGIN });
  const client = createSessionClient({
    fetch: daemon.fetch, indexedDB: idb, origin: ORIGIN, now: () => clock.t,
  });
  return { daemon, client, idb, clock };
}

async function ready(opts) {
  const s = setup(opts);
  s.client.setBoot(s.daemon.issueBoot());
  assert.equal(await s.client.establish(BRIDGE), 'ready');
  return s;
}

function storedRecord(idb) {
  return idb.dbs.get(SESSION_DB).get('session').get('current');
}

test('registration payload: fields, key size, and a proof that verifies', async () => {
  const { daemon, client } = setup();
  const boot = daemon.issueBoot();
  client.setBoot(boot);
  assert.equal(await client.establish(BRIDGE), 'ready');

  const [reg] = daemon.requests((r) => r.path === '/api/session/register');
  assert.equal(reg.method, 'POST');
  assert.equal(reg.headers['content-type'], 'application/json');
  const body = JSON.parse(new TextDecoder().decode(reg.body));
  assert.deepEqual(Object.keys(body), ['v', 'boot', 'pub', 'ts', 'pop']);
  assert.equal(body.v, 1);
  assert.equal(body.boot, boot);
  assert.equal(unb64u(body.pub).length, 65);
  assert.equal(unb64u(body.pub)[0], 0x04);
  assert.equal(unb64u(body.pop).length, 64);
  assert.equal(typeof body.ts, 'number');
  const proof = specRegisterProof({ origin: ORIGIN, boot, pub: body.pub, ts: body.ts });
  assert.equal(await verifyP1363(body.pub, proof, body.pop), true);
  // The proof covers the boot: moved to another link it no longer verifies.
  const other = specRegisterProof({ origin: ORIGIN, boot: daemon.issueBoot(), pub: body.pub, ts: body.ts });
  assert.equal(await verifyP1363(body.pub, other, body.pop), false);
});

test('the private key is not extractable and nothing exposes it', async () => {
  const { client, idb } = await ready();
  const key = storedRecord(idb).privateKey;
  assert.equal(key.type, 'private');
  assert.equal(key.extractable, false);
  for (const format of ['pkcs8', 'jwk']) {
    await assert.rejects(crypto.subtle.exportKey(format, key), (e) => e.name === 'InvalidAccessError' || e.name === 'InvalidAccessException' || /extract/i.test(e.message), format);
  }
  const info = client.info();
  assert.ok(!('privateKey' in info));
  assert.ok(!JSON.stringify(info).includes('privateKey'));
  assert.deepEqual(Object.keys(info).sort(), ['bridge', 'expiresAt', 'origin', 'persisted', 'scopes', 'sid']);
});

test('requests are signed per the canonical string and verify with WebCrypto', async () => {
  const { client, daemon } = await ready();
  const resp = await client.signedFetch(`${BRIDGE}/api/status`);
  assert.equal(resp.status, 200);

  const bodyText = JSON.stringify({ mid: 'miasma:x', data_shards: 3, total_shards: 5 });
  const resp2 = await client.signedFetch(`${BRIDGE}/api/retrieve?x=%E3%81%82&y=1`, {
    method: 'post', headers: { 'Content-Type': 'application/json' }, body: bodyText,
  });
  assert.equal(resp2.status, 200);

  const sent = daemon.requests((r) => r.headers.authorization && r.headers.authorization.startsWith('MiasmaSig '));
  assert.equal(sent.length, 2);
  const pub = b64u(unb64u(JSON.parse(new TextDecoder().decode(daemon.requests((r) => r.path === '/api/session/register')[0].body)).pub));
  for (const r of sent) {
    const m = /sid=([^,]+), ts=(\d+), n=([^,]+), sig=(.+)$/.exec(r.headers.authorization);
    const canonical = specCanonical({
      method: r.method, target: r.target, origin: ORIGIN, sid: m[1], ts: m[2], nonce: m[3], bodyHash: await sha256Hex(r.body),
    });
    assert.equal(await verifyP1363(pub, canonical, m[4]), true, r.target);
    // One changed byte of the body, or of the path, breaks it.
    const tampered = specCanonical({ method: r.method, target: `${r.target}x`, origin: ORIGIN, sid: m[1], ts: m[2], nonce: m[3], bodyHash: await sha256Hex(r.body) });
    assert.equal(await verifyP1363(pub, tampered, m[4]), false);
  }
  assert.equal(sent[1].method, 'POST');
  assert.equal(sent[1].target, '/api/retrieve?x=%E3%81%82&y=1');
  assert.equal(new TextDecoder().decode(sent[1].body), bodyText);
  assert.equal(sent[1].headers['content-type'], 'application/json');
});

test('body hash covers the exact bytes (string, bytes, empty, multibyte)', async () => {
  const { client, daemon } = await ready();
  const bodies = [undefined, '', 'plain', '日本語 \u{1F600}', new Uint8Array([0, 1, 2, 255]), new Uint8Array([9, 9, 9, 9]).subarray(1, 3), new Uint8Array([5, 6]).buffer];
  for (const body of bodies) {
    const resp = await client.signedFetch(`${BRIDGE}/api/publish`, { method: 'POST', body });
    assert.equal(resp.status, 200, String(body));
  }
  // The daemon fake recomputed each hash from the bytes it received and verified the signature.
  assert.equal(daemon.requests((r) => r.path === '/api/publish').length, bodies.length);
});

test('a caller-supplied Authorization header is replaced, never forwarded', async () => {
  const { client, daemon } = await ready();
  await client.signedFetch(`${BRIDGE}/api/status`, { headers: { authorization: 'Bearer leaked', 'X-Test': '1' } });
  const last = daemon.log.at(-1);
  assert.ok(last.headers.authorization.startsWith('MiasmaSig '));
  assert.ok(!JSON.stringify(last.headers).includes('leaked'));
  assert.equal(last.headers['x-test'], '1');
});

test('timestamps follow the clock and nonces never repeat', async () => {
  const { client, daemon, clock } = await ready();
  const nonces = new Set();
  const stamps = [];
  for (let i = 0; i < 300; i++) {
    clock.t += i % 7 === 0 ? 0 : 5; // several requests in the same millisecond
    await client.signedFetch(`${BRIDGE}/api/status`);
    const m = /ts=(\d+), n=([^,]+)/.exec(daemon.log.at(-1).headers.authorization);
    nonces.add(m[2]);
    stamps.push(Number(m[1]));
  }
  assert.equal(nonces.size, 300);
  for (const ts of stamps) assert.ok(Math.abs(ts - clock.t) < 5000);
  assert.deepEqual([...stamps].sort((a, b) => a - b), stamps, 'timestamps never run backwards');
  for (const n of nonces) assert.equal(unb64u(n).length, 16);
});

test('the daemon clock offset from registration is applied to later requests', async () => {
  const { client, daemon } = await ready({ daemonSkew: 20000 }); // daemon 20 s ahead of the browser
  // 20 s ahead is inside the daemon's accepted window only because the offset is applied.
  const resp = await client.signedFetch(`${BRIDGE}/api/status`);
  assert.equal(resp.status, 200);
  const m = /ts=(\d+)/.exec(daemon.log.at(-1).headers.authorization);
  assert.equal(Number(m[1]), daemon.now());
});

test('a stale timestamp is retried once with a new nonce; other failures are not retried', async () => {
  const { client, daemon, clock } = await ready();
  // The daemon's clock jumps 5 minutes: the next request is stale, the retry carries the daemon's time.
  daemon.now = () => clock.t + 300000;
  const resp = await client.signedFetch(`${BRIDGE}/api/status`);
  assert.equal(resp.status, 200);
  const tail = daemon.log.slice(-2);
  assert.equal(tail.length, 2);
  const nonce = (r) => /n=([^,]+)/.exec(r.headers.authorization)[1];
  assert.notEqual(nonce(tail[0]), nonce(tail[1]));

  // A second stale answer is returned to the caller, not retried again.
  const before = daemon.log.length;
  daemon.failNext.push(
    jsonResponse(401, { error: 'clock', code: 'stale_timestamp', server_time_ms: daemon.now() }),
    jsonResponse(401, { error: 'clock', code: 'stale_timestamp', server_time_ms: daemon.now() }),
  );
  const again = await client.signedFetch(`${BRIDGE}/api/status`);
  assert.equal(again.status, 401);
  assert.equal(daemon.log.length - before, 2);

  // Other 401s, 5xx and network errors: exactly one attempt.
  for (const next of [
    jsonResponse(401, { error: 'x', code: 'replayed_nonce' }),
    jsonResponse(401, { error: 'x', code: 'bad_signature' }),
    jsonResponse(500, { error: 'boom' }),
    new Error('network down'),
  ]) {
    const n0 = daemon.log.length;
    daemon.failNext.push(next);
    if (next instanceof Error) await assert.rejects(client.signedFetch(`${BRIDGE}/api/status`), /network down/);
    else assert.equal((await client.signedFetch(`${BRIDGE}/api/status`)).status, next.status);
    assert.equal(daemon.log.length - n0, 1);
  }
});

test('registration with a wrong clock retries once with the daemon time and a fresh proof', async () => {
  const { daemon, client } = setup({ daemonSkew: 600000 }); // 10 minutes off
  client.setBoot(daemon.issueBoot());
  assert.equal(await client.establish(BRIDGE), 'ready');
  const regs = daemon.requests((r) => r.path === '/api/session/register');
  assert.equal(regs.length, 2);
  const parse = (r) => JSON.parse(new TextDecoder().decode(r.body));
  assert.notEqual(parse(regs[0]).ts, parse(regs[1]).ts);
  assert.notEqual(parse(regs[0]).pop, parse(regs[1]).pop);
  assert.equal(parse(regs[0]).pub, parse(regs[1]).pub, 'same key for both tries');
});

test('a reload reuses the stored key and session without a new link', async () => {
  const first = await ready();
  assert.equal(first.client.info().persisted, true);
  const sid = first.client.info().sid;

  const reloaded = createSessionClient({ fetch: first.daemon.fetch, indexedDB: first.idb, origin: ORIGIN, now: () => first.clock.t });
  assert.equal(reloaded.hasSession(), false);
  assert.equal(await reloaded.establish(BRIDGE), 'ready');
  assert.equal(reloaded.info().sid, sid);
  const registrations = first.daemon.requests((r) => r.path === '/api/session/register').length;
  assert.equal((await reloaded.signedFetch(`${BRIDGE}/api/status`)).status, 200);
  assert.equal(first.daemon.requests((r) => r.path === '/api/session/register').length, registrations, 'no second registration');
  assert.equal(storedRecord(first.idb).privateKey.extractable, false);
});

test('a new launch link replaces the stored session', async () => {
  const first = await ready();
  const oldSid = first.client.info().sid;
  const again = createSessionClient({ fetch: first.daemon.fetch, indexedDB: first.idb, origin: ORIGIN, now: () => first.clock.t });
  again.setBoot(first.daemon.issueBoot());
  assert.equal(await again.establish(BRIDGE), 'ready');
  assert.notEqual(again.info().sid, oldSid);
  assert.equal(storedRecord(first.idb).sid, again.info().sid);
});

test('a stored session is not used for another page or another daemon address', async () => {
  const first = await ready();
  const otherPage = createSessionClient({ fetch: first.daemon.fetch, indexedDB: first.idb, origin: 'http://localhost:17842', now: () => first.clock.t });
  assert.equal(await otherPage.establish(BRIDGE), 'missing');
  const otherDaemon = createSessionClient({ fetch: first.daemon.fetch, indexedDB: first.idb, origin: ORIGIN, now: () => first.clock.t });
  assert.equal(await otherDaemon.establish('http://127.0.0.1:9999'), 'missing');
  assert.equal(otherDaemon.hasSession(), false);
});

test('a stored key that is extractable is refused and erased', async () => {
  const idb = fakeIndexedDb();
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const open = idb.open(SESSION_DB);
  await new Promise((resolve) => {
    open.onupgradeneeded = (e) => e.target.result.createObjectStore('session');
    open.onsuccess = (e) => {
      const tx = e.target.result.transaction('session', 'readwrite');
      tx.objectStore('session').put({ v: 1, sid: b64u(new Uint8Array(16)), privateKey: pair.privateKey, pub: 'x', origin: ORIGIN, bridge: BRIDGE }, 'current');
      tx.oncomplete = resolve;
    };
  });
  const { client } = setup({ idb });
  assert.equal(await client.establish(BRIDGE), 'missing');
  assert.deepEqual(idb.stats.deleted, [SESSION_DB]);
});

test('without crypto.subtle (an insecure context) there is a clear state, no key and no request', async () => {
  for (const cryptoLike of [{}, { getRandomValues: () => {} }, { subtle: undefined, getRandomValues: () => {} }, undefined]) {
    const daemon = new FakeDaemon();
    const client = createSessionClient({ crypto: cryptoLike || {}, fetch: daemon.fetch, indexedDB: fakeIndexedDb(), origin: ORIGIN });
    client.setBoot(daemon.issueBoot());
    assert.equal(client.isSupported(), false);
    assert.equal(await client.establish(BRIDGE), 'unsupported');
    assert.equal(client.noSessionState(), 'unsupported');
    assert.equal(client.hasSession(), false);
    await assert.rejects(client.signedFetch(`${BRIDGE}/api/status`), (e) => e instanceof SessionError && e.code === 'session_required');
    assert.equal(daemon.log.length, 0, 'nothing was sent');
  }
  const resp = noSessionResponse('unsupported');
  assert.equal(resp.status, 401);
  assert.match((await resp.json()).error, /cannot create the signing key/);
});

test('a refused link is final; an unreachable daemon keeps the link for another try', async () => {
  const { daemon, client } = setup();
  const boot = daemon.issueBoot();
  client.setBoot(boot);
  daemon.failNext.push(new Error('connection refused'));
  assert.equal(await client.establish(BRIDGE), 'missing');
  assert.equal(client.hasBoot(), true);
  assert.equal(await client.establish(BRIDGE), 'ready', 'the same link works once the daemon answers');
  assert.equal(client.hasBoot(), false);

  const used = createSessionClient({ fetch: daemon.fetch, indexedDB: fakeIndexedDb(), origin: ORIGIN });
  used.setBoot(boot);
  assert.equal(await used.establish(BRIDGE), 'expired');
  assert.equal(used.noSessionState(), 'expired');
  assert.equal(used.hasBoot(), false);
  const unknown = createSessionClient({ fetch: daemon.fetch, indexedDB: fakeIndexedDb(), origin: ORIGIN });
  unknown.setBoot(b64u(new Uint8Array(32).fill(7)));
  assert.equal(await unknown.establish(BRIDGE), 'expired');
});

test('malformed boot values are ignored', async () => {
  const { client } = setup();
  for (const bad of ['', 'short', 'a'.repeat(44), `${'a'.repeat(42)}=`, null, undefined]) {
    client.setBoot(bad);
    assert.equal(client.hasBoot(), false, String(bad));
  }
});

test('the daemon ending a session wipes it here, in memory and on disk', async () => {
  const { client, idb } = await ready();
  await client.invalidate('expired');
  assert.equal(client.hasSession(), false);
  assert.equal(client.noSessionState(), 'expired');
  assert.deepEqual(idb.stats.deleted, [SESSION_DB]);
});

test('end() tells the daemon, then forgets the key', async () => {
  const { client, daemon, idb } = await ready();
  await client.end();
  const last = daemon.log.at(-1);
  assert.equal(last.method, 'POST');
  assert.equal(last.path, '/api/session/end');
  assert.ok(last.headers.authorization.startsWith('MiasmaSig '));
  assert.equal(client.hasSession(), false);
  assert.ok(idb.stats.deleted.includes(SESSION_DB));
});

test('clear with lock deletes the stored key and refuses to make another', async () => {
  const { client, daemon, idb } = await ready();
  await client.clear({ lock: true });
  assert.equal(client.hasSession(), false);
  assert.equal(idb.dbs.has(SESSION_DB), false);
  client.setBoot(daemon.issueBoot());
  assert.equal(await client.establish(BRIDGE), 'missing');
  assert.equal(client.hasSession(), false);
});

test('wipeEverything deletes the stored signing key', async () => {
  const { client, idb } = await ready();
  const env = { sessionStorage: { clear() {} }, localStorage: { clear() {} } };
  const result = await wipeEverything({
    env, clearToken: () => {}, lockDb: () => {}, removeDatabase: async () => {},
    clearSession: () => client.clear({ lock: true }),
  });
  assert.equal(result.ok, true);
  assert.equal(idb.dbs.has(SESSION_DB), false);
  assert.equal(client.hasSession(), false);
});

test('storage that fails leaves a working in-memory session', async () => {
  const daemon = new FakeDaemon();
  const broken = { open() { throw new Error('IndexedDB is disabled'); }, deleteDatabase() { throw new Error('nope'); } };
  const client = createSessionClient({ fetch: daemon.fetch, indexedDB: broken, origin: ORIGIN });
  client.setBoot(daemon.issueBoot());
  assert.equal(await client.establish(BRIDGE), 'ready');
  assert.equal(client.info().persisted, false);
  assert.equal((await client.signedFetch(`${BRIDGE}/api/status`)).status, 200);
  const none = createSessionClient({ fetch: daemon.fetch, indexedDB: undefined, origin: ORIGIN });
  none.setBoot(daemon.issueBoot());
  assert.equal(await none.establish(BRIDGE), 'ready');
});

test('requests for another host or with an unsupported body are refused before anything is signed', async () => {
  const { client, daemon } = await ready();
  const n = daemon.log.length;
  await assert.rejects(client.signedFetch('http://evil.example/api/status'), (e) => e.code === 'wrong_host');
  await assert.rejects(client.signedFetch(`http://127.0.0.1:9999/api/status`), (e) => e.code === 'wrong_host');
  await assert.rejects(client.signedFetch(`${BRIDGE}/api/publish`, { method: 'POST', body: new URLSearchParams({ a: '1' }) }), (e) => e.code === 'unsupported_body');
  assert.equal(daemon.log.length, n);
});

test('auth mode follows what the daemon advertises', () => {
  assert.equal(chooseAuthMode({ ok: true, web_auth: ['bearer', 'sig-v1'] }), 'sig-v1');
  assert.equal(chooseAuthMode({ ok: true, web_auth: ['sig-v1'] }), 'sig-v1');
  // Old daemon: the field is absent.
  assert.equal(chooseAuthMode({ ok: true }), 'legacy-bearer');
  assert.equal(chooseAuthMode(null), 'legacy-bearer');
  assert.equal(chooseAuthMode({ ok: true, web_auth: null }), 'legacy-bearer');
  // Advertised without a scheme this page speaks: never Bearer.
  assert.equal(chooseAuthMode({ ok: true, web_auth: ['bearer'] }), 'unsupported');
  assert.equal(chooseAuthMode({ ok: true, web_auth: [] }), 'unsupported');
  assert.equal(chooseAuthMode({ ok: true, web_auth: 'sig-v1' }), 'unsupported');
  assert.equal(chooseAuthMode({ ok: true, web_auth: ['sig-v2'] }), 'unsupported');
});

test('refusal codes map to the message the user should see', () => {
  for (const code of ['session_unknown', 'session_expired', 'boot_invalid', 'boot_expired', 'boot_already_used']) {
    assert.equal(authStateForCode(code), 'expired', code);
  }
  assert.equal(authStateForCode('session_required'), 'missing');
  for (const code of ['bad_signature', 'bad_auth_header', 'replayed_nonce', 'stale_timestamp', 'origin_mismatch', 'scope_required', 'root_token_not_accepted_from_browser', '', undefined]) {
    assert.equal(authStateForCode(code), 'rejected', String(code));
  }
});

// ── Vectors for the daemon's tests ───────────────────────────────────────────

test('signed requests can be written out for the Rust daemon tests (MIASMA_WS_VECTORS_OUT)', async () => {
  const { client, daemon, clock } = await ready();
  const wanted = [
    { path: '/api/status' },
    { path: '/api/publish', method: 'POST', body: JSON.stringify({ data: 'aGk=', data_shards: 3, total_shards: 5 }) },
    { path: '/api/retrieve?x=%E3%81%82&y=a%2Fb', method: 'POST', body: '日本語' },
    { path: '/api/transfers/ab%20cd', method: 'POST' },
    { path: '/api/directed/send', method: 'POST', body: new Uint8Array([0, 255, 10, 13]) },
  ];
  const reg = JSON.parse(new TextDecoder().decode(daemon.requests((r) => r.path === '/api/session/register')[0].body));
  const requests = [];
  for (const w of wanted) {
    clock.t += 1;
    const resp = await client.signedFetch(`${BRIDGE}${w.path}`, { method: w.method, body: w.body });
    assert.equal(resp.status, 200);
    const sent = daemon.log.at(-1);
    const m = /^MiasmaSig v=1, sid=([^,]+), ts=(\d+), n=([^,]+), sig=(.+)$/.exec(sent.headers.authorization);
    const bodyHash = await sha256Hex(sent.body);
    requests.push({
      method: sent.method,
      path_and_query: sent.target,
      origin: ORIGIN,
      sid: m[1],
      ts: m[2],
      nonce: m[3],
      body_b64: Buffer.from(sent.body).toString('base64'),
      body_sha256_hex: bodyHash,
      canonical: specCanonical({ method: sent.method, target: sent.target, origin: ORIGIN, sid: m[1], ts: m[2], nonce: m[3], bodyHash }),
      authorization: sent.headers.authorization,
      sig: m[4],
    });
  }
  // Every vector must verify here before it is handed to anyone else.
  for (const r of requests) assert.equal(await verifyP1363(reg.pub, r.canonical, r.sig), true);

  const out = process.env.MIASMA_WS_VECTORS_OUT;
  if (!out) return; // the file is only written on request
  const file = {
    format: 'miasma-websession-vectors',
    version: 1,
    alg: 'ES256',
    note: 'Generated by web/tests/websession.test.mjs with a fresh key per run. Public data only.',
    origin: ORIGIN,
    pub: reg.pub,
    register: {
      boot: reg.boot, ts: reg.ts, pop: reg.pop,
      canonical: specRegisterProof({ origin: ORIGIN, boot: reg.boot, pub: reg.pub, ts: reg.ts }),
    },
    requests,
    // The same signatures against altered inputs: each must be rejected.
    must_fail: requests.slice(0, 3).flatMap((r) => [
      { why: 'path changed', canonical: r.canonical.replace(r.path_and_query, `${r.path_and_query}x`), sig: r.sig },
      { why: 'method changed', canonical: r.canonical.replace(`\n${r.method}\n`, '\nDELETE\n'), sig: r.sig },
      { why: 'origin changed', canonical: r.canonical.replace(ORIGIN, 'http://localhost:17842'), sig: r.sig },
      { why: 'body hash changed', canonical: r.canonical.replace(r.body_sha256_hex, '0'.repeat(64)), sig: r.sig },
      { why: 'signature bit flipped', canonical: r.canonical, sig: b64u(Uint8Array.from(unb64u(r.sig), (b, i) => (i === 10 ? b ^ 1 : b))) },
    ]),
  };
  fs.writeFileSync(out, `${JSON.stringify(file, null, 2)}\n`);
  assert.ok(fs.statSync(out).size > 500);
});
