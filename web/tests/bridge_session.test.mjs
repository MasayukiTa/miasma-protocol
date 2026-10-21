// bridge.js against a fake daemon: launch-link parsing, which credential is
// used, and what the page does when the session ends.
//
// bridge.js reads the launch fragment once, when it is first imported, so this
// file sets up the page globals first and imports it afterwards.

import assert from 'node:assert/strict';
import test from 'node:test';
import { FakeDaemon, fakeIndexedDb, newBoot, unb64u } from './fakes.mjs';

const ORIGIN = 'http://127.0.0.1:17842';
const LEGACY_TOKEN = 'ab'.repeat(32);
const daemon = new FakeDaemon({ pageOrigin: ORIGIN });
const idb = fakeIndexedDb();
const firstBoot = daemon.issueBoot();
const replaced = [];

globalThis.window = {
  miasma: undefined,
  location: {
    protocol: 'http:', origin: ORIGIN, pathname: '/', search: '',
    hash: `#boot=${firstBoot}&token=${LEGACY_TOKEN}`,
  },
  history: { state: null, replaceState: (...args) => replaced.push(args) },
};
globalThis.location = globalThis.window.location; // in a page, window is globalThis
globalThis.indexedDB = idb;
globalThis.fetch = (url, init) => daemon.fetch(url, init);

const bridgeModule = await import('../js/bridge.js');
const { MiasmaBridge, parseLaunchFragment, getAuthState, getAuthMode, clearControlState } = bridgeModule;
const { sessionClient } = await import('../js/websession.js');

const nonPing = (r) => r.path !== '/api/ping';
const wait = () => new Promise((r) => setTimeout(r, 0));

async function startBridge(t) {
  const bridge = new MiasmaBridge();
  t.after(() => { if (bridge._pollTimer) clearInterval(bridge._pollTimer); });
  await bridge.init({});
  return bridge;
}

test('launch fragment: boot, token and bridge are read; bad values are dropped', () => {
  const boot = newBoot();
  assert.deepEqual(parseLaunchFragment(`#boot=${boot}`), { token: '', boot, bridge: '' });
  assert.deepEqual(
    parseLaunchFragment(`#boot=${boot}&bridge=http://127.0.0.1:18000/&token=${LEGACY_TOKEN}`),
    { token: LEGACY_TOKEN, boot, bridge: 'http://127.0.0.1:18000' },
  );
  for (const bad of [`#boot=${boot.slice(1)}`, `#boot=${boot}x`, `#boot=${boot.slice(0, 42)}=`, '#boot=', '#boot=%20', '#', '', '#token=zz']) {
    assert.equal(parseLaunchFragment(bad).boot, '', bad);
  }
  // The bridge address must stay on this computer: a boot value must not be sent elsewhere.
  assert.equal(parseLaunchFragment(`#boot=${boot}&bridge=http://evil.example:17842`).bridge, '');
  assert.equal(parseLaunchFragment(`#boot=${boot}&bridge=http://127.0.0.1.evil.example`).bridge, '');
});

test('the fragment was removed from the address bar before anything else ran', () => {
  assert.equal(replaced.length, 1);
  assert.equal(replaced[0][2], '/');
});

test('daemon advertises sig-v1: the boot value is registered and every request is signed, never Bearer', async (t) => {
  const bridge = await startBridge(t);
  assert.equal(bridge.mode, 'http');
  assert.equal(getAuthMode(), 'sig-v1');
  assert.equal(bridge.connected, true);
  assert.equal(getAuthState(), 'ok');

  const result = await bridge.dissolve('hello', 3, 5);
  assert.equal(result.networkPublished, true);

  const requests = daemon.requests(nonPing);
  assert.equal(requests.filter((r) => r.path === '/api/session/register').length, 1);
  const rest = requests.filter((r) => r.path !== '/api/session/register');
  assert.ok(rest.length >= 2);
  for (const r of rest) assert.match(r.headers.authorization, /^MiasmaSig v=1, sid=/, r.path);
  // The legacy token was in the same link; it must not be sent anywhere.
  assert.ok(!JSON.stringify(daemon.log.map((r) => r.headers)).includes(LEGACY_TOKEN));
  assert.ok(!JSON.stringify(daemon.log.map((r) => r.headers)).includes('Bearer'));
  assert.ok(!daemon.log.some((r) => r.path === '/api/ping' && r.headers.authorization), 'ping stays unauthenticated');
  // The key was stored for the next load, and it cannot be read out.
  const record = idb.dbs.get('miasma-session').get('session').get('current');
  assert.equal(record.privateKey.extractable, false);
});

test('after a reload the stored session is used without a new link', async (t) => {
  sessionClient.dropMemory(); // what a reload does to the page's memory
  const before = daemon.requests((r) => r.path === '/api/session/register').length;
  const bridge = await startBridge(t);
  assert.equal(bridge.connected, true);
  assert.equal(getAuthState(), 'ok');
  assert.equal(daemon.requests((r) => r.path === '/api/session/register').length, before);
});

test('the daemon forgetting the session shows "expired", clears the key and stops sending', async (t) => {
  const bridge = await startBridge(t);
  daemon.forgetSessions(); // a daemon restart
  const states = [];
  const { onAuthChange } = bridgeModule;
  const off = onAuthChange((s) => states.push(s));
  t.after(off);
  await bridge.status();
  assert.equal(getAuthState(), 'expired');
  assert.deepEqual(states, ['expired']);
  assert.equal(bridge.connected, false);
  assert.equal(sessionClient.hasSession(), false);
  assert.equal(idb.dbs.has('miasma-session'), false, 'the stored key is gone');

  const n = daemon.log.length;
  await assert.rejects(bridge.dissolve('x', 1, 1), (e) => e.code === 'auth' && e.state === 'expired');
  assert.equal(daemon.log.length, n, 'no request leaves the page without a session');
  assert.equal(getAuthState(), 'expired');
});

test('a new link after that works again', async (t) => {
  sessionClient.setBoot(daemon.issueBoot());
  const bridge = await startBridge(t);
  assert.equal(getAuthState(), 'ok');
  assert.equal(bridge.connected, true);
});

test('no session and no link: "missing", and nothing is sent', async (t) => {
  clearControlState();
  await sessionClient.clear();
  const n = daemon.requests(nonPing).length;
  const bridge = await startBridge(t);
  assert.equal(getAuthState(), 'missing');
  assert.equal(bridge.connected, false);
  assert.equal(daemon.requests(nonPing).length, n);
});

test('browser without WebCrypto: "unsupported", and the legacy token is not used as a way around it', async (t) => {
  const boot = daemon.issueBoot();
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  // What an insecure context looks like: getRandomValues exists, subtle does not.
  Object.defineProperty(globalThis, 'crypto', { value: { getRandomValues: (a) => a }, configurable: true });
  t.after(() => Object.defineProperty(globalThis, 'crypto', original));
  bridgeModule.setControlToken(LEGACY_TOKEN);
  sessionClient.setBoot(boot);
  const n = daemon.requests(nonPing).length;
  const bridge = await startBridge(t);
  assert.equal(getAuthState(), 'unsupported');
  assert.equal(bridge.connected, false);
  assert.equal(daemon.requests(nonPing).length, n, 'neither a boot registration nor a Bearer request was sent');
  assert.ok(!JSON.stringify(daemon.log.map((r) => r.headers)).includes(LEGACY_TOKEN));
});

test('old daemon (ping has no web_auth): the Bearer token from the link is used, from memory only', async (t) => {
  clearControlState();
  await sessionClient.clear();
  daemon.webAuth = undefined;
  daemon.token = LEGACY_TOKEN;
  bridgeModule.setControlToken(LEGACY_TOKEN);
  const registrations = daemon.requests((r) => r.path === '/api/session/register').length;
  const bridge = await startBridge(t);
  assert.equal(getAuthMode(), 'legacy-bearer');
  assert.equal(bridge.connected, true);
  assert.equal(getAuthState(), 'ok');
  assert.equal(daemon.log.at(-1).headers.authorization, `Bearer ${LEGACY_TOKEN}`);
  assert.equal(daemon.requests((r) => r.path === '/api/session/register').length, registrations, 'no session attempted');
  assert.equal(globalThis.sessionStorage, undefined);
});

test('old daemon refusing the token reports "rejected" as before', async (t) => {
  daemon.token = 'cd'.repeat(32);
  const bridge = await startBridge(t);
  assert.equal(getAuthState(), 'rejected');
  assert.equal(bridge.connected, false);
});

test('daemon advertising only schemes this page does not speak: "unsupported", no Bearer', async (t) => {
  daemon.webAuth = ['bearer'];
  daemon.token = LEGACY_TOKEN;
  bridgeModule.setControlToken(LEGACY_TOKEN);
  const n = daemon.requests(nonPing).length;
  const bridge = await startBridge(t);
  assert.equal(getAuthMode(), 'unsupported');
  assert.equal(getAuthState(), 'unsupported');
  assert.equal(bridge.connected, false);
  assert.equal(daemon.requests(nonPing).length, n);
});

test('registration payload sent by the page uses the page origin and a 65-byte key', async () => {
  await wait();
  const reg = daemon.requests((r) => r.path === '/api/session/register')[0];
  const body = JSON.parse(new TextDecoder().decode(reg.body));
  assert.equal(unb64u(body.pub).length, 65);
  assert.equal(body.boot, firstBoot);
});
