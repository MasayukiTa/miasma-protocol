import test from 'node:test';
import assert from 'node:assert/strict';

function installWindow(networkReady) {
  globalThis.window = {
    miasma: {
      ping: () => JSON.stringify({ ok: true }),
      status: () => JSON.stringify({ network_ready: networkReady, share_count: 3 }),
    },
    location: { protocol: 'file:', hash: '', origin: 'null', pathname: '/', search: '' },
    history: { state: null, replaceState() {} },
  };
}

installWindow(false);
const { MiasmaBridge } = await import('../js/bridge.js');

test('WebView host presence does not imply the embedded daemon is network-ready', async (t) => {
  const bridge = new MiasmaBridge();
  t.after(() => {
    if (bridge._pollTimer) clearInterval(bridge._pollTimer);
    delete globalThis.window;
  });

  await bridge.init({});
  assert.equal(bridge.mode, 'webview');
  assert.equal(bridge.connected, false);
  assert.equal(bridge.lastStatus.network_ready, false);

  window.miasma.status = () => JSON.stringify({ network_ready: true, peer_count: 2 });
  const status = await bridge.status();
  assert.equal(status.peer_count, 2);
  assert.equal(bridge.connected, true);
});


test('WebView inbox errors are not disguised as an empty inbox', async (t) => {
  installWindow(true);
  window.miasma.directedInbox = () => JSON.stringify({ error: 'authorization failed' });
  const bridge = new MiasmaBridge();
  t.after(() => {
    if (bridge._pollTimer) clearInterval(bridge._pollTimer);
    delete globalThis.window;
  });

  await bridge.init({});
  await assert.rejects(() => bridge.directedInbox(), /authorization failed/);
});


// ── Android message channel (window.miasma has postMessage/onmessage only) ──

function installChannelHost(handler) {
  const sent = [];
  const host = {
    postMessage(text) {
      const req = JSON.parse(text);
      sent.push(req);
      const answer = handler(req);
      if (answer === undefined) return; // never answers
      setTimeout(() => host.onmessage && host.onmessage({ data: JSON.stringify({ id: req.id, ...answer }) }), 0);
    },
  };
  globalThis.window = {
    miasma: host,
    location: { protocol: 'https:', hash: '', origin: 'https://appassets.androidplatform.net', pathname: '/assets/web/index.html', search: '' },
    history: { state: null, replaceState() {} },
  };
  return sent;
}

test('Android channel: request/response with ids, no callable methods on the host object', async (t) => {
  const sent = installChannelHost((req) => {
    if (req.method === 'ping') return { result: { ok: true } };
    if (req.method === 'status') return { result: { network_ready: true, peer_count: 1 } };
    if (req.method === 'directedRevoke') return { result: { ok: true } };
    return { error: 'unknown method' };
  });
  const bridge = new MiasmaBridge();
  t.after(() => {
    if (bridge._pollTimer) clearInterval(bridge._pollTimer);
    delete globalThis.window;
  });

  await bridge.init({});
  assert.equal(bridge.mode, 'webview');
  assert.equal(bridge.connected, true);
  assert.equal(bridge.hostError, null);
  assert.equal(window.miasma.ping, undefined);

  await bridge.directedRevoke('env-1');
  const last = sent[sent.length - 1];
  assert.equal(last.method, 'directedRevoke');
  assert.deepEqual(last.args, ['env-1']);
  assert.equal(typeof last.id, 'number');
  const ids = sent.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, 'request ids are unique');
});

test('Android channel: a protocol error is surfaced, not swallowed', async (t) => {
  installChannelHost((req) => {
    if (req.method === 'ping') return { result: { ok: true } };
    if (req.method === 'status') return { result: { network_ready: true } };
    if (req.method === 'directedInbox') return { error: 'argument too large' };
    return { error: 'unknown method' };
  });
  const bridge = new MiasmaBridge();
  t.after(() => {
    if (bridge._pollTimer) clearInterval(bridge._pollTimer);
    delete globalThis.window;
  });
  await bridge.init({});
  await assert.rejects(() => bridge.directedInbox(), /argument too large/);
});

test('Android channel: a host that never answers is reported, and the page falls back to local mode', async (t) => {
  installChannelHost(() => undefined);
  globalThis.fetch = async () => { throw new Error('no bridge'); };
  const bridge = new MiasmaBridge();
  t.after(() => {
    if (bridge._pollTimer) clearInterval(bridge._pollTimer);
    delete globalThis.window;
    delete globalThis.fetch;
  });
  await bridge.init({});
  assert.notEqual(bridge.mode, 'webview');
  assert.match(bridge.hostError, /did not answer/);
});
