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
