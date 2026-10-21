// Which sender the Inbox screen shows for a private share. Run: node --test web/tests/
//
// The PeerId is observed on the connection that delivered the invite; the key inside the
// share is copied from the envelope and can be set to anything by whoever built it.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { senderDisplay } from '../js/format.js';

test('the connection PeerId is shown as verified, not the key from the envelope', () => {
  const item = { sender_peer_id: '12D3KooWRealSender', sender_pubkey: 'msk:someone-elses-key' };
  assert.deepEqual(senderDisplay(item), { kind: 'verified', id: '12D3KooWRealSender' });
});

test('a record with only the claimed key is shown as unverified', () => {
  const claimed = senderDisplay({ sender_pubkey: 'msk:claimed' });
  assert.equal(claimed.kind, 'unverified');
  assert.equal(claimed.id, 'msk:claimed');
  assert.equal(senderDisplay({ sender_peer_id: null, sender_pubkey: 'msk:claimed' }).kind, 'unverified');
  assert.equal(senderDisplay({ sender_peer_id: '', sender_pubkey: 'msk:claimed' }).kind, 'unverified');
  assert.equal(senderDisplay({ sender_peer_id: '   ', sender_pubkey: 'msk:claimed' }).kind, 'unverified');
});

test('nothing usable is unknown, and nonsense input never throws', () => {
  for (const bad of [undefined, null, {}, { sender_peer_id: 5, sender_pubkey: 7 }, { sender_pubkey: '' }]) {
    assert.deepEqual(senderDisplay(bad), { kind: 'unknown', id: '' });
  }
});

test('every locale has the three sender labels', () => {
  const src = fs.readFileSync(new URL('../js/i18n.js', import.meta.url), 'utf8');
  for (const key of ['inbox_sender_verified', 'inbox_sender_unverified', 'inbox_sender_unknown']) {
    const count = src.split(`${key}:`).length - 1;
    assert.equal(count, 3, `${key} should appear once in each of en, ja and zh`);
  }
});

test('the Inbox screen does not print the envelope key as the sender', () => {
  const src = fs.readFileSync(new URL('../js/app.js', import.meta.url), 'utf8');
  assert.ok(src.includes("senderDisplay(item)"));
  assert.ok(!/'From: '\s*\+\s*\(item\.sender_pubkey/.test(src));
});
