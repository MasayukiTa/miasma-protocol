// Pure helpers of the Transfers screen. Run: node --test web/tests/
//
// The expected values are the ones the desktop app's own tests pin
// (crates/miasma-desktop/src/transfers.rs), so the two screens agree.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatBytes, formatRate, formatEta, permille, formatPermille, timeSplit, fill, plainPath,
  fileNameOf, titleOf, transferId, chipTone, sortJobs, canResume, buildStrip, MAX_STRIP_CELLS, errorKey,
} from '../js/format.js';

test('formatBytes: units, truncation, and no float rounding for big sizes', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(1023), '1023 B');
  assert.equal(formatBytes(1024), '1.0 KiB');
  assert.equal(formatBytes(1536), '1.5 KiB');
  assert.equal(formatBytes(1024 * 1024 - 1), '1023.9 KiB'); // truncated, never rounded up to 1024.0
  assert.equal(formatBytes(100 * 1024 ** 3), '100.0 GiB');
  assert.equal(formatBytes(256 * 1024 ** 2), '256.0 MiB');
  assert.equal(formatBytes(2 ** 53), '8.0 PiB'); // the edge of exact JSON numbers
  assert.equal(formatBytes(2n ** 64n - 1n), '15.9 EiB'); // u64::MAX
  assert.equal(formatBytes(2n ** 63n), '8.0 EiB');
});

test('formatBytes: nonsense is zero, never NaN or a throw', () => {
  for (const bad of [undefined, null, NaN, -5, Infinity, '12', {}]) assert.equal(formatBytes(bad), '0 B');
  assert.equal(formatBytes(1e30), formatBytes(BigInt(1e30))); // above 2^64: still finite, still a string
});

test('formatRate: zero, negative and non-numbers show a dash', () => {
  for (const bad of [0, 0.5, -1, NaN, Infinity, null, undefined]) assert.equal(formatRate(bad), '-');
  assert.equal(formatRate(1), '1 B/s');
  assert.equal(formatRate(3.5 * 1024 * 1024), '3.5 MiB/s');
});

test('formatEta', () => {
  assert.equal(formatEta(null), '-');
  assert.equal(formatEta(undefined), '-');
  assert.equal(formatEta(0), '00:00:00');
  assert.equal(formatEta(42), '00:00:42');
  assert.equal(formatEta(3661), '01:01:01');
  assert.equal(formatEta(86400 + 3600 * 3 + 60 * 20 + 11, 'd'), '1d 03:20:11');
  assert.equal(formatEta(2 * 86400, '日'), '2日 00:00:00');
  assert.equal(formatEta(1000 * 86400, 'd'), '>999d');
  assert.equal(formatEta(-1), '-');
  assert.equal(formatEta(NaN), '-');
});

test('permille: a zero or unknown total never divides by zero', () => {
  assert.equal(permille(0, 0, 'Running'), null);
  assert.equal(permille(50, 0, 'Running'), null);
  assert.equal(permille(0, 1000, 'Running'), 0);
  assert.equal(permille(1, 3, 'Running'), 333);
  assert.equal(permille(500, 1000, 'Running'), 500);
  assert.equal(permille(2000, 1000, 'Running'), 1000); // done past total is clamped
  assert.equal(permille(0, 0, 'Complete'), 1000); // a finished transfer is always 100 %
  assert.equal(permille(NaN, 100, 'Running'), 0);
  assert.equal(permille(2 ** 53, 2 ** 53, 'Running'), 1000);
});

test('formatPermille', () => {
  assert.equal(formatPermille(null), '-');
  assert.equal(formatPermille(0), '0.0%');
  assert.equal(formatPermille(333), '33.3%');
  assert.equal(formatPermille(1000), '100.0%');
});

test('timeSplit sums to 100 and is null when nothing was measured', () => {
  assert.equal(timeSplit(0, 0, 0), null);
  assert.deepEqual(timeSplit(600, 80, 320), [60, 8, 32]);
  const [a, b, c] = timeSplit(1, 1, 1);
  assert.equal(a + b + c, 100);
  assert.deepEqual(timeSplit(5, 0, 0), [100, 0, 0]);
});

test('fill replaces every occurrence', () => {
  assert.equal(fill('{a} of {b}, {a}', { a: 1, b: 2 }), '1 of 2, 1');
  assert.equal(fill('no keys', {}), 'no keys');
});

test('names: either OS separator, the Windows verbatim prefix, and the MID fallback', () => {
  assert.equal(plainPath('\\\\?\\C:\\data\\x.bin'), 'C:\\data\\x.bin');
  assert.equal(fileNameOf('C:\\data\\x.bin'), 'x.bin');
  assert.equal(fileNameOf('/home/u/x.bin'), 'x.bin');
  assert.equal(fileNameOf('/home/u/dir/'), 'dir');
  assert.equal(titleOf({ name: '/a/b.bin', mid: 'miasma:x' }), 'b.bin');
  assert.equal(titleOf({ name: '', mid: '' }), '-');
  assert.equal(titleOf({ name: '', mid: 'miasma:short' }), 'miasma:short');
  assert.equal(titleOf({ name: '', mid: `miasma:${'x'.repeat(40)}` }), `miasma:${'x'.repeat(17)}...`);
});

test('transferId: the bridge value, else derived as the daemon does', () => {
  assert.equal(transferId({ id: 'miasma:abc', kind: 'Receive', mid: 'miasma:zzz' }), 'miasma:abc');
  assert.equal(transferId({ kind: 'Receive', mid: 'miasma:abc', name: 'x' }), 'miasma:abc');
  assert.equal(transferId({ kind: 'Send', mid: '', name: '/data/big.bin' }), 'send:/data/big.bin');
});

test('chip tones and ordering match the desktop', () => {
  assert.equal(chipTone('Running'), 'info');
  assert.equal(chipTone('Paused'), 'warning');
  assert.equal(chipTone('Complete'), 'success');
  assert.equal(chipTone('Failed'), 'danger');
  assert.equal(chipTone('Cancelled'), 'faint');
  const jobs = [
    { state: 'Complete', name: 'a' }, { state: 'Running', name: 'z' }, { state: 'Failed', name: 'b' },
    { state: 'Paused', name: 'c' }, { state: 'Cancelled', name: 'd' }, { state: 'Running', name: 'y' },
  ];
  assert.deepEqual(sortJobs(jobs).map((j) => j.name), ['y', 'z', 'c', 'b', 'd', 'a']);
  assert.equal(jobs[0].name, 'a', 'sorting must not mutate its input');
});

test('canResume: paused, stopped and failed, not running or complete', () => {
  assert.deepEqual(
    ['Running', 'Paused', 'Complete', 'Failed', 'Cancelled'].map(canResume),
    [false, true, false, true, true],
  );
});

test('buildStrip: one cell per segment, done / in flight / pending', () => {
  const s = buildStrip(6, 2, true, 0);
  assert.deepEqual(s.cells, ['done', 'done', 'inflight', 'pending', 'pending', 'pending']);
  assert.equal(s.perCell, 1);
  assert.equal(s.resumeCell, null);
  // Not running: nothing is in flight.
  assert.deepEqual(buildStrip(3, 1, false, 0).cells, ['done', 'pending', 'pending']);
  // Finished.
  assert.deepEqual(buildStrip(3, 3, false, 0).cells, ['done', 'done', 'done']);
});

test('buildStrip: resume marker only where the counters agree', () => {
  assert.equal(buildStrip(10, 6, true, 4).resumeCell, 4);
  assert.equal(buildStrip(10, 6, true, 0).resumeCell, null); // fresh
  assert.equal(buildStrip(10, 3, true, 7).resumeCell, null); // resumed past done: contradiction
});

test('buildStrip: a huge segment count is bucketed and never divides by zero', () => {
  assert.deepEqual(buildStrip(0, 0, true, 0), { cells: [], perCell: 1, resumeCell: null });
  const big = buildStrip(100_000, 50_000, true, 0);
  assert.equal(big.perCell, 250);
  assert.equal(big.cells.length, 400);
  assert.ok(big.cells.length <= MAX_STRIP_CELLS);
  assert.equal(big.cells[199], 'done');
  assert.equal(big.cells[200], 'inflight');
  assert.equal(big.cells[201], 'pending');
  // done is clamped to total, junk is zero
  assert.deepEqual(buildStrip(2, 99, true, 0).cells, ['done', 'done']);
  assert.deepEqual(buildStrip('x', 'y', true, 'z').cells, []);
  // total near u32::MAX
  const huge = buildStrip(4_294_967_295, 1, true, 0);
  assert.equal(huge.cells.length, 400);
});

test('errorKey maps the errors a person can act on', () => {
  assert.equal(errorKey('output path rejected: output path must be absolute'), 'tf_err_path');
  assert.equal(errorKey('invalid MID: bad'), 'tf_err_mid');
  assert.equal(errorKey('wrong password'), 'tf_err_wrong_password');
  assert.equal(errorKey('this transfer is password-protected; a password is required'), 'tf_err_password_required');
  assert.equal(errorKey('disk full'), '');
});
