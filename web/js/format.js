// Miasma Web — pure helpers for the Transfers screen.
//
// No DOM, no network: every function here is a port of the desktop app's
// (crates/miasma-desktop/src/transfers.rs) and is tested with `node --test`
// (web/tests/format.test.mjs). The daemon's sizes are u64: they arrive as JSON
// numbers, which are exact up to 2^53 (8 PiB); above that they are rounded by
// JSON.parse before we see them, so nothing here may assume more than a finite,
// non-negative number, and nothing divides by a size or a rate that can be zero.

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];

function toBigInt(n) {
  if (typeof n === 'bigint') return n < 0n ? 0n : n;
  if (typeof n !== 'number' || !Number.isFinite(n) || n <= 0) return 0n;
  return BigInt(Math.trunc(n));
}

/** `1536` -> `1.5 KiB`. Integer arithmetic (BigInt), the fraction truncated to one decimal. */
export function formatBytes(bytes) {
  const b = toBigInt(bytes);
  if (b < 1024n) return `${b} B`;
  let idx = 1;
  let shift = 10n;
  while (idx < UNITS.length - 1 && (b >> (shift + 10n)) > 0n) {
    idx += 1;
    shift += 10n;
  }
  const tenths = (b * 10n) >> shift;
  return `${tenths / 10n}.${tenths % 10n} ${UNITS[idx]}`;
}

/** Bytes per second as text, or `-` when the rate is zero, negative or not a number. */
export function formatRate(bps) {
  if (typeof bps !== 'number' || !Number.isFinite(bps) || bps < 1) return '-';
  return `${formatBytes(bps)}/s`;
}

/** `hh:mm:ss`, or `Nd hh:mm:ss` from a day up (`day` is the locale's suffix). null is `-`. */
export function formatEta(secs, day = 'd') {
  if (secs === null || secs === undefined || typeof secs !== 'number' || !Number.isFinite(secs) || secs < 0) return '-';
  const s = Math.floor(secs);
  const days = Math.floor(s / 86400);
  if (days > 999) return `>999${day}`;
  const pad = (v) => String(v).padStart(2, '0');
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return days > 0 ? `${days}${day} ${pad(h)}:${pad(m)}:${pad(sec)}` : `${pad(h)}:${pad(m)}:${pad(sec)}`;
}

/**
 * Progress in tenths of a percent (0..=1000), or null when the total is unknown
 * (a legacy record has bytes_total 0). A finished transfer is always 100 %.
 */
export function permille(done, total, state) {
  if (state === 'Complete') return 1000;
  const t = toBigInt(total);
  if (t === 0n) return null;
  let d = toBigInt(done);
  if (d > t) d = t;
  return Number((d * 1000n) / t);
}

export function formatPermille(p) {
  if (p === null || p === undefined) return '-';
  return `${Math.floor(p / 10)}.${p % 10}%`;
}

/** Integer share of the three phase times, summing to 100, or null when nothing is measured. */
export function timeSplit(fetchMs, decodeMs, writeMs) {
  const f = toBigInt(fetchMs);
  const d = toBigInt(decodeMs);
  const w = toBigInt(writeMs);
  const total = f + d + w;
  if (total === 0n) return null;
  const a = Number((f * 100n) / total);
  const b = Number((d * 100n) / total);
  return [a, b, 100 - a - b];
}

/** Replace `{key}` placeholders in a locale template. */
export function fill(template, pairs) {
  let out = String(template);
  for (const [k, v] of Object.entries(pairs)) out = out.split(`{${k}}`).join(String(v));
  return out;
}

/** A path without the Windows `\\?\` prefix that `canonicalize` adds. */
export function plainPath(path) {
  return typeof path === 'string' && path.startsWith('\\\\?\\') ? path.slice(4) : String(path || '');
}

/** Last component of a path from either OS (the daemon may run on the other one). */
export function fileNameOf(path) {
  const p = plainPath(path);
  const parts = p.split(/[\\/]/).filter((s) => s.length > 0);
  return parts.length ? parts[parts.length - 1] : p;
}

/** What to call a transfer in the list: its file name, or the start of its MID. */
export function titleOf(job) {
  if (job.name) return fileNameOf(job.name);
  const mid = job.mid || '';
  if (!mid) return '-';
  const chars = Array.from(mid);
  return chars.length <= 24 ? mid : `${chars.slice(0, 24).join('')}...`;
}

/** The id the daemon knows a transfer by: the bridge reports it; otherwise derive it as the daemon does. */
export function transferId(job) {
  if (job.id) return job.id;
  return job.kind === 'Send' ? `send:${job.name}` : job.mid;
}

/** running = info, paused = warning, complete = success, failed = danger, cancelled = faint. */
export function chipTone(state) {
  switch (state) {
    case 'Running': return 'info';
    case 'Paused': return 'warning';
    case 'Complete': return 'success';
    case 'Failed': return 'danger';
    default: return 'faint';
  }
}

const RANK = { Running: 0, Paused: 1, Failed: 2, Cancelled: 3, Complete: 4 };

/** List order: running first, then what needs attention, then finished ones. */
export function sortJobs(jobs) {
  const rank = (j) => (j.state in RANK ? RANK[j.state] : 5);
  return [...jobs].sort((a, b) =>
    rank(a) - rank(b)
    || String(a.name || '').localeCompare(String(b.name || ''))
    || String(a.mid || '').localeCompare(String(b.mid || '')));
}

/**
 * Something stopped can be started again with the same request (the journal is what
 * resumes it). A failed one is offered too: a wrong password fails the job, and typing
 * it again is the fix.
 */
export function canResume(state) {
  return state === 'Paused' || state === 'Cancelled' || state === 'Failed';
}

/** Complete, Failed or Cancelled: nothing more will happen to it on its own. */
export function isFinished(state) {
  return state === 'Complete' || state === 'Failed' || state === 'Cancelled';
}

/**
 * A finished transfer can be taken off the list. A running one cannot, and neither can a
 * paused one: it keeps its journal so it can resume ("Start over" is the other action).
 */
export function canRemove(job) {
  return !!job && isFinished(job.state);
}

/** Removing it would throw away partial data (a stopped transfer that can still resume). */
export function removeNeedsDiscard(job) {
  return !!job && isFinished(job.state) && !!job.resumable;
}

/** Finished rows that "Clear finished" removes without losing anything. */
export function clearable(job) {
  return !!job && isFinished(job.state) && !job.resumable;
}

/** Above this many segments several are drawn as one cell, so the strip stays legible. */
export const MAX_STRIP_CELLS = 400;

/**
 * One cell per segment, or per bucket of `perCell` segments. A cell is done only when
 * every segment in it is; the cell holding the segment being worked on (`done`) is in
 * flight while the transfer runs and pending otherwise. `resumeCell` is the cell holding
 * the first segment this session had to fetch, when that is not the start.
 */
export function buildStrip(total, done, running, resumedFrom) {
  total = Math.max(0, Math.floor(Number(total) || 0));
  if (total === 0) return { cells: [], perCell: 1, resumeCell: null };
  done = Math.min(Math.max(0, Math.floor(Number(done) || 0)), total);
  const perCell = Math.max(1, Math.ceil(total / MAX_STRIP_CELLS));
  const count = Math.ceil(total / perCell);
  const cells = [];
  for (let i = 0; i < count; i++) {
    const start = i * perCell;
    const end = Math.min((i + 1) * perCell, total);
    if (end <= done) cells.push('done');
    else if (running && done >= start && done < end) cells.push('inflight');
    else cells.push('pending');
  }
  // A resume position beyond what is done would contradict the counters: not drawn.
  resumedFrom = Math.floor(Number(resumedFrom) || 0);
  const resumeCell = resumedFrom > 0 && resumedFrom <= done ? Math.min(Math.floor(resumedFrom / perCell), count - 1) : null;
  return { cells, perCell, resumeCell };
}

/** Map an error string from the bridge to a locale key, when it is one a person can act on. */
export function errorKey(message) {
  const m = String(message || '');
  if (m.startsWith('output path rejected') && m.includes('is a folder, not a file')) return 'tf_err_path_folder';
  // An unwritable place: the daemon names the path and the OS error, which is the useful text.
  if (m.startsWith('output path rejected') && /cannot |no file name|not a folder/.test(m)) return '';
  if (m.startsWith('output path rejected')) return 'tf_err_path';
  if (m.includes('transfer is still running')) return 'tf_err_remove_running';
  if (m.includes('transfer is paused')) return 'tf_err_remove_paused';
  if (m.startsWith('invalid MID')) return 'tf_err_mid';
  if (m.includes('wrong password')) return 'tf_err_wrong_password';
  if (m.includes('a password is required') || m.includes('password-protected')) return 'tf_err_password_required';
  return '';
}
