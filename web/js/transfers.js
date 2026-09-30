// Miasma Web — the Transfers screen.
//
// Mirrors the desktop app's Transfers tab: a list (direction, name, progress bar,
// bytes, speed, ETA, state chip), a detail pane (MID, segment strip, time split,
// pieces, retries, last error, Stop / Resume) and a form to receive a file.
//
// What it does not do: start a big publish. A browser has no filesystem path to hand
// the daemon, so sending large files is the desktop app's and the CLI's job and the
// screen says so.
//
// Everything shown comes from GET /api/transfers, polled about once a second while
// the screen is open and the tab is visible (slower while a job runs elsewhere, not
// at all when there is nothing to watch). Text from the daemon (file names, errors)
// only ever goes through textContent.

import {
  formatBytes, formatRate, formatEta, permille, formatPermille, timeSplit, fill, plainPath,
  titleOf, transferId, chipTone, sortJobs, canResume, buildStrip, errorKey,
  canRemove, removeNeedsDiscard, clearable, transferIdKind,
} from './format.js';
import { parseWeakPasswordCodes } from './password_policy.js';

const POLL_VISIBLE_MS = 1000;   // screen open, tab visible
const POLL_BACKGROUND_MS = 3000; // a job runs, but the screen is not the one shown
const POLL_HIDDEN_MS = 5000;     // a job runs, tab hidden

const STATE_KEY = { Running: 'tf_st_running', Paused: 'tf_st_paused', Complete: 'tf_st_complete', Failed: 'tf_st_failed', Cancelled: 'tf_st_cancelled' };
const PHASE_KEY = {
  Preparing: 'tf_ph_preparing', Hashing: 'tf_ph_hashing', Verifying: 'tf_ph_verifying',
  Transferring: 'tf_ph_transferring', Finalizing: 'tf_ph_finalizing', Done: 'tf_ph_done',
};

const el = (id) => document.getElementById(id);

function make(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

function arrow(up) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '18');
  svg.setAttribute('height', '18');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', up ? 'M12 19V5M5 12l7-7 7 7' : 'M12 5v14M19 12l-7 7-7-7');
  svg.appendChild(path);
  return svg;
}

/**
 * @param {object} deps
 * @param {import('./bridge.js').MiasmaBridge} deps.bridge
 * @param {(key: string) => string} deps.t
 * @param {(msg: string, type?: string) => void} deps.showToast
 * @param {(text: string, msg?: string) => void} deps.copyToClipboard
 * @param {() => string} deps.authMessage  why the daemon refuses this page
 */
export function createTransfers({ bridge, t, showToast, copyToClipboard, authMessage }) {
  let jobs = [];
  let selectedId = null;
  let viewActive = false;
  let timer = null;
  let polling = false;
  let offline = false;       // the last poll failed
  let authFailed = false;
  let everLoaded = false;
  let restartArmed = false;
  let discardArmed = false;   // asking whether to discard a stopped transfer's partial data
  const rows = new Map();    // id -> row element
  let stripSignature = '';

  // ── Polling ─────────────────────────────────────────────────────

  function anyRunning() {
    return jobs.some((j) => j.state === 'Running');
  }

  function nextDelay() {
    const visible = document.visibilityState !== 'hidden';
    const running = anyRunning();
    if (visible) {
      if (viewActive) return POLL_VISIBLE_MS;
      return running ? POLL_BACKGROUND_MS : 0;
    }
    // A hidden tab is polled only to notice that a running job has ended.
    return running ? POLL_HIDDEN_MS : 0;
  }

  function schedule() {
    clearTimeout(timer);
    timer = null;
    if (!bridge || !bridge.supportsTransfers) return;
    const delay = nextDelay();
    if (delay > 0) timer = setTimeout(poll, delay);
  }

  async function poll() {
    if (polling) return;
    polling = true;
    try {
      jobs = await bridge.transfers();
      offline = false;
      authFailed = false;
      everLoaded = true;
    } catch (e) {
      offline = true;
      authFailed = !!(e && e.code === 'auth');
    } finally {
      polling = false;
    }
    render();
    schedule();
  }

  function onVisibility() {
    if (document.visibilityState === 'visible' && (viewActive || anyRunning())) poll();
    else schedule();
  }
  document.addEventListener('visibilitychange', onVisibility);

  // ── Rendering: list ─────────────────────────────────────────────

  function createRow(id) {
    const row = make('button', 'tf-row');
    row.type = 'button';
    row.setAttribute('role', 'option');
    row.dataset.id = id;
    row.append(
      make('span', 'tf-dir'),
      (() => { const n = make('span', 'tf-name'); n.append(make('span', 'tf-title'), make('span', 'tf-sub')); return n; })(),
      (() => {
        const b = make('span', 'tf-bar');
        const track = make('span', 'tf-track');
        track.appendChild(make('span', 'tf-fill'));
        b.append(track, make('span', 'tf-pct'));
        return b;
      })(),
      (() => { const m = make('span', 'tf-metabox'); m.append(make('span', 'tf-size'), make('span', 'tf-speed'), make('span', 'tf-eta')); return m; })(),
      make('span', 'chip tf-state'),
    );
    row.addEventListener('click', () => select(id));
    return row;
  }

  function progressOf(job) {
    return permille(job.bytes_done, job.bytes_total, job.state);
  }

  function setFill(fill_, pm, state) {
    fill_.style.width = pm === null ? '0%' : `${pm / 10}%`;
    fill_.dataset.tone = chipTone(state);
    fill_.classList.toggle('indeterminate', pm === null && state === 'Running');
  }

  function stateLabel(state) {
    return t(STATE_KEY[state] || 'tf_st_failed');
  }

  function updateRow(row, job) {
    const id = transferId(job);
    const send = job.kind === 'Send';
    const pm = progressOf(job);
    const tone = chipTone(job.state);
    row.setAttribute('aria-selected', id === selectedId ? 'true' : 'false');

    const dir = row.querySelector('.tf-dir');
    if (dir.dataset.kind !== job.kind) {
      dir.dataset.kind = job.kind;
      dir.replaceChildren(arrow(send));
    }
    dir.title = t(send ? 'tf_send' : 'tf_receive');
    row.querySelector('.tf-title').textContent = titleOf(job);
    row.querySelector('.tf-sub').textContent = t(send ? 'tf_send' : 'tf_receive');
    setFill(row.querySelector('.tf-fill'), pm, job.state);
    row.querySelector('.tf-pct').textContent = formatPermille(pm);
    const total = job.bytes_total > 0 ? ` / ${formatBytes(job.bytes_total)}` : '';
    row.querySelector('.tf-size').textContent = `${formatBytes(job.bytes_done)}${total}`;
    const running = job.state === 'Running';
    row.querySelector('.tf-speed').textContent = running ? formatRate(job.rate_bps) : '-';
    row.querySelector('.tf-eta').textContent = running ? formatEta(job.eta_secs, t('tf_day')) : '-';
    const chip = row.querySelector('.tf-state');
    chip.className = `chip chip-${tone} tf-state`;
    chip.textContent = stateLabel(job.state);
  }

  function renderList() {
    const list = el('tf-list');
    const order = sortJobs(jobs);
    const seen = new Set();
    order.forEach((job, index) => {
      const id = transferId(job);
      seen.add(id);
      let row = rows.get(id);
      if (!row) {
        row = createRow(id);
        rows.set(id, row);
      }
      updateRow(row, job);
      // Keep DOM order equal to sort order without recreating rows (focus survives).
      if (list.children[index] !== row) list.insertBefore(row, list.children[index] || null);
    });
    for (const [id, row] of rows) {
      if (!seen.has(id)) {
        row.remove();
        rows.delete(id);
      }
    }
    el('tf-toolbar').classList.toggle('hidden', !jobs.some(clearable));
    el('tf-empty').classList.toggle('hidden', order.length > 0 || (!everLoaded && offline));
    el('tf-headings').classList.toggle('hidden', order.length === 0);
    el('tf-list').classList.toggle('hidden', order.length === 0);
  }

  // ── Rendering: detail ───────────────────────────────────────────

  function selectedJob() {
    return jobs.find((j) => transferId(j) === selectedId) || null;
  }

  function select(id) {
    if (selectedId !== id) {
      selectedId = id;
      restartArmed = false;
      discardArmed = false;
      el('tf-d-password').value = '';
      stripSignature = '';
    }
    render();
  }

  function detailText(id, text) {
    el(id).textContent = text;
  }

  function renderStrip(job) {
    const running = job.state === 'Running';
    const strip = buildStrip(job.segments_total, job.segments_done, running, job.resumed_from_segment);
    const signature = `${strip.cells.join(',')}|${strip.resumeCell}|${job.state}`;
    const box = el('tf-d-strip');
    box.dataset.tone = job.state === 'Complete' ? 'success' : 'info';
    if (signature !== stripSignature) {
      stripSignature = signature;
      const cells = strip.cells.map((state, i) => {
        const c = make('span', `tf-cell tf-cell-${state}`);
        if (i === strip.resumeCell) c.classList.add('tf-cell-resume');
        return c;
      });
      box.replaceChildren(...cells);
    }
    const legend = el('tf-d-legend');
    legend.dataset.tone = box.dataset.tone;
    legend.replaceChildren();
    if (strip.cells.length === 0) {
      legend.textContent = t('tf_strip_unknown');
      box.setAttribute('aria-label', t('tf_strip_unknown'));
      return;
    }
    const item = (cls, label) => {
      const s = make('span', 'tf-legend-item');
      s.append(make('i', `tf-swatch tf-cell-${cls}`), document.createTextNode(label));
      return s;
    };
    legend.append(item('done', t('tf_strip_done')));
    if (running) legend.append(item('inflight', t('tf_strip_inflight')));
    legend.append(item('pending', t('tf_strip_pending')));
    if (strip.resumeCell !== null) {
      legend.append(make('span', 'tf-legend-item', fill(t('tf_strip_resumed'), { n: job.resumed_from_segment })));
    }
    if (strip.perCell > 1) {
      legend.append(make('span', 'tf-legend-item', fill(t('tf_strip_per_cell'), { n: strip.perCell })));
    }
    box.setAttribute('aria-label', `${job.segments_done} / ${job.segments_total}`);
  }

  function renderDetail() {
    const job = selectedJob();
    el('tf-select-hint').classList.toggle('hidden', !!job);
    el('tf-detail-body').classList.toggle('hidden', !job);
    if (!job) return;

    const send = job.kind === 'Send';
    const pm = progressOf(job);
    const running = job.state === 'Running';

    detailText('tf-d-title', titleOf(job));
    const chip = el('tf-d-chip');
    chip.className = `chip chip-${chipTone(job.state)}`;
    chip.textContent = stateLabel(job.state);
    detailText('tf-d-direction', t(send ? 'tf_send' : 'tf_receive') + (job.name ? ' ·' : ''));
    // A path is drawn in the monospace font: Meiryo shows a backslash as a yen sign.
    detailText('tf-d-path', job.name ? plainPath(job.name) : '');
    detailText('tf-d-mid', job.mid || '-');
    el('tf-d-copy').disabled = !job.mid;
    // The Share ID is what to give the receiver (it also lets them check who published it).
    const shareId = job.share_id || '';
    el('tf-share-row').classList.toggle('hidden', !shareId);
    detailText('tf-d-share', shareId);
    el('tf-d-share-note').classList.toggle('hidden', !(shareId && send));
    // A receive says whether the publisher was authenticated.
    const pub = el('tf-d-publisher');
    const showPub = !send && !!job.mid;
    pub.classList.toggle('hidden', !showPub);
    pub.classList.toggle('tf-warn', showPub && !job.publisher_authenticated);
    detailText('tf-d-publisher', showPub ? t(job.publisher_authenticated ? 'tf_publisher_verified' : 'tf_publisher_unverified') : '');
    // A receive over iroh says how the data travels: a public relay is much slower than a direct path.
    const pathEl = el('tf-d-path');
    const showPath = !send && (job.path === 'direct' || job.path === 'relay');
    pathEl.classList.toggle('hidden', !showPath);
    pathEl.classList.toggle('tf-warn', showPath && job.path === 'relay');
    detailText('tf-d-path', showPath ? t(job.path === 'direct' ? 'tf_path_direct' : 'tf_path_relay') : '');

    setFill(el('tf-d-fill'), pm, job.state);
    detailText('tf-d-pct', formatPermille(pm));
    detailText('tf-d-phase', t(PHASE_KEY[job.phase] || 'tf_ph_preparing'));
    detailText('tf-d-elapsed', formatEta(Math.floor(job.elapsed_secs || 0), t('tf_day')));
    detailText('tf-d-bytes', `${formatBytes(job.bytes_done)}${job.bytes_total > 0 ? ` / ${formatBytes(job.bytes_total)}` : ''}`);
    detailText('tf-d-speed', running ? formatRate(job.rate_bps) : '-');
    detailText('tf-d-eta', running ? formatEta(job.eta_secs, t('tf_day')) : '-');
    detailText('tf-d-segcount', `${job.segments_done} / ${job.segments_total}`);
    renderStrip(job);

    detailText('tf-d-resumed', job.resumed_from_segment > 0 ? String(job.resumed_from_segment) : t('tf_resumed_fresh'));
    const split = timeSplit(job.fetch_ms, job.decode_ms, job.write_ms);
    detailText('tf-d-split', split ? fill(t(send ? 'tf_split_send' : 'tf_split_recv'), { a: split[0], b: split[1], c: split[2] }) : '-');
    detailText('tf-d-pieces', fill(t('tf_pieces_fmt'), { ok: job.pieces_fetched || 0, bad: job.pieces_rejected || 0 }));
    detailText('tf-d-retries', String(job.segment_retries || 0));

    const err = job.last_error;
    el('tf-d-error').classList.toggle('hidden', !err);
    if (err) {
      const key = errorKey(err);
      detailText('tf-d-error-text', key ? t(key) : weakPasswordText(err) || err);
    }

    // Actions.
    el('tf-d-stop').classList.toggle('hidden', !running);
    const resumable = !send && canResume(job.state) && !!job.name;
    el('tf-d-resume').classList.toggle('hidden', !resumable);
    el('tf-d-send-hint').classList.toggle('hidden', !(send && canResume(job.state)));
    el('tf-d-nopath').classList.toggle('hidden', send || !canResume(job.state) || !!job.name);
    el('tf-d-restart-confirm').classList.toggle('hidden', !restartArmed);
    el('tf-d-restart-btn').classList.toggle('hidden', restartArmed);

    // Removing a finished transfer: neutral buttons, and a line saying what is not deleted.
    const removable = canRemove(job);
    el('tf-d-remove').classList.toggle('hidden', !removable);
    if (removable) {
      const needsDiscard = removeNeedsDiscard(job);
      let note = 'tf_remove_note_plain';
      if (needsDiscard) note = 'tf_remove_note_partial';
      else if (job.state === 'Complete') note = send ? 'tf_remove_note_send' : 'tf_remove_note_recv';
      detailText('tf-d-remove-note', t(note));
      el('tf-d-discard-confirm').classList.toggle('hidden', !discardArmed);
      el('tf-d-remove-btn').classList.toggle('hidden', discardArmed);
    }
  }

  // ── Rendering: the whole screen ─────────────────────────────────

  function render() {
    const connected = !!(bridge && bridge.supportsTransfers && bridge.connected);
    const notice = el('tf-offline');
    let message = '';
    if (!bridge || !bridge.supportsTransfers) message = t('tf_offline_note');
    else if (authFailed) message = authMessage();
    else if (offline || !bridge.connected) message = everLoaded ? `${t('tf_offline_note')} ${t('tf_stale_note')}` : t('tf_offline_note');
    notice.textContent = message;
    notice.classList.toggle('hidden', !message);

    el('tf-forms-offline').classList.toggle('hidden', connected && !offline);
    for (const id of ['tf-mid', 'tf-path', 'tf-pw', 'tf-via', 'tf-start']) el(id).disabled = !connected;
    el('tf-clear').disabled = !connected;
    el('tf-clear').title = t('tf_clear_finished_hint');
    el('tf-d-remove-btn').disabled = !connected;

    renderList();
    renderDetail();
  }

  // ── Actions ─────────────────────────────────────────────────────

  // The daemon's refusal of a weak publish password (`weak password: too_short,no_symbol`),
  // in the page language. A transfer started from the CLI or desktop app can fail this way
  // and show up in the list. Receiving never checks the policy.
  function weakPasswordText(message) {
    const codes = parseWeakPasswordCodes(message);
    if (!codes) return '';
    const reasons = codes.map((c) => t('tf_pw_' + c)).join(t('tf_pw_sep'));
    return `${t('tf_pw_weak_prefix')} ${reasons}. ${t('tf_pw_hint')}`;
  }

  function explain(e) {
    if (e && e.code === 'auth') return authMessage();
    const key = errorKey(e && e.message);
    return key ? t(key) : weakPasswordText(e && e.message) || (e && e.message) || String(e);
  }

  async function stop() {
    const job = selectedJob();
    if (!job) return;
    try {
      await bridge.transferCancel(transferId(job));
      showToast(t('tf_stop_requested'), 'success');
    } catch (e) {
      showToast(explain(e), 'error');
    }
    poll();
  }

  /** Take the selected finished transfer off the list (and its partial data, if asked). */
  async function removeSelected(discardPartial) {
    const job = selectedJob();
    if (!job || !canRemove(job)) return;
    const id = transferId(job);
    try {
      await bridge.transferRemove(id, discardPartial);
      showToast(t('tf_removed'), 'success');
      // Gone from this page at once; the daemon's next list is what stays.
      jobs = jobs.filter((j) => transferId(j) !== id);
      selectedId = null;
      discardArmed = false;
    } catch (e) {
      // It holds partial data the list did not know about: ask before discarding.
      if (e && e.code === 'http' && /discard_partial/.test(e.message || '')) {
        discardArmed = true;
      } else {
        showToast(explain(e), 'error');
      }
    }
    render();
    poll();
  }

  async function clearFinished() {
    try {
      await bridge.transferClearFinished();
      showToast(t('tf_cleared'), 'success');
      jobs = jobs.filter((j) => !clearable(j));
    } catch (e) {
      showToast(explain(e), 'error');
    }
    render();
    poll();
  }

  // Ids started with a via URL in this page, so Resume goes to the same endpoint (the
  // daemon's journal does not record it).
  const viaById = new Map();

  async function startReceive({ mid, outputPath, password, restart, via }) {
    try {
      const id = await bridge.transferReceive({ mid, outputPath, password, restart, via });
      if (via && via.length) viaById.set(id, via);
      showToast(t('tf_started'), 'success');
      selectedId = id;
      stripSignature = '';
      await poll();
      return true;
    } catch (e) {
      showToast(explain(e), 'error');
      return false;
    }
  }

  async function resume(restart) {
    const job = selectedJob();
    if (!job || job.kind === 'Send' || !job.name) return;
    const pwInput = el('tf-d-password');
    const password = pwInput.value;
    const via = viaById.get(job.mid);
    // The share ID it was started from, so a resume keeps verifying the publisher.
    const ok = await startReceive({ mid: job.share_id || job.mid, outputPath: plainPath(job.name), password, restart, via });
    if (ok) {
      pwInput.value = '';
      restartArmed = false;
      render();
    }
  }

  async function submitForm() {
    const mid = el('tf-mid').value.trim();
    const path = el('tf-path').value.trim();
    const pw = el('tf-pw');
    if (!transferIdKind(mid)) { showToast(t('tf_err_mid'), 'error'); return; }
    if (!path) { showToast(t('tf_err_no_path'), 'error'); return; }
    const viaUrl = el('tf-via').value.trim();
    const button = el('tf-start');
    button.disabled = true;
    const ok = await startReceive({
      mid, outputPath: path, password: pw.value, restart: false,
      via: viaUrl ? [viaUrl] : undefined,
    });
    if (ok) {
      // The password is never kept around; the rest is on screen in the list now.
      pw.value = '';
      el('tf-mid').value = '';
      el('tf-path').value = '';
      el('tf-via').value = '';
    }
    button.disabled = !(bridge && bridge.connected);
  }

  // ── Wiring ──────────────────────────────────────────────────────

  el('tf-d-stop').addEventListener('click', stop);
  el('tf-d-copy').addEventListener('click', () => {
    const job = selectedJob();
    if (job && job.mid) copyToClipboard(job.mid, t('copied'));
  });
  el('tf-d-share-copy').addEventListener('click', () => {
    const job = selectedJob();
    if (job && job.share_id) copyToClipboard(job.share_id, t('copied'));
  });
  el('tf-d-resume-btn').addEventListener('click', () => resume(false));
  el('tf-d-restart-btn').addEventListener('click', () => { restartArmed = true; renderDetail(); });
  el('tf-d-restart-no').addEventListener('click', () => { restartArmed = false; renderDetail(); });
  el('tf-d-restart-yes').addEventListener('click', () => resume(true));
  el('tf-d-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') resume(false); });
  el('tf-d-remove-btn').addEventListener('click', () => {
    const job = selectedJob();
    if (job && removeNeedsDiscard(job)) { discardArmed = true; renderDetail(); } else removeSelected(false);
  });
  el('tf-d-discard-yes').addEventListener('click', () => removeSelected(true));
  el('tf-d-discard-no').addEventListener('click', () => { discardArmed = false; renderDetail(); });
  el('tf-clear').addEventListener('click', clearFinished);
  el('tf-start').addEventListener('click', submitForm);
  for (const id of ['tf-mid', 'tf-path', 'tf-pw', 'tf-via']) {
    el(id).addEventListener('keydown', (e) => { if (e.key === 'Enter') submitForm(); });
  }

  return {
    /** The screen was opened. */
    show() {
      viewActive = true;
      render();
      poll();
    },
    /** The screen was left; polling continues only while a job runs. */
    hide() {
      viewActive = false;
      schedule();
    },
    /** Text set from code has to be redrawn after a language change. */
    refresh() { stripSignature = ''; render(); },
    /** For tests and diagnostics. */
    get jobs() { return jobs; },
  };
}
