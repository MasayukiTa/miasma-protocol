// Miasma Web — Main Application

import { t, getLang, setLang, applyTranslations } from './i18n.js';
import { initDB, saveShares, getSharesByMidPrefix, getShareCount, getMidCount, getStorageEstimate, clearAll } from './storage.js';
import { MiasmaBridge } from './bridge.js';

let wasm = null;
let bridge = null;
let currentView = 'loading';
let dissolveResult = null;
let retrieveShares = [];
let selectedFile = null;

// ── Feature Detection ─────────────────────────────────────────────

function checkBrowserSupport() {
  const missing = [];
  if (typeof WebAssembly === 'undefined') missing.push('WebAssembly');
  if (typeof indexedDB === 'undefined') missing.push('IndexedDB');
  if (!window.crypto || !window.crypto.getRandomValues) missing.push('crypto.getRandomValues');
  if (typeof BigInt === 'undefined') missing.push('BigInt');
  return missing;
}

// ── Init ──────────────────────────────────────────────────────────

async function init() {
  // Feature detection first
  const missing = checkBrowserSupport();
  if (missing.length > 0) {
    const container = document.querySelector('.loading-container');
    container.querySelector('.loading-spinner')?.remove();
    const el = container.querySelector('p');
    el.innerHTML = `<strong>Browser not supported</strong><br>` +
      `Missing features: ${missing.join(', ')}<br><br>` +
      `Miasma Web requires a modern browser with WebAssembly support.<br>` +
      `Recommended: Chrome 89+, Firefox 89+, Edge 89+, Safari 15+`;
    el.style.color = 'var(--danger)';
    el.style.textAlign = 'center';
    el.style.lineHeight = '1.6';
    return;
  }

  try {
    const module = await import('../pkg/miasma_wasm.js');
    await module.default();
    wasm = module;
    await initDB();

    // Initialize bridge (detects WebView / HTTP / local-only)
    bridge = new MiasmaBridge();
    await bridge.init(wasm);
    bridge.onStateChange = onBridgeStateChange;

    showView('home');
    setupEventListeners();
    applyTranslations();
    updateStats();
    updateConnectionUI();
    const vi = document.getElementById('version-info');
    if (vi) vi.textContent = wasm.protocol_version();
    showInstallBanner();
  } catch (e) {
    console.error('Init failed:', e);
    document.querySelector('.loading-container p').textContent =
      'Failed to load: ' + e.message;
  }
}

// ── View Navigation ───────────────────────────────────────────────

function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const view = document.getElementById('view-' + name);
  if (view) {
    view.classList.add('active');
    currentView = name;
  }
  if (name === 'home') updateStats();
  if (name === 'settings') updateSettingsView();
  if (name === 'dissolve') {
    // Reset dissolve state
    document.getElementById('dissolve-result').classList.add('hidden');
    document.getElementById('dissolve-progress').classList.add('hidden');
  }
  if (name === 'retrieve') {
    // Reset retrieve state
    document.getElementById('retrieve-result').classList.add('hidden');
  }
  if (name === 'send') {
    loadSendContactInfo();
    document.getElementById('send-result').classList.add('hidden');
  }
  if (name === 'inbox') {
    refreshInbox();
  }
  if (name === 'outbox') {
    refreshOutbox();
  }
}

// ── Event Listeners ───────────────────────────────────────────────

function setupEventListeners() {
  // Navigation
  document.querySelectorAll('[data-view]').forEach(el => {
    el.addEventListener('click', () => showView(el.dataset.view));
  });

  // Language
  document.getElementById('btn-lang').addEventListener('click', () => {
    const cycle = { en: 'ja', ja: 'zh', zh: 'en' };
    setLang(cycle[getLang()] || 'en');
  });
  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', () => setLang(btn.dataset.lang));
  });

  // Input mode toggle
  document.getElementById('btn-text-mode').addEventListener('click', () => {
    setInputMode('text');
  });
  document.getElementById('btn-file-mode').addEventListener('click', () => {
    setInputMode('file');
  });

  // Text input byte count
  document.getElementById('dissolve-text').addEventListener('input', (e) => {
    const bytes = new TextEncoder().encode(e.target.value).length;
    document.getElementById('text-byte-count').textContent = formatBytes(bytes);
  });

  // File input
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) handleFileSelect(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) handleFileSelect(e.target.files[0]);
  });
  document.getElementById('btn-clear-file').addEventListener('click', clearFileSelection);

  // Dissolve
  document.getElementById('btn-dissolve').addEventListener('click', handleDissolve);

  // Result actions
  document.getElementById('btn-copy-mid').addEventListener('click', () => {
    if (dissolveResult) copyToClipboard(dissolveResult.mid, t('copied'));
  });
  document.getElementById('btn-save-shares').addEventListener('click', handleSaveShares);
  document.getElementById('btn-export-shares').addEventListener('click', handleExportShares);

  // Retrieve
  document.getElementById('retrieve-mid').addEventListener('input', handleMidInput);
  document.getElementById('btn-import-file').addEventListener('click', () => {
    document.getElementById('import-file-input').click();
  });
  document.getElementById('import-file-input').addEventListener('change', handleImportFile);
  document.getElementById('btn-import-paste').addEventListener('click', () => {
    document.getElementById('paste-modal').classList.remove('hidden');
  });
  document.getElementById('btn-paste-cancel').addEventListener('click', () => {
    document.getElementById('paste-modal').classList.add('hidden');
  });
  document.getElementById('btn-paste-confirm').addEventListener('click', handlePasteImport);
  document.getElementById('btn-retrieve').addEventListener('click', handleRetrieve);
  document.getElementById('btn-copy-text').addEventListener('click', () => {
    const text = document.getElementById('retrieve-text-content').textContent;
    copyToClipboard(text, t('copied'));
  });

  // Directed Send
  document.getElementById('btn-directed-send').addEventListener('click', handleDirectedSend);

  // Inbox
  document.getElementById('btn-inbox-refresh').addEventListener('click', refreshInbox);

  // Outbox
  document.getElementById('btn-outbox-refresh').addEventListener('click', refreshOutbox);

  // Settings
  document.getElementById('btn-clear-all').addEventListener('click', handleClearAll);

  // Install banner dismiss
  const installBanner = document.getElementById('install-banner');
  if (installBanner) {
    document.getElementById('btn-dismiss-install')?.addEventListener('click', () => {
      installBanner.classList.add('hidden');
      localStorage.setItem('miasma-install-dismissed', '1');
    });
  }
}

// ── Input Mode ────────────────────────────────────────────────────

function setInputMode(mode) {
  const textBtn = document.getElementById('btn-text-mode');
  const fileBtn = document.getElementById('btn-file-mode');
  const textArea = document.getElementById('text-input-area');
  const fileArea = document.getElementById('file-input-area');

  if (mode === 'text') {
    textBtn.classList.add('active');
    fileBtn.classList.remove('active');
    textArea.classList.remove('hidden');
    fileArea.classList.add('hidden');
  } else {
    fileBtn.classList.add('active');
    textBtn.classList.remove('active');
    fileArea.classList.remove('hidden');
    textArea.classList.add('hidden');
  }
}

function handleFileSelect(file) {
  // Check size limit (~100MB practical limit for in-memory WASM)
  if (file.size > 100 * 1024 * 1024) {
    showToast(t('error_file_too_large'), 'error');
    return;
  }
  selectedFile = file;
  document.getElementById('file-info').classList.remove('hidden');
  document.getElementById('file-name').textContent = file.name;
  document.getElementById('file-size').textContent = formatBytes(file.size);
  document.getElementById('drop-zone').classList.add('hidden');
}

function clearFileSelection() {
  selectedFile = null;
  document.getElementById('file-info').classList.add('hidden');
  document.getElementById('drop-zone').classList.remove('hidden');
  document.getElementById('file-input').value = '';
}

// ── Dissolve ──────────────────────────────────────────────────────

async function handleDissolve() {
  const k = parseInt(document.getElementById('param-k').value);
  const n = parseInt(document.getElementById('param-n').value);

  if (Number.isNaN(k) || Number.isNaN(n) || k >= n || k < 2 || n < 3 || k > 255 || n > 255) {
    showToast(t('error_invalid_params'), 'error');
    return;
  }

  let data;
  const isTextMode = document.getElementById('btn-text-mode').classList.contains('active');

  if (isTextMode) {
    const text = document.getElementById('dissolve-text').value;
    if (!text.trim()) {
      showToast(t('error_no_input'), 'error');
      return;
    }
    data = { type: 'text', content: text };
  } else {
    if (!selectedFile) {
      showToast(t('error_no_input'), 'error');
      return;
    }
    const buf = await selectedFile.arrayBuffer();
    data = { type: 'bytes', content: new Uint8Array(buf) };
  }

  const btn = document.getElementById('btn-dissolve');
  const progress = document.getElementById('dissolve-progress');
  const result = document.getElementById('dissolve-result');

  btn.disabled = true;
  btn.classList.add('dissolving');
  progress.classList.remove('hidden');
  result.classList.add('hidden');

  // Start dissolve particle animation
  startDissolveAnimation();

  // Allow UI to update before heavy WASM computation
  await new Promise(r => setTimeout(r, 50));

  try {
    const inputData = data.type === 'text' ? data.content : data.content;
    const bridgeResult = await bridge.dissolve(inputData, k, n);

    dissolveResult = bridgeResult;

    // Show result
    document.getElementById('result-mid').textContent = bridgeResult.mid;

    if (bridgeResult.networkPublished) {
      // Connected mode: published to network
      document.getElementById('result-share-count').textContent =
        t('published_to_network') + ` (k=${k}, n=${n})`;
      document.getElementById('result-share-size').textContent = '';
      // Hide local save/export buttons when published to network
      document.getElementById('btn-save-shares').style.display = 'none';
      document.getElementById('btn-export-shares').style.display = 'none';
    } else {
      // Local mode: show share details
      document.getElementById('result-share-count').textContent =
        `${bridgeResult.shares.length} shares (k=${k}, n=${n})`;
      const totalSize = JSON.stringify(bridgeResult.shares).length;
      document.getElementById('result-share-size').textContent = formatBytes(totalSize);
      document.getElementById('btn-save-shares').style.display = '';
      document.getElementById('btn-export-shares').style.display = '';
    }

    progress.classList.add('hidden');
    result.classList.remove('hidden');

    // Success pulse on result
    result.style.animation = 'none';
    result.offsetHeight;
    result.style.animation = '';
  } catch (e) {
    console.error('Dissolve failed:', e);
    showToast(t('error_dissolve_failed'), 'error');
    progress.classList.add('hidden');
  } finally {
    btn.disabled = false;
    btn.classList.remove('dissolving');
    stopDissolveAnimation();
  }
}

// ── Dissolve Animation ────────────────────────────────────────────

let animationContainer = null;
let animationFrame = null;

function startDissolveAnimation() {
  if (animationContainer) stopDissolveAnimation();

  animationContainer = document.createElement('div');
  animationContainer.className = 'dissolve-particles';
  document.getElementById('view-dissolve').appendChild(animationContainer);

  const particles = 24;
  for (let i = 0; i < particles; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    const angle = (i / particles) * Math.PI * 2;
    const delay = (i / particles) * 1.5;
    const distance = 40 + Math.random() * 80;
    p.style.setProperty('--angle', angle + 'rad');
    p.style.setProperty('--distance', distance + 'px');
    p.style.setProperty('--delay', delay + 's');
    p.style.setProperty('--size', (2 + Math.random() * 4) + 'px');
    animationContainer.appendChild(p);
  }
}

function stopDissolveAnimation() {
  if (animationContainer) {
    animationContainer.remove();
    animationContainer = null;
  }
  if (animationFrame) {
    cancelAnimationFrame(animationFrame);
    animationFrame = null;
  }
}

// ── Save / Export ─────────────────────────────────────────────────

async function handleSaveShares() {
  if (!dissolveResult) return;
  const btn = document.getElementById('btn-save-shares');
  btn.disabled = true;
  try {
    const k = parseInt(document.getElementById('param-k').value);
    const n = parseInt(document.getElementById('param-n').value);
    await saveShares(dissolveResult.mid, dissolveResult.shares, { k, n });
    showToast(t('saved'), 'success');
    btn.textContent = '\u2713 ' + t('saved');
    updateStats();
  } catch (e) {
    showToast('Error: ' + e.message, 'error');
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = t('save_locally');
      applyTranslations();
    }, 2000);
  }
}

function handleExportShares() {
  if (!dissolveResult) return;
  const exportData = {
    version: 1,
    mid: dissolveResult.mid,
    data_shards: dissolveResult.data_shards,
    total_shards: dissolveResult.total_shards,
    shares: dissolveResult.shares,
    exported_at: new Date().toISOString(),
  };
  const json = JSON.stringify(exportData, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const midShort = dissolveResult.mid.slice(7, 19);
  a.download = `miasma-${midShort}.miasma`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(t('exported'), 'success');
}

// ── Retrieve ──────────────────────────────────────────────────────

async function handleMidInput() {
  const midStr = document.getElementById('retrieve-mid').value.trim();
  retrieveShares = [];
  document.getElementById('local-share-count').textContent = '0';
  document.getElementById('import-share-count').textContent = '0';
  document.getElementById('retrieve-result').classList.add('hidden');

  if (!midStr.startsWith('miasma:')) {
    updateShareProgress();
    return;
  }

  // Search local shares
  try {
    const b58part = midStr.slice(7);
    const digestBytes = decodeBase58(b58part);
    if (digestBytes && digestBytes.length >= 8) {
      const prefix = Array.from(digestBytes.slice(0, 8))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      const localShares = await getSharesByMidPrefix(prefix);
      if (localShares.length > 0) {
        retrieveShares = localShares.map(s => s.data);
        document.getElementById('local-share-count').textContent = localShares.length.toString();
      }
    }
  } catch (_) { /* ignore parse errors during typing */ }

  updateShareProgress();
}

function updateShareProgress() {
  const k = parseInt(document.getElementById('retrieve-k').value);
  const total = retrieveShares.length;
  const isConnected = bridge && bridge.connected;
  const pct = Math.min(100, (total / k) * 100);

  document.getElementById('share-progress-text').textContent = `${total} / ${k}`;
  document.getElementById('share-progress-fill').style.width = pct + '%';

  const btn = document.getElementById('btn-retrieve');

  if (isConnected) {
    // In connected mode, retrieve button is always enabled when MID is entered
    const midStr = document.getElementById('retrieve-mid').value.trim();
    btn.disabled = !midStr.startsWith('miasma:');
    if (!btn.disabled) btn.classList.add('ready');
    else btn.classList.remove('ready');
  } else {
    btn.disabled = total < k;
    if (total >= k) {
      btn.classList.add('ready');
    } else {
      btn.classList.remove('ready');
    }
  }
}

async function handleImportFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    let shares;
    if (Array.isArray(data)) {
      shares = data;
    } else if (data.shares && Array.isArray(data.shares)) {
      shares = data.shares;
      // Auto-fill MID and params if present
      if (data.mid) {
        document.getElementById('retrieve-mid').value = data.mid;
        // Trigger local share search
        await handleMidInput();
      }
      if (data.data_shards) document.getElementById('retrieve-k').value = data.data_shards;
      if (data.total_shards) document.getElementById('retrieve-n').value = data.total_shards;
    } else {
      throw new Error('Invalid share file format');
    }
    addImportedShares(shares);
  } catch (err) {
    console.error('Import failed:', err);
    showToast(t('error_import_failed'), 'error');
  }
  e.target.value = '';
}

function handlePasteImport() {
  const text = document.getElementById('paste-textarea').value.trim();
  try {
    const data = JSON.parse(text);
    let shares;
    if (Array.isArray(data)) {
      shares = data;
    } else if (data.shares) {
      shares = data.shares;
      // Auto-fill MID and params
      if (data.mid) {
        document.getElementById('retrieve-mid').value = data.mid;
      }
      if (data.data_shards) document.getElementById('retrieve-k').value = data.data_shards;
      if (data.total_shards) document.getElementById('retrieve-n').value = data.total_shards;
    } else {
      shares = [];
    }
    addImportedShares(shares);
    document.getElementById('paste-modal').classList.add('hidden');
    document.getElementById('paste-textarea').value = '';
  } catch (err) {
    console.error('Paste parse failed:', err);
    showToast(t('error_parse_failed'), 'error');
  }
}

function sanitizeShare(s) {
  // Only keep known share fields — strips __proto__, constructor, etc.
  if (typeof s !== 'object' || s === null) return null;
  if (typeof s.slot_index !== 'number') return null;
  return {
    version: s.version,
    mid_prefix: s.mid_prefix,
    segment_index: s.segment_index,
    slot_index: s.slot_index,
    shard_data: s.shard_data,
    key_share: s.key_share,
    shard_hash: s.shard_hash,
    nonce: s.nonce,
    original_len: s.original_len,
    timestamp: s.timestamp,
    bincode: s.bincode || '',
  };
}

function addImportedShares(shares) {
  const existing = new Set(retrieveShares.map(s => s.slot_index));
  let added = 0;
  for (const raw of shares) {
    const s = sanitizeShare(raw);
    if (!s) continue;
    if (!existing.has(s.slot_index)) {
      retrieveShares.push(s);
      existing.add(s.slot_index);
      added++;
    }
  }
  const importCount = document.getElementById('import-share-count');
  importCount.textContent = (parseInt(importCount.textContent) + added).toString();
  showToast(`${added} ${t('imported')}`, 'success');
  updateShareProgress();
}

async function handleRetrieve() {
  const midStr = document.getElementById('retrieve-mid').value.trim();
  const k = parseInt(document.getElementById('retrieve-k').value);
  const n = parseInt(document.getElementById('retrieve-n').value);

  if (!midStr) {
    showToast(t('error_no_mid'), 'error');
    return;
  }
  if (!midStr.startsWith('miasma:')) {
    showToast(t('error_invalid_mid_format'), 'error');
    return;
  }

  const isConnected = bridge && bridge.connected;

  // In local mode, require manual shares
  if (!isConnected && retrieveShares.length < k) {
    showToast(`${t('error_insufficient')}: ${retrieveShares.length}/${k}`, 'error');
    return;
  }

  const btn = document.getElementById('btn-retrieve');
  btn.disabled = true;
  btn.textContent = t('processing');

  await new Promise(r => setTimeout(r, 50));

  try {
    let bytes;

    if (isConnected) {
      // Connected mode: retrieve from P2P network via daemon
      bytes = await bridge.retrieve(midStr, k, n);
    } else {
      // Local mode: reconstruct from manually collected shares
      const sharesJson = JSON.stringify(retrieveShares);
      bytes = wasm.retrieve_from_shares(midStr, sharesJson, k, n);
    }

    const resultSection = document.getElementById('retrieve-result');
    const textResult = document.getElementById('retrieve-text-result');
    const binaryResult = document.getElementById('retrieve-binary-result');

    resultSection.classList.remove('hidden');

    if (isLikelyText(bytes)) {
      const text = new TextDecoder().decode(bytes);
      document.getElementById('retrieve-text-content').textContent = text;
      textResult.classList.remove('hidden');
      binaryResult.classList.add('hidden');
    } else {
      document.getElementById('retrieve-binary-size').textContent = formatBytes(bytes.length);
      textResult.classList.add('hidden');
      binaryResult.classList.remove('hidden');

      document.getElementById('btn-download').onclick = () => {
        const blob = new Blob([bytes]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'miasma-retrieved';
        a.click();
        URL.revokeObjectURL(url);
      };
    }

    // Scroll to result
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e) {
    console.error('Retrieve failed:', e);
    showToast(t('error_retrieve'), 'error');
  } finally {
    btn.disabled = !isConnected && retrieveShares.length < k;
    applyTranslations();
  }
}

// ── Directed Send ─────────────────────────────────────────────────

async function loadSendContactInfo() {
  const el = document.getElementById('send-my-contact');
  const infoSection = document.getElementById('send-contact-info');
  if (!bridge || !bridge.connected) {
    infoSection.style.display = 'none';
    return;
  }
  try {
    const info = await bridge.sharingKey();
    if (info && info.contact) {
      el.textContent = info.contact;
      infoSection.style.display = '';
    } else {
      infoSection.style.display = 'none';
    }
  } catch (_) {
    infoSection.style.display = 'none';
  }
}

async function handleDirectedSend() {
  if (!bridge || !bridge.connected) {
    showToast(t('error_not_connected'), 'error');
    return;
  }

  const recipient = document.getElementById('send-recipient').value.trim();
  const password = document.getElementById('send-password').value;
  const retentionSecs = parseInt(document.getElementById('send-retention').value);
  const fileInput = document.getElementById('send-file-input');

  if (!recipient) {
    showToast(t('error_no_input'), 'error');
    return;
  }
  if (!fileInput.files || fileInput.files.length === 0) {
    showToast(t('error_no_input'), 'error');
    return;
  }

  const file = fileInput.files[0];
  if (file.size > 100 * 1024 * 1024) {
    showToast(t('error_file_too_large'), 'error');
    return;
  }

  const btn = document.getElementById('btn-directed-send');
  btn.disabled = true;
  btn.textContent = t('processing');

  try {
    const buf = await file.arrayBuffer();
    const data = new Uint8Array(buf);
    const result = await bridge.directedSend(recipient, data, password, retentionSecs, file.name);

    document.getElementById('send-envelope-id').textContent = result.envelope_id;
    document.getElementById('send-result').classList.remove('hidden');
    showToast(t('send_success'), 'success');
  } catch (e) {
    console.error('Directed send failed:', e);
    showToast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = t('send_btn');
    applyTranslations();
  }
}

// ── Inbox ─────────────────────────────────────────────────────────

function inboxStateBadge(state) {
  const map = {
    'Pending': { label: t('inbox_pending'), color: 'var(--warning, #f0b432)' },
    'ChallengeIssued': { label: t('inbox_challenge_issued'), color: 'var(--warning, #f0b432)' },
    'Confirmed': { label: t('inbox_confirmed'), color: 'var(--success)' },
    'Retrieved': { label: t('inbox_retrieved'), color: 'var(--success)' },
    'Expired': { label: t('inbox_expired'), color: 'var(--text-dim)' },
    'SenderRevoked': { label: t('inbox_sender_revoked'), color: 'var(--danger)' },
    'RecipientDeleted': { label: t('inbox_revoked'), color: 'var(--text-dim)' },
    'ChallengeFailed': { label: t('inbox_challenge_failed'), color: 'var(--danger)' },
    'PasswordFailed': { label: t('inbox_password_failed'), color: 'var(--danger)' },
  };
  return map[state] || { label: state, color: 'var(--text-dim)' };
}

async function refreshInbox() {
  const listEl = document.getElementById('inbox-list');
  const emptyEl = document.getElementById('inbox-empty');

  if (!bridge || !bridge.connected) {
    listEl.innerHTML = '';
    emptyEl.classList.remove('hidden');
    return;
  }

  try {
    const items = await bridge.directedInbox();
    listEl.innerHTML = '';

    if (!items || items.length === 0) {
      emptyEl.classList.remove('hidden');
      return;
    }
    emptyEl.classList.add('hidden');

    for (const item of items) {
      const card = document.createElement('div');
      card.className = 'source-card';

      const header = document.createElement('div');
      header.className = 'source-header';

      const idSpan = document.createElement('code');
      idSpan.textContent = (item.envelope_id || '').substring(0, 16) + '...';
      idSpan.style.fontSize = '0.75rem';
      header.appendChild(idSpan);

      // State badge
      const state = item.state || 'Pending';
      const badgeInfo = inboxStateBadge(state);
      const badge = document.createElement('span');
      badge.className = 'share-badge';
      badge.textContent = badgeInfo.label;
      badge.style.background = badgeInfo.color;
      header.appendChild(badge);
      card.appendChild(header);

      // Sender
      if (item.sender_pubkey) {
        const senderRow = document.createElement('div');
        senderRow.className = 'source-desc';
        senderRow.style.fontSize = '0.75rem';
        senderRow.style.color = 'var(--text-dim)';
        senderRow.textContent = 'From: ' + (item.sender_pubkey || '').substring(0, 20) + '...';
        card.appendChild(senderRow);
      }

      // Filename if present
      if (item.filename) {
        const fnRow = document.createElement('div');
        fnRow.className = 'source-desc';
        fnRow.textContent = item.filename;
        if (item.file_size > 0) {
          fnRow.textContent += ` (${formatBytes(item.file_size)})`;
        }
        card.appendChild(fnRow);
      }

      // Challenge code for pending items
      if (item.challenge_code) {
        const challengeRow = document.createElement('div');
        challengeRow.className = 'setting-row';
        challengeRow.style.marginTop = '0.5rem';
        const label = document.createElement('span');
        label.textContent = t('inbox_challenge') + ': ';
        label.style.color = 'var(--success)';
        label.style.fontWeight = 'bold';
        const code = document.createElement('code');
        code.textContent = item.challenge_code;
        code.style.fontSize = '1.1rem';
        code.style.letterSpacing = '0.1rem';
        challengeRow.appendChild(label);
        challengeRow.appendChild(code);
        card.appendChild(challengeRow);
      }

      // Terminal state messages
      if (state === 'Expired') {
        const msg = document.createElement('div');
        msg.style.color = 'var(--danger)';
        msg.style.marginTop = '0.5rem';
        msg.textContent = t('inbox_expired');
        card.appendChild(msg);
      } else if (state === 'SenderRevoked') {
        const msg = document.createElement('div');
        msg.style.color = 'var(--danger)';
        msg.style.marginTop = '0.5rem';
        msg.textContent = t('inbox_sender_revoked');
        card.appendChild(msg);
      } else if (state === 'PasswordFailed') {
        const msg = document.createElement('div');
        msg.style.color = 'var(--danger)';
        msg.style.marginTop = '0.5rem';
        msg.textContent = t('inbox_attempts_exhausted');
        card.appendChild(msg);
      }

      // Inline retrieve form (Confirmed state only)
      const isTerminal = ['Retrieved', 'SenderRevoked', 'RecipientDeleted',
                          'Expired', 'ChallengeFailed', 'PasswordFailed'].includes(state);
      if (state === 'Confirmed') {
        const retrieveForm = document.createElement('div');
        retrieveForm.style.marginTop = '0.5rem';
        retrieveForm.style.display = 'flex';
        retrieveForm.style.gap = '0.5rem';
        retrieveForm.style.alignItems = 'center';

        const pwLabel = document.createElement('label');
        pwLabel.textContent = t('inbox_password_label') + ':';
        pwLabel.style.fontSize = '0.85rem';
        retrieveForm.appendChild(pwLabel);

        const pwInput = document.createElement('input');
        pwInput.type = 'password';
        pwInput.placeholder = t('inbox_password_label');
        pwInput.style.flex = '1';
        pwInput.style.padding = '0.3rem 0.5rem';
        pwInput.style.borderRadius = '4px';
        pwInput.style.border = '1px solid var(--border)';
        pwInput.style.background = 'var(--bg)';
        pwInput.style.color = 'var(--text)';
        retrieveForm.appendChild(pwInput);

        const retrieveBtn = document.createElement('button');
        retrieveBtn.className = 'btn-small btn-accent';
        retrieveBtn.textContent = t('inbox_retrieve_btn');
        retrieveBtn.addEventListener('click', async () => {
          if (!pwInput.value) return;
          retrieveBtn.disabled = true;
          retrieveBtn.textContent = t('processing');
          try {
            const result = await bridge.directedRetrieve(item.envelope_id, pwInput.value);
            const blob = new Blob([result.data]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = result.filename || 'miasma-directed';
            a.click();
            URL.revokeObjectURL(url);
            showToast(t('retrieved'), 'success');
            refreshInbox();
          } catch (e) {
            console.error('Directed retrieve failed:', e);
            showToast(e.message || t('inbox_wrong_password'), 'error');
          } finally {
            retrieveBtn.disabled = false;
            retrieveBtn.textContent = t('inbox_retrieve_btn');
          }
        });
        retrieveForm.appendChild(retrieveBtn);
        card.appendChild(retrieveForm);
      }

      // Delete button for non-terminal states
      if (!isTerminal) {
        const actions = document.createElement('div');
        actions.className = 'import-actions';
        actions.style.marginTop = '0.5rem';
        const revokeBtn = document.createElement('button');
        revokeBtn.className = 'btn-small';
        revokeBtn.textContent = t('inbox_revoke');
        revokeBtn.addEventListener('click', () => handleDirectedRevoke(item.envelope_id));
        actions.appendChild(revokeBtn);
        card.appendChild(actions);
      }

      listEl.appendChild(card);
    }
  } catch (e) {
    console.error('Inbox refresh failed:', e);
    listEl.innerHTML = '';
    emptyEl.classList.remove('hidden');
  }
}

async function handleDirectedRevoke(envelopeId) {
  if (!confirm(t('confirm_clear'))) return;
  try {
    const ok = await bridge.directedRevoke(envelopeId);
    if (ok) {
      showToast(t('cleared'), 'success');
      refreshInbox();
      refreshOutbox();
    } else {
      showToast(t('error_retrieve'), 'error');
    }
  } catch (e) {
    showToast(e.message, 'error');
  }
}

// ── Outbox ────────────────────────────────────────────────────────

function outboxStateBadge(state) {
  const map = {
    'Pending': { label: t('outbox_waiting'), color: 'var(--warning, #f0b432)' },
    'ChallengeIssued': { label: t('outbox_confirm_label'), color: 'var(--warning, #f0b432)' },
    'Confirmed': { label: t('outbox_confirmed'), color: 'var(--success)' },
    'Retrieved': { label: t('outbox_retrieved'), color: 'var(--success)' },
    'Expired': { label: t('outbox_expired'), color: 'var(--text-dim)' },
    'SenderRevoked': { label: t('outbox_revoked'), color: 'var(--danger)' },
    'RecipientDeleted': { label: t('outbox_revoked'), color: 'var(--text-dim)' },
    'ChallengeFailed': { label: t('outbox_challenge_failed'), color: 'var(--danger)' },
    'PasswordFailed': { label: t('outbox_password_failed'), color: 'var(--danger)' },
  };
  return map[state] || { label: state, color: 'var(--text-dim)' };
}

async function refreshOutbox() {
  const listEl = document.getElementById('outbox-list');
  const emptyEl = document.getElementById('outbox-empty');

  if (!bridge || !bridge.connected) {
    listEl.innerHTML = '';
    emptyEl.classList.remove('hidden');
    return;
  }

  try {
    const items = await bridge.directedOutbox();
    listEl.innerHTML = '';

    if (!items || items.length === 0) {
      emptyEl.classList.remove('hidden');
      return;
    }
    emptyEl.classList.add('hidden');

    for (const item of items) {
      const card = document.createElement('div');
      card.className = 'source-card';

      const header = document.createElement('div');
      header.className = 'source-header';

      const idSpan = document.createElement('code');
      idSpan.textContent = (item.envelope_id || '').substring(0, 16) + '...';
      idSpan.style.fontSize = '0.75rem';
      header.appendChild(idSpan);

      // State badge
      const state = item.state || 'Pending';
      const badgeInfo = outboxStateBadge(state);
      const badge = document.createElement('span');
      badge.className = 'share-badge';
      badge.textContent = badgeInfo.label;
      badge.style.background = badgeInfo.color;
      header.appendChild(badge);
      card.appendChild(header);

      // Recipient
      if (item.recipient_pubkey) {
        const recipRow = document.createElement('div');
        recipRow.className = 'source-desc';
        recipRow.style.fontSize = '0.75rem';
        recipRow.style.color = 'var(--text-dim)';
        recipRow.textContent = t('outbox_to') + ': ' + (item.recipient_pubkey || '').substring(0, 20) + '...';
        card.appendChild(recipRow);
      }

      // Filename
      if (item.filename) {
        const fnRow = document.createElement('div');
        fnRow.className = 'source-desc';
        fnRow.textContent = item.filename;
        if (item.file_size > 0) {
          fnRow.textContent += ` (${formatBytes(item.file_size)})`;
        }
        card.appendChild(fnRow);
      }

      // Sender confirmation: challenge code entry for ChallengeIssued state
      if (state === 'ChallengeIssued') {
        const confirmForm = document.createElement('div');
        confirmForm.style.marginTop = '0.5rem';
        confirmForm.style.display = 'flex';
        confirmForm.style.gap = '0.5rem';
        confirmForm.style.alignItems = 'center';

        const codeLabel = document.createElement('label');
        codeLabel.textContent = t('outbox_confirm_label') + ':';
        codeLabel.style.fontSize = '0.85rem';
        confirmForm.appendChild(codeLabel);

        const codeInput = document.createElement('input');
        codeInput.type = 'text';
        codeInput.placeholder = t('outbox_confirm_hint');
        codeInput.style.flex = '1';
        codeInput.style.padding = '0.3rem 0.5rem';
        codeInput.style.borderRadius = '4px';
        codeInput.style.border = '1px solid var(--border)';
        codeInput.style.background = 'var(--bg)';
        codeInput.style.color = 'var(--text)';
        codeInput.style.fontFamily = 'monospace';
        codeInput.style.letterSpacing = '0.1rem';
        confirmForm.appendChild(codeInput);

        const confirmBtn = document.createElement('button');
        confirmBtn.className = 'btn-small btn-accent';
        confirmBtn.textContent = t('outbox_confirm_btn');
        confirmBtn.addEventListener('click', async () => {
          if (!codeInput.value.trim()) return;
          confirmBtn.disabled = true;
          confirmBtn.textContent = t('processing');
          try {
            const ok = await bridge.directedConfirm(item.envelope_id, codeInput.value.trim());
            if (ok) {
              showToast(t('outbox_confirm_success'), 'success');
              refreshOutbox();
            } else {
              showToast(t('outbox_challenge_failed'), 'error');
            }
          } catch (e) {
            console.error('Confirm failed:', e);
            showToast(e.message || t('outbox_challenge_failed'), 'error');
          } finally {
            confirmBtn.disabled = false;
            confirmBtn.textContent = t('outbox_confirm_btn');
          }
        });
        confirmForm.appendChild(confirmBtn);
        card.appendChild(confirmForm);
      }

      // Pending state hint
      if (state === 'Pending') {
        const hint = document.createElement('div');
        hint.style.color = 'var(--warning, #f0b432)';
        hint.style.marginTop = '0.5rem';
        hint.style.fontSize = '0.85rem';
        hint.textContent = t('outbox_waiting');
        card.appendChild(hint);
      }

      // Revoke button for non-terminal states
      const isTerminal = ['Retrieved', 'SenderRevoked', 'RecipientDeleted',
                          'Expired', 'ChallengeFailed', 'PasswordFailed'].includes(state);
      if (!isTerminal) {
        const actions = document.createElement('div');
        actions.className = 'import-actions';
        actions.style.marginTop = '0.5rem';
        const revokeBtn = document.createElement('button');
        revokeBtn.className = 'btn-small';
        revokeBtn.textContent = t('outbox_revoke');
        revokeBtn.addEventListener('click', async () => {
          if (!confirm(t('confirm_clear'))) return;
          try {
            await bridge.directedRevoke(item.envelope_id);
            showToast(t('cleared'), 'success');
            refreshOutbox();
          } catch (e) {
            showToast(e.message, 'error');
          }
        });
        actions.appendChild(revokeBtn);
        card.appendChild(actions);
      }

      listEl.appendChild(card);
    }
  } catch (e) {
    console.error('Outbox refresh failed:', e);
    listEl.innerHTML = '';
    emptyEl.classList.remove('hidden');
  }
}

// ── Settings ──────────────────────────────────────────────────────

async function updateSettingsView() {
  const count = await getShareCount();
  const est = await getStorageEstimate();
  document.getElementById('settings-share-count').textContent = count.toString();
  document.getElementById('settings-storage-size').textContent = formatBytes(est);
}

async function handleClearAll() {
  if (!confirm(t('confirm_clear'))) return;
  await clearAll();
  showToast(t('cleared'), 'success');
  updateStats();
  updateSettingsView();
}

// ── Stats ─────────────────────────────────────────────────────────

async function updateStats() {
  try {
    const shares = await getShareCount();
    const mids = await getMidCount();
    document.getElementById('stat-shares').textContent = shares.toString();
    document.getElementById('stat-mids').textContent = mids.toString();
  } catch (_) {}
}

// ── PWA Install Banner ────────────────────────────────────────────

function showInstallBanner() {
  // Only show on iOS Safari when not already installed as PWA
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
  const isStandalone = window.navigator.standalone === true;
  const dismissed = localStorage.getItem('miasma-install-dismissed');

  if (!isIOS || isStandalone || dismissed) return;

  const banner = document.getElementById('install-banner');
  if (banner) {
    banner.classList.remove('hidden');
  }
}

// ── Utilities ─────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function isLikelyText(bytes) {
  const check = Math.min(bytes.length, 512);
  let textChars = 0;
  for (let i = 0; i < check; i++) {
    const b = bytes[i];
    if (b === 0) return false;
    if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13 || b >= 0xC0) {
      textChars++;
    }
  }
  return check === 0 || (textChars / check) > 0.85;
}

async function copyToClipboard(text, successMsg) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(successMsg || t('copied'), 'success');
  } catch (_) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast(successMsg || t('copied'), 'success');
  }
}

let toastTimer = null;
function showToast(msg, type = '') {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = 'toast ' + type;
  toast.offsetHeight;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2500);
}

// Base58 decoder (Bitcoin alphabet)
function decodeBase58(str) {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const BASE = 58n;
  let num = 0n;
  for (const c of str) {
    const idx = ALPHABET.indexOf(c);
    if (idx < 0) return null;
    num = num * BASE + BigInt(idx);
  }
  const hex = num.toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ── Connection State UI ───────────────────────────────────────────

function updateConnectionUI() {
  const dot = document.getElementById('connection-status');
  const scopeNotice = document.getElementById('scope-notice');
  const shareSourceSection = document.querySelector('.share-source-section');
  const peersContainer = document.getElementById('stat-peers-container');
  if (!dot) return;

  const isConnected = bridge && bridge.connected;
  const mode = bridge ? bridge.mode : 'local';

  // Connection dot
  dot.className = 'connection-dot';
  if (isConnected) {
    dot.classList.add('connected');
    dot.title = t('connection_connected');
  } else {
    dot.classList.add('local');
    dot.title = t('connection_local');
  }

  // Scope notice: update text based on connection state
  if (scopeNotice) {
    const p = scopeNotice.querySelector('p');
    if (p) {
      if (isConnected) {
        p.textContent = t('scope_connected');
        scopeNotice.classList.add('scope-connected');
      } else {
        p.textContent = t('scope_notice');
        scopeNotice.classList.remove('scope-connected');
      }
    }
  }

  // In connected mode, hide the manual share source section and show network retrieve
  if (shareSourceSection) {
    shareSourceSection.style.display = isConnected ? 'none' : '';
  }

  // Show peer count when connected
  if (peersContainer) {
    peersContainer.style.display = isConnected ? '' : 'none';
    if (isConnected && bridge.lastStatus) {
      document.getElementById('stat-peers').textContent =
        (bridge.lastStatus.peer_count || 0).toString();
    }
  }

  // Update retrieve button state
  updateShareProgress();
}

function onBridgeStateChange(mode, connected, status) {
  updateConnectionUI();
  if (connected && status) {
    const peerEl = document.getElementById('stat-peers');
    if (peerEl) peerEl.textContent = (status.peer_count || 0).toString();
  }
}

// ── Service Worker Registration ───────────────────────────────────

if ('serviceWorker' in navigator) {
  // Use relative path so the SW works when hosted at a subpath
  navigator.serviceWorker.register('./sw.js').catch(() => {
    // SW registration failure is non-fatal (e.g. localhost without HTTPS)
  });
}

// ── Start ─────────────────────────────────────────────────────────

init();
