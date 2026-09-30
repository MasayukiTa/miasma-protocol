// Design tokens of web/css/style.css: the light and dark values must match the
// plan's token table (docs/tasks/protected-resumable-transfer-plan.md, section 9)
// except where a value had to change to keep text at 4.5:1, and every text/background
// pair the client uses must reach 4.5:1 in both themes.
//
// Run: node --test web/tests/

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'css', 'style.css'), 'utf8');

/** `--name: value;` pairs of the first block that starts with `selector {`. */
function tokens(selector) {
  const start = css.indexOf(selector + ' {');
  assert.ok(start >= 0, `no block for ${selector}`);
  const end = css.indexOf('\n}', start);
  const body = css.slice(start, end);
  const out = {};
  for (const m of body.matchAll(/--([a-z-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim();
  return out;
}

const light = tokens(':root');
const dark = tokens(':root[data-theme="dark"]');
// The System-mode copy lives one level deeper (inside @media).
const mediaStart = css.indexOf('@media (prefers-color-scheme: dark)');
const mediaBlock = css.slice(mediaStart, css.indexOf('\n}\n', css.indexOf(':root:not([data-theme="light"]) {', mediaStart)));
const systemDark = {};
for (const m of mediaBlock.matchAll(/--([a-z-]+):\s*([^;]+);/g)) systemDark[m[1]] = m[2].trim();

function lum(hex) {
  const n = parseInt(hex.replace('#', ''), 16);
  const f = (v) => { const x = v / 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * f((n >> 16) & 255) + 0.7152 * f((n >> 8) & 255) + 0.0722 * f(n & 255);
}

function contrast(a, b) {
  const [la, lb] = [lum(a), lum(b)];
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

// From the plan's table. `faint` (dark) and `danger` (dark) are deliberately lighter.
const PLAN_LIGHT = {
  bg: '#f7f6f2', surface: '#ffffff', 'surface-subtle': '#f4f4f2', selected: '#e7e5de',
  border: '#d8d6cf', 'border-strong': '#d4d4d0', text: '#18181b', muted: '#5f5f66', faint: '#6b6b73',
  accent: '#c4400d', 'accent-fill': '#c4400d', success: '#15803d', warning: '#b45309', danger: '#b91c1c', info: '#2563eb',
};
const PLAN_DARK = {
  bg: '#111111', surface: '#181818', 'surface-subtle': '#202020', selected: '#2c2c2c',
  border: '#2e2e2e', 'border-strong': '#3a3a3a', text: '#f4f4f5', muted: '#a1a1aa',
  accent: '#f97316', 'accent-fill': '#c2410c', success: '#22c55e', warning: '#f59e0b', info: '#60a5fa',
};
const DELIBERATE_DARK = { faint: '#8b8b94', danger: '#f87171' };

test('light tokens are the desktop palette', () => {
  for (const [k, v] of Object.entries(PLAN_LIGHT)) assert.equal(light[k], v, `light --${k}`);
});

test('dark tokens are the desktop palette, except the two lightened for contrast', () => {
  for (const [k, v] of Object.entries(PLAN_DARK)) assert.equal(dark[k], v, `dark --${k}`);
  for (const [k, v] of Object.entries(DELIBERATE_DARK)) assert.equal(dark[k], v, `dark --${k}`);
});

test('System-mode dark equals explicit dark', () => {
  assert.deepEqual(systemDark, dark);
});

for (const [name, t] of [['light', light], ['dark', dark]]) {
  test(`${name}: text reaches 4.5:1 on every surface it is drawn on`, () => {
    const backgrounds = ['bg', 'surface', 'surface-subtle', 'selected'];
    const foregrounds = ['text', 'muted', 'faint', 'success', 'warning', 'danger', 'info'];
    for (const bg of backgrounds) {
      for (const fg of foregrounds) {
        // Status colours are only drawn as text on the page and on cards/chips, and `faint` is
        // never used on the row-selection tint (selected rows use `muted`), see style.css.
        if (bg === 'selected' && ['success', 'warning', 'danger', 'info', 'faint'].includes(fg)) continue;
        const c = contrast(t[fg], t[bg]);
        assert.ok(c >= 4.5, `${name}: --${fg} on --${bg} is ${c.toFixed(2)}:1`);
      }
    }
  });

  test(`${name}: the primary button's text reaches 4.5:1 on its fill`, () => {
    const c = contrast(t['on-accent'], t['accent-fill']);
    assert.ok(c >= 4.5, `${name}: on-accent on accent-fill is ${c.toFixed(2)}:1`);
  });
}

test('no rule draws a coloured left rail or fills a card with a status colour', () => {
  assert.ok(!/border-left\s*:/.test(css), 'border-left on a block');
  // A status colour may be a text colour, a dot or a bar, never a background of a container.
  for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const [, selector, body] = m;
    for (const d of body.split(';')) {
      const [prop, val] = d.split(/:(.+)/).map((s) => (s || '').trim());
      if ((prop === 'background' || prop === 'background-color') && /var\(--(success|warning|danger)\)/.test(val)) {
        // Only dots, thin bars and strip cells may use a status colour as a background.
        assert.ok(/::before|progress-fill|\.chip|\.connection-dot|\.tf-fill|\.tf-cell/.test(selector), `status background on: ${selector.trim()}`);
      }
    }
  }
});

test('the font stack is the owner\'s, with Meiryo first and no bundled font', () => {
  assert.match(css, /--font:\s*Meiryo,\s*"Hiragino Sans",\s*"Hiragino Kaku Gothic ProN",\s*"Yu Gothic",\s*"Microsoft YaHei",\s*"PingFang SC",\s*system-ui,\s*sans-serif;/);
  assert.ok(!/@font-face/.test(css), 'a font must not be bundled or linked');
});
