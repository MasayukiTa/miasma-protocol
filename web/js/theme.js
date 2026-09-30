// Miasma Web — theme (light / dark / system)
//
// A classic script, loaded in <head> before the stylesheet paints, so the chosen
// theme is on <html> from the first frame (no flash of the wrong one). The page's
// CSS does the rest: with no data-theme attribute the OS setting decides
// (`prefers-color-scheme`); data-theme="light" or "dark" overrides it.
//
// The choice is remembered in localStorage. Every access is guarded: private
// windows and blocked site data throw, and the page must still work.

(function () {
  'use strict';

  var KEY = 'miasma-theme';
  var root = document.documentElement;
  // <meta name="theme-color">: the browser chrome colour on phones (the page background).
  var CHROME = { light: '#f7f6f2', dark: '#111111' };
  var listeners = [];

  function read() {
    try {
      var v = localStorage.getItem(KEY);
      return v === 'light' || v === 'dark' ? v : 'system';
    } catch (_) {
      return 'system';
    }
  }

  var mode = read();

  function systemIsDark() {
    return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  }

  function resolved() {
    return mode === 'system' ? (systemIsDark() ? 'dark' : 'light') : mode;
  }

  function apply() {
    if (mode === 'light' || mode === 'dark') root.setAttribute('data-theme', mode);
    else root.removeAttribute('data-theme');
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', CHROME[resolved()]);
    for (var i = 0; i < listeners.length; i++) {
      try { listeners[i](mode, resolved()); } catch (_) { /* a listener must not break theming */ }
    }
  }

  function set(next) {
    mode = next === 'light' || next === 'dark' ? next : 'system';
    try {
      if (mode === 'system') localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, mode);
    } catch (_) { /* not remembered, still applied */ }
    apply();
  }

  // In System mode follow the OS while the page is open.
  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var onChange = function () { if (mode === 'system') apply(); };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }

  window.MiasmaTheme = {
    /** 'system' | 'light' | 'dark' — what the person chose. */
    mode: function () { return mode; },
    /** 'light' | 'dark' — what is actually shown. */
    resolved: resolved,
    set: set,
    onChange: function (fn) { listeners.push(fn); },
  };

  apply();
})();
