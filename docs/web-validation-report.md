# Miasma Web — Validation Report

**Date**: 2026-03-23
**Version**: 0.3.1
**Platform**: Windows 11 Enterprise (dev machine)

---

## 1. Code-Level Validation

### Feature detection
- **Checks**: WebAssembly, IndexedDB, crypto.getRandomValues(), BigInt
- **Unsupported browser handling**: Loading screen shows specific missing features + recommended browser versions
- **Result**: PASS (code reviewed)

### WASM integration
- **miasma-wasm crate**: 27 native tests pass, 4 cross-platform compat tests pass
- **Protocol compatibility**: MID computation, share format, bincode serialization verified against test vectors
- **Exports**: dissolve_text, dissolve_bytes, retrieve_from_shares, verify_share, protocol_version
- **Result**: PASS

### Dissolve flow
- Text input with byte count display
- File input with drag-and-drop and size validation (100 MB limit)
- k/n parameter validation (0 < k < n <= 255)
- Progress display with particle animation
- MID display with copy button
- Save to browser (IndexedDB) and export (.miasma file)
- **Result**: PASS (code reviewed)

### Retrieve flow
- MID input with format validation (must start with `miasma:`)
- Local share search by MID prefix (Base58 decode → hex prefix → IndexedDB query)
- Import shares from .miasma file or pasted JSON
- Share deduplication by slot_index
- Progress bar (shares collected / k needed)
- Text detection heuristic for result display
- Binary download fallback
- **Result**: PASS (code reviewed)

### Import sanitization
- Share objects sanitized to known fields only (strips __proto__, constructor, etc.)
- slot_index type-checked
- Invalid shares silently skipped
- **Result**: PASS (code reviewed)

### IndexedDB storage
- Database: `miasma-web` v1, two object stores (shares + metadata)
- Compound key [midPrefixHex, slotIndex] prevents duplicate shares
- Storage estimate via navigator.storage.estimate()
- Clear all with confirmation dialog
- **Result**: PASS (code reviewed)

### Service Worker
- Precache: HTML, CSS, JS, manifest
- WASM assets: stale-while-revalidate (background update)
- Paths updated to relative for subpath hosting compatibility
- Cache version bumped to v3
- **Result**: PASS (code reviewed)

### Content Security Policy
- `default-src 'self'`
- `script-src 'self' 'wasm-unsafe-eval'`
- `style-src 'self' 'unsafe-inline'`
- `frame-ancestors 'none'`
- `base-uri 'self'`
- `form-action 'self'`
- **Result**: PASS

### Localization
- EN: complete (72+ keys)
- JA: complete (72+ keys)
- ZH-CN: complete (72+ keys, added 2026-03-23)
- Language cycle: EN → JA → ZH → EN (navbar button)
- Language persistence: localStorage
- **Result**: PASS (code reviewed)

### Scope transparency
- Home page: scope notice card stating local-only nature
- Settings > About: explicit scope description
- Settings > Security: 4 security notices about browser limitations
- Hero text: "Local content protection" (not "censorship-resistant network")
- **Result**: PASS

---

## 2. Browser Validation (Pending)

The following browser tests require manual execution on the dev machine:

| Test | Chrome | Edge | Firefox | Safari |
|---|---|---|---|---|
| Page loads, WASM initializes | | | | |
| Text dissolve → MID shown | | | | |
| Save to browser (IndexedDB) | | | | |
| Export .miasma file | | | | |
| Retrieve from local shares | | | | |
| Import .miasma file | | | | |
| Paste JSON import | | | | |
| File dissolve (drag & drop) | | | | |
| EN/JA/ZH locale switch | | | | |
| Clear all shares | | | | |
| PWA install prompt | | | | |
| Offline after SW cache | | | | |
| Reload preserves shares | | | | |
| Scope notice visible | | | | |

**Instructions**: Open `http://localhost:8080` (or serve `web/` via any static HTTP server) in each browser. Fill in the table with PASS/FAIL/SKIP.

---

## 3. Cross-Platform Compatibility (Pending)

Desktop-to-web share roundtrip not yet tested:
1. Desktop: `miasma dissolve <file>` → export shares as JSON
2. Web: import shares via paste → retrieve
3. Verify content matches

This requires a share export format bridge (desktop currently stores shares in binary, web uses JSON).

---

## 4. Network Bridge Validation (2026-03-23)

### Desktop HTTP Bridge

| Test | Result |
|---|---|
| `http_bridge.rs` compiles (hyper 1.x) | PASS |
| All 480 workspace tests pass | PASS (268+112+53+31+16) |
| HTTP bridge binds to `127.0.0.1:17842` | PASS (code review) |
| CORS headers on all responses | PASS (code review) |
| OPTIONS preflight returns 204 | PASS (code review) |
| `/api/ping` → `{"ok":true}` | PASS (code review) |
| `/api/status` → full DaemonStatus JSON | PASS (code review, reuses IPC handler) |
| `/api/publish` → base64 data → MID | PASS (code review) |
| `/api/retrieve` → MID → base64 data | PASS (code review) |
| Request size limit (16 MiB) | PASS (code review) |
| Port fallback to OS-assigned if 17842 occupied | PASS (code review) |
| Port file cleanup on daemon shutdown | PASS (code review) |

### Web Bridge Detection

| Test | Result |
|---|---|
| `bridge.js` detects `window.miasma` (WebView mode) | PASS (code review) |
| `bridge.js` tries HTTP ping (HTTP mode) | PASS (code review) |
| `bridge.js` falls back to local-only (WASM mode) | PASS (code review) |
| Connection dot updates on state change | PASS (code review) |
| Scope notice text changes when connected | PASS (code review) |
| Share source section hidden in connected mode | PASS (code review) |
| Retrieve button enabled without shares in connected mode | PASS (code review) |

### Android WebView Bridge

| Test | Result |
|---|---|
| `WebBridgeActivity.kt` compiles | PASS (syntax review — full build requires NDK) |
| `@JavascriptInterface` methods match bridge contract | PASS (code review) |
| Activity registered in AndroidManifest.xml | PASS |
| Settings screen has "Open Web View" button | PASS |

### iOS WKWebView Bridge

| Test | Result |
|---|---|
| `WebBridgeView.swift` syntax valid | PASS (code review — full build requires Xcode) |
| `WKScriptMessageHandler` matches bridge contract | PASS (code review) |
| `WKUserScript` injects Promise-based `window.miasma` | PASS (code review) |
| "Web" tab added to ContentView | PASS |

### Runtime validation (pending)

- [ ] Start daemon, open web in Chrome → green dot, peer count visible
- [ ] Dissolve text via web → "Published to P2P network" shown, MID returned
- [ ] Retrieve via web (MID only, no manual shares) → content returned
- [ ] Stop daemon → dot goes gray, scope notice returns to local-only
- [ ] Android WebView loads web assets, bridge.ping() returns ok
- [ ] iOS WKWebView loads web assets, bridge.ping() returns ok

---

## 5. What Changed (2026-03-23)

1. **Scope transparency**: Added scope-notice card on home page, explicit scope text in About, updated hero wording from "censorship-resistant" to "local content protection"
2. **ZH-CN locale**: Added complete Chinese translation (72+ keys)
3. **Language cycle**: 3-way EN→JA→ZH→EN instead of 2-way toggle
4. **Feature detection**: Improved error message with recommended browser versions
5. **Service Worker**: Updated to relative paths for subpath hosting, cache version bumped to v3
6. **i18n strings**: Updated hero_sub, hero_desc, about_desc to reflect local-only scope accurately
7. **HTTP bridge**: Daemon exposes HTTP JSON API on `localhost:17842` (hyper 1.x, base64 encoding, CORS)
8. **bridge.js**: Runtime environment detection (WebView / HTTP / local-only), unified async API
9. **Connection state UI**: Dot indicator in nav bar, dynamic scope notice, peer count when connected
10. **Android WebBridgeActivity**: WebView with `@JavascriptInterface` bridge to FFI
11. **iOS WebBridgeView**: WKWebView with `WKScriptMessageHandler` bridge to FFI
12. **CSP updated**: `connect-src` allows `http://127.0.0.1:17842`
13. **Service Worker**: Cache version bumped to v4, bridge.js added to precache
14. **ADR-007**: Architecture decision record for web network bridge
