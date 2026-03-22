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

## 4. What Changed (2026-03-23)

1. **Scope transparency**: Added scope-notice card on home page, explicit scope text in About, updated hero wording from "censorship-resistant" to "local content protection"
2. **ZH-CN locale**: Added complete Chinese translation (72+ keys)
3. **Language cycle**: 3-way EN→JA→ZH→EN instead of 2-way toggle
4. **Feature detection**: Improved error message with recommended browser versions
5. **Service Worker**: Updated to relative paths for subpath hosting, cache version bumped to v3
6. **i18n strings**: Updated hero_sub, hero_desc, about_desc to reflect local-only scope accurately
