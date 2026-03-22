## Miasma Web/PWA — Current State and Next Steps

### Product Definition

Miasma Web is a **local-only browser tool** for the Miasma Protocol. It provides dissolution and retrieval of content entirely within the browser using WebAssembly. No data leaves the device.

It is **not** a networked client, a companion to the desktop app, or a full peer in the Miasma network.

### Current Scope

**What it does now:**
- Dissolve text or files into k-of-n encrypted shares (AES-256-GCM + Reed-Solomon + Shamir SSS + BLAKE3)
- Retrieve content from k-of-n shares
- Store shares locally in IndexedDB
- Export shares as `.miasma` files (JSON) for manual transfer between devices
- Import shares from `.miasma` files or pasted JSON
- Verify share integrity (coarse verify: MID prefix + shard hash)
- Work offline as a PWA (Service Worker caches all assets)
- Support EN, JA, ZH-CN locales
- Run on modern browsers with WebAssembly support

**What it cannot do:**
- No peer discovery or network connectivity
- No daemon communication
- No external retrieval (cannot fetch shares from other devices)
- No anonymity or routing features (onion, relay, rendezvous)
- No automatic share exchange — all transfers are manual export/import
- No distress wipe (IndexedDB can be cleared manually)

### Architecture

```
Browser (PWA)
├── index.html          Single-page app
├── css/style.css       Dark-themed responsive design
├── js/app.js           Main controller (707 lines)
├── js/i18n.js          EN/JA/ZH-CN translations
├── js/storage.js       IndexedDB layer (shares + metadata)
├── sw.js               Service Worker (offline cache)
├── manifest.json       PWA manifest
└── pkg/                Compiled WASM (miasma-wasm crate)
    ├── miasma_wasm.js
    └── miasma_wasm_bg.wasm
```

The `miasma-wasm` crate is **completely self-contained** — it does not depend on miasma-core. It reimplements the same cryptographic pipeline independently for browser compatibility:
- AES-256-GCM (aes-gcm crate)
- Reed-Solomon erasure coding (reed-solomon-simd)
- Shamir Secret Sharing (sharks)
- BLAKE3 content addressing (blake3)
- Protocol-compatible share format (bincode + JSON)

### Security Posture

- **Security audit completed** (2026-03-22): All CRITICAL/HIGH/MEDIUM issues fixed
- C-1: SSS parameter truncation (u8 cast) — fixed with validate_params()
- H-1: Zeroize limitation in WASM — documented (inherent browser constraint)
- H-2: original_len u32 truncation — fixed with size check + 100MB limit
- H-3: bincode OOM DoS — fixed with MAX_BINCODE_SIZE = 1MB
- M-1 through M-8: CSP hardened, SW cache strategy, input sanitization
- Remaining LOW/INFO: documented and accepted

**Honest limitations (documented in UI):**
- Browser memory management cannot guarantee key material zeroization
- IndexedDB is not encrypted (shares are individually meaningless but accessible)
- WASM linear memory is readable from JS context
- Do not use for highly sensitive content

### Test Coverage

- **27 native unit tests** in miasma-wasm (MID, AES, SSS, RS, pipeline, JSON, verification)
- **4 cross-platform compat tests** (BLAKE3 digest, param_bytes, RS shard length, bincode layout)
- **Browser validation**: see docs/web-validation-report.md

### Browser Support Target

| Browser | Version | Status |
|---|---|---|
| Chrome | 89+ | Supported (primary) |
| Edge | 89+ | Supported |
| Firefox | 89+ | Supported |
| Safari | 15+ | Supported (PWA with limitations) |
| Safari iOS | 16+ | Supported (PWA "Add to Home Screen") |

Required features: WebAssembly, IndexedDB, crypto.getRandomValues(), BigInt

### Known Limitations

1. **Local-only**: No networking. Share transfer between devices requires manual export/import.
2. **100 MB input limit**: Browser memory constraint. Larger files will fail.
3. **No background processing**: Closing the tab interrupts dissolution/retrieval.
4. **PWA limitations**: iOS Safari has restrictive storage and Service Worker lifecycle.
5. **No Secure Enclave**: Web Crypto API non-extractable keys are not compatible with the Miasma pipeline.

### Completion Status (Original Spec)

All items from the original implementation specification are complete:
- [x] `wasm-pack build` succeeds
- [x] dissolve → retrieve roundtrip works in browser
- [x] MID generation matches miasma-core (cross-platform test vectors)
- [x] Share format is bincode-compatible
- [x] PWA offline installable
- [x] Security constraints documented in UI
- [x] IndexedDB share save/restore works
- [x] Security audit completed

### Next Milestone

**Web scope hardening (current)**:
- [x] Explicit local-only scope statement in UI and docs
- [x] ZH-CN locale added (3-locale parity with desktop)
- [x] Browser support target defined
- [x] Feature detection with helpful error messages
- [x] Service Worker paths fixed for subpath hosting
- [ ] Browser validation report (Chrome, Edge, Firefox, Safari)
- [ ] Cross-platform share format compatibility test (WASM ↔ desktop roundtrip)

**Future milestones (not started)**:
- Browser compatibility validation across all target browsers
- Cross-platform share import/export testing (desktop → web → desktop)
- Future networking architecture decision (see docs/platform-roadmap.md Track E)

### Architecture Decision: Future Web Networking

The web app is intentionally local-only today. Adding network connectivity would require one of:

1. **WebRTC data channels** — Browser-to-browser P2P, but requires signaling server and has NAT traversal challenges. Would need a new protocol layer incompatible with libp2p.

2. **Relay/proxy server** — A server-assisted model where a Miasma relay bridges browser requests to the DHT. Simplest path but introduces a centralized trust point.

3. **Desktop companion mode** — The browser sends requests to a locally-running desktop daemon via localhost HTTP/WebSocket. Most compatible but requires desktop app running.

4. **libp2p-wasm** — Experimental libp2p WebTransport/WebRTC support exists but is immature and not production-ready for libp2p 0.54.

**Current decision**: Deferred. The local-only tool provides real value without networking. Any networking path requires an ADR and significant architecture work. The local-only positioning is honest and sustainable.
