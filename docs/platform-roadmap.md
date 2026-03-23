# Miasma Platform Roadmap

**Date**: 2026-03-23
**Version**: 0.3.1

---

## 1. Current Maturity by Platform

### Windows — Shipping Beta

- **Audience**: Protocol testers, developers, early adopters
- **Maturity**: Beta (validated)
- **What it can do**: Initialize node, daemon lifecycle, dissolve/retrieve, dual-mode desktop GUI (Easy/Technical), 3-locale i18n (EN/JA/ZH-CN), mDNS same-network peer discovery, manual bootstrap, shell integration (magnet:/torrent), BitTorrent bridge import, diagnostics export, installer (MSI/EXE/portable ZIP), upgrade/uninstall lifecycle, distress wipe, persistent logging, **directed private sharing** (send, confirm, retrieve, revoke, inbox, outbox — CLI + GUI + Web)
- **What it should not claim**: Cross-network retrieval proven at scale, code-signed, externally audited, production-ready

### Web/PWA — Local-Only Browser Tool

- **Audience**: Browser-only users wanting portable dissolution/retrieval without installing software
- **Maturity**: Foundation (security-audited, scope-hardened, browser validation pending)
- **What it can do**: Dissolve text/bytes via WASM, retrieve from locally-held shares (IndexedDB), export/import shares as .miasma files, PWA offline support, 3-locale i18n (EN/JA/ZH-CN), protocol-compatible with miasma-core v1, **directed private sharing in connected mode** (send, confirm, retrieve, revoke, inbox, outbox — via HTTP bridge to local daemon)
- **What it should not claim**: Peer discovery, network retrieval, daemon connectivity, anonymity features, production-grade key management (WASM memory model limits apply)
- **Key constraint**: Completely self-contained — no miasma-core dependency, no networking, local-only share storage. Share transfer between devices is manual (export/import only)
- **Product scope decision**: Local-only dissolution tool. Future networking deferred pending architecture decision (WebRTC, relay, or companion mode)

### Android — Network-Capable Mobile Node

- **Audience**: Mobile users participating in directed sharing
- **Maturity**: Foundation (embedded daemon implemented, cross-device validation pending)
- **What it can do**: Initialize node, embedded daemon with full libp2p networking, HTTP bridge on localhost, dissolve/retrieve (local + network), **directed private sharing** (send, confirm, retrieve, revoke, inbox, outbox — native Compose UI + WebView), Compose UI with 8 screens, foreground service managing daemon lifecycle, Keystore-backed master key, distress wipe
- **What it should not claim**: Cross-device validation proven, production key management, persistent background networking
- **Architecture**: Embedded daemon via FFI — MiasmaNode + DaemonServer + HTTP bridge run within the app process. Native UI and WebView both use HTTP bridge at 127.0.0.1.

### iOS — Retrieval-First Network Client

- **Audience**: Mobile recipients of directed shares
- **Maturity**: Foundation (embedded daemon implemented, real device validation pending)
- **What it can do**: Embedded daemon with full libp2p networking, HTTP bridge, **retrieval-first directed sharing** (inbox with challenge display, password-gated retrieval, delete), sharing contact display, SwiftUI app with 6 tabs (Home, Inbox, Dissolve, Retrieve, Status, Web), daemon lifecycle management, distress wipe
- **What it should not claim**: Sending directed shares (intentionally deferred), persistent background daemon, production validation
- **Key constraint**: Retrieval-first by design — can receive and retrieve directed shares but cannot send them in this milestone

---

## 2. Platform Capability Matrix

| Capability | Windows | Web/PWA | Android | iOS |
|---|---|---|---|---|
| Initialize | Real | N/A | Real (FFI+daemon) | Real (FFI+daemon) |
| Status/health | Real | N/A | Real (FFI+daemon) | Real (FFI+daemon) |
| Dissolve/store | Real | Real (WASM) | Real (FFI+daemon) | Real (FFI+daemon) |
| Retrieve/get | Real | Real (local) | Real (FFI+daemon, local+network) | Real (FFI+daemon, local+network) |
| Diagnostics export | Real | Unsupported | Unsupported | Unsupported |
| Localization (i18n) | Real (3 locales) | Partial (JS i18n) | Unsupported | Unsupported |
| Import flows | Real (magnet/torrent) | Unsupported | Unsupported | Unsupported |
| Shell/share integration | Real (registry) | Unsupported | Unsupported | Unsupported |
| Background behavior | Real (daemon) | Partial (SW) | Real (foreground service+daemon) | Foundation (embedded daemon) |
| Same-network discovery | Real (mDNS) | Unsupported | Partial (libp2p mDNS via daemon) | Partial (libp2p mDNS via daemon) |
| External peer retrieval | Partial (DHT) | Unsupported | Partial (DHT via daemon) | Partial (DHT via daemon) |
| Release packaging | Real (MSI/EXE/ZIP) | N/A (static site) | Foundation (APK) | Stub (Xcode) |
| Security posture | Audited + hardened | Audited + hardened | Audited (1 critical open) | Not audited |
| Distress wipe | Real | Unsupported | Real (FFI+Keystore) | Real (FFI) |
| Cross-device retrieval | Partial (mDNS+DHT) | Unsupported | Partial (daemon networking) | Partial (daemon networking) |
| Directed private sharing | Real (CLI+GUI+Web) | Real (Web+Daemon) | Real (Native+WebView) | Partial (retrieval-first, Inbox only) |

**Legend**: Real = validated and working. Partial = implemented but not fully validated. Foundation = code exists, not user-testable. Stub = binding/shell only. Unsupported = intentionally absent.

---

## 3. Recommended Milestone Order

### Milestone 1: Windows Broader-Tester Readiness

**Why now**: Windows is the only shipping surface. Cross-device validation (Stage 1) is in progress with the mDNS fix. The immediate bottleneck is proving same-network peer discovery works, then progressing through VPN stages.

**What it unlocks**: Confidence to distribute beta to external testers. Validated cross-device retrieval. Honest install/upgrade/uninstall lifecycle on non-dev machines.

**What it postpones**: Android network integration, iOS retrieval wiring, web networking.

**Concrete tasks**:
1. Complete `windows-staged-cross-device-validation.md` Stages 1-3
2. Fix any findings from cross-device testing
3. Code signing certificate (eliminates SmartScreen friction)
4. External tester distribution via `windows-broader-tester-expansion.md`

### Milestone 2: Android Cross-Device Validation *(architecture decided, directed sharing implemented)*

**Status**: Embedded daemon architecture chosen and implemented. Full directed sharing UI (Send/Inbox/Outbox) in native Compose + WebView. Remaining work is cross-device validation.

**What it unlocks**: Proven Windows↔Android directed share exchange. Confidence that the embedded daemon approach works on real devices.

**What it postpones**: Android production hardening (persistent reconnect, i18n), App Store distribution.

**Concrete tasks**:
1. ~~Evaluate networking architecture~~ → **DECIDED: embedded daemon via FFI**
2. ~~Implement directed sharing UI~~ → **DONE: Send/Inbox/Outbox screens + WebView bridge**
3. Complete `android-staged-validation.md` (build → emulator → device → network)
4. Wire Keystore wrapping into FFI key lifecycle (C-1 from security audit)
5. Cross-device validation: Windows→Android and Android→Windows directed share exchange

### Milestone 3: Web Scope Hardening and Honest Positioning

**Why now**: Web/WASM is functional and security-audited, but its scope is unclear. It cannot discover peers or retrieve from the network. Its value proposition needs to be defined: is it a standalone tool, a demo, or a companion to the desktop client?

**What it unlocks**: Clear product positioning for web. Honest README/docs that don't imply parity with desktop.

**What it postpones**: Web networking (requires WebRTC or relay server, fundamentally different from libp2p).

**Concrete tasks**:
1. Define web product scope: local-only dissolution tool, or future networked client?
2. If local-only: document limitations honestly, position as "portable dissolution"
3. If future-networked: design relay/WebRTC bridge architecture (ADR needed)
4. Browser compatibility testing (Chrome, Firefox, Edge, Safari WASM support)

### Milestone 4: iOS Cross-Device Validation *(architecture decided, retrieval-first implemented)*

**Status**: Embedded daemon implemented (shared FFI with Android). Retrieval-first UI (Inbox with challenge display, password retrieval, delete) in SwiftUI + WebView. Sending intentionally deferred.

**What it unlocks**: Proven Windows→iOS directed share retrieval. Validated retrieval-first product surface.

**What it postpones**: iOS sending support, App Store distribution, i18n.

**Concrete tasks**:
1. ~~Implement retrieval-first UI~~ → **DONE: Inbox tab + WebView bridge**
2. Complete `ios-staged-validation.md` (simulator → device → retrieval loop)
3. Cross-device validation: Windows→iOS directed share retrieval
4. Real device testing (Xcode + cargo cross-compilation required)

### Milestone 5: Shared Protocol/Support/Release Convergence

**Why now**: Only after individual surfaces are validated. This milestone reduces fragmentation.

**What it unlocks**: Unified versioning, cross-platform compatibility guarantees, shared test vectors.

**What it postpones**: Nothing — this is maintenance work.

**Concrete tasks**:
1. Cross-platform share format compatibility tests (WASM ↔ core ↔ FFI)
2. Unified version stamp and release cadence
3. Shared test vectors for dissolution/retrieval
4. README platform maturity section (honest, per-surface)

---

## 4. Shared Backend and Protocol Convergence

### What is truly shared

- **Miasma Protocol v1**: AES-256-GCM + Reed-Solomon + Shamir SSS + BLAKE3 MID. Identical pipeline across miasma-core, miasma-wasm, and miasma-ffi.
- **Share format**: bincode serialization, MiasmaShare struct fields, MID computation — protocol-compatible across all implementations.
- **Content ID format**: `miasma:<base58>` with BLAKE3 digest.

### What is platform-specific by design

- **miasma-core**: Full networking (libp2p, DHT, relay, onion, trust). Desktop/daemon only.
- **miasma-wasm**: Browser-compatible reimplementation. No networking. WASM memory model.
- **miasma-ffi**: UniFFI bridge exposing local operations + embedded daemon (full networking) to Kotlin/Swift.
- **miasma-desktop**: egui GUI. Windows-specific (fonts, registry, CREATE_NO_WINDOW).
- **miasma-bridge**: BitTorrent import. Desktop/CLI only.

### What should be unified next

1. **Cross-platform test vectors**: A shared set of known-good dissolution/retrieval vectors to verify protocol compatibility across miasma-core, miasma-wasm, and miasma-ffi.
2. **FFI networking**: ~~The biggest gap.~~ **RESOLVED** — embedded daemon via FFI chosen and implemented. MiasmaNode + DaemonServer + HTTP bridge run within the app process. Both Android and iOS use this architecture.

---

## 5. Validation Strategy by Platform

### Windows
1. Unit tests (480, automated)
2. Smoke tests (13 scenarios, automated)
3. Installer lifecycle (install/upgrade/uninstall, semi-automated)
4. Same-network cross-device (Stage 1 — in progress)
5. VPN cross-device (Stage 2 — pending Stage 1)
6. Hostile network cross-device (Stage 3 — pending Stage 2)
7. External tester expansion (pending Stage 1-3 completion)

### Web/PWA
1. Unit tests (27 native + 4 compat, automated)
2. Security audit (complete — all CRITICAL/HIGH/MEDIUM fixed)
3. Browser compatibility testing (not started)
4. Offline/PWA behavior testing (not started)
5. Cross-platform share format compatibility (not started)

### Android
1. Security audit (complete — 1 CRITICAL open: Keystore integration)
2. Build reproducibility (`android-mobile-node-foundation.md`)
3. Emulator testing (`android-staged-validation.md` Stage 2)
4. Real device testing (Stage 3)
5. Network behavior testing (Stage 4 — requires FFI networking)

### iOS
1. Build reproducibility (`ios-retrieval-client-foundation.md`)
2. Simulator testing (`ios-staged-validation.md` Stage 2)
3. Real device testing (Stage 3)
4. Real retrieval loop (Stage 4 — requires FFI networking or local shares)

---

## 6. Release and Versioning Strategy

### Versioned together (workspace)
All Rust crates share workspace version (currently 0.3.1). This is correct — they are co-developed and protocol-compatible.

### Platform-specific beta status
- **Windows**: `v0.3.1-beta.1` — the only surface that uses version in user-facing artifacts (MSI, Start Menu, about screen)
- **Web**: No versioned release. Static site served from `web/` directory. Version visible via `protocol_version()` WASM export.
- **Android**: No versioned release. APK version would come from `build.gradle`.
- **iOS**: No versioned release.

### README and release notes
- README should include a "Platform Maturity" section with the matrix from Section 2
- Release notes should be Windows-focused until other platforms ship user-facing builds
- Each platform's beta status should be stated explicitly (not implied by workspace version)

### Avoiding same-version confusion
The 0.3.0 → 0.3.0 upgrade issue (same version, different binaries with mDNS fix) happened because the workspace version wasn't bumped for a behavioral fix. The version is now 0.3.1. Going forward: **any binary change that requires re-distribution must bump the patch version.**

---

## 7. What Should NOT Be Worked On Yet

1. **Web networking** — Requires fundamental architecture decision (WebRTC, relay server, or hybrid). Not worth designing until web product scope is defined.
2. **iOS sending support** — iOS is retrieval-first by design. The embedded daemon has full capability, but Send/Outbox UI is explicitly deferred. Adding it now would blur the product distinction.
3. **Code signing** — Important for tester expansion but does not block current validation work. Should happen between Milestone 1 cross-device validation and external distribution.
4. **Constant-rate traffic shaping** — Listed in README roadmap but is a deep protocol change. No user-facing value until cross-network retrieval is proven.
5. **External security audit** — Premature until cross-device validation is complete and the product surface is stable.
6. **Multi-language Android/iOS** — Localization should wait until the mobile UIs are validated in English first.

---

## 8. Immediate Next Task Per Platform

| Platform | Next Task | Existing Task File |
|---|---|---|
| Windows | Complete Stage 1 cross-device validation (mDNS fix deployed, retry pending) | `docs/tasks/windows-staged-cross-device-validation.md` |
| Android | Cross-device directed sharing validation (Windows↔Android exchange) | `docs/tasks/android-staged-validation.md` |
| Web | Define product scope (local-only vs future-networked) | None — needs new decision, not a task file |
| iOS | Cross-device retrieval validation (Windows→iOS directed share retrieval) | `docs/tasks/ios-staged-validation.md` |

---

## 9. Cross-Platform Task Dependency Graph

```
Windows Stage 1-3 validation
    └── Windows broader-tester expansion
        └── Code signing
            └── External tester distribution

Android directed sharing (DONE: embedded daemon + native UI + WebView)
    └── Android cross-device validation (Windows↔Android exchange)
        └── Android production hardening (persistent reconnect, i18n)

iOS retrieval-first (DONE: embedded daemon + Inbox UI + WebView)
    └── iOS cross-device validation (Windows→iOS retrieval)
        └── iOS sending support (future milestone)

Web scope decision
    └── (if local-only) Documentation + browser testing
    └── (if networked) Relay architecture ADR

Cross-platform convergence (depends on Android + iOS validation)
    └── Shared test vectors (WASM ↔ core ↔ FFI)
    └── Unified version stamp and release cadence
```
