# Miasma Connectivity Model

**Date**: 2026-03-23
**Version**: 0.3.1 (post-mobile-directed-sharing)

This document describes the real current network posture of each active
surface. It is intentionally conservative.

---

## 1. Connectivity Classification

| Surface | Classification | Network Capable Today | Directed Sharing Today |
|---|---|---:|---:|
| Windows Desktop | Full network participant | Yes | Yes (complete) |
| Web in Desktop Browser | Host-assisted bridge | Yes, via local daemon HTTP bridge | Yes (complete) |
| Standalone Browser (no daemon) | Local-only fallback | No | No |
| Android App | Embedded daemon participant | Yes, via embedded daemon + HTTP bridge | Yes (send + receive) |
| Android-Hosted Web | Daemon-assisted bridge | Yes, via embedded daemon HTTP bridge | Yes (complete via web surface) |
| iOS App | Embedded daemon (retrieval-first) | Yes, via embedded daemon + HTTP bridge | Retrieval-first (inbox/confirm/retrieve/delete) |
| iOS-Hosted Web | Daemon-assisted bridge | Yes, via embedded daemon HTTP bridge | Retrieval-first (via web surface) |

---

## 2. Surface Details

### Windows Desktop

**Classification**: Full network participant

Windows remains the reference surface.

Current capabilities:

- native daemon process
- libp2p networking
- same-network peer discovery
- DHT-backed retrieval/publish path
- CLI, desktop GUI, and daemon IPC
- **complete directed sharing lifecycle**

Directed sharing status:

- protocol and crypto: fully implemented
- CLI: all 7 commands (sharing-key, send, confirm, receive, revoke, inbox, outbox)
- desktop GUI: full Send, Inbox, and Outbox panels
  - sender confirmation with challenge code entry in Outbox
  - recipient challenge display with copy button in Inbox
  - inline password entry for retrieval
  - colored state badges for all 9 envelope states
  - filename and file size display
  - revoke/delete from both Inbox and Outbox
  - 3-locale support (EN/JA/ZH-CN) including all new strings
- security hardening:
  - challenge file cleanup on terminal states
  - terminal state enforcement (recipient delete blocked on terminal)
  - inbox/outbox size limit (10,000 envelopes)
  - password never persisted to disk

### Web in Desktop Browser

**Classification**: Host-assisted bridge

The desktop browser web surface connects through the local daemon via the
HTTP bridge at `http://127.0.0.1:17842`.

Current capabilities:

- local-only WASM fallback remains available
- connected mode via HTTP bridge
- daemon-backed status/publish/retrieve flow
- **complete directed sharing flow in connected mode**:
  - Send panel with file upload, recipient contact, password, retention
  - Inbox panel with inline password retrieval (no more prompt())
  - **Outbox panel** with sender confirmation (challenge code entry)
  - colored state badges for all 9 envelope states
  - filename and file size display
  - revoke/delete from both Inbox and Outbox
  - connection status indicator (connected/local-only)
  - 3-locale support (EN/JA/ZH-CN) including all new strings

Current limitations:

- depends on local daemon availability
- browser validation still pending as end-to-end manual test
- standalone (no daemon) mode has no directed sharing capability

### Standalone Browser (No Daemon)

**Classification**: Local-only fallback

If no native host is present, the browser surface remains local-only.

Current capabilities:

- dissolve/retrieve in browser storage
- manual export/import
- PWA behavior

Current limitations:

- no peer discovery
- no network retrieval
- no directed sharing over the network

### Android App

**Classification**: Embedded daemon participant

Android runs an embedded daemon within the app process via FFI. The daemon
starts automatically with the foreground service and provides full libp2p
networking and an HTTP bridge on `127.0.0.1`.

Architecture decision: **Embedded daemon via FFI** — chosen because:
- Reuses the proven DaemonServer + HTTP bridge infrastructure
- No subprocess management needed (complex on Android)
- Both native Compose UI and WebView can access the HTTP bridge
- Same trust model as desktop (localhost-only binding)

Current capabilities:

- embedded MiasmaNode (libp2p, DHT, peer discovery)
- HTTP bridge on localhost (same endpoints as desktop)
- foreground service managing daemon lifecycle
- **directed sharing** (complete send + receive):
  - Send screen: recipient contact, message, password, retention
  - Inbox screen: challenge display, password-gated retrieval, state badges
  - Outbox screen: sender confirmation with challenge code entry, revoke
  - WebView: full directed sharing via JS bridge → HTTP bridge
- sharing contact display for cross-device exchange
- Keystore-backed master key wrapping
- distress wipe (FFI + Keystore deletion)

Current limitations:

- daemon binary size includes full libp2p stack
- no persistent reconnect across app restarts (daemon restarts fresh)
- cross-device validation requires manual testing
- no i18n yet (English only)

### Android-Hosted Web

**Classification**: Daemon-assisted bridge

The Android-hosted web surface runs in a WebView with a JavaScript bridge
that routes directed sharing operations through the embedded daemon's HTTP
bridge. When the daemon is running, the web surface has full directed
sharing capability equivalent to the desktop web surface.

### iOS App

**Classification**: Embedded daemon (retrieval-first)

iOS runs the same embedded daemon as Android, providing full networking.
However, the UI scope is intentionally retrieval-first: iOS can receive
and retrieve directed shares, but sending is deferred to a future milestone.

Architecture decision: **Same embedded daemon as Android** — chosen because:
- Shared FFI crate serves both platforms
- Retrieval requires network access (DHT, peer connections)
- Companion mode (connecting to a desktop daemon) was rejected as too fragile

Current capabilities:

- embedded MiasmaNode via FFI
- HTTP bridge on localhost
- **retrieval-first directed sharing**:
  - Inbox tab: list incoming shares, display challenge codes, state badges
  - Password-gated retrieval
  - Delete envelopes
  - Sharing contact display (for others to send to this device)
- WebView: directed sharing via JS bridge → HTTP bridge
- daemon lifecycle (start/stop from UI)
- distress wipe

Current limitations:

- **sending directed shares not supported in this milestone** (no Send/Outbox UI)
- no persistent daemon across app backgrounding
- cross-device validation requires manual testing on real hardware
- no i18n (English only)
- FFI stubs exist for IDE navigation; real build requires Xcode + cargo cross-compilation

### iOS-Hosted Web

**Classification**: Daemon-assisted bridge

Same as Android-hosted web: WKWebView with JS bridge routing through the
embedded daemon's HTTP bridge. Capability matches the native iOS scope
(retrieval-first).

---

## 3. Directed Sharing Support Matrix

| Surface | Send | Confirm | Receive | Revoke/Delete | Notes |
|---|---:|---:|---:|---:|---|
| Windows CLI | Yes | Yes | Yes | Yes | Complete — most direct path |
| Windows Desktop GUI | Yes | Yes | Yes | Yes | Complete — Send/Inbox/Outbox panels |
| Desktop Web + Daemon | Yes | Yes | Yes | Yes | Complete — all bridge endpoints wired |
| Standalone Browser | No | No | No | No | Local-only fallback |
| Android Native | Yes | Yes | Yes | Yes | Complete — Send/Inbox/Outbox screens via HTTP bridge |
| Android WebView | Yes | Yes | Yes | Yes | Complete — JS bridge → HTTP bridge |
| iOS Native | No | No | Yes | Yes | Retrieval-first — Inbox only, no Send/Outbox |
| iOS WebView | No | No | Yes | Yes | Retrieval-first — via JS bridge |

---

## 4. Honest Summary

Today:

- **Windows desktop is a complete directed-sharing product surface.** CLI,
  desktop GUI, and web (with daemon) all support the full lifecycle: send,
  challenge confirmation, password-gated retrieval, revoke, delete, inbox,
  and outbox with proper state visibility.
- **Desktop web is a real host-assisted directed-sharing client** when a
  local daemon is present.
- Standalone web remains local-only with no directed sharing.
- **Android is a complete directed-sharing mobile surface.** The embedded
  daemon provides full networking. Native Compose UI has Send, Inbox, and
  Outbox screens. WebView has full directed sharing via JS bridge.
  Windows → Android and Android → Windows directed share exchange is
  architecturally supported.
- **iOS is a retrieval-first directed-sharing surface.** The embedded
  daemon provides networking. Inbox with challenge display, password-gated
  retrieval, and delete are implemented. Sending is explicitly deferred —
  iOS cannot initiate directed shares in this milestone.
- **Hosted web on both Android and iOS** reflects native capability
  honestly: Android-hosted web has full directed sharing; iOS-hosted web
  has retrieval-first directed sharing.

What changed in this pass:

- FFI crate gained embedded daemon support (start/stop/port/contact)
- Android: MiasmaService starts embedded daemon with full networking
- Android: 3 new Compose screens (SendScreen, InboxScreen, OutboxScreen)
- Android: DirectedApi HTTP client for all directed sharing operations
- Android: WebBridgeActivity extended with 7 directed sharing JS methods
- Android: ViewModel extended with directed sharing state and operations
- iOS: MiasmaViewModel gains daemon lifecycle (start/stop)
- iOS: InboxView with challenge display, password retrieval, state badges
- iOS: ContentView gains Inbox tab, daemon auto-start on launch
- iOS: WebBridgeView extended with directed sharing JS methods
- iOS: FFI stubs updated with all new function signatures
- validate_data_dir extended to accept iOS paths (/var/mobile/, Library/)
- Documentation updated to reflect honest mobile capability
