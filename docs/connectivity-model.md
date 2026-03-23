# Miasma Connectivity Model

**Date**: 2026-03-23
**Version**: 0.3.1 (post-directed-sharing completion)

This document describes the real current network posture of each active
surface. It is intentionally conservative.

---

## 1. Connectivity Classification

| Surface | Classification | Network Capable Today | Directed Sharing Today |
|---|---|---:|---:|
| Windows Desktop | Full network participant | Yes | Yes (complete) |
| Web in Desktop Browser | Host-assisted bridge | Yes, via local daemon HTTP bridge | Yes (complete) |
| Standalone Browser (no daemon) | Local-only fallback | No | No |
| Android App | Local-only native shell | No | No |
| Android-Hosted Web | Local-only hosted bridge | No | No |
| iOS App | Retrieval-first groundwork | Not yet validated | No |
| iOS-Hosted Web | Retrieval-first hosted bridge | Not yet validated | No |

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

**Classification**: Local-only native shell

Android has UI, service, and FFI groundwork, but does not yet have a completed,
validated network-capable path for the current milestone.

Current capabilities:

- local/native app shell
- local operations through FFI
- hosted web surface path exists conceptually

Current limitations:

- no completed validated network participation in this milestone
- **no directed sharing UI screens implemented**
- infrastructure (FFI bridge, activity, service) exists for future integration

### Android-Hosted Web

**Classification**: Local-only hosted bridge

The Android-hosted web surface exists, but it does not yet expose a completed
network-capable path equivalent to desktop-hosted web.

### iOS App

**Classification**: Retrieval-first groundwork

iOS remains the least mature surface. It should be treated as groundwork, not
as a validated network participant.

Current limitations:

- no validated end-to-end network retrieval for this milestone
- **no directed sharing views implemented**

### iOS-Hosted Web

**Classification**: Retrieval-first hosted bridge

Same honesty boundary as the iOS app: this is groundwork, not a validated
network-capable surface today.

---

## 3. Directed Sharing Support Matrix

| Surface | Send | Confirm | Receive | Revoke/Delete | Notes |
|---|---:|---:|---:|---:|---|
| Windows CLI | Yes | Yes | Yes | Yes | Complete — most direct path |
| Windows Desktop GUI | Yes | Yes | Yes | Yes | Complete — Send/Inbox/Outbox panels |
| Desktop Web + Daemon | Yes | Yes | Yes | Yes | Complete — all bridge endpoints wired |
| Standalone Browser | No | No | No | No | Local-only fallback |
| Android | No | No | No | No | Not implemented |
| iOS | No | No | No | No | Not implemented |

---

## 4. Honest Summary

Today:

- **Windows desktop is a complete directed-sharing product surface.** CLI,
  desktop GUI, and web (with daemon) all support the full lifecycle: send,
  challenge confirmation, password-gated retrieval, revoke, delete, inbox,
  and outbox with proper state visibility.
- **Desktop web is a real host-assisted directed-sharing client** when a
  local daemon is present. The outbox, sender confirmation, and inline
  password retrieval are all available.
- Standalone web remains local-only with no directed sharing.
- **Android and iOS do not have directed sharing.** The protocol and crypto
  infrastructure is ready for them, but no UI screens have been implemented
  for either mobile platform.

What changed in this pass:

- Desktop GUI gained Outbox tab with sender challenge confirmation
- Desktop GUI inbox enhanced with state badges, filename, error states
- Web gained outbox view with sender confirmation flow
- Web inbox replaced prompt() with inline password form
- Security: challenge file cleanup, terminal state enforcement, inbox size limit
- 8 new adversarial tests (136 total)
