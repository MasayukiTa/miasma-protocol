# Miasma Connectivity Model

**Date**: 2026-03-23  
**Version**: 0.3.1

This document describes the real current network posture of each active
surface. It is intentionally conservative.

---

## 1. Connectivity Classification

| Surface | Classification | Network Capable Today | Directed Sharing Today |
|---|---|---:|---:|
| Windows Desktop | Full network participant | Yes | Yes |
| Web in Desktop Browser | Host-assisted bridge | Yes, via local daemon HTTP bridge | Partial |
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
- directed sharing core flow

Directed sharing status:

- protocol and crypto are implemented
- CLI path exists
- desktop GUI first pass exists
- still needs full end-to-end validation and UX completion

### Web in Desktop Browser

**Classification**: Host-assisted bridge

The desktop browser web surface can now connect through the local daemon by
using the HTTP bridge. It is no longer purely local-only when opened on a
desktop machine with a running daemon.

Current capabilities:

- local-only WASM fallback remains available
- connected mode via `http://127.0.0.1:17842`
- daemon-backed status/publish/retrieve flow
- first-pass directed sharing bridge endpoints and UI hooks

Current limitations:

- depends on local daemon availability
- browser validation is still pending
- sender confirmation / outbox UX is not yet fully finished
- fallback vs connected mode still needs clearer product behavior

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
- no validated directed sharing flow

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
- no validated directed sharing support

### iOS-Hosted Web

**Classification**: Retrieval-first hosted bridge

Same honesty boundary as the iOS app: this is groundwork, not a validated
network-capable surface today.

---

## 3. Directed Sharing Support Matrix

| Surface | Send | Confirm | Receive | Revoke/Delete | Notes |
|---|---:|---:|---:|---:|---|
| Windows CLI | Yes | Yes | Yes | Yes | Most complete current path |
| Windows Desktop GUI | Partial | Not fully complete | Partial | Partial | First pass exists; UX completion still required |
| Desktop Web + Daemon | Partial | Not fully complete | Partial | Partial | Bridge exists; product flow still incomplete |
| Standalone Browser | No | No | No | No | Local-only fallback |
| Android | No | No | No | No | Not completed |
| iOS | No | No | No | No | Not completed |

---

## 4. Honest Summary

Today:

- Windows is the only real network-capable product surface.
- Desktop web is now a real host-assisted network client when a local daemon is
  present.
- Standalone web remains local-only.
- Android and iOS are not yet complete directed-sharing clients.

That is the baseline the next task should close from.
