# ADR-007: Web Surface Network Bridge Architecture

**Date**: 2026-03-23
**Status**: Accepted
**Supersedes**: N/A

## Context

The Miasma Web/PWA surface was local-only — dissolution and retrieval ran entirely in the browser via WASM, with no network connectivity.  This made it a useful portable tool but not a real Miasma client.  The web surface needed to connect to the Miasma network when opened from desktop, Android, or iOS.

## Decision

**Hybrid bridge architecture**: HTTP bridge for desktop, WebView bridge for mobile.

### Desktop: HTTP Bridge

The daemon exposes a lightweight HTTP/1.1 JSON API on `127.0.0.1:17842` alongside the existing TCP IPC.  The browser connects via `fetch()`.

- **Endpoints**: `GET /api/ping`, `GET /api/status`, `POST /api/publish`, `POST /api/retrieve`, `POST /api/wipe`
- **Binary encoding**: Base64 for publish data and retrieved content
- **CORS**: Wildcard `Access-Control-Allow-Origin: *` (safe because binding is localhost-only)
- **Security**: Same trust model as IPC — local process = local user
- **Port**: Fixed at 17842 (browser cannot read filesystem port files); falls back to OS-assigned if occupied

The handler reuses `process_request()`, the same function the IPC handler calls, guaranteeing behavioral parity.

### Android: WebView with JavaScript Bridge

The Android app hosts the web UI in a `WebView` loaded from app assets (`file:///android_asset/web/`).  A `@JavascriptInterface` object is injected as `window.miasma`, with methods that call through to UniFFI-generated Kotlin bindings.

### iOS: WKWebView with Message Handler

The iOS app hosts the web UI in a `WKWebView` loaded from app bundle resources.  A `WKScriptMessageHandler` handles JS→Swift messages, and a `WKUserScript` injects the `window.miasma` Promise-based bridge object at document start.

### Detection Order

The web app's `bridge.js` detects its environment at init:

1. `window.miasma` exists and `ping()` succeeds → **WebView** mode
2. `fetch('http://127.0.0.1:17842/api/ping')` succeeds → **HTTP** mode
3. Fallback → **Local-only** mode (WASM, no network)

### Connection State

The web app shows visible connection state:
- Green dot = connected (daemon/WebView bridge active)
- Gray dot = local-only (WASM fallback)
- Orange dot = connecting
- Red dot = error

## Alternatives Considered

### Browser-Native libp2p (WebTransport/WebRTC)

**Rejected.** libp2p 0.54's WASM support is immature.  WebTransport requires server-side support that Miasma peers don't provide.  WebRTC requires a signaling server and introduces incompatible NAT traversal challenges.  This would be a multi-month effort with no guaranteed success.

### Relay/Server-Assisted Bridge

**Rejected.** A central relay bridging browser requests to the DHT introduces a centralized trust point, contradicting Miasma's censorship-resistance design.  It also requires hosting infrastructure.

### Desktop Companion via WebSocket

**Considered but not primary.** WebSocket would work but HTTP is simpler for request-response API patterns.  HTTP also has better tooling (curl, browser devtools).  WebSocket could be added later for push-based status updates if needed.

## Consequences

### Positive

- Web surface becomes a real networked client on all three platforms
- Shared web UI codebase across desktop, Android, and iOS
- Zero new protocol work — reuses existing daemon request handler
- Local-only fallback preserved when no backend is available

### Negative

- Fixed HTTP port (17842) could conflict on some machines
- Android/iOS WebView bridge requires bundling web assets in the app
- Android FFI currently exposes local-only operations (no networking through FFI)
- iOS is retrieval-first — full node capabilities not available

### Platform Limitations (Honest)

- **Android**: FFI networking not yet exposed.  WebView bridge calls dissolve/retrieve locally, not through the P2P network.  Full network participation requires FFI networking work (Milestone 2).
- **iOS**: Same FFI limitation.  Retrieval-first by design.
- **Desktop**: Full network capability via daemon HTTP bridge.  This is the only platform where the web surface has real P2P network access today.

## Implementation

- `crates/miasma-core/src/daemon/http_bridge.rs` — HTTP bridge (hyper 1.x)
- `web/js/bridge.js` — Bridge abstraction layer
- `android/.../WebBridgeActivity.kt` — Android WebView + JS bridge
- `ios/.../WebBridgeView.swift` — iOS WKWebView + message handler
