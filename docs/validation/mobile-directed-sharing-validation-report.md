# Mobile Directed Sharing — Cross-Device Validation Report

**Date**: 2026-03-23
**Version**: 0.3.1
**Author**: Automated validation + code review

---

## 1. What Android Can Really Do Now

### Implemented and Code-Complete
- **Embedded daemon**: MiasmaNode + DaemonServer + HTTP bridge run within the app process via FFI. Full libp2p networking (DHT, mDNS, relay).
- **Directed sharing (complete)**:
  - **Send**: Native Compose SendScreen — recipient contact, message, password, retention. Format validation on recipient contact (msk:…@PeerId).
  - **Inbox**: Native Compose InboxScreen — incoming envelopes with state badges, challenge code display with copy button, inline password retrieval, delete.
  - **Outbox**: Native Compose OutboxScreen — outgoing envelopes with state badges, challenge code entry for sender confirmation, revoke with confirmation dialog.
  - **WebView**: 7 JS bridge methods (sharingKey, directedInbox, directedOutbox, directedSend, directedConfirm, directedRetrieve, directedRevoke) all route through HTTP bridge.
- **HTTP client**: DirectedApi.kt with JSON parsing safety (try-catch on malformed responses).
- **Lifecycle**: Foreground service manages daemon. START_STICKY for restart resilience. Lifecycle-scoped polling detects daemon start, death, and port changes. Stale state cleared on service restart.
- **Security**: Keystore-backed master key wrapping (wrap-on-startup, unwrap-on-restart), distress wipe (FFI + Keystore deletion + wrapped blob deletion).
- **Daemon error propagation**: Daemon startup errors shown in UI (not just notification). ViewModel resets inbox/outbox when daemon dies.

### Known Limitations
- **No persistent reconnect**: Daemon restarts fresh on each app launch. Peer connections are not preserved across backgrounding.
- **No i18n**: English only. Localization deferred until UX is validated.
- **No background networking**: When app is backgrounded, foreground service keeps daemon alive but no push notification for incoming shares.
- **Keystore wrapping Phase 1**: Plaintext `master.key` remains on disk alongside encrypted blob (Rust FFI reads from file). Phase 2 would delete plaintext after node loads it.

### Architecture
```
Android App Process
├── MiasmaService (foreground service)
│   └── startEmbeddedDaemon() via FFI
│       ├── MiasmaNode (libp2p)
│       ├── DaemonServer
│       │   ├── HTTP bridge (127.0.0.1:{port})
│       │   └── IPC server
│       └── MiasmaCoordinator
├── Native Compose UI
│   ├── SendScreen → DirectedApi → HTTP bridge
│   ├── InboxScreen → DirectedApi → HTTP bridge
│   └── OutboxScreen → DirectedApi → HTTP bridge
└── WebView → JS bridge → HTTP bridge
```

---

## 2. What iOS Can Really Do Now

### Implemented and Code-Complete
- **Embedded daemon**: Same FFI as Android. MiasmaNode + DaemonServer + HTTP bridge in-process.
- **Directed sharing (retrieval-first)**:
  - **Inbox**: SwiftUI InboxView — incoming envelopes with colored state badges, challenge code display with text selection, expiry countdown ("Expires in Xh Ym"), SecureField for password, retrieve button with progress indicator, delete.
  - **No Send/Outbox**: Sending directed shares is explicitly deferred. This is a product decision, not a technical limitation.
  - **WebView**: 7 JS bridge methods all wired through HTTP bridge. `directedSend`/`directedOutbox` technically functional but not exposed in native UI.
- **Lifecycle**: Daemon auto-starts on app launch. Start/stop from Status tab.
- **Security**: Distress wipe via FFI. Long-press gesture on title (3s).
- **Foreground refresh**: Inbox and status refresh when app returns to foreground.

### Known Limitations
- **No sending**: iOS cannot initiate directed shares in this milestone. Inbox-only.
- **No persistent daemon**: Daemon does not survive app backgrounding. iOS suspends the process.
- **No i18n**: English only.
- **HTTP timeout added (15s)**: Previously no timeout — requests could hang indefinitely. Now times out after 15 seconds.
- **Synchronous HTTP model**: Uses DispatchSemaphore blocking (not async/await). Functional but not idiomatic Swift concurrency.
- **FFI stubs for IDE navigation**: Real build requires Xcode + cargo cross-compilation. Stubs allow code editing without Rust toolchain.
- **Background task placeholder**: Registered but immediately completes. No actual background work.
- **Web UI claims capabilities beyond native scope**: JS bridge exposes Send/Outbox methods, but iOS native UI doesn't use them. Web UI loaded in WebView might show Send tab.

### Architecture
```
iOS App Process
├── MiasmaApp (SwiftUI lifecycle)
│   └── MiasmaViewModel.startDaemon() via FFI
│       ├── MiasmaNode (libp2p)
│       ├── DaemonServer + HTTP bridge (127.0.0.1:{port})
│       └── MiasmaCoordinator
├── SwiftUI Tabs
│   ├── InboxView → HTTP GET/POST → HTTP bridge
│   ├── HomeView (sharing contact display, daemon status)
│   └── StatusView (daemon start/stop, emergency wipe)
└── WKWebView → JS bridge → HTTP bridge
```

---

## 3. Which Cross-Device Flows Were Actually Proven

### Proven by Automated Tests (36 tests, all passing)

| Flow | Test | Result |
|---|---|---|
| Full lifecycle (Pending→ChallengeIssued→Confirmed→Retrieved) | `directed_cross_device_full_lifecycle` | PASS |
| Password attempt exhaustion (3 wrong → PasswordFailed terminal) | `directed_password_attempt_exhaustion` | PASS |
| Challenge attempt exhaustion (3 wrong → ChallengeFailed terminal) | `directed_challenge_attempt_exhaustion` | PASS |
| Terminal state resurrection prevention (all 6 terminal states) | `directed_terminal_state_resurrection_prevention` | PASS |
| Revoked envelope not retrievable | `directed_revoked_envelope_not_retrievable` | PASS |
| Challenge file cleanup on all terminal states | `directed_challenge_cleanup_all_terminal_states` | PASS |
| Expiry timing boundary (exact second) | `directed_expiry_timing_boundary` | PASS |
| Cross-device sender revoke (both sides terminal, challenge cleaned) | `directed_cross_device_sender_revoke` | PASS |
| Multiple envelope isolation (operations don't cross-contaminate) | `directed_multiple_envelope_isolation` | PASS |
| Envelope crypto roundtrip (ECDH + Argon2id + ChaCha20-Poly1305) | `directed_envelope_crypto_roundtrip` | PASS |
| Wrong password rejection | `directed_wrong_password_rejection` | PASS |
| Wrong recipient rejection | `directed_wrong_recipient_rejection` | PASS |
| Envelope tampering detection | `directed_envelope_tampering_detection` | PASS |
| Challenge constant-time verification | `directed_challenge_wrong_code_same_length` | PASS |
| Inbox listing includes challenge code | `directed_inbox_listing_includes_challenge_code` | PASS |
| EnvelopeSummary JSON roundtrip (HTTP bridge transport format) | `directed_envelope_summary_json_roundtrip` | PASS |
| Sharing key/contact format roundtrip | `directed_sharing_key_format_roundtrip`, `directed_sharing_contact_format_roundtrip` | PASS |
| Recipient delete blocked on terminal state | `directed_recipient_delete_blocked_on_terminal` | PASS |
| Inbox size limit enforcement | `directed_inbox_size_limit` | PASS |
| Password salt uniqueness per envelope | `directed_password_salt_uniqueness` | PASS |

### What These Tests Prove
The core protocol layer — shared by Windows, Android, and iOS — correctly enforces:
- State machine integrity (no invalid transitions, terminal states are permanent)
- Cryptographic security (ECDH binding, password derivation, tampering detection)
- Challenge and password attempt exhaustion (fails closed at 3 attempts)
- Expiry enforcement (precise to the second)
- Challenge file cleanup (no orphaned secrets)
- Isolation between concurrent envelopes

### NOT Proven (Requires Real Devices)

| Flow | Blocker | Status |
|---|---|---|
| Windows → Android directed share exchange | Requires Android device with APK installed | Not tested |
| Android → Windows directed share exchange | Requires Android device on same network | Not tested |
| Windows → iOS directed share retrieval | Requires iOS device with Xcode build | Not tested |
| Android → iOS directed share retrieval | Requires both mobile devices | Not tested |
| Embedded daemon starts on real Android device | Requires ARM64 cross-compilation + real device | Not tested |
| Embedded daemon starts on real iOS device | Requires Xcode + Apple signing + real device | Not tested |
| mDNS peer discovery across Android/iOS | Requires devices on same network | Not tested |
| DHT retrieval from mobile device | Requires network with bootstrap peers | Not tested |
| App backgrounding + daemon survival (Android) | Requires real device lifecycle testing | Not tested |
| App backgrounding + daemon suspension (iOS) | Requires real device lifecycle testing | Not tested |

---

## 4. Security and Lifecycle Cases Validated

### Security Boundaries (All Automated)

| Boundary | Enforcement | Test Coverage |
|---|---|---|
| 3 wrong challenge attempts → ChallengeFailed (terminal) | Counter in envelope, fails closed | `directed_challenge_attempt_exhaustion` |
| 3 wrong password attempts → PasswordFailed (terminal) | Counter in envelope, fails closed | `directed_password_attempt_exhaustion` |
| Terminal states remain terminal | `is_terminal()` + `expire_all()` skips terminal | `directed_terminal_state_resurrection_prevention`, `directed_expire_all_skips_terminal` |
| Deleted/revoked items cannot be resurrected | Protocol-layer enforcement (not storage-layer) | `directed_deleted_envelope_cannot_resurrect`, `directed_revoked_envelope_not_retrievable` |
| Challenge files cleaned up on terminal | `cleanup_challenge()` + `expire_all()` | `directed_challenge_cleanup_all_terminal_states`, `directed_challenge_file_cleanup_on_terminal` |
| Wrong recipient cannot decrypt | ECDH keypair binding | `directed_wrong_recipient_rejection` |
| Wrong password cannot decrypt | Argon2id + AEAD tag verification | `directed_wrong_password_rejection` |
| Envelope tampering detected | AEAD authentication | `directed_envelope_tampering_detection` |
| Challenge verification constant-time | BLAKE3 + `subtle::ct_eq` | `directed_challenge_wrong_code_same_length` |
| Password salt unique per envelope | Random 32-byte salt | `directed_password_salt_uniqueness` |
| Inbox size limit (10,000 envelopes) | Check before save | `directed_inbox_size_limit` |

### Lifecycle (Partially Validated)

| Scenario | Android | iOS |
|---|---|---|
| Cold start → daemon running | Code path exists (MiasmaService.onStartCommand) | Code path exists (ContentView.onAppear → startDaemon) |
| App foreground → refresh | ViewModel polls every 1s | .onReceive(willEnterForegroundNotification) refreshes inbox+status |
| Daemon error → fallback | Falls back to local-only initializeNode() | Falls back to local-only initializeNode() |
| Distress wipe | FFI + Keystore deletion | FFI deletion + daemon stop |
| Concurrent daemon start | Not guarded (race condition possible) | Guarded by isDaemonStarting flag |
| HTTP timeout | Not explicitly set (URLConnection defaults) | 15s timeout on DispatchSemaphore |

---

## 5. What Remains Fragile or Incomplete

### Critical Gaps (Block Beta Confidence)
1. **No real-device validation on either mobile platform**. All automated tests run against the Rust core library, not the mobile app binaries. The FFI boundary, ARM64 cross-compilation, and Android/iOS runtime behavior are untested.
2. **No cross-device directed share exchange has been observed**. The protocol is proven in isolation, but the full path (daemon startup → peer discovery → protocol exchange → HTTP bridge → UI display) has not been exercised end-to-end.
3. **Android Keystore integration (C-1 critical)**: Security audit flagged this. Keystore wrapping exists in code but has not been validated on a real device.

### Fragile Areas (Work But May Break Under Stress)
1. **Android daemon lifecycle**: START_STICKY service restart + 1s polling is a best-effort mechanism. Process death during retrieval could lose state.
2. **iOS daemon suspension**: iOS will suspend the process when backgrounded. Daemon connections will drop. No reconnect mechanism.
3. **Error message quality**: Improved but still partially raw exception messages in some paths.
4. **WebView scope mismatch on iOS**: Web UI exposes Send/Outbox methods that the native iOS UI intentionally omits. A user in WebView tab could attempt to send, which would succeed at the daemon level but not be visible in native Inbox/Outbox.

### Not Yet Implemented
1. **Push notifications for incoming shares** (both platforms)
2. **Background sync** (both platforms)
3. **i18n** (both platforms — English only)
4. **Android release packaging** (signed APK/AAB, ProGuard, version management)
5. **iOS release packaging** (App Store signing, TestFlight)

---

## 6. Recommended Next Milestone

### Android Cross-Device Validation and Beta Hardening

**Why this, not iOS**: Android has the more complete surface (send + receive), the architecture is proven in code, and it shares the FFI with iOS. Proving Android works on a real device directly de-risks iOS.

**Concrete tasks**:
1. **ARM64 cross-compilation**: Build miasma-ffi for `aarch64-linux-android` target. Verify APK includes the correct .so.
2. **Real device test**: Install APK on a physical Android device. Start daemon, observe HTTP bridge port.
3. **Windows → Android exchange**: Send a directed share from Windows CLI, retrieve on Android. Document the full flow.
4. **Android → Windows exchange**: Send from Android, confirm + retrieve on Windows.
5. **Lifecycle testing**: Background the app, return, verify daemon survives. Kill the app, relaunch, verify clean restart.
6. **Keystore validation**: Verify Keystore-backed master key survives app restart and is not extractable.
7. **Fix WebView scope on iOS**: Either restrict the web UI loaded in iOS WebView to retrieval-only, or document that WebView has full capability intentionally.

**Success criteria**: At least one end-to-end Windows↔Android directed share exchange observed and documented with device model, OS version, and network conditions.

---

## Appendix: Test Suite Summary

| Suite | Count | Failures |
|---|---|---|
| miasma-core unit tests | 288 | 0 |
| miasma-core adversarial tests | 148 | 0 |
| miasma-core integration tests | 53 (1 ignored) | 0 |
| miasma-desktop tests | 16 | 0 |
| miasma-ffi tests | 0 (no unit tests) | 0 |
| miasma-wasm tests | 29 | 0 |
| miasma-wasm compat tests | 4 | 0 |
| miasma-core binary tests | 31 | 0 |
| **Total** | **569 (+33 WASM)** | **0** |

Of the 148 adversarial tests, **36 are directed sharing** (12 new in this pass):
- 24→36: +12 cross-device lifecycle, security boundary, and state-machine tests
