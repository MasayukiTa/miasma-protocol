# Reconnect Hardening & Field Proof Report

**Date**: 2026-03-31
**Environment**: Windows 11 Enterprise 10.0.22631, x86_64
**Network**: Corporate LAN with GlobalProtect active
**Miasma version**: 0.3.1
**Rust**: rustc 1.93.1

---

## Executive Summary

Track 1.5 (reconnect self-heal) delivered a real code fix and field-proven
automatic recovery. Tracks 2-4 are bounded by environment constraints
(no Android NDK/device, Tor installation prohibited) and one architectural
finding (directed sharing is incompatible with Tor by design).

---

## Track 1.5: Reconnect / Bootstrap Self-Heal — FIXED & FIELD-PROVEN

### Root Cause

Two bugs prevented automatic reconnection after peer crash/restart:

1. **Bootstrap peers not saved for recovery**: `DhtCommand::AddBootstrapPeer`
   handler (the path used by CLI startup) did not save peers to the
   `bootstrap_peers` recovery vector. The direct `add_bootstrap_peer()` method
   did save them, but the DhtCommand route — the only route used in production
   — left the vector empty.

2. **Event-driven timer starvation**: Periodic self-heal checks ran on
   `event_tick % 500`, where `event_tick` increments only on SwarmEvents.
   With zero peers and no network traffic, events arrive at ~1/second (ping
   timeouts), so 500 events takes ~8 minutes — far too slow for recovery.

### Fix (2 changes in `network/node.rs`)

**Change 1 — Time-based bootstrap re-dial**:
```
Added tokio::time::interval(30s) to the run() select loop.
periodic_bootstrap_redial() fires every 30 seconds, independently of
swarm events. When connected_peers == 0:
  - Re-dials all configured bootstrap peers
  - Respects flap damping
  - Resets circuit breaker for bootstrap peers (they are the lifeline)
  - Logs attempts at INFO level for diagnostics
```

**Change 2 — Bootstrap peer persistence**:
```
DhtCommand::AddBootstrapPeer handler now saves (peer_id, addr) to
self.bootstrap_peers (deduped), matching the direct method's behavior.
```

### Field Test Evidence

```
Phase 1: Both nodes connected (peers: 1)
Phase 2: Node A force-killed → Node B detects loss (peers: 0)
Phase 3: Node A restarted on same fixed port
         → 30s later: bootstrap_redial.attempted peers=1
         → Immediately: Connected: 12D3KooWGcf...
         → Both nodes: Connected peers: 1
```

**Recovery time**: ~30 seconds (one timer interval).

### Test Results

- 412 unit tests: all pass
- 182 adversarial tests: all pass
- No regressions

### Interaction with Existing Self-Heal

| Component | Behavior |
|-----------|----------|
| Flap damping | Respected — redial skipped during damping window |
| Reconnection scheduler | Bootstrap peers exempt from circuit breaker |
| PartialFailureDetector | Still runs on event_tick for non-bootstrap recovery |
| Dial backoff | Still applies per-attempt, but reset on timer for bootstrap |

---

## Track 2: Android Toolchain & ARM64 Readiness

### What Was Done

| Step | Status |
|------|--------|
| `aarch64-linux-android` Rust target installed | DONE |
| `cargo-ndk` v4.1.2 installed | DONE |
| `cargo ndk build` attempted | BLOCKED — NDK not found |
| `cargo build --target aarch64-linux-android` attempted | BLOCKED — `aarch64-linux-android-clang` not found |
| miasma-ffi host build (Windows DLL) | DONE |
| Java version check | Java 1.8 found (needs 17+ for Android) |
| Gradle wrapper check | `gradle/wrapper/` directory empty, no gradlew |
| Android SDK/NDK search | Not present on host |

### Exact Blocker Chain

```
APK build requires:
  1. Android NDK (provides aarch64-linux-android-clang)  ← MISSING
     └── enables: cargo ndk build → libmiasma_ffi.so (ARM64)
  2. uniffi-bindgen (generates MiasmaFfi.kt from .so)   ← Available but needs .so
  3. Gradle wrapper (gradlew + wrapper jar)              ← MISSING
  4. Android SDK (provides build-tools, platform)        ← MISSING
  5. Java 17+ (Gradle requirement)                       ← Have Java 8 only

Each is sequential — 1 blocks 2, 3+4+5 block APK assembly.
```

### What Is Ready (Pre-NDK)

- Rust source: 13 FFI functions in `miasma-ffi/src/lib.rs` (713 lines)
- Kotlin source: 18 files, 3,417 lines covering all features
- Build scripts: `build.gradle.kts` with JNI lib configuration
- UniFFI stubs: 64-line placeholder (5 of 13 functions)
- Android Manifest: complete with permissions, services, activities

### What Remains for Build-Ready

1. Install Android NDK (command-line tools or Android Studio)
2. Run `cargo ndk -t arm64-v8a build --release -p miasma-ffi`
3. Generate UniFFI Kotlin bindings from the .so
4. Add Gradle wrapper (`gradle wrapper` command)
5. Upgrade Java to 17+
6. Run `./gradlew assembleDebug`

### Honest Assessment

Android is **toolchain-partially-ready, build-blocked**. The Kotlin and Rust
source is complete. The gap is entirely toolchain/environment: NDK, Gradle
wrapper, Java version. These are standard setup steps, not code problems.

---

## Track 3: Windows ↔ Android Directed Sharing — BLOCKED

**Blocker**: Track 2 (no Android build → no APK → no device test).

**What Code Analysis Confirms**:
- Directed sharing uses libp2p request-response protocol (`/miasma/directed/1.0.0`)
- Android uses the same FFI → embedded daemon → HTTP bridge → same P2P protocol
- The wire format is identical between platforms (bincode-serialized `DirectedRequest`)
- No platform-specific code in the directed sharing path

**What Would Need to Happen**:
1. Build APK (Track 2 unblocked)
2. Install on ARM64 device
3. Start embedded daemon
4. Connect to same LAN as Windows node
5. Exchange sharing contacts
6. Run full send→challenge→confirm→receive→revoke cycle

**Risk Assessment**: Low risk of platform-specific failures because the protocol
is pure Rust running in the same daemon. The main unknown is Android foreground
service lifecycle (app backgrounding, daemon death detection).

---

## Track 4: Tor Directed Sharing — ARCHITECTURAL BLOCKER

### Finding: Directed Sharing Is Incompatible with Tor by Design

This is NOT an environment blocker — it's a code architecture issue that would
prevent Tor directed sharing even if Tor were available.

### The Break Point

**Directed sharing uses libp2p request-response protocol**, which requires
bidirectional P2P connectivity. Tor SOCKS5 is only integrated into the
**payload transport pipeline** (share fetches for dissolve/retrieve), not
the P2P protocol layer.

| Component | Transport Used | Tor-Aware? |
|-----------|---------------|------------|
| dissolve/retrieve (shares) | Payload transport (WSS/TCP/Tor/SS) | YES |
| directed send (invite) | libp2p request-response | NO |
| directed confirm | libp2p request-response (sync) | NO |
| directed receive | libp2p request-response | NO |
| directed revoke | libp2p request-response | NO |

### Code Evidence

1. **Tor SOCKS5 scope** (`transport/tor.rs:206-220`):
   Only used in `fetch_share()` — outbound share payload fetches.

2. **Directed sharing transport** (`network/node.rs:2004-2008`):
   Uses `swarm.behaviour_mut().directed_sharing.send_request(&peer_id, request)`
   — raw libp2p, no proxy, no relay circuit wrapping.

3. **Confirm requires sync response** (`daemon/mod.rs:1313-1319`):
   `coord.send_directed_request(peer_id, ...).await` waits for inbound
   response, requiring the recipient to be directly reachable.

### What Would Break

| Scenario | Invite | Confirm | Receive |
|----------|--------|---------|---------|
| Both on same LAN (no Tor) | WORKS | WORKS | WORKS |
| Both behind Tor | FAILS | FAILS | FAILS |
| Sender behind Tor, recipient not | MAY WORK* | FAILS | FAILS |
| Recipient behind Tor, sender not | MAY WORK* | FAILS | FAILS |

*May work if mDNS or relay circuit provides reachability, but Tor SOCKS5 is
not used for the libp2p connection.

### What Would Fix It

To make directed sharing work over Tor, the protocol would need:
1. Route directed requests through relay circuits (like onion retrieval does)
2. Or tunnel directed request-response through the HTTP bridge over Tor SOCKS5
3. Or implement Tor hidden service support in libp2p

This is a non-trivial architectural change, not a configuration issue.

### Honest Boundary

**Directed sharing over Tor is not blocked by environment — it is blocked by
architecture.** The protocol currently assumes bidirectional P2P connectivity
that Tor SOCKS5 cannot provide. Even with Tor installed, directed sharing
would fail at the confirm step.

This should be clearly stated in release documentation: "Directed sharing
requires direct or relay P2P connectivity. It does not work over Tor SOCKS5."

---

## Completion Checklist

| Requirement | Status |
|-------------|--------|
| Reconnect/self-heal improved with evidence | DONE — 30s auto-recovery, field-tested |
| Android build readiness materially advanced | DONE — target+cargo-ndk installed, exact blocker chain documented |
| Win↔Android directed sharing proven or blocked | BLOCKED — no NDK/device, low code risk |
| Tor directed sharing proven or blocked | BLOCKED — architectural incompatibility identified |
| Docs separate proof boundaries honestly | DONE — this report |

## Next True Blockers

1. **Android NDK installation** → unblocks ARM64 build → APK → device test
2. **Tor-aware directed sharing** → architectural change to route requests through relay/proxy
3. **Real Android device** → validates FFI loading, lifecycle, foreground service
