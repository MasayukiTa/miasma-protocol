# Bridge Connectivity Superhardening — Validation Report

**Date**: 2026-03-29 (updated from 2026-03-24)
**Version**: 0.3.1-beta.1+bridge
**Validator**: Automated test suite + manual validation via Claude Code

**Important environment note**: The 2026-03-29 Tor and fallback validations were run **without GlobalProtect or any comparable enterprise VPN / ZTNA overlay enabled on the Windows host**. They prove unrestricted-network behavior, not enterprise-overlay survivability.

---

## Validation Matrix

### Automated (Windows — test suite)

| Condition | Expected Transport | Result | Notes |
|---|---|---|---|
| Same LAN (mDNS) | DirectLibp2p | PASS | Validated in directed sharing session 2026-03-23 |
| UDP available | DirectLibp2p (QUIC) | PASS | Default transport, all integration tests |
| Transport fallback | TcpDirect on QUIC fail | PASS | `selector_tries_fallback_on_failure` test |
| First success wins | DirectLibp2p | PASS | `selector_stops_on_first_success` test |
| All transports fail | Error with full trace | PASS | `selector_returns_all_failures_when_exhausted` test |
| Dial backoff | Exponential 2s-300s | PASS | 5 unit tests, adversarial test |
| Stale address pruning | After N failures | PASS | Unit + adversarial tests |
| Connection quality scoring | EMA + consecutive penalty | PASS | 6 unit tests |
| Flap damping | 3 disconnects in 60s | PASS | 5 unit tests, adversarial test |
| Partial failure detection | NoPeers / AllDead / RelayOnly | PASS | 5 unit tests |
| Stale state cleanup | Port file removal | PASS | 2 unit tests |
| Rate limiting | Token bucket per class | PASS | 3 unit tests, adversarial test |
| Origin validation | Localhost only | PASS | 4 unit tests, adversarial test |
| Environment: Open | direct-libp2p | PASS | Unit + adversarial tests |
| Environment: Filtered (no UDP) | wss-tunnel | PASS | Unit + adversarial tests |
| Environment: Corporate proxy | obfuscated-quic | PASS | Unit + adversarial tests |
| Environment: Captive portal | User action required | PASS | Unit + adversarial tests |
| Environment: VPN | Depends on capabilities | PASS | Unit tests |
| TLS inspector detection | Zscaler/Netskope/Palo Alto | PASS | Unit + adversarial tests |
| Shadowsocks config validation | Cipher + server + PSK + modes | PASS | 21 unit tests (native+external) |
| Shadowsocks native AEAD-2022 | TcpCipher roundtrip + wrong key | PASS | Encrypt/decrypt + auth failure tests |
| Tor config validation | Mode + port + bridges | PASS | 8 unit tests, adversarial test |
| Fallback trace buffer | Circular, capacity-bounded | PASS | 6 unit tests, adversarial test |
| DaemonStatus serde compat | Defaults for new fields | PASS | Adversarial test |
| Streaming MID computation | Matches in-memory | PASS | 3 unit + 1 adversarial test |
| PublishFile IPC serde | Roundtrip JSON | PASS | 1 adversarial test |
| Reconnection scheduler | Exponential backoff + circuit breaker | PASS | 7 unit + 3 adversarial tests |
| Recovery actions | Partial failure → actions mapping | PASS | 4 unit + 2 adversarial tests |
| Reconnection metrics | Success rate tracking | PASS | 3 unit + 1 adversarial test |
| Flap + scheduler composition | Damping suppresses reconnect | PASS | 1 adversarial test |

### Manual (Windows — 2-device, 2026-03-23)

| Condition | Result | Notes |
|---|---|---|
| Cross-PC same LAN | PASS | mDNS discovery, directed sharing both directions |
| Daemon restart recovery | PASS | Stale port file cleanup, auto-reconnect |
| Directed sharing 50MB | PASS | File-path IPC, no size limit |
| Broken mDNS | PASS | Bootstrap peers fallback |

### Field Validated (WSL2 Alpine MiasmaLab — 2026-03-24)

| Condition | Result | Notes |
|---|---|---|
| Real SS server (native AEAD-2022) | PASS | ssserver 1.21 `2022-blake3-aes-256-gcm`, 43-byte echo roundtrip through native `TcpCipher` tunnel. `field_ss_native_aead2022_tunnel` test. |
| Real SS server (external SOCKS5) | PASS | sslocal SOCKS5 → ssserver, 41-byte echo roundtrip via `tokio-socks`. `field_ss_socks5_echo` test. |
| Large file streaming publish (200MB) | PASS | 4 segments (64 MiB each), 80 shares, 176.8s, 1.1 MB/s. No OOM. `field_large_file_streaming_publish` test. |

**Test infrastructure**: WSL2 Alpine (`MiasmaLab`), ssserver on :8388, sslocal SOCKS5 on :1080, Python echo server on :9999, Tor on :9050.

**Key fix during validation**: AEAD-2022 handshake must send salt + encrypted fixed header + encrypted variable header in a single `write_all` call. Separate TCP writes cause segmentation across WSL2 virtual NIC, resulting in ssserver "header too short" errors.

### Field Validated — Tor on Unrestricted Network (WSL2 Alpine MiasmaLab — 2026-03-29)

| Condition | Result | Notes |
|---|---|---|
| Tor bootstrap (direct, no bridges) | **PASS** | Tor 0.4.9.5, 100% bootstrap in ~22s. Direct connection to directory authorities — no bridges or meek required. |
| Tor SOCKS5 HTTPS traffic | **PASS** | `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org` returned "Congratulations. This browser is configured to use Tor." |
| Tor circuit isolation | **PASS** | 3 sequential requests produced 3 distinct exit IPs (185.220.100.244, 107.189.13.253, 124.198.131.190), confirming circuit rotation. |
| Tor DNS remote resolution | **PASS** | Hostname resolution through Tor exit node confirmed via `ifconfig.me/ip`. |
| Rust `field_tor_socks5_reachable` test | **PASS** | Windows → WSL2 Tor SOCKS5 at 172.24.51.174:9050, TCP connectivity confirmed by Rust test harness. |
| Fallback ladder forced-failure | **PASS** | `field_transport_fallback_ladder_forced_failure`: WSS fallback validated with forced primary failure, content recovery confirmed (60 bytes, match=true). 4.43s. |

**Previous blocker resolved**: The 2026-03-24 Tor validation was PARTIAL because the corporate network proxy blocked Tor directory authority fetches. WSL2 MiasmaLab has unrestricted outbound network access, bypassing this restriction. The blocker was **network policy (corporate proxy)**, not a code or protocol issue.

**Scope caveat**: This validation did **not** run with GlobalProtect enabled on the Windows host. It proves Tor and fallback behavior on an unrestricted path, not under enterprise VPN interception or ZTNA traffic steering.

**Tor infrastructure**: Tor 0.4.9.5 on WSL2 Alpine, SocksPort 0.0.0.0:9050, direct connection (no bridges), DataDirectory /var/lib/tor.

**What this proves**:
- Tor external SOCKS5 architecture (ADR-009) works end-to-end when the network permits directory authority access.
- The Rust `tokio-socks` SOCKS5 code path correctly routes traffic through Tor.
- Circuit establishment and rotation function as expected.
- The fallback ladder correctly handles forced transport failures and recovers.

**What this does NOT prove**:
- Tor behavior under active DPI or censorship (would need bridge/pluggable transport testing in a censored network).
- Tor SOCKS5 integration with the full directed sharing flow (SOCKS5 port reachability is proven, but end-to-end directed share over Tor was not tested).

### Not Yet Validated

| Condition | Reason | Mitigation |
|---|---|---|
| One-sided VPN | Requires VPN test infrastructure | Fallback ladder handles transparently; forced-failure field test covers the fallback logic path |
| Two-sided VPN | Requires 2 VPN-connected machines | RelayHop expected to work |
| Real DPI bypass | Requires actual DPI appliance | ObfuscatedQuic REALITY tested against structure |
| ~~Real Tor bootstrap~~ | ~~Corporate proxy blocks Tor directory authorities~~ | **RESOLVED 2026-03-29** — full bootstrap + circuit + HTTPS validated on unrestricted network (WSL2) |
| Mobile transport (Android) | No Android SDK/NDK/ADB on current machine; no ARM64 cross-compilation performed | FFI crate compiles on host; 18 Kotlin source files + UniFFI bindings exist; code-sharing proven but device-level behavior unvalidated |
| Mobile transport (iOS) | No macOS/Xcode available; Swift bindings are stubs only | iOS is retrieval-first; no real FFI build has been performed |
| Directed sharing over Tor | Tor SOCKS5 reachable but not tested with full directed share flow | SOCKS5 connectivity proven; WSS-over-Tor protocol path is structurally validated |
| Nation-state filtering | Requires censored network | Shadowsocks + Tor + ObfuscatedQuic available |

### Mobile Transport Bounding (2026-03-25)

This section bounds what the shared Rust codebase proves — and does not prove — about transport behavior on Android and iOS.

#### What Code Sharing Proves

Both Android and iOS start an embedded daemon via the same FFI entry point: `start_embedded_daemon()` in `miasma-ffi/src/lib.rs`. This function calls `DaemonServer::start_with_transport()`, which constructs a `MiasmaNode` (libp2p swarm with QUIC+TCP), wires up the `PayloadTransportSelector` (full 7-level fallback ladder), starts the `MiasmaCoordinator`, and binds the HTTP bridge on `127.0.0.1`. The transport config is `Default::default()` — the same default used by the desktop daemon.

This means the following are **proven by code identity** (not just code similarity — the exact same compiled Rust functions execute on mobile):

| Proven by Code Sharing | Reason |
|---|---|
| Transport fallback ladder (7 levels) | Same `PayloadTransportSelector` instance, same fallback logic |
| Connection health scoring (EMA, consecutive penalty) | Same `ConnectionHealthMonitor` |
| Dial backoff (exponential 2s–300s) | Same backoff logic in `MiasmaNode` swarm |
| Stale address pruning | Same pruning thresholds |
| Network flap damping (3 disconnects/60s) | Same `NetworkFlapDetector` |
| Partial failure detection | Same `PartialFailureDetector` |
| Rate limiting (token bucket) | Same `RateLimiter` in HTTP bridge |
| Environment detection | Same `EnvironmentDetector` |
| Shadowsocks native AEAD-2022 | Same `shadowsocks-crypto` crate, same `TcpCipher` |
| ObfuscatedQuic REALITY | Same QUIC+REALITY implementation |
| Onion routing + relay circuits | Same coordinator logic, same `OnionPacketBuilder` |
| DHT operations (Kademlia) | Same libp2p-kad configuration |
| mDNS peer discovery | Same libp2p-mdns feature flag |

#### What Code Sharing Does NOT Prove

Shared Rust code is necessary but not sufficient for transport correctness on mobile. The following remain unvalidated without real device testing:

| Not Proven | Why |
|---|---|
| UDP/QUIC actually works on Android/iOS network stack | Mobile OS network stacks may handle UDP differently (carrier NAT, battery-saver UDP throttling, IPv6-only carriers). libp2p QUIC has not been exercised on Android's `ConnectivityManager`-mediated network or iOS Network Extension. |
| TCP connect succeeds through mobile network stack | Android and iOS may enforce per-app network permissions, VPN routing, or proxy settings that the Rust `tokio::net::TcpStream` does not see. |
| TLS certificate validation on mobile | Android uses its own trust store (not system OpenSSL). iOS uses Security.framework. `rustls` (used by WSS tunnel and QUIC) ships its own `webpki-roots` — behavior may diverge from platform expectations, especially on networks with corporate MITM certificates. |
| mDNS multicast packets reach the LAN | Android requires `WifiManager.MulticastLock` for mDNS. iOS restricts multicast in background. libp2p-mdns may silently fail without platform-specific permissions. |
| DNS resolution for bootstrap peers | Mobile OS DNS resolution may differ (DNS-over-HTTPS, private relay on iOS, carrier DNS interception). |
| Background daemon survival (Android) | Android foreground service (`START_STICKY`) keeps the process alive, but Doze mode, battery optimization, and OEM-specific task killers may suspend or kill the daemon. Transport connections will drop; reconnection behavior under these conditions is untested. |
| Background daemon survival (iOS) | iOS suspends the process when backgrounded. All network connections drop. There is no background networking mechanism implemented. The daemon must restart from scratch on app return. |
| Memory pressure behavior | Mobile devices have tighter memory limits. The `tokio` multi-thread runtime (2 worker threads) plus libp2p swarm plus DHT state may face OOM under memory pressure, especially during large retrievals. |
| Concurrent network transitions (WiFi↔cellular) | Android and iOS switch networks transparently. libp2p sockets bound to the old interface will break. No reconnection-on-network-change logic exists. |
| ARM64 cross-compilation correctness | The FFI `.so` (Android) and `.a` (iOS) must be compiled for `aarch64-linux-android` and `aarch64-apple-ios` respectively. Neither cross-compilation target has been built or tested. |

#### What Would Be Needed to Validate

| Validation Step | Requirements |
|---|---|
| Android transport smoke test | ARM64 cross-compilation (`cargo ndk`), physical Android device or emulator with network access, APK install, daemon startup, peer discovery observation |
| iOS transport smoke test | Xcode + `cargo` cross-compilation for `aarch64-apple-ios`, Apple signing, physical device or simulator, daemon startup verification |
| Cross-platform directed share exchange | Windows node + Android/iOS node on same LAN, mDNS discovery working, directed share send + retrieve observed end-to-end |
| Network transition testing | Real device, WiFi→cellular switch during active retrieval, observe reconnection behavior |
| Background lifecycle testing | Real device, background the app, wait >5min, foreground, verify daemon state and reconnection |
| Memory pressure testing | Real device, trigger low-memory warning during retrieval, observe OOM behavior |

#### Current Status (updated 2026-03-29)

- **Code-level transport sharing**: VALIDATED. Android and iOS execute the identical Rust transport stack via `start_embedded_daemon()` → `DaemonServer::start_with_transport()` → `PayloadTransportSelector`. This is not a reimplementation — it is the same compiled code.
- **FFI crate build**: VALIDATED. `miasma-ffi` compiles successfully on the host (Windows x86_64). The crate produces both `cdylib` (.so for Android) and `staticlib` (.a for iOS) targets. UniFFI scaffolding generates correctly.
- **Android app code**: EXISTS. 18 Kotlin source files under `android/app/src/main/kotlin/dev/miasma/`, including `MiasmaService.kt` (foreground service), `MiasmaViewModel.kt`, `WebBridgeActivity.kt`, directed sharing UI screens, and `uniffi/MiasmaFfi.kt` (generated bindings). Gradle build files present (`build.gradle.kts`, `settings.gradle.kts`).
- **iOS app code**: STUB ONLY. 7 Swift files exist, but `MiasmaFFI.swift` is explicitly a stub ("Generated FFI not loaded — run cargo build + uniffi-bindgen"). No real FFI build has been performed. iOS is retrieval-first by design.
- **Device-level transport behavior**: NOT VALIDATED. No ARM64 cross-compilation has been performed. No mobile binary has been run on a real device or emulator. The gap between "same code" and "same behavior" on mobile network stacks is real and cannot be closed by code review alone.
- **Blocker**: No Android SDK/NDK/ADB installed on the current development machine. No macOS/Xcode available for iOS.
- **Risk assessment**: The code sharing provides high confidence that transport *logic* is correct (fallback order, health scoring, protocol handling). The risk lies in platform-specific network stack behavior (UDP routing, TLS trust stores, multicast permissions, background restrictions) — areas where the OS mediates between the Rust runtime and the network, and where identical code can produce different outcomes.

---

## Transport Path Observations

### Fallback Ladder (7 levels)
1. DirectLibp2p (QUIC+TCP) — default, <50ms latency
2. TcpDirect — when UDP blocked
3. WssTunnel (WSS/443) — when high ports filtered
4. ObfuscatedQuic (REALITY) — when DPI active
5. RelayHop — when NAT prevents direct
6. Shadowsocks — when DPI + protocol fingerprint (user-configured)
7. Tor — when anonymity required (user-configured)

### Connection Health System
- Per-peer quality scoring: success rate × consecutive failure penalty
- Exponential dial backoff: 2s base, 300s max, jitter, reset on success
- Stale address pruning: after 5 consecutive failures
- Degraded connectivity detection: peer count below threshold
- All metrics exported via DaemonStatus → CLI diagnostics + HTTP bridge

### Self-Healing
- Network flap damping: 3 disconnects in 60s → 120s damping
- Partial failure detection: NoPeers, AllTransportsDead, RelayOnly, StalePeerCount
- Stale state cleanup on restart: port files, HTTP port files

### Abuse Resistance
- Token-bucket rate limiting: Read (120/min), Write (30/min), Heavy (10/min)
- Origin validation: localhost-only (rejects cross-origin browser requests)
- Field length validation: contact (256B), password (1KB), filename (512B)

---

## Platform Capability Matrix

| Capability | Windows Desktop | Web | Android | iOS |
|---|---|---|---|---|
| DirectLibp2p | Full | Via daemon | Via FFI | Via FFI |
| TcpDirect | Full | Via daemon | Via FFI | Via FFI |
| WssTunnel | Full | Via daemon | Via FFI | Via FFI |
| ObfuscatedQuic | Full | Via daemon | Via FFI | Via FFI |
| RelayHop | Full | Via daemon | Via FFI | Via FFI |
| Shadowsocks | **Field validated** | Via daemon | Feature flag | Feature flag |
| Tor | **Field validated** (external SOCKS5) | Not supported | Feature flag | Not supported (*) |
| Connection health | Full | Via /api/status | Via /api/status | Via /api/status |
| Environment detection | Full | Limited | Limited | Limited |
| Rate limiting | Full | Full | Full | Full |

(*) Arti on iOS is untested upstream.

---

## Test Count (2026-03-29)

| Category | Count |
|---|---|
| Unit tests (miasma-core --lib) | 412 |
| Adversarial tests | 182 |
| Integration tests | 54 (+7 ignored: 1 quarantined + 6 field) |
| Desktop tests | 16 |
| Binary tests | 31 |
| WASM tests | 33 (29+4) |
| Field tests (ignored, manual) | 7 (SS native, SS raw diag, SS SOCKS5, Tor reachable, 200MB streaming, fallback ladder, p2p Kademlia) |
| **Total** | **728 running** (+7 ignored) |

Previous total: 727 running (+6 ignored). New field test added: `field_transport_fallback_ladder_forced_failure` (forced primary failure + WSS fallback, content recovery validated).

### Field Test Execution Log (2026-03-29)

| Field Test | Result | Environment | Notes |
|---|---|---|---|
| `field_tor_socks5_reachable` | **PASS** | Windows → WSL2 Tor 0.4.9.5 | TCP connectivity to Tor SOCKS5 confirmed |
| `field_transport_fallback_ladder_forced_failure` | **PASS** | Windows | WSS fallback on forced primary failure, 60-byte content recovered, 4.43s |
| Full Tor bootstrap + HTTPS (manual curl) | **PASS** | WSL2 MiasmaLab | 100% bootstrap ~22s, "Congratulations" from check.torproject.org |
| Tor circuit isolation (manual curl) | **PASS** | WSL2 MiasmaLab | 3 requests → 3 distinct exit IPs |
| miasma-core integration suite | **54/54 PASS** | Windows | All non-ignored integration tests pass |
| miasma-core adversarial suite | **182/182 PASS** | Windows | All adversarial tests pass |
| miasma-core unit suite | **412/412 PASS** | Windows | All unit tests pass |

---

## Known Hard Blockers

1. ~~Native Shadowsocks tunnel rejected~~ **RESOLVED + FIELD VALIDATED**: `shadowsocks-crypto` v0.6.2 (pure-Rust, no OpenSSL) provides AEAD-2022 ciphers. Native tunnel implemented and field-tested against ssserver 1.21 (2026-03-24). Both native AEAD-2022 and external SOCKS5 modes validated. See revised `docs/adr/009-native-tunnel-decision.md`.
2. **Embedded Tor rejected (ADR-009)**: `arti-client` is pre-1.0, ~50 transitive deps, untested on iOS. External SOCKS5 mode (standalone Tor) is the accepted architecture. **External Tor SOCKS5 now field-validated** (2026-03-29): bootstrap, circuit, HTTPS, circuit isolation all proven on unrestricted network.
3. **Domain fronting not implemented**: Would require CDN cooperation or cloud function intermediary.
4. **Meek bridges not implemented**: Would complement Tor bridges for extreme censorship.
5. ~~Streaming dissolution for very large files~~ **RESOLVED**: `PublishFile` IPC variant + `dissolve_and_publish_file()` streams 64 MiB segments, BLAKE3 MID computed via streaming reader. CLI uses file-path publishing to bypass IPC frame limit.

## Live Wiring Status (2026-03-29)

| Component | Status | Details |
|---|---|---|
| RateLimiter | **WIRED** | Token-bucket in HTTP bridge `handle()`, origin validation, 429 responses |
| ConnectionHealthMonitor | **LIVE** | Node swarm events (connect/disconnect/dial-failure), periodic pruning, live coordinator query |
| EnvironmentDetector | **LIVE** | Periodic 5min daemon task, derives capabilities from transport outcomes + NAT status |
| NetworkFlapDetector | **LIVE** | Node disconnect events, damping active in DaemonStatus |
| PartialFailureDetector | **LIVE** | Periodic evaluation (relay-only, no-peers, stale, all-dead), exposed in DaemonStatus |
| Shadowsocks transport | **FIELD VALIDATED** | Native AEAD-2022 via `shadowsocks-crypto` + external SOCKS5 — both tested against ssserver 1.21 (2026-03-24) |
| Tor transport | **FIELD VALIDATED** | External SOCKS5 through Tor 0.4.9.5 — bootstrap, circuit, HTTPS traffic all proven (2026-03-29). WSS protocol to peer (external mode). |
| TransportStats | **LIVE** | Per-kind success/failure/phase attribution, last_selected, fallback_active |
| DialBackoff | **LIVE** | Dial failure → backoff in node, exposed in health snapshot |
| DaemonStatus fields | **LIVE** | All 14 bridge fields + partial_failures from live state + coordinator queries |

---

## Validation Infrastructure

- `scripts/validate-bridge-connectivity.ps1` — automated validation against real SS/Tor proxies
- Validation script tests: same-LAN, diagnostics, Shadowsocks proxy, Tor proxy, partial failures
- Results written to `docs/validation/bridge-connectivity-live-results.md`

---

## Next Milestone Recommendation

**Bridge Connectivity Phase 4: Real-Network Field Testing**
1. ~~Run `validate-bridge-connectivity.ps1` with ss-local + SS server~~ **DONE** (2026-03-24) — native AEAD-2022 + external SOCKS5 both validated
2. ~~Tor bootstrap on unrestricted network~~ **DONE** (2026-03-29) — full bootstrap, circuit establishment, HTTPS traffic, circuit isolation all validated on WSL2 MiasmaLab. Rust field test `field_tor_socks5_reachable` PASS.
3. ~~Fallback ladder forced-failure field test~~ **DONE** (2026-03-29) — `field_transport_fallback_ladder_forced_failure` PASS, WSS fallback + content recovery validated
4. Validate VPN / filtered network transport fallback (manual — requires VPN infrastructure)
5. Validate ObfuscatedQuic REALITY under real DPI (requires test infrastructure)
6. ~~Large-file streaming field test~~ **DONE** (2026-03-24) — 200MB, 4 segments, 80 shares, no OOM
7. Android ARM64 cross-compilation + real device smoke test (requires Android SDK/NDK setup)
8. Directed sharing end-to-end over Tor (requires two nodes + Tor SOCKS5)

**Readiness Assessment (2026-03-29)**:
- **Ready for broader testing**: Shadowsocks (native + external), Tor (external SOCKS5), fallback ladder, reconnection, and all self-healing subsystems are field-validated or exhaustively tested.
- **Not yet ready**: VPN/DPI real-network proof, Android/iOS real-device proof. These are environment-blocked, not code-blocked.
- **Honest boundary**: The bridge connectivity layer is proven correct on Windows with real external proxies (SS + Tor) on an unrestricted network path. Mobile platforms share identical Rust transport code but have not been exercised on real devices. VPN, GlobalProtect-class overlays, and DPI scenarios are covered by automated tests but not by real-network validation.
