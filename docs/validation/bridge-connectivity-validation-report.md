# Bridge Connectivity Superhardening — Validation Report

**Date**: 2026-03-24
**Version**: 0.3.1-beta.1+bridge
**Validator**: Automated test suite + manual validation via Claude Code

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

### Manual (Windows — 2-device, 2026-03-23)

| Condition | Result | Notes |
|---|---|---|
| Cross-PC same LAN | PASS | mDNS discovery, directed sharing both directions |
| Daemon restart recovery | PASS | Stale port file cleanup, auto-reconnect |
| Directed sharing 50MB | PASS | File-path IPC, no size limit |
| Broken mDNS | PASS | Bootstrap peers fallback |

### Not Yet Validated

| Condition | Reason | Mitigation |
|---|---|---|
| One-sided VPN | Requires VPN test infrastructure | Fallback ladder handles transparently |
| Two-sided VPN | Requires 2 VPN-connected machines | RelayHop expected to work |
| Real DPI bypass | Requires actual DPI appliance | ObfuscatedQuic REALITY tested against structure |
| Real Shadowsocks server (native) | Requires SS server + PSK | Native AEAD-2022 implemented, needs field test |
| Real Shadowsocks server (external) | Requires ss-local + SS server | External SOCKS5 implemented, needs field test |
| Real Tor network | Requires Internet + Tor | External SOCKS5 mode reuses proven proxy code |
| Mobile transport (Android/iOS) | Requires device testing | Uses same FFI daemon — transport code shared |
| Nation-state filtering | Requires censored network | Shadowsocks + Tor + ObfuscatedQuic available |

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
| Shadowsocks | Config ready | Via daemon | Feature flag | Feature flag |
| Tor | Config ready | Not supported | Feature flag | Not supported (*) |
| Connection health | Full | Via /api/status | Via /api/status | Via /api/status |
| Environment detection | Full | Limited | Limited | Limited |
| Rate limiting | Full | Full | Full | Full |

(*) Arti on iOS is untested upstream.

---

## Test Count

| Category | Count |
|---|---|
| Unit tests (miasma-core --lib) | 393 |
| Adversarial tests | 168 |
| Integration tests | 53 (+1 ignored) |
| Desktop tests | 16 |
| Binary tests | 31 |
| WASM tests | 33 (29+4) |
| **Total** | **694** (+1 ignored) |

Previous total: 682. New tests added: **12** (native Shadowsocks AEAD-2022 + config validation).

---

## Known Hard Blockers

1. ~~Native Shadowsocks tunnel rejected~~ **RESOLVED**: `shadowsocks-crypto` v0.6.2 (pure-Rust, no OpenSSL) provides AEAD-2022 ciphers. Native tunnel implemented. See revised `docs/adr/009-native-tunnel-decision.md`.
2. **Embedded Tor rejected (ADR-009)**: `arti-client` is pre-1.0, ~50 transitive deps, untested on iOS. External SOCKS5 mode (standalone Tor) is the accepted architecture.
3. **Domain fronting not implemented**: Would require CDN cooperation or cloud function intermediary.
4. **Meek bridges not implemented**: Would complement Tor bridges for extreme censorship.
5. **Streaming dissolution for very large files**: Files >100MB held in RAM during encryption.

## Live Wiring Status (2026-03-24)

| Component | Status | Details |
|---|---|---|
| RateLimiter | **WIRED** | Token-bucket in HTTP bridge `handle()`, origin validation, 429 responses |
| ConnectionHealthMonitor | **LIVE** | Node swarm events (connect/disconnect/dial-failure), periodic pruning, live coordinator query |
| EnvironmentDetector | **LIVE** | Periodic 5min daemon task, derives capabilities from transport outcomes + NAT status |
| NetworkFlapDetector | **LIVE** | Node disconnect events, damping active in DaemonStatus |
| PartialFailureDetector | **LIVE** | Periodic evaluation (relay-only, no-peers, stale, all-dead), exposed in DaemonStatus |
| Shadowsocks transport | **LIVE** | Native AEAD-2022 via `shadowsocks-crypto` + external SOCKS5 fallback |
| Tor transport | **LIVE** | Real SOCKS5 proxy through Tor → WSS protocol to peer (external mode) |
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
1. Run `validate-bridge-connectivity.ps1` with ss-local + SS server
2. Run `validate-bridge-connectivity.ps1` with Tor daemon
3. Validate VPN / filtered network transport fallback (manual)
4. Validate ObfuscatedQuic REALITY under real DPI (requires test infrastructure)
5. Mobile platform transport validation (Android/iOS)
6. Revisit native tunnels if `shadowsocks-crypto` gains pure-Rust AEAD or Arti reaches 1.0
