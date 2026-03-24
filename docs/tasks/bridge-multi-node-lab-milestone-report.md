# Bridge Multi-Node Lab & Hard Blocker Burndown — Milestone Report

**Date**: 2026-03-24
**Version**: 0.3.1-beta.1+bridge
**Test count**: 727 (+33 from milestone start at 694)

---

## 1. Lab Environment

### What was attempted
- WSL2 Ubuntu install → **BLOCKED** by corporate proxy (error `0x80072eff`)
- Docker → **NOT AVAILABLE** on this machine
- SSH → Available (OpenSSH 10.2) but no remote Linux host accessible

### What exists
- Single Windows 11 Enterprise machine with Rust toolchain
- SSH client available for future Linux node setup
- WSL2 framework installed but distro download blocked by corporate network

### Infrastructure blockers
The enterprise environment blocks WSL2 distro downloads (Microsoft Store / CDN) and Docker is not installed. A multi-node lab requires either:
1. Admin action to install WSL2 Ubuntu from an offline `.appx` package
2. Provisioning a Linux VPS or VM accessible from this machine
3. A second physical device running Linux

**Verdict**: Track A (multi-node lab) and Track B (real multi-node validation) are blocked by infrastructure. Track C (real SS/Tor validation) is similarly blocked — no Linux host to run `ssserver` or `tor`.

---

## 2. Hard Blockers Burned Down (Track D)

### RESOLVED: Streaming dissolution for large files (>100MB)

Previously: `ControlRequest::Publish` loaded entire file into memory, serialized over IPC (16 MiB limit).

**Changes**:
- `ContentId::compute_from_reader()` — streaming BLAKE3 MID via `std::io::Read` (64 KiB buffer)
- `ControlRequest::PublishFile` — new IPC variant taking file path instead of data bytes
- `MiasmaCoordinator::dissolve_and_publish_file()` — per-segment (64 MiB) streaming dissolution
- CLI updated to use `PublishFile` for all publish operations

**Files**: `crypto/hash.rs`, `daemon/ipc.rs`, `network/coordinator.rs`, `daemon/mod.rs`, `miasma-cli/src/main.rs`
**Tests**: 3 unit (streaming hash) + 2 adversarial (IPC serde + streaming MID match)

### RESOLVED: Reconnect quality after hard network failure

Previously: PartialFailureDetector detected degraded states but only logged warnings. No recovery actions, no reconnection scheduling, no circuit breaker, no metrics.

**Changes**:
- `RecoveryAction` enum — concrete actions (ReDialBootstrap, RefreshDescriptors, EscalateTransport, AcceptRelayOnly, AbandonPeer)
- `recovery_actions_for()` — maps partial failures to recovery actions
- `ReconnectionScheduler` — per-peer exponential backoff (5s→600s), circuit breaker after N failures, `should_attempt()`, `peers_due_for_reconnect()`, `abandoned_peers()`
- `ReconnectionMetrics` — attempts/successes/failures/circuit_breaker_trips/recovery_actions_triggered, success_rate()
- `BridgeHealthStatus` extended with reconnection metrics

**Files**: `daemon/self_heal.rs`
**Tests**: 16 unit + 6 adversarial (circuit breaker, recovery actions, flap+scheduler composition)

### Previously resolved: Native Shadowsocks AEAD-2022

`shadowsocks-crypto` v0.6.2 (pure-Rust, no OpenSSL). 21 unit tests. Dual mode (native + external SOCKS5 fallback).

---

## 3. Shadowsocks/Tor Evidence

### Shadowsocks
- **Code**: Complete native AEAD-2022 implementation (`transport/shadowsocks.rs`, ~550 lines)
- **Tests**: 21 unit tests including crypto roundtrip, wrong key, config validation, connection errors, fallback behavior
- **Not yet validated**: Against a real SS server. Requires Linux host running `ssserver`.

### Tor
- **Code**: Complete external SOCKS5 mode (`transport/tor.rs`)
- **Tests**: 8 unit tests including config validation, mode selection, connection errors
- **Not yet validated**: Against a real Tor daemon. Requires `tor` binary.

---

## 4. Evidence Improvement

### Before this milestone
- 694 tests total
- Streaming dissolution: not implemented (>100MB = OOM)
- Reconnection: detection only, no recovery actions
- SS: native AEAD-2022 just implemented, not yet hardened
- Lab: single device only

### After this milestone
- 727 tests total (+33)
- Streaming dissolution: **RESOLVED** — 64 MiB segment streaming, no file size limit
- Reconnection: **RESOLVED** — scheduler, circuit breaker, recovery actions, metrics, flap composition
- SS: 21 unit tests + adversarial coverage
- Lab: still single device (corporate infrastructure blocking)

---

## 5. What Still Remains Hard

1. **Multi-node lab** — blocked by corporate infrastructure. Needs admin action or VPS provisioning.
2. **Real SS/Tor validation** — blocked by lack of Linux host. Code is complete but untested against real infrastructure.
3. **Reconnection wiring into node event loop** — `ReconnectionScheduler` and `recovery_actions_for()` are pure logic; wiring into the actual node event loop (calling `dial()`, refreshing descriptors, escalating transports) requires integration work.
4. **VPN/degraded network validation** — needs multi-node lab or manual testing on different network topologies.
5. **Soak testing under sustained load** — `soak-test.ps1` exists but only exercises single-device daemon lifecycle.

---

## 6. Bounded Backlog for Follow-On Model (Track G)

### Infrastructure Tasks (require admin/provisioning, not code)

| # | Task | Acceptance Criteria | Effort |
|---|---|---|---|
| I-1 | Install WSL2 Ubuntu from offline `.appx` | `wsl --list` shows Ubuntu, `cargo` works inside | Admin action |
| I-2 | OR: provision accessible Linux VPS | SSH from Windows host, `cargo build` works | 1-2 hours |
| I-3 | Install `ssserver` on Linux node | Listening on configurable port, reachable from Windows | 30 min |
| I-4 | Install `tor` on Linux node | SOCKS5 proxy on port 9050, reachable from Windows | 30 min |

### Code Tasks (bounded, clear acceptance criteria)

| # | Task | Acceptance Criteria | Effort |
|---|---|---|---|
| C-1 | Wire `ReconnectionScheduler` into node event loop | `record_failure()`/`record_success()` called on connect/disconnect events; `peers_due_for_reconnect()` checked periodically; `abandoned_peers()` triggers `AbandonPeer` action | 2-3 hours |
| C-2 | Wire `recovery_actions_for()` into daemon | When PartialFailureDetector fires, dispatch recovery actions (redial bootstrap, refresh descriptors) | 1-2 hours |
| C-3 | Add `ReconnectionMetrics` to `DaemonStatus` | 5 new fields in DaemonStatus, shown in CLI `diagnostics`, serde-compatible | 1 hour |
| C-4 | CLI `publish` progress for streaming dissolution | Print segment progress ("segment 3/12 dissolved...") during `dissolve_and_publish_file()` | 1 hour |
| C-5 | HTTP bridge streaming publish endpoint | `POST /api/publish-file` with file path, returns MID | 1 hour |

### Validation Tasks (require lab infrastructure)

| # | Task | Acceptance Criteria | Effort |
|---|---|---|---|
| V-1 | Windows↔Linux directed sharing | Send from Windows, retrieve on Linux (or vice versa) | 1-2 hours |
| V-2 | Real SS validation | Connect through `ssserver`, observe transport attribution in diagnostics | 1-2 hours |
| V-3 | Real Tor validation | Connect through Tor SOCKS5, observe transport attribution | 1-2 hours |
| V-4 | Fallback ladder validation | Block UDP, observe WSS fallback; block all direct, observe relay | 2-3 hours |
| V-5 | Large file (>100MB) streaming validation | `miasma network publish bigfile.bin` succeeds without OOM | 1 hour |
| V-6 | Soak test multi-node | Extended run (>1h) with periodic publish/retrieve across nodes | 2-3 hours |

### Documentation Tasks

| # | Task | Acceptance Criteria | Effort |
|---|---|---|---|
| D-1 | Update validation report with multi-node evidence | Fill in "Manual" section with real cross-node results | 1 hour |
| D-2 | Update censorship-resistance posture with real SS/Tor evidence | Replace "implemented but not field-tested" with actual results | 30 min |
| D-3 | Write lab setup guide | Reproducible steps for the chosen lab approach (WSL2 or VPS) | 1 hour |

**Total estimated effort**: ~20-25 hours, mostly blocked by infrastructure provisioning (I-1 or I-2).
