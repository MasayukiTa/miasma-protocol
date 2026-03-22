# Miasma Protocol

Miasma is a censorship-resistant content storage and retrieval protocol inspired by Freenet. The long-term vision is mobile-first, but the current release ships on Windows as a validation testbed for the protocol stack, routing trust model, and operational UX.

This project is not claiming "finished anonymous file sharing." It is building toward that goal in explicit, documented phases.

## v0.3.1-beta.1

The current public release is **v0.3.1-beta.1**, a Windows beta prerelease for technical users and protocol testers.

- Release page: [GitHub Releases](https://github.com/MasayukiTa/miasma-protocol/releases)
- Recommended artifact: `MiasmaSetup-0.3.1-x64.exe`

### What ships in this release

- **Encrypted dissolution and retrieval** -- erasure coding + encryption with content-addressed storage
- **P2P DHT-based content routing** via libp2p Kademlia with signed DHT records
- **5-level privacy hierarchy** for retrieval:
  1. Direct -- baseline DHT lookup
  2. Relay circuit -- IP-hiding via relay peer (`/p2p-circuit`)
  3. Rendezvous -- NAT'd nodes reachable through introduction points
  4. Onion -- content-blind 3-hop encryption (X25519 + XChaCha20-Poly1305 per hop)
  5. Onion + rendezvous -- content-blind retrieval from NAT'd holders
- **BBS+ anonymous credentials** with within-epoch unlinkability (BLS12-381 pairing-based, selective disclosure, link-secret non-transferability)
- **Pseudonymous peer descriptors** with epoch rotation and churn tracking
- **Active relay trust verification** -- relay probing (`/miasma/relay-probe/1.0.0`), forwarding verification through circuit addresses, evidence-based trust tiers (Claimed / Observed / Verified)
- **Same-network peer discovery** -- mDNS for LAN discovery, with manual bootstrap fallback for restrictive networks
- **Transport obfuscation**: WSS+TLS, ObfuscatedQuic+REALITY, SOCKS5 proxy support
- **Windows daemon + CLI + desktop GUI + BitTorrent bridge**
- **Secure key storage** with Win32 API-based restricted file creation (ACL-enforced `master.key`)
- **Distress wipe** -- immediate key material destruction
- **WiX MSI installer** with bootstrapper EXE (VC++ runtime bundled)

### What this beta does well

- Local encrypted storage with distress wipe
- Multi-transport payload delivery across network conditions
- Layered anonymity with content-blind onion routing
- Pseudonymous trust without identity linkability across epochs
- Relay verification with passive observation, active probing, and forwarding verification
- Operational diagnostics (CLI, desktop, JSON export)

### What it does NOT claim to solve

- **No protection against a strong global passive adversary.** A network-level observer who can see all traffic can correlate flows.
- **Onion padding is fixed-size, not constant-rate.** Packets are padded to 8 KiB to prevent size correlation, but traffic timing analysis is still possible.
- **Small relay pool in early deployment.** Anonymity set is limited by the number of participating relay nodes.
- **Automatic discovery is limited to the local network.** Same-network peers now use mDNS; restrictive networks may still need manual bootstrap peers.
- **No code signing certificate.** Windows SmartScreen will warn on install.
- **Not audited.** No external security review has been performed.
- **Mobile not yet operational.** Android and iOS runtime work is pending.
- **Bootstrap trust is self-referential.** Early nodes credential each other; the trust bootstrapping problem is real.

## Threat Model Boundaries

Be explicit about what this system resists and what it does not.

**Resists:**

- Casual observation of network traffic (transport obfuscation, encrypted payloads)
- Non-targeted surveillance (pseudonymous descriptors, epoch rotation, unlinkable credentials)
- Content seizure via single node compromise (erasure coding distributes shards, encryption at rest)

**Does not resist:**

- Targeted adversary with network-level visibility (traffic correlation, timing analysis)
- ISP-level deep packet inspection correlation (GlobalProtect/Zscaler-class MITM can fingerprint despite REALITY)
- Traffic analysis via timing (fixed-size padding prevents size correlation, but no constant-rate cover traffic)
- Sybil attacks at scale (PoW admission raises cost but does not eliminate it)
- Bootstrap trust circular dependency (first nodes in a deployment credential each other)

## Platform Maturity

| Surface | Maturity | Networking | User-facing |
|---|---|---|---|
| **Windows** | Beta (validated) | Full (libp2p, mDNS, DHT, onion, relay) | Desktop GUI + CLI + installer |
| **Web/PWA** | Foundation (audited) | None (local-only WASM) | Browser dissolve/retrieve + export/import |
| **Android** | Foundation (audited) | None (local FFI only) | Compose UI shell |
| **iOS** | Stub | None (FFI bindings only) | SwiftUI shell |

See `docs/platform-roadmap.md` for capability matrix, milestone order, and detailed analysis.

### Windows

Windows is the current shipping beta. It proves:

- Installer and upgrade flow (MSI + bootstrapper EXE)
- Desktop and daemon UX (auto-start, crash recovery, stale detection)
- Routing, trust, and transport behavior
- Same-network peer discovery (mDNS) and manual bootstrap
- Operational diagnostics and release process

### Web/PWA

Local-only browser tool for dissolution and retrieval via WASM. Protocol-compatible with miasma-core v1. Security-audited (all CRITICAL/HIGH/MEDIUM fixed). No networking — shares stay in browser IndexedDB. Transfer between devices requires manual export/import of `.miasma` files. Does not connect to the Miasma network or provide anonymity features. Supports EN, JA, ZH-CN.

### Android

Android is the intended first-class mobile node target. FFI foundation exists (security-audited, 5 functions exposed via UniFFI). Hard problems still to solve:

- Battery cost and background execution limits
- NAT traversal and reconnect behavior
- Storage pressure and bandwidth caps
- Keystore integration for master key wrapping (C-1 from audit)
- FFI networking (not yet exposed)

### iOS

Retrieval-focused client first, not an always-on full node. Swift bindings generated, app shell exists. Depends on FFI maturity from Android work.

## Repository Structure

```
crates/miasma-core     Protocol, storage, routing, trust, transport, credentials
crates/miasma-cli      CLI and daemon entry points
crates/miasma-desktop  Windows desktop GUI (native Win32)
crates/miasma-bridge   BitTorrent bridge (librqbit-based ingestion)
crates/miasma-ffi      UniFFI bridge for Android (Kotlin) and iOS (Swift)
crates/miasma-wasm     Browser WASM dissolution/retrieval (self-contained)
docs/adr/              Architecture decision records
scripts/               Build, package, sign, smoke test, soak test scripts
```

## Building

Requires Rust toolchain (stable) and a Windows environment for the desktop and installer targets.

```
cargo build --release
cargo test --workspace
```

The test suite includes 480 tests (268 core unit + 112 adversarial + 53 integration + 31 bridge + 16 desktop), with 0 failures.

One test (`p2p_kademlia_full_roundtrip`) is quarantined with `#[ignore]` due to timing sensitivity. It can be run manually and is also covered by `scripts/smoke-loopback.ps1`.

## Security Note

This is a beta-stage networked system. It has not been externally audited.

The protocol contains meaningful security work: Ed25519 DHT record verification, PoW admission, BBS+ credentials, onion encryption, relay trust verification, ACL-enforced key storage, and a completed security hotfix sprint (VULN-001 through VULN-005). But unknown peers, hostile environments, adversarial routing pressure, and long-term retention behavior all require more validation.

Treat the current release as:

- Serious engineering progress toward censorship-resistant storage
- Suitable for technical beta testing and protocol evaluation
- Not a finished, production-hardened anonymity network

## Near-Term Roadmap

- Constant-rate traffic shaping (timing-analysis resistance beyond fixed-size padding)
- Android runtime implementation
- Code signing certificate (Authenticode)
- Broader real-network adversarial validation
- External security audit

## License

See [LICENSE](LICENSE) for details.
