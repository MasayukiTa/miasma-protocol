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
- **Pseudonymous Ed25519 credentials** with cross-epoch unlinkability (a BLS12-381 BBS+ scheme for within-epoch unlinkability also exists in the tree, but it is forgeable and is not used for any trust decision — see `docs/adr/006-bbs-plus-known-breaks.md`)
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
- Content seizure via single-node compromise, **when the publisher had genuine peer availability at publish time**: erasure-coded shards are pushed to other admission-verified peers (`/miasma/share-store/1.0.0`), each holder reports its own dialable address, and a shard-holder-diversity cap keeps any one peer from ending up with more than it should -- taking the *original publisher* offline afterward does not make the content unavailable. Tested directly: `retrieve_from_network_succeeds_when_publisher_goes_offline_after_publish` retrieves successfully from remote holders alone after the publisher has fully shut down. See `docs/tasks/p2p-content-transfer-hardening.md`'s Phase 2.1 entry for exactly what's verified, by which tests, and the design review that shaped it.

**Does not resist:**

- Targeted adversary with network-level visibility (traffic correlation, timing analysis)
- ISP-level deep packet inspection correlation (GlobalProtect/Zscaler-class MITM can fingerprint despite REALITY)
- Traffic analysis via timing (fixed-size padding prevents size correlation, but no constant-rate cover traffic)
- Sybil attacks at scale (PoW admission raises cost but does not eliminate it)
- Bootstrap trust circular dependency (first nodes in a deployment credential each other)
- Content seizure via single node compromise **when published while effectively isolated**: `dissolve_and_publish`/`dissolve_and_publish_file` still succeed by default with zero or too few connected peers (an early-beta desktop user is not blocked from publishing just because no one else is online yet) -- in that case distribution is genuinely best-effort and may not happen at all, so the content is only as available as the publisher itself, same as a regular server. Callers that need the stronger guarantee enforced rather than merely attempted must opt in explicitly (`PublishOptions::strict`), which fails loudly instead of publishing a record that looks normal but isn't actually recoverable without the publisher.
- Direct share-push reveals the publisher's real PeerId to every peer chosen to host a shard (retrieval already has onion/relay routing; the push path does not yet) -- a real, currently undocumented-elsewhere-until-now anonymity gap in the distribution mechanism itself, flagged during this phase's external design review.
- True Kademlia-closest shard placement, fetch/audit-based holder reputation, storage retention leases, and automatic repair scheduling are all deferred follow-ups, not yet implemented -- current placement picks from currently-connected, admission-verified peers only.

## Platform Maturity

| Surface | Maturity | Networking | User-facing |
|---|---|---|---|
| **Windows** | Beta (validated) | Full (libp2p, mDNS, DHT, onion, relay) | Desktop GUI + CLI + installer |
| **Web/PWA** | Foundation (audited) | Desktop: HTTP bridge; Mobile: WebView bridge; Standalone: local-only | Browser dissolve/retrieve + network when bridged |
| **Android** | Foundation (audited) | WebView bridge (local FFI; network FFI pending) | Compose UI + WebView |
| **iOS** | Stub | WebView bridge (local FFI; network FFI pending) | SwiftUI + WKWebView |

See `docs/platform-roadmap.md` for capability matrix, milestone order, and detailed analysis.

### Windows

Windows is the current shipping beta. It proves:

- Installer and upgrade flow (MSI + bootstrapper EXE)
- Desktop and daemon UX (auto-start, crash recovery, stale detection)
- Routing, trust, and transport behavior
- Same-network peer discovery (mDNS) and manual bootstrap
- Operational diagnostics and release process

### Web/PWA

Browser-based dissolution and retrieval. Protocol-compatible with miasma-core v1. Security-audited (all CRITICAL/HIGH/MEDIUM fixed). Supports EN, JA, ZH-CN.

**Network modes** (detected automatically):
- **Desktop**: Connects to the local daemon via HTTP bridge (`localhost:17842`). Full P2P network access — dissolve publishes to DHT, retrieve fetches from peers.
- **Android WebView**: Loaded inside the Android app with a JavaScript bridge to native FFI. Currently local-only (FFI networking not yet exposed).
- **iOS WKWebView**: Loaded inside the iOS app with a message handler bridge. Currently local-only.
- **Standalone browser**: Falls back to local-only WASM. Shares stay in IndexedDB, transferred manually via `.miasma` export/import.

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

The test suite runs 780 tests with 0 failures: 463 core unit + 194 adversarial + 63 integration (`miasma-core`), 35 unit + 3 cross-process (`miasma-bridge`), 22 (`miasma-desktop`). The three `miasma-bridge` integration tests spawn the real compiled binary and move payload bytes over a loopback BitTorrent connection against an in-process seeder.

Seven further tests carry `#[ignore]` and are excluded from that count: six `field_*` tests that need real external network I/O (Tor and shadowsocks reachability, large-file streaming over a live link) plus `retrieve_from_network_gives_up_on_nonexistent_record`.

`p2p_kademlia_full_roundtrip` is no longer among them. It had been quarantined as flaky since it was written; the root cause turned out to be in the product, not the test — DHT PUT reported success as soon as the record hit the *local* Kademlia store, without waiting for network propagation, which a fixed sleep in the test could not reliably cover. With the PUT made to wait for a real acknowledgement, the test runs in the normal suite.

## Security Note

This is a beta-stage networked system. It has not been externally audited.

The protocol contains meaningful security work: Ed25519 DHT record verification, PoW admission, onion encryption, relay trust verification, ACL-enforced key storage, and a completed security hotfix sprint (VULN-001 through VULN-005). But unknown peers, hostile environments, adversarial routing pressure, and long-term retention behavior all require more validation.

One component is known-broken and disconnected rather than fixed: the self-written BBS+ credential scheme is forgeable in two independent ways, demonstrated by executable forgery tests in the repository. It no longer feeds any trust decision. The reasoning, the containment, and the conditions for re-enabling it are in `docs/adr/006-bbs-plus-known-breaks.md`. Every other cryptographic component uses reviewed library primitives in conventional compositions.

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
