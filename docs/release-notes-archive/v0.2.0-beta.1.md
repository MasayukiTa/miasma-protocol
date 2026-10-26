# Release Notes -- Miasma Protocol v0.2.0-beta.1

**Release date:** 2026-03-22
**Platform:** Windows x64
**Audience:** Technical beta users and protocol testers

This is the first beta release of the v0.2 series. It represents a major protocol upgrade from v0.1.0, adding the full anonymity stack, anonymous credentials, relay trust verification, and a security hotfix sprint.

## What's New Since v0.1.0

### Anonymity Stack (5-Level Privacy Hierarchy)

v0.1.0 had direct DHT retrieval only. v0.2.0-beta.1 ships a full 5-level privacy hierarchy:

1. **Direct** -- baseline DHT lookup, no relay intermediary
2. **Relay circuit** -- IP-hiding via relay peer using libp2p `/p2p-circuit` addresses
3. **Rendezvous** -- NAT'd nodes publish introduction points; retrievers contact them through relays
4. **Onion** -- 3-hop content-blind encryption (X25519 ECDH + XChaCha20-Poly1305 per hop). R1 knows initiator but not target/content; R2 knows R1+target but not initiator/content; Target sees content but not initiator
5. **Onion + rendezvous** -- content-blind retrieval from NAT'd holders, using introduction points as R2 in onion circuits

The coordinator selects the strongest available path based on relay availability and anonymity mode (Opportunistic or Required).

### BBS+ Anonymous Credentials

- BLS12-381 pairing-based multi-message signatures (~800 lines)
- Selective disclosure with within-epoch unlinkability
- Link secret non-transferability (credentials bound to holder)
- Dual scheme support: Ed25519Scheme and BbsPlusScheme via `CredentialScheme` trait
- Live credential lifecycle: issuance on peer promotion, exchange over `/miasma/credential/1.0.0` protocol, verification before storage, epoch rotation with re-request
- Bootstrap mode: all verified peers act as issuers in early deployment

### Pseudonymous Peer Descriptors

- `PeerDescriptor` with pseudonym, capabilities, reachability kind, onion pubkey
- Descriptor exchange over `/miasma/descriptor/1.0.0` protocol
- Signature verification on receipt
- DescriptorStore with capacity limit (10K), stale rejection, periodic refresh
- Three reachability kinds: Direct, Relayed, Rendezvous (with introduction points)
- Epoch rotation: pseudonym churn tracking, stale pruning, descriptor refresh and broadcast

### Relay Trust Verification

- **Active relay probing**: `/miasma/relay-probe/1.0.0` protocol with nonce echo
- **Forwarding verification**: probe sent through relay's circuit address to prove it actually forwards traffic
- **Trust tiers**: Claimed (default) -> Observed (>=1 success or probe) -> Verified (forwarding verified + success, or probe + >=2 successes at >=66%, or >=3 successes at >=75%)
- **Epoch decay**: observation counters halved on rotation, timestamps preserved
- **Pre-retrieval probing**: up to 3 stale relay candidates probed before each retrieval
- **NAT-driven relay capability**: `can_relay` set from live autonat status, not self-declaration

### Transport Obfuscation

- **ObfuscatedQuic + REALITY**: QUIC transport with REALITY TLS camouflage (new in v0.2)
- WSS + TLS transport (carried over from v0.1)
- SOCKS5 proxy support for all transports

### Routing Security

- Ed25519 signed DHT records
- PoW-gated peer admission with dynamic difficulty (8-24 bits)
- Hybrid admission policy with AdmissionSignals
- PeerRegistry trust tiers (Claimed -> Observed -> Verified)
- IP prefix diversity (/16 for IPv4, /48 for IPv6) for eclipse resistance
- Reliability tracking with decay

### Per-Hop Onion Encryption

- `OnionPacketBuilder::build_e2e()` -- 3-layer encryption with per-hop ECDH
- Per-hop `return_key` in `LayerPayload` for response encryption
- Fixed-size packet padding (8 KiB) to prevent size-based correlation
- Replay protection via bounded BLAKE3 fingerprint cache (4096 entries)
- `/miasma/onion/1.0.0` relay protocol with 64KiB max packet size
- `onion_pubkey` (X25519 static) in PeerDescriptor, signature-covered
- Node-level onion handler: R1 relay, R2 relay, target decryption + share serving

### Secure Key Storage

- Win32 API-based restricted file creation (`secure_file` module)
- ACL-enforced `master.key` with owner-only access
- Mandatory ACL check on startup

### Desktop and CLI Improvements

- Welcome flow with guided first-run setup
- Connection header and grouped status display
- Open Data Folder button
- Persistent logging with daily rotation (3 files retained) for daemon, desktop, and bridge
- Expanded diagnostics: NAT status, relay trust, anonymity metrics, retrieval stats per privacy mode
- `miasma diagnostics [--json]` with log paths, transport readiness, trust/anonymity metrics

### Installer

- WiX v6 MSI with bootstrapper EXE
- VC++ Redistributable auto-detection and install
- Start Menu shortcuts, PATH registration
- Major-upgrade support, silent install (`/install /quiet`)

## Security Fixes

The following vulnerabilities were identified and fixed in a security hotfix sprint:

| ID | Summary | Severity |
|----|---------|----------|
| VULN-001 | Zero-key acceptance in onion packet processing | High |
| VULN-002 | R1 == R2 allowed in onion path selection | Medium |
| VULN-003 | min_hops not enforced in path builder | Medium |
| VULN-004 | ACL race condition in master.key creation | Medium |
| VULN-005 | ShareCodec unbounded allocation | Medium |

All fixes are covered by adversarial tests that verify the vulnerability cannot regress.

### Hardening (post-hotfix)

- **Onion packet padding**: fixed-size 8 KiB data field with random fill, preventing size-based correlation
- **Onion replay protection**: bounded BLAKE3 fingerprint cache (4096 entries) rejects replayed packets
- **Anti-gaming demotion**: relays with ≥2 failures and <50% success rate are demoted to Claimed regardless of probe evidence
- **Periodic background relay probing**: node event loop probes one stale relay per ~5000 ticks
- **DhtCommand backpressure**: fire-and-forget commands use `try_send()` (non-blocking drop on full channel); request-reply commands have 30s timeout

## Breaking Changes

- **Wire protocol versions**: credential, descriptor, onion, and relay-probe protocols are new and not backward-compatible with v0.1.0 nodes
- **Data directory**: v0.2 writes a `version` stamp file; v0.1 data directories are compatible but will be stamped on first v0.2 startup
- **Config format**: new fields for anonymity mode, relay settings, and transport configuration; old configs are accepted with defaults

## Test Suite

464 tests total:
- 268 core unit tests
- 112 adversarial tests (security invariants, hostile peer behavior, edge cases)
- 53 integration tests (1 quarantined: `p2p_kademlia_full_roundtrip`)
- 31 bridge tests

0 failures, 0 warnings.

## Known Limitations

- Onion padding is fixed-size (8 KiB), not constant-rate -- timing-based traffic analysis is still possible
- Small relay pool in early deployment limits anonymity set
- No automatic peer discovery; bootstrap peers must be configured manually
- No code signing certificate -- Windows SmartScreen will warn
- Not externally audited
- Mobile (Android/iOS) not yet operational
- Forwarding verification requires both peers online simultaneously
- Background relay probing runs every ~5000 ticks, probing one stale relay per cycle (not exhaustive)
- Bootstrap trust is self-referential (early nodes credential each other)
- `p2p_kademlia_full_roundtrip` test is timing-sensitive and quarantined

## Installation

### Recommended: Bootstrapper EXE

Download `MiasmaSetup-0.2.0-beta.1-x64.exe` from the [release page](https://github.com/MasayukiTa/miasma-protocol/releases).

```
MiasmaSetup-0.2.0-beta.1-x64.exe
```

This installs the VC++ runtime (if needed) and the Miasma MSI. After install:

- Launch "Miasma Desktop" from the Start Menu, or
- Open a terminal and run `miasma init` followed by `miasma daemon`

For silent install:

```
MiasmaSetup-0.2.0-beta.1-x64.exe /install /quiet
```

### Advanced: MSI Only

For IT deployment or machines that already have the VC++ runtime:

```
msiexec /i miasma-0.2.0-beta.1-windows-x64.msi
```

### Building from Source

```
cargo build --release
```

Binaries are produced in `target/release/`: `miasma.exe`, `miasma-desktop.exe`, `miasma-bridge.exe`.

## Checksums

SHA-256 checksums are provided alongside release artifacts in `.sha256` files. Verify with:

```powershell
Get-FileHash .\MiasmaSetup-0.2.0-beta.1-x64.exe -Algorithm SHA256
```
