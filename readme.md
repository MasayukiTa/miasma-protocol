# Miasma Protocol

Miasma is a mobile-first, Freenet-inspired storage and retrieval protocol.
The current public beta is on Windows because Windows is the fastest place to validate the protocol, routing, installer flow, and operational UX before we harden the mobile product.

This repository is not claiming "finished anonymous file sharing" yet.
It is building toward that goal in explicit phases.

## Project Status

Miasma is still in the validation stage.

- The current **shipping beta** is a Windows beta prerelease.
- The **product direction** is still mobile-first.
- Windows exists first so we can validate the protocol stack, routing trust model, installer flow, diagnostics, and adversarial behavior on a platform that is easier to iterate on quickly.

In other words:

- **Windows** is the current validation platform and operator testbed.
- **Android** is the intended first-class mobile node target.
- **iOS** should be treated as a retrieval-focused client first, not as an always-on equal full node from day one.

## Platform Strategy

### Windows

Windows is where we currently prove:

- installer and upgrade flow
- desktop and daemon UX
- routing, trust, and transport behavior
- local and loopback retrieval
- operational diagnostics and release process

### Android

Android remains the main mobile target for meaningful peer participation.
The hard problems we still need to solve there are the real ones:

- battery cost
- background execution limits
- NAT traversal and reconnect behavior
- storage pressure
- bandwidth caps
- quota enforcement
- long-running reliability under mobile network churn

### iOS

iOS should not be designed around the fantasy of a permanently available equal full node.
The realistic first target is a retrieval-focused client with selective participation, while heavier storage, relay, and long-lived routing duties stay on stronger peers.

## What Exists Today

### Live, implemented foundations

- encrypted content-addressed dissolution and retrieval pipeline
- local encrypted share storage
- daemon, CLI, desktop, bridge, and Windows installer flow
- WSS and proxy-aware transport work
- routing security phases 3a-3c:
  - real Ed25519 DHT record verification
  - PoW-gated peer admission
  - trust tiers
  - address-class separation
  - prefix diversity and first eclipse-resistance logic
  - routing and admission diagnostics
- Windows beta prerelease with installer-first distribution

### Landed in code, but not fully wired into the live network path yet

- anonymous credential layer
- descriptor-based routing layer
- onion-aware path selection
- hybrid mobile-friendly admission policy
- adversarial simulation harness

These are important because they are part of the real Freenet-like direction, but they are not yet fully driving the live end-to-end network behavior.

## Freenet-Style Goals: Where We Actually Are

The point of Miasma is not only "can it get through a network."
The real goals are harder than that.

### 1. Censorship resistance

**Status:** partial, real progress

What exists:

- routing trust model
- admission cost via PoW
- signature-validated DHT records
- prefix-diversity and first eclipse-resistance controls

What is still missing:

- descriptor-first live routing
- stronger relay and rendezvous integration
- larger real-world adversarial validation

### 2. Difficulty of identifying participants and flows

**Status:** partial, not solved

What exists:

- encrypted storage pipeline
- transport experimentation
- onion-oriented design direction
- anonymous credential groundwork

What is still missing:

- live anonymous trust exchange
- stronger onion-native retrieval path
- stronger unlinkability than epoch-scoped pseudonyms
- BBS+ or equivalent upgrade for better within-epoch privacy

### 3. Content retention

**Status:** limited / experimental

Miasma is currently closer to a controlled replicated store than a proven long-lived global content-retention network.
Retention policy, replication behavior, and real-world durability under churn still need much stronger validation.

### 4. Retrieval success rate

**Status:** promising locally, not yet proven at internet scale

What exists:

- loopback and local validation
- Windows beta flows
- installer and diagnostics

What is still missing:

- larger multi-node internet validation
- churn-heavy success-rate measurement
- long-lived relay/descriptor-backed retrieval behavior

### 5. Safety as the network grows

**Status:** early but improving

Routing-security foundations are now much stronger than before, but large-scale node growth, churn, and adversarial pressure are not yet fully characterized.
This is one of the main reasons the project should still be described as beta and validation-stage.

### 6. Practical speed

**Status:** not yet a solved story

Local and controlled-path behavior is workable.
Real practical speed under mobile constraints, multiple hops, relay use, and adversarial-safe routing remains an open engineering problem.

## Why This README Is Being Explicit

Miasma should not overclaim.
If the project says "mobile-first" while only shipping Windows artifacts, that has to be explained clearly.

The honest position is:

- Windows ships first to validate the protocol and operator experience
- mobile remains the actual destination
- the most important unfinished work is still protocol-core and mobile systems work, not cosmetic platform parity

## Current Beta Release

The current public release is a **Windows beta prerelease**.

- Release page: [GitHub Releases](https://github.com/MasayukiTa/miasma-protocol/releases)
- Recommended artifact: `MiasmaSetup-<version>-x64.exe`
- Audience: technical beta users and protocol testers

Important:

- no external security audit yet
- no Authenticode code signing yet
- no claim of production anonymity or production-grade censorship resistance yet

## Near-Term Protocol Milestones

The next core milestones are focused on turning the new foundations into live behavior:

- credential issuance and exchange in the live admission path
- descriptor publication and retrieval in the real network path
- onion-aware path selection feeding real retrieval
- hybrid admission replacing simple binary PoW checks
- stronger relay and rendezvous integration
- adversarial simulations that exercise real end-to-end network behavior

## Repository Structure

- `crates/miasma-core` - protocol, storage, routing, trust, transport
- `crates/miasma-cli` - CLI and daemon entry points
- `crates/miasma-desktop` - Windows desktop app
- `crates/miasma-bridge` - BitTorrent bridge
- `docs/adr/` - architecture decisions and protocol design notes

## Security Note

This project now contains meaningful routing-security and admission work, but it is still a beta-stage networked system.
Unknown peers, hostile environments, adversarial routing pressure, and long-term retention behavior all require more validation.

Treat the current release as:

- serious engineering progress
- suitable for technical beta testing
- not yet a finished, production-hardened anonymity network
