# ADR-008: Transport Strategy and Fallback Ladder

**Status**: Accepted
**Date**: 2026-03-24
**Context**: Bridge Connectivity Superhardening (Phase 1)

## Problem

Miasma has multiple transport types but no documented strategy for when each is tried, what conditions trigger fallback, or how the system behaves under various network restrictions. This ambiguity makes it difficult to reason about connectivity guarantees.

## Decision

Define a canonical fallback ladder and per-condition transport strategy.

### Fallback Ladder (ordered by preference)

| Priority | Transport | Condition | DPI-Resistant | NAT Traversal |
|----------|-----------|-----------|---------------|---------------|
| 1 | DirectLibp2p (QUIC+TCP) | Default, fastest | No | AutoNAT+DCUtR |
| 2 | TcpDirect | QUIC blocked (UDP filtered) | No | No |
| 3 | WssTunnel (WSS/443) | High ports filtered, only 443 open | Yes (SNI) | Via proxy |
| 4 | ObfuscatedQuic (REALITY) | DPI active | Yes (active-probe resistant) | No |
| 5 | RelayHop | Direct connectivity impossible | Partial | Yes |
| 6 | Shadowsocks* | DPI + protocol fingerprinting | Yes | Via SS server |
| 7 | Tor* | Anonymity required or all else fails | Yes | Via Tor network |

*Shadowsocks and Tor are feature-gated and require user configuration.

### Per-Condition Behavior

| Network Condition | Primary Transport | Fallback Path |
|-------------------|-------------------|---------------|
| Healthy LAN | DirectLibp2p | — |
| UDP filtered | TcpDirect → WssTunnel | RelayHop |
| TCP high-ports filtered | WssTunnel (443) | RelayHop |
| DPI active (protocol inspection) | ObfuscatedQuic | WssTunnel → Shadowsocks* |
| Full TLS inspection (ZTNA) | ObfuscatedQuic (if QUIC allowed) | WSS with real SNI |
| NAT (both sides) | RelayHop | DCUtR hole-punch |
| Broken mDNS | Bootstrap peers | Cached peers → Kademlia |
| Stale peer state | Connection health prunes stale | Re-bootstrap |
| Captive portal | Detect + user notification | Retry after auth |
| Nation-state filtering* | Shadowsocks → Tor | ObfuscatedQuic |

### Transport Selection Logic

The `PayloadTransportSelector` tries transports sequentially in priority order. On failure at any transport, it records a `TransportAttempt` and moves to the next.

Key behaviors:
- **First success wins**: no unnecessary transport probing
- **All attempts recorded**: the `FallbackTraceBuffer` logs every sequence for diagnostics
- **Backoff on failure**: `DialBackoff` prevents hammering dead addresses
- **Stale pruning**: addresses with repeated failures are removed from the routing table

### Connection Health

The `ConnectionHealthMonitor` provides:
- Per-peer quality scoring (success rate × consecutive-failure penalty)
- Exponential dial backoff (2s base, 300s max, jitter)
- Stale address pruning after 5 consecutive failures
- Degraded connectivity detection (peer count below threshold)

### Diagnostics Visibility

Every transport operation produces a `FallbackTrace` recording:
- Which transports were tried, in what order
- Which succeeded or failed, with error details
- Wall time per step
- Total sequence duration

Available via `miasma diagnostics` CLI and `/api/diagnostics` HTTP endpoint.

## Consequences

- Clear, documented transport selection behavior
- Actionable diagnostics when connectivity fails
- Foundation for Shadowsocks/Tor integration (Phases 3-4)
- No silent ambiguity about which transport is active
