# ADR-010: Directed Sharing Transport Architecture

## Status: Accepted (Part 2 implemented — 2026-04-01)

## Date: 2026-03-31

---

## Context

During enterprise overlay validation (Track 4, 2026-03-31), directed sharing
was found to be architecturally incompatible with Tor SOCKS5 proxy. This ADR
documents that finding, defines the current product boundary, and specifies the
concrete next implementation path.

### How directed sharing currently uses the network

The directed sharing control plane uses **libp2p request-response**
(`/miasma/directed/1.0.0`). Every operation in the protocol — Invite, Confirm,
SenderRevoke — is an outbound `send_request(&peer_id, request)` call that
requires an **established libp2p connection** to the target peer (`node.rs:2004-2008`).

The payload transport layer (Tor SOCKS5, Shadowsocks, WSS, TCP) is used only
for **share fetches** (`fetch_share()` in `transport/`). It has no role in the
directed sharing control plane.

### Why Tor SOCKS5 does not work for directed sharing

Tor SOCKS5 is an **outbound-only** TCP proxy. It allows a node to reach Tor
hidden services and clearnet addresses via Tor circuits, but it does not make
the node reachable for **inbound** connections.

The directed sharing confirm step (`DirectedRequest::Confirm`) requires the
recipient to send a response to the sender. Both peers must be mutually reachable
at the libp2p layer. Tor SOCKS5 provides outbound-only connectivity — the
confirm step fails because the sender is not reachable for the response.

| Step | Direction | Tor SOCKS5 helps? |
|------|-----------|-------------------|
| Invite: sender → recipient | Outbound | Maybe (if recipient is a Tor HS) |
| Invite: recipient → sender (accept) | Inbound | NO |
| Confirm: sender → recipient | Outbound | Maybe |
| Confirm: recipient → sender (code) | Inbound | NO |
| Revoke: sender → recipient | Outbound | Maybe |
| Revoke: recipient → sender (ack) | Inbound | NO |

**Conclusion**: Tor SOCKS5 cannot provide directed sharing. It is not a
configuration issue or a deployment gap — it is a structural mismatch between
a unidirectional outbound proxy and a bidirectional P2P protocol.

---

## Decision

### Part 1 — Current product boundary (immediate)

> **Directed sharing requires bidirectional P2P reachability between sender
> and recipient. Tor SOCKS5 proxy is not used for the directed sharing control
> plane (`/miasma/directed/1.0.0`).**

Permitted connectivity modes for directed sharing:

| Mode | Works? | Notes |
|------|--------|-------|
| Direct libp2p (same LAN, mDNS) | YES | Field-proven (Track A, Track B) |
| Direct libp2p (public internet, routable IP) | YES | Requires reachable listen addr |
| Relay circuit (`/p2p/{relay}/p2p-circuit`) | YES (see Part 2) | Relay infra exists; not yet wired to directed |
| Tor SOCKS5 proxy | NO | Outbound-only; confirm/revoke require inbound |
| Shadowsocks proxy | NO | Same reason as Tor |

This must be stated in release documentation and user-visible help text.

### Part 2 — Next implementation path (relay circuit fallback)

The project already has a complete relay circuit infrastructure (Phase 4c through
4e++):

- Relay peers are tracked in `DescriptorStore` with trust tiers
- Relay circuit addresses (`/p2p/{relay}/p2p-circuit/p2p/{target}`) are built
  and used for share retrieval (`retrieve_via_relay`, `RelayRewritingDhtExecutor`)
- Active relay probing (`/miasma/relay-probe/1.0.0`) validates relay reachability

The same relay circuit mechanism can provide bidirectional P2P connectivity for
directed sharing. A relay circuit connection is still a full libp2p connection —
once established, `send_request(&peer_id, request)` works over it without changes
to the request-response protocol.

**Concrete implementation task**: Relay dial fallback in `SendDirectedRequest`

When `DhtCommand::SendDirectedRequest` is dispatched and the peer is not already
connected:

1. Check if any relay peers are available in the `DescriptorStore` with
   `RelayTrustTier::Observed` or `Verified`.
2. For each relay peer (sorted by trust tier, highest first):
   a. Build the circuit address: `/p2p/{relay}/p2p-circuit/p2p/{target}`
   b. Dial the target via the circuit address using `swarm.dial(circuit_addr)`.
   c. Wait for `ConnectionEstablished` event (bounded timeout, e.g. 10s).
3. If a circuit connection is established, proceed with `send_request`.
4. If all circuit attempts fail, return `MiasmaError::Network(...)` as now.

This extends the existing relay circuit path from the data plane to the control
plane. The directed sharing protocol itself is unchanged.

**Scope boundary**: This fallback applies when the target peer is not already
connected. If the peer is already connected (direct or existing circuit), no
relay lookup is performed.

**Out-of-scope for this task**:

- Tor hidden service integration for directed sharing — requires Tor HS support
  in libp2p, which is not on the current roadmap.
- Asynchronous/mailbox delivery — a different protocol model requiring separate
  ADR.
- Shadowsocks proxy for control plane — same structural mismatch as Tor SOCKS5.

---

## Consequences

### What changes (Part 1 — documentation only)

- ADR-006 limitation section updated: "Tor SOCKS5 is not used for the directed
  sharing control plane."
- Release documentation: "Directed sharing requires direct or relay P2P
  connectivity. It does not work over Tor SOCKS5."
- Validation reports: Track D accurately describes the architectural boundary
  rather than framing it as a missing field test.

### What changes (Part 2 — IMPLEMENTED 2026-04-01)

- `node.rs` `DhtCommand::SendDirectedRequest` handler: relay circuit fallback
  added. When the target peer is not directly connected, the handler inspects
  `DescriptorStore::relay_peer_info()` for relay-capable peers (sorted by trust
  tier: Verified > Observed > Claimed), builds circuit multiaddrs
  (`/p2p/{relay}/p2p-circuit/p2p/{target}`), and registers them with the swarm
  so libp2p can dial via relay. Self-relay (target == relay) is excluded.
- `DhtHandle::send_directed_request`: no signature change; fallback is internal
  to the node.
- 7 adversarial tests: circuit address format, no-candidates empty, trust-tier
  sorting, target-self-exclusion, request serde (Invite/Confirm/Revoke/Status),
  multiple-candidate multiple-circuit, response serde roundtrip.

### What does NOT change

- The directed sharing cryptographic protocol (ADR-006) is unchanged.
- Share retrieval (dissolve/retrieve) continues to use the existing relay/onion
  paths.
- Tor SOCKS5 continues to work for payload transport.

---

## Relationship to other ADRs

- **ADR-005**: The relay circuit infrastructure used by Part 2 was built in
  Phase 4c and extended through 4e++. This ADR reuses that infrastructure for
  the directed sharing control plane.
- **ADR-006**: The "connectivity requirement" section must be updated to reflect
  this boundary. The aspirational statement "including onion routing and relay
  circuits when configured" is accurate for the data plane (share retrieval)
  but was not yet accurate for the control plane. Part 2 of this ADR makes it
  accurate for relay circuits (not Tor/onion).
- **ADR-008 / ADR-009**: Transport strategy decisions are not affected. This
  ADR concerns the P2P control plane routing, not transport fallback ladders.

---

## Non-options considered and rejected

### Tor hidden service for directed sharing

Would require implementing Tor hidden service support at the libp2p transport
level. The `libp2p-tor` crate is experimental and not integrated. This is a
multi-month effort with significant external dependency risk. Rejected for now.

### HTTP bridge relay over Tor

Route directed requests through the daemon's HTTP bridge, which can use Tor
SOCKS5 for outbound connections. This requires: (a) the recipient's HTTP bridge
to be accessible (it only listens on localhost), (b) some form of rendevouz or
relay for the HTTP path. No existing infrastructure supports this. Rejected.

### Asynchronous mailbox/inbox layer

Sender deposits envelope to a relay node; recipient polls. Eliminates
simultaneous connectivity requirement. This is a different protocol model
(store-and-forward vs. live handshake), requires ADR-006 redesign, and loses
the anti-misdirection property (sender cannot confirm recipient identity
before content becomes retrievable). Deferred as a potential future protocol
extension, not a near-term implementation.
