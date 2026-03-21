# ADR-004: Routing Trust Model and Sybil Resistance

## Status: Accepted (Phase 3 — implementation in progress)

## Context

Miasma's network layer inherits Kademlia's open-routing model: any peer can
advertise addresses for itself or others, and those addresses are added to
the routing table with no verification. This creates three related
vulnerabilities:

1. **H3 — Stub signature verification.** `SignedDhtRecord::verify_signature()`
   accepts any non-zero signature bytes. An attacker can publish arbitrary
   DHT records claiming content exists at attacker-controlled nodes.

2. **H4 — PoW exists but is not enforced.** `mine_pow()` and `verify_pow()`
   are implemented but never called. Generating thousands of peer IDs costs
   nothing.

3. **H5 — No address-class separation.** Peer-advertised addresses, Identify
   observed addresses, and relay descriptors are all treated identically.
   A malicious peer can inject loopback, private, or link-local addresses
   into the routing table, enabling SSRF and eclipse attacks.

### The old trust model

```
Peer says "I am PeerId X at address A"
  → We add X→A to Kademlia routing table
  → We dial A when we need to reach X
  → No verification that X controls A or that A is reachable
```

This is fine for cooperative test networks. It is not acceptable for a system
that aims for censorship resistance and routing independence.

### Why tactical patches are insufficient

Simply filtering private IPs or requiring PoW does not address the fundamental
problem: Miasma treats all address claims as trusted routing material. The
correct architecture separates the question of "who exists" from "how to
reach them" and requires evidence before promoting addresses to the routing
table.

## Decision

### New trust model

Address information flows through three tiers of trust:

```
┌─────────────────────────────────────────────────────────┐
│ Tier 1: CLAIMED                                         │
│   Source: peer-advertised, DHT records, bootstrap config │
│   Trust: NONE — stored for reference, never routed to   │
│   Validation: format check + address-class filter only  │
└───────────────────────────┬─────────────────────────────┘
                            │ dial attempt + Identify exchange
                            ▼
┌─────────────────────────────────────────────────────────┐
│ Tier 2: OBSERVED                                        │
│   Source: successful Identify protocol exchange          │
│   Trust: LOW — peer responded, but liveness is unknown  │
│   Validation: Identify confirms PeerId, addr reachable  │
│   Eligible for: Kademlia routing table (provisional)    │
└───────────────────────────┬─────────────────────────────┘
                            │ PoW verification + signature check
                            ▼
┌─────────────────────────────────────────────────────────┐
│ Tier 3: VERIFIED                                        │
│   Source: PoW-valid PeerId + signed Identify exchange   │
│   Trust: HIGH — admitted to routing, can serve records  │
│   Validation: PoW difficulty met, Ed25519 sig valid     │
│   Eligible for: full DHT participation                  │
└─────────────────────────────────────────────────────────┘
```

### Address classes

All addresses are classified before any routing decision:

| Class | Example | Trusted from peers? | Action |
|-------|---------|-------------------|--------|
| Loopback | `127.0.0.1`, `::1` | NEVER | Reject immediately |
| Link-local | `169.254.x.x`, `fe80::` | NEVER | Reject immediately |
| Private | `10.x`, `172.16-31.x`, `192.168.x` | Only from local bootstrap config | Reject from DHT/Identify |
| Global unicast | Public IPv4/IPv6 | After Identify exchange | Accept to Tier 2 |
| Relay/circuit | `/p2p/X/p2p-circuit` | After relay registration | Accept to Tier 2 |
| Onion | `.onion` addresses (future) | After descriptor verification | Accept to Tier 2 |

### Signature verification

DHT records must carry a valid Ed25519 signature:

```
signed_message = BLAKE3(
    domain_separator  ||  // "miasma-v1-dht-record-sig"
    record_key        ||  // 32-byte MID digest
    record_value      ||  // serialized DhtRecord
    signer_pubkey         // 32-byte Ed25519 public key
)

signature = Ed25519.sign(dht_signing_key, signed_message)
```

Domain separation prevents cross-protocol signature reuse. The signing key
is derived from the master key via HKDF (already implemented in
`keyderive.rs` as `LABEL_DHT_SIGN`).

### PoW enforcement

Node IDs must satisfy `BLAKE3(pubkey || nonce)` with `difficulty_bits`
leading zero bits. Enforcement points:

1. **Identify exchange:** remote peer must include PoW proof in Identify
   `AgentVersion` or custom protocol extension. Peers without valid PoW
   are not added to Kademlia.

2. **DHT record validation:** records signed by peers without valid PoW
   are rejected.

3. **Graceful rollout:** initial difficulty is low (8 bits, ~256 hashes)
   to avoid blocking honest nodes. Difficulty increases as the network
   grows.

## Implementation plan

### Phase 3a (this cycle)

- [x] `PeerAddress` type with address classification and trust tiers
- [x] `AddressClass` enum: Loopback, LinkLocal, Private, GlobalUnicast, Relay
- [x] Address filtering in `handle_event` for Identify addresses
- [x] Replace stub `verify_signature()` with real Ed25519 verification
- [x] Wire `verify_pow()` into Identify handler as a gating check
- [x] Design doc (this ADR)

### Phase 3b (this cycle — implemented)

- [x] PoW proof exchange via `/miasma/admission/1.0.0` request-response protocol
- [x] `PeerRegistry` trust-tier state machine: Claimed → Observed → Verified
- [x] PoW-gated routing admission: peers are NOT added to Kademlia until
      they pass the admission handshake (Identify + PoW verification)
- [x] `AdmissionCodec` wire protocol with size limits (4 KiB)
- [x] `SignedDhtRecord` envelope for DHT PUT: all published records are signed
- [x] DHT GET signature validation: records with invalid signatures rejected
- [x] Transition compatibility: unsigned legacy records accepted on GET
- [x] Admission diagnostics in `DaemonStatus`: verified/observed peers, rejection count
- [x] `verify_remote_pow()`: validates PoW pubkey matches peer identity
- [x] Structured admission logging: `admission.requested`, `admission.verified`,
      `admission.rejected` with peer ID and rejection reason
- [ ] Routing table eviction policy (prefer verified peers) — deferred to 3c
- [ ] Relay-aware address discovery — deferred to 3c

### Phase 3c (this cycle — implemented)

- [x] `RoutingTable` overlay: trust-based peer ranking, IP diversity,
      reliability tracking — operates above libp2p Kademlia
- [x] Eclipse resistance: `/16` IPv4 and `/48` IPv6 prefix diversity limits
      (`MAX_PEERS_PER_IPV4_SLASH16 = 3`, `MAX_PEERS_PER_IPV6_SLASH48 = 3`)
- [x] Diversity checks wired into `handle_identify()` production path:
      peers violating prefix limits are rejected before admission
- [x] Per-peer reliability tracking with exponential decay
      (`INTERACTION_WINDOW = 200`, `UNRELIABLE_THRESHOLD = 0.3`)
- [x] Peer ranking: `rank_peers()` scores by trust tier (Verified 300,
      Observed 100, Claimed 0), reliability, and diversity bonus
- [x] Dynamic PoW difficulty adjustment: `observe_network_size()` feeds
      median-based schedule (8/12/16/20/24 bits), `verify_remote_pow()`
      uses `routing_table.current_difficulty()` instead of hardcoded constant
- [x] Reliability tracking wired into Kademlia events: `record_success()`
      on PutRecord OK and valid GET signatures, `record_failure()` on
      invalid signatures
- [x] Routing overlay cleanup on disconnect: `remove_peer()` frees prefix slots
- [x] Routing diagnostics in `DaemonStatus`: routing_peers, routing_unreliable,
      routing_unique_prefixes, routing_max_prefix_concentration,
      routing_diversity_rejections, routing_pow_difficulty
- [x] `GetRoutingStats` DhtCommand + `DhtHandle::routing_stats()` +
      `MiasmaCoordinator::routing_stats()` query path
- [x] 16 unit tests in routing.rs + 7 integration tests for diversity,
      ranking, difficulty, stats, and prefix extraction
- [ ] Onion-aware routing descriptors — deferred to 3d
- [ ] Relay registration and descriptor verification — deferred to 3d
- [ ] Peer state persistence across restarts — deferred to 3d

### Phase 3d (future)

- [ ] Onion-aware routing descriptors
- [ ] Relay registration and descriptor verification
- [ ] Peer state persistence across restarts
- [ ] Dynamic difficulty: wire ranking into share fetch path (coordinator)

## Consequences

- Honest nodes on private networks must use explicit bootstrap config
  (private addresses are rejected from DHT peers). This is intentional.
- Initial PoW difficulty is low — Sybil attacks are more expensive but
  not prohibitively so. This is a tradeoff for network bootstrapping.
- DHT record publishing requires the signing key. Nodes that have been
  wiped cannot publish records until they re-derive keys via `init`.
- Backward-incompatible: old nodes without PoW proofs will be rejected
  once enforcement is enabled. Migration requires re-init.
