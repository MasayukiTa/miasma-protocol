# ADR-005: Anonymous Trust Layer, Descriptor Routing, and Onion-Native Architecture

## Status: Accepted (Phase 4e+++ — unified relay trust, forwarding verification, pre-retrieval probing, security hotfix sprint, v0.2.0-beta.1 hardening)

## Context

ADR-004 established a routing trust model with PoW-gated admission, trust
tiers, signed DHT records, and IP diversity constraints. This foundation is
necessary but insufficient for a truly Freenet-like system because:

1. **No anonymity in trust assertions.** Proving trust-tier membership
   currently requires revealing the peer's PeerId. A peer cannot prove
   "I am Verified" without also proving "I am PeerId X."

2. **Address-centric routing.** The routing table still fundamentally maps
   PeerId → Multiaddr. In a censorship-resistant system, raw network
   addresses should not be the primary routing material.

3. **Onion as a side path.** The onion routing module exists but the
   default retrieval path is direct. Anonymity should be the design centre,
   not an optional add-on.

4. **Single-axis Sybil resistance.** PoW alone penalises resource-constrained
   devices (mobile) while providing only one cost axis for attackers.

5. **No adversarial testing.** The trust model has unit tests but no
   simulation of realistic attack scenarios.

## Decision

### 1. Anonymous credential layer

Implement a pseudonymous credential system using epoch-scoped ephemeral
Ed25519 keypairs:

```
Issuance:
  Holder generates ephemeral keypair (eph_sk, eph_pk) per epoch
  holder_tag = BLAKE3("miasma-cred-holder-v1" || eph_pk)
  Issuer signs: CredentialBody { tier, epoch, capabilities, holder_tag }
  Holder stores: (SignedCredential, eph_sk)

Presentation:
  Holder shows: SignedCredential + eph_pk + Ed25519.sign(eph_sk, context)
  Verifier checks:
    1. Issuer signature valid
    2. BLAKE3(eph_pk) == holder_tag
    3. Context signature valid (proof of possession)
    4. Epoch within window (current ± 1)
    5. Tier meets minimum
```

**Privacy properties:**
- Cross-epoch unlinkability (new ephemeral key each epoch)
- Issuer-holder separation (other peers don't learn PeerId)
- Non-transferability (need ephemeral secret key)
- Clear upgrade path to BBS+ for within-epoch unlinkability

**Credential tiers:**
- `Observed` — passed Identify exchange
- `Verified` — passed PoW admission
- `Endorsed` — vouched by a credential-issuing authority

### 2. Descriptor-based routing

Replace raw (PeerId, Multiaddr) pairs with structured `PeerDescriptor`s:

| Field | Purpose |
|-------|---------|
| `pseudonym` | BLAKE3 of ephemeral pubkey (unlinkable across epochs) |
| `reachability` | Direct, Relayed, or Rendezvous |
| `addresses` | May be relay circuit addresses (not raw IPs) |
| `capabilities` | can_store, can_relay, can_route, can_issue |
| `resource_profile` | Desktop, Mobile, Constrained |
| `credential` | Optional credential presentation (tier proof) |
| `signature` | Ed25519 over descriptor body |

Descriptors separate discovery (learning a peer exists), introduction (how
to initiate contact), and transport reachability (actual network path).

### 3. Anonymity-aware path selection

Three anonymity policies:
- **Direct**: no anonymity protection
- **Opportunistic**: use onion routing if relays available, fall back to direct
- **Required**: refuse without sufficient hops

Path construction enforces:
- Trust-tier minimum for relay nodes
- IP prefix diversity between consecutive hops
- Preference for desktop/server nodes as relays
- Exclusion of destination from relay set

### 4. Hybrid admission model

Multi-signal Sybil resistance that accommodates mobile devices:

```
admission_score = pow_score + diversity_bonus + reachability_bonus + credential_bonus

  pow_score       = difficulty_bits × 10
  diversity_bonus = 50 if prefix unique
  reachability    = 30 if probe succeeded
  credential      = 100 if valid Verified+ credential

Thresholds:
  Desktop:      100  (PoW at 10 bits alone suffices)
  Mobile:        80  (PoW at 4 bits + credential = 140, passes)
  Constrained:   60  (lowest bar, requires some combination)

Hard floor: MIN_POW_DIFFICULTY = 4 bits (always required)
```

### 5. Adversarial simulation harness

Integration-level attack simulations:
- Sybil cluster (100 peers from same /16 → only 3 admitted)
- Eclipse attempt (attacker diluted by trust ranking)
- Poisoned descriptors (forged credentials rejected)
- Credential replay (context binding prevents reuse)
- Credential theft (holder tag mismatch without ephemeral key)
- Routing pressure (unreliable attackers deprioritised)
- Hybrid admission gaming (minimum PoW floor prevents zero-cost Sybil)

## Implementation

### Phase 4a (this cycle — implemented)

- [x] `credential.rs`: `EphemeralIdentity`, `CredentialBody`, `SignedCredential`,
      `CredentialPresentation`, `CredentialIssuer`, `CredentialWallet`,
      `IssuerRegistry`, `verify_presentation()` — 12 unit tests
- [x] `descriptor.rs`: `PeerDescriptor`, `PeerCapabilities`, `ResourceProfile`,
      `ReachabilityKind` (Direct/Relayed/Rendezvous), `DescriptorStore`,
      signed descriptors with tamper detection — 7 unit tests
- [x] `path_selection.rs`: `AnonymityPolicy`, `PathConstraints`, `PathHop`,
      `RoutingPath`, `PathSelector::select()` with diversity-enforced
      multi-hop path construction — 7 unit tests
- [x] `admission_policy.rs`: `HybridAdmissionPolicy`, `AdmissionSignals`,
      `AdmissionDecision`, `ScoreBreakdown`, mobile/desktop/constrained
      thresholds, minimum PoW floor — 10 unit tests
- [x] Adversarial simulation test suite (`adversarial_test.rs`):
      17 tests covering Sybil clusters, eclipse resistance, poisoned
      descriptors, credential replay/theft, routing pressure, hybrid
      admission gaming, path selection under adversarial relay sets
- [x] Routing table overflow fix: `saturating_sub` for unreliable penalty
- [x] Module wiring: all new modules in `network/mod.rs`, exported via `lib.rs`
- [x] Design doc (this ADR)

### Phase 4b (implemented)

- [x] Wire credential issuance into admission flow: dual Ed25519+BBS+
      issuance on `promote_peer_to_verified()`
- [x] Wire descriptor publication: nodes build and exchange descriptors on
      promotion, including credential presentations and BBS+ proofs
- [x] Wire hybrid admission policy into `verify_remote_pow()`: replace
      binary PoW check with multi-signal `HybridAdmissionPolicy.evaluate()`
- [x] Credential exchange protocol: `/miasma/credential/1.0.0` with verified
      storage (issuer signature + holder tag + epoch + BBS+ proof verification)
- [x] Descriptor exchange protocol: `/miasma/descriptor/1.0.0` with self-verification,
      stale rejection, capacity limits, periodic refresh and broadcast
- [x] BBS+ credentials (bbs_credential.rs ~800 lines): BLS12-381 pairing-based
      multi-message signatures, selective disclosure, within-epoch unlinkability,
      link secret non-transferability, pairing verification LIVE
- [x] DaemonStatus + CLI diagnostics: Trust & Anonymity + Network Health sections
- [x] Epoch rotation: `maybe_rotate()` in event loop, credential re-request,
      descriptor refresh, BBS+ wallet pruning
- [x] End-to-end epoch rotation: wallet rotates identity, expired credentials
      pruned, descriptors refreshed and broadcast

### Phase 4c (implemented)

- [x] **Descriptor-backed relay retrieval**: `retrieve_with_anonymity()` routes
      share fetches through real relay peers selected from the descriptor store.
      Uses libp2p relay circuit addresses (`/p2p/{relay}/p2p-circuit`).
      `Opportunistic` falls back to direct; `Required` fails without relays.
- [x] **Relay peer info pipeline**: `DhtCommand::GetRelayPeers` →
      `DhtHandle::relay_peers()` → `RelayRewritingDhtExecutor` rewrites
      shard location addresses through relay circuits.
- [x] **Pseudonym churn tracking**: `DescriptorStore` tracks epoch transitions,
      computes live churn rate (fraction of pseudonyms new this epoch).
      Wired into `OutcomeMetrics.pseudonym_churn_rate`.
- [x] **Expanded outcome metrics**: `relay_peers_routable`, `bbs_credentialed_count`,
      `stale_descriptor_count`, `descriptor_utilisation`, `pseudonym_churn_rate`
      — all computed from live network state.
- [x] **DaemonStatus extended**: 5 new metric fields wired into CLI diagnostics.
- [x] **Adversarial tests** (12 new, 45 total): epoch rotation churn tracking,
      full pseudonym turnover, idempotent rotation, relay peer info routing,
      relay exclusion, wallet rotation invalidation, BBS+ epoch pruning,
      metrics under churn, BBS+ credentialed count, descriptor utilisation,
      required path selection with descriptors, opportunistic relay preference.
- [x] **ADR-005 updated** to reflect Phase 4b+4c reality.
- [x] **PathSelector wired into coordinator**: relay descriptors from
      `DescriptorStore` drive real retrieval routing decisions.

### Phase 4d (implemented — onion encryption)

- [x] **Per-hop onion encryption**: 2-hop X25519 ECDH + XChaCha20-Poly1305
      per-hop keying so relay peers cannot read share-fetch content.
      `OnionPacketBuilder::build_e2e()` wraps requests in 3 encryption layers:
      outer (R1), inner (R2), and end-to-end (Target).
- [x] **Onion relay protocol**: `/miasma/onion/1.0.0` libp2p request-response
      protocol. Three message types: `Packet` (Initiator→R1), `Forward`
      (R1→R2), `Deliver` (R2→Target). Each relay peels one layer and
      encrypts the response with its per-hop return_key before forwarding back.
- [x] **`onion_pubkey` in descriptors**: X25519 static public key published
      in `PeerDescriptor`, signature-covered for tamper detection.
      `DescriptorStore::relay_onion_info()` returns relay peers with keys.
- [x] **Node-level onion handler**: `MiasmaNode` derives onion static key
      from master key, handles all three onion roles (R1 relay, R2 relay,
      Target delivery), and processes return-path response encryption.
- [x] **Coordinator integration**: `retrieve_via_onion()` builds e2e-encrypted
      onion packets per shard, routes through relay peers, and decrypts
      3-layer responses (r1_return_key → r2_return_key → session_key).
      `AnonymityPolicy::Required` uses onion encryption when relay nodes
      with onion pubkeys are available, falls back to relay circuit rewriting.
- [x] **Adversarial tests** (6 new, 51 total): per-hop content blindness,
      hostile relay wrong-key rejection, per-hop return-key uniqueness,
      descriptor onion_pubkey tamper detection, relay onion info filtering,
      cross-circuit return-key isolation.
- [x] **Unit tests** (4 new in onion_relay.rs): R1 forward, R2 deliver,
      response encryption layering, e2e encrypted build and relay delivery.

### Phase 4d+ (implemented — relay detection, retrieval tracking)

- [x] **Real relay capability detection**: `MiasmaNode.nat_publicly_reachable`
      tracks AutoNAT status transitions. `build_local_descriptor()` sets
      `can_relay` from live NAT status (no longer hardcoded `false`).
      `DhtCommand::GetNatStatus` + `DhtHandle::nat_publicly_reachable()`
      expose to coordinator/daemon. CLI diagnostics show NAT status.
- [x] **Per-anonymity-mode retrieval tracking**: `RetrievalStats` in
      coordinator tracks attempts/successes/failures per mode (Direct,
      Opportunistic relay/fallback, Required onion/relay/failure).
      Wired through `DaemonStatus` to CLI diagnostics.
- [x] **Adversarial tests** (6 new, 57 total): NAT-driven relay capability
      in descriptors, false relay capability acceptance, retrieval stats
      defaults and serde roundtrip, relay onion info filtering with
      capability + pubkey requirements, NAT transition descriptor updates.

### Phase 4e (implemented — rendezvous descriptors, relay trust verification)

- [x] **Rendezvous descriptors with introduction points**: NAT'd nodes
      publish `ReachabilityKind::Rendezvous { intro_points }` containing
      pseudonyms of relay peers that serve as introduction points. Clear
      distinction maintained: Direct (public IP), Relayed (circuit), and
      Rendezvous (intro-point mediated, NAT-driven).
- [x] **Relay trust tiers (behaviour-observed)**: `RelayTrustTier` enum
      (Claimed → Observed → Verified) based on passive relay outcome
      observation — not self-description. Promotion: ≥1 success → Observed,
      ≥3 successes with ≥75% rate → Verified. Demotion on failure.
- [x] **Relay observation with epoch decay**: `RelayObservation` tracks
      successes/failures per pseudonym. Counters halved on epoch rotation
      so stale trust doesn't linger. Cleaned when descriptors pruned.
- [x] **Per-kind descriptor freshness**: Rendezvous descriptors expire in
      20 minutes (`MAX_RENDEZVOUS_AGE_SECS = 1200`) vs 1 hour for Direct/
      Relayed, because intro points change under NAT re-binding and churn.
- [x] **Introduction point resolution and selection**:
      `DescriptorStore::resolve_intro_points()` resolves pseudonyms →
      (PeerId, addresses, relay_tier, onion_pubkey) sorted by trust tier
      (Verified first). `select_intro_points()` picks relay peers for
      rendezvous publication, preferring higher trust tiers.
- [x] **NAT-driven reachability**: `build_local_descriptor()` sets
      Rendezvous when NAT is private and relay peers available, Direct
      when publicly reachable. AutoNAT status drives the decision.
- [x] **Rendezvous retrieval**: `retrieve_via_rendezvous()` resolves intro
      points from descriptors, tries each in trust-tier order, records
      relay outcomes per attempt. Integrated into `retrieve_via_relay()`
      for shard holders with Rendezvous reachability.
- [x] **Per-mode retrieval tracking (extended)**: `RetrievalStats` now
      tracks rendezvous_attempts, rendezvous_successes, rendezvous_failures,
      rendezvous_direct_fallbacks. Wired through DaemonStatus to CLI.
- [x] **Observability**: relay tier counts (claimed/observed/verified),
      rendezvous peer count, rendezvous retrieval stats all in DaemonStatus
      and CLI diagnostics.
- [x] **Adversarial tests** (11 new, 68 total): relay trust promotion/
      demotion (4), rendezvous descriptor creation/resolution (4), stats
      and serde (2), relay peer sorting by trust tier (1).

### Phase 4e+ (implemented — onion+rendezvous composition)

- [x] **Onion + rendezvous composition in Required mode**: NAT'd shard holders
      with `ReachabilityKind::Rendezvous` are now retrievable through a
      content-blind onion path. The intro point is used as R2 in the 2-hop
      circuit: Initiator → R1 → R2(intro point) → Target(via relay circuit).
      R2/intro point cannot read the e2e-encrypted payload.
- [x] **Per-shard path selection**: `retrieve_via_onion_rendezvous()` handles
      mixed DHT records where some holders are Direct and others Rendezvous.
      For each shard, R2 is chosen based on the holder's reachability kind.
- [x] **Fixed target onion pubkey lookup**: New `DhtHandle::peer_onion_pubkey()`
      uses `DescriptorStore::onion_pubkey_for_peer()` to look up any peer's
      onion pubkey, not just relay-capable peers. Fixes a pre-existing issue
      where `retrieve_via_onion()` fell back to wrong keys.
- [x] **Path hierarchy in Required mode**: (1) Onion+rendezvous for NAT'd
      holders, (2) standard onion for direct holders, (3) relay circuit
      fallback. Coordinator tries strongest privacy first.
- [x] **Rendezvous+onion stats**: `rendezvous_onion_attempts/successes/failures`
      tracked independently. Content-blind retrievals distinguishable from
      IP-privacy-only retrievals via `required_onion_successes` +
      `rendezvous_onion_successes` vs `required_relay_successes` +
      `rendezvous_successes`.
- [x] **Diagnostics**: DaemonStatus extended with 3 new fields, CLI shows
      "Rendezvous+Onion (content-blind)" row when applicable.
- [x] **Adversarial tests** (7 new, 75 total): onion-capable intro point
      preference, no-onion-intro fallback, mixed holders with onion pubkeys,
      broken intro with fallback, rendezvous+onion stats serde, content-blind
      vs IP-only distinction, R1≠R2 constraint validation.
- [x] **Shared helper**: `decrypt_onion_response()` extracted for 3-layer
      response decryption, used by both `retrieve_via_onion()` and
      `retrieve_via_onion_rendezvous()`.

### Phase 4e++ (implemented — full path hierarchy, active relay probing)

- [x] **Opportunistic mode: full path hierarchy**: `retrieve_via_relay()` now
      tries all 4 privacy paths in descending strength order:
      (1) Onion+rendezvous → (2) standard onion → (3) rendezvous relay →
      (4) relay circuit. Falls through on failure, with direct as final fallback.
- [x] **Active relay probing protocol**: `/miasma/relay-probe/1.0.0` —
      separate protocol (not onion wire format mutation). `ProbeRequest{nonce}`
      / `ProbeResponse{nonce}` echo. `RelayProbeCodec` (bincode + 4-byte LE
      length-prefix, 256B max). Wired into node swarm event loop: inbound echo
      (relay side), outbound verification (prober side). `DhtHandle::probe_relay()`
      generates nonce, sends probe, verifies echo. `MiasmaCoordinator::probe_relay()`
      records observation for trust tier tracking.
- [x] **Granular opportunistic stats**: `opportunistic_onion_successes`,
      `opportunistic_onion_rendezvous_successes`, `opportunistic_rendezvous_successes`
      — each path separately counted alongside existing `relay_successes`
      and `direct_fallbacks`.
- [x] **Relay probe stats**: `relay_probes_sent`, `relay_probes_succeeded`,
      `relay_probes_failed` tracked in `RetrievalStats`.
- [x] **5-level privacy model in diagnostics**: CLI now shows all 5 paths
      clearly in the Retrieval Tracking section: onion+rendezvous (content-blind
      +NAT), onion (content-blind), rendezvous relay (IP-only+NAT), relay circuit
      (IP-only), direct fallback. Relay probe stats shown separately.
- [x] **DaemonStatus extended**: 9 new fields for granular opportunistic stats
      and relay probe counters.
- [x] **Adversarial tests** (6 new, 81 total): opportunistic stats granularity,
      relay probe stats tracking, relay probe nonce echo, nonce mismatch failure,
      zero nonce sentinel failure, five privacy paths distinguishable.

### Phase 4e+++ (implemented — unified relay trust, forwarding verification, pre-retrieval probing)

- [x] **Automatic pre-retrieval relay probing**: Before each Opportunistic or
      Required retrieval, `probe_stale_relay_candidates()` probes up to 3 relay
      peers without fresh evidence (freshness window: 300s). Stale candidates
      are probed, outcomes recorded, trust tiers updated before path selection.
      One forwarding verification attempted for top relay if it has a fresh
      probe but no forwarding evidence.
- [x] **Forwarding verification via circuit-routed probe**: `verify_relay_forwarding()`
      proves R1 actually forwards traffic by sending a relay probe to R2 through
      R1's relay circuit address (`/p2p/{R1}/p2p-circuit/p2p/{R2}`). If R2 echoes
      the nonce, R1 demonstrably forwarded the request. No new wire protocol
      needed — reuses existing `/miasma/relay-probe/1.0.0`.
- [x] **Unified relay trust model**: `RelayObservation` extended with
      `probe_succeeded_at` and `forwarding_verified_at` timestamps. Trust tier
      computation now uses all evidence coherently:
      (1) Forwarding-verified + ≥1 passive success → Verified (strongest)
      (2) Probe-verified + ≥2 passive successes at ≥66% rate → Verified
      (3) ≥3 passive successes at ≥75% rate → Verified (original rule)
      (4) ≥1 passive success OR probe success → Observed
      (5) Otherwise → Claimed.
      Probe/forwarding timestamps survive epoch decay (time-based freshness).
- [x] **Retrieval-path decision coherence**: Extracted `try_relay_paths()` —
      single shared path hierarchy for both Opportunistic and Required modes.
      Eliminates duplicated fallback logic. Both modes: onion+rendezvous →
      onion → rendezvous relay → relay circuit. Mode parameter controls which
      stats counters increment and how failures are handled.
- [x] **Extended diagnostics**: Probe cache freshness (`probed_fresh`),
      forwarding-verified relay count, forwarding probe stats (sent/ok/fail),
      pre-retrieval sweep count — all in DescriptorStats, DaemonStatus, CLI.
      CLI shows relay trust evidence quality and verification status.
- [x] **DhtCommand plumbing**: `RecordProbeSuccess`, `RecordForwardingVerification`,
      `HasFreshProbe`, `GetRelayObservation` — all wired through node event loop.
- [x] **Adversarial tests** (8 new, 89 total): probe cache freshness/expiry,
      forwarding fast-track to Verified, mixed evidence (probe+passive),
      forwarding survives epoch decay, descriptor store probe freshness,
      descriptor store forwarding verification, circuit address format,
      forwarding probe stats serde.

### Phase 4e+++ remaining boundaries

- **Periodic background probing**: Pre-retrieval probing is reactive (runs
  before each retrieval). Periodic probing on a timer or on descriptor
  receipt is not wired. The current approach is sufficient for retrieval
  quality but does not build trust evidence during idle periods.
- **Forwarding verification requires both R1 and R2 online**: The circuit-
  routed probe fails if R2 is unreachable or doesn't support the probe
  protocol. This is acceptable — forwarding verification is best-effort
  evidence that fast-tracks trust when available.
- **No cooperative third-party forwarding test**: The forwarding verification
  proves R1 forwards to R2 specifically. It does not prove R1 forwards to
  arbitrary third parties. A fully general forwarding test would require a
  cooperative verification service, which is architecturally complex and
  deferred.

### Security hotfix sprint (pre-beta)

Targeted fixes for concrete security bugs identified during review:

1. **VULN-001 (CRITICAL) — Zero-key onion fallback eliminated**: Both
   `retrieve_via_onion()` and `retrieve_via_onion_rendezvous()` previously
   fell back to `[0u8; 32]` when the self-onion-pubkey lookup failed. This
   would produce trivially decryptable onion packets. Fixed: both paths now
   skip the shard on failure, matching the remote-peer path. Additionally,
   `DescriptorStore::relay_onion_info()` and `onion_pubkey_for_peer()` now
   filter out all-zero pubkeys at the data layer.

2. **VULN-002 (HIGH) — R1≠R2 invariant enforced**: The onion+rendezvous
   path previously used `unwrap_or(&relays[0])` when no distinct R1 existed,
   potentially making R1==R2 and collapsing 2-hop privacy to zero. Fixed:
   the path now skips the shard with a warning when no distinct R1 is
   available. This is a hard invariant, not best-effort.

3. **VULN-003 (MEDIUM-HIGH) — min_hops enforced per path step**: Each
   path in `try_relay_paths()` now checks whether it provides enough hops
   to satisfy `min_relay_hops`. Onion paths provide 2 hops; rendezvous relay
   and relay circuit provide 1 hop. `Required { min_hops: 2 }` now correctly
   skips single-hop paths. If no path satisfies the requested hop count, the
   retrieval fails with an explicit error.

4. **VULN-004 (MEDIUM) — Windows key-file ACL race fully eliminated**:
   The `secure_file` module uses Win32 `CreateFileW` with a
   `SECURITY_ATTRIBUTES` / `SECURITY_DESCRIPTOR` containing a DACL that
   grants only the current user full control.  The file is **born
   restricted** — there is no window where it exists with inherited
   (permissive) ACLs.  On Unix, `open()` with mode `0o600` is used.
   `master.key` uses `atomic_write_restricted()` (create restricted temp →
   rename) for additional safety.  The old `icacls`-based approach has been
   fully replaced.

5. **VULN-005 (MEDIUM) — Config credentials protected and wipe-scrubbed**:
   `config.toml` is written via `secure_file::write_restricted()` when proxy
   credentials are present — same Win32 DACL approach as master.key.  Files
   without credentials use normal permissions.  `distress_wipe()` calls
   `scrub_credentials()` to remove proxy username/password from config.toml.
   `verify_restricted()` provides programmatic ACL verification used in
   unit tests and the `validate-acl.ps1` CI script.

### v0.2.0-beta.1 hardening (completed)

All items below were shipped before the beta cut:

1. **Onion packet padding**: `LayerPayload.data` padded to 8 KiB
   (`ONION_PAD_TARGET`) with 4-byte LE length prefix + random fill.
   Prevents size-based traffic correlation.  Timing correlation remains
   a known limitation.

2. **Onion replay protection**: bounded `VecDeque<[u8; 32]>` cache of
   BLAKE3(circuit_id || ephemeral_pubkey) fingerprints (4096 entries).
   Replayed packets rejected before `process_onion_layer`.

3. **Anti-gaming demotion**: `recompute_tier()` forces `Claimed` when
   a relay has ≥2 failures and <50% success rate, regardless of probe
   or forwarding evidence.  Prevents selective-drop strategies.

4. **Periodic background relay probing**: node event loop probes one
   stale relay (no fresh probe within 300s) per ~5000 ticks via the
   existing `/miasma/relay-probe/1.0.0` protocol.

5. **DhtCommand backpressure**: fire-and-forget commands (`record_relay_outcome`,
   `record_probe_success`, `record_forwarding_verification`) use `try_send()`
   — non-blocking, warn-and-drop on full channel.  Request-reply commands
   have a 30s timeout on the oneshot reply to prevent indefinite hangs.

**Remaining (not beta blockers)**:
- SSD secure deletion limitations (documented, not fixable in software)
- Constant-rate traffic padding (currently only fixed-size, not constant-rate)

### Phase 4f (future)

- [ ] Cooperative third-party forwarding verification service
- [ ] Service descriptors: advertise storage capacity, relay bandwidth
- [ ] Credential delegation: trust authorities can delegate issuance
- [ ] Mobile-specific optimisations: credential caching, PoW offloading

### Mobile readiness (design constraints)

**Android** is the first-class mobile node target:
- Full node participation with adaptive PoW (hybrid admission scores credential
  bonus, allowing mobile min_pow=4 with credential to pass desktop thresholds)
- `ResourceProfile::Mobile` propagated in descriptors so the network assigns
  appropriate workloads
- Background execution requires foreground service or WorkManager for epoch rotation
- Reconnect after sleep: credential wallet re-requests on epoch rotation
- NAT traversal: libp2p autonat + DCUtR + relay client already wired
- Battery pressure: relay and storage duties should be opt-in on mobile

**iOS** is retrieval-first, not an equal always-on full node:
- Retrieval-only mode using `AnonymityPolicy::Opportunistic`
- Background execution limited by iOS (no long-lived daemon feasible)
- No relay or storage capability advertised
- Bandwidth and storage pressure are explicit constraints
- Credential caching across app launches reduces re-admission cost

## Consequences

- **New module dependencies**: credential.rs depends on ed25519-dalek and
  blake3 (both already available). No new crate dependencies added.
- **Epoch rotation**: credential wallet needs periodic rotation. Failure to
  rotate means stale credentials that verifiers will reject.
- **Issuer trust bootstrapping**: in bootstrap mode, all Verified peers are
  implicit issuers. This is a pragmatic choice that should be narrowed as
  the network grows.
- **Descriptor storage overhead**: each descriptor is ~500 bytes. At 10,000
  peers, the descriptor store uses ~5 MB of memory.
- **Path selection latency**: multi-hop paths add relay latency. The
  Opportunistic policy mitigates this by falling back to direct when
  anonymity is not needed.
- **Onion encryption overhead**: each share-fetch request incurs 3 ECDH
  operations (R1, R2, Target) plus 3 XChaCha20-Poly1305 encrypt/decrypt
  per direction. At ~1 µs per ECDH on modern hardware, this adds <10 µs
  per shard fetch — negligible vs network latency.
- **Mobile admission**: the hybrid model allows mobile devices to
  participate with reduced PoW if they have a credential from a known
  issuer. This explicitly trades some Sybil resistance for accessibility.

## Relationship to ADR-004

This ADR extends ADR-004's three-tier trust model:

```
ADR-004 tiers:     Claimed → Observed → Verified
ADR-005 extension: Claimed → Observed → Verified → Endorsed (credential-backed)
```

The anonymous credential layer sits *above* the existing admission system.
A peer first passes ADR-004's admission (PoW + diversity), then optionally
receives a credential that can be presented pseudonymously. The two systems
are complementary, not replacements.
