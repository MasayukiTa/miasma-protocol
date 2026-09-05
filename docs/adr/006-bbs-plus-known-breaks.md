# Known breaks in the BBS+ credential scheme

**Status: the self-written BBS+ implementation is forgeable and is not used for
any trust decision.** Do not re-enable it as an admission input until the
conditions at the bottom of this document are met.

Found and confirmed 2026-09-05. Both breaks are demonstrated by executable
forgery tests in `crates/miasma-core/src/network/bbs_credential.rs`
(`known_generator_dlogs_allow_attribute_forgery_without_the_issuer_key`,
`pairing_check_is_not_bound_to_the_message_commitment`). They are theory-free:
each one constructs a forgery and asserts the verifier accepts it.

## Scope

The two forgeries below are specific to `network/bbs_credential.rs`. Content
dissolution, retrieval and onion routing are unaffected, and every cryptographic
primitive in this repository comes from a reviewed library (`aes-gcm`,
`chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `blake3`, `hkdf`+`sha2`,
`argon2`, `rustls`) used in a conventional composition.

**An earlier revision of this section claimed the Ed25519 credential scheme was
unaffected. That was wrong**, and the correction matters more than the forgeries
do:

- A received descriptor is only checked with `verify_self()` — that it was
  signed by the `signing_pubkey` its own sender embedded in it.
  `credential::verify_presentation`, which checks the issuer, the issuer's
  signature, the holder tag and the epoch, has one production call site, and it
  is a holder checking a credential it was just issued. So the Ed25519 tier is
  self-declared too.
- Measured, not inferred: two nodes that admit each other end up holding **no
  credential at all** (`credential_exchange_actually_stores_a_credential`), for
  both schemes. A node registers its own issuer key as
  `blake3("miasma-cred-issuer-v1" || dht_signing_key)` but registers every
  remote peer by `pow.pubkey`, its identity key. Those never match, so every
  genuinely issued credential is rejected as `UnknownIssuer`.

The credential layer as a whole is therefore implemented, unit-tested, reported
in CLI status — and has never once functioned end to end.

## Break 1 — generators have publicly computable discrete logs

`generators()` documents itself as "hashing domain-separated indices to G1" but
computes `G1Projective::generator() * hash_to_scalar(..)`, which is a scalar
multiple of the base point, not a hash-to-curve. Every generator therefore
satisfies `h_i = t_i * g` for a `t_i` that anyone can derive from public values.

BBS+ unforgeability requires the generators to have *unknown* discrete-log
relationships. Because they do not, the signature commitment collapses to a
single scalar:

```
B = g * ( t0 + s*t1 + sum_i m_i * t_{i+2} )
```

Given one honestly issued signature `(A, e, s)` over messages `m`, an attacker
solves for a blinding factor that leaves the aggregate unchanged:

```
s' = ( T(m,s) - t0 - sum_i m'_i * t_{i+2} ) / t1
```

and `(A, e, s')` is then a valid signature over *any* chosen `m'`. The forgery
test checks this against the real signature equation
`e(A, pk + e*G2) == e(B', G2)` and then round-trips it through
`bbs_create_proof` / `bbs_verify_proof`.

**Effect:** one issued credential is enough to mint `Endorsed` tier, every
capability bit, and an attacker-chosen link secret — which also defeats the
non-transferability the link secret exists to provide.

## Break 2 — the pairing check is not bound to the message commitment

The verifier performs two checks that never meet:

1. a Schnorr proof over the **prover-supplied** commitment `b_point`, and
2. a pairing check `e(A', W) == e(A_bar, G2)`.

No relation ties `b_point` to `(A', A_bar)`. The pairing equality is preserved
when both points are scaled by the same `r`, and the Schnorr half only shows the
prover knows the openings of a commitment it chose itself.

**Effect:** an attacker with **no credential and no issuer key** takes one
observed proof — proofs travel inside peer descriptors — scales `(A', A_bar)`,
builds a fresh commitment over attributes of its choosing, and produces an
accepted `Endorsed` proof. This break survives any fix to Break 1.

## Contributing weakness

`deserialize_g1` returns `G1Projective::generator()` when the input does not
parse, instead of failing. The sibling `parse_scalar_proof` was hardened for
VULN-001/VULN-002; the G1 path was missed.

## Why a fully green test suite did not catch this

The module had 20 passing tests. Every one of them had an honest prover build a
proof and then damaged it — wrong context, malformed encodings, a tampered
disclosed tier. None constructed a proof the way an attacker would, from the
values an attacker can actually obtain. Errors of *construction* are invisible
to tests shaped that way, because the implementation is being checked against
itself.

This is the reason the repair plan builds the verification harness (reference
vectors, differential testing, adversarial construction) *before* touching the
scheme.

## Containment currently in place

- **No credential tier is trusted at admission.** `credential_tier` is `None`;
  neither `bbs_tier()` nor the Ed25519 tier is read, because neither is
  verified. An earlier revision of this document said admission had fallen back
  to the Ed25519 tier — that was the mistake described under Scope, and it is
  corrected in the code.
- Descriptors no longer carry a BBS+ proof, and the BBS+ link secret is no
  longer sent to issuers.
- BBS+ issuer keys are no longer derived from a peer's public PoW key.
- The README no longer advertises BBS+ credentials as a security property.

Still open, tracked rather than fixed: a peer may still attach an arbitrary
`bbs_proof` to a descriptor, which is stored and counted by the
`bbs_credentialed` metrics — so those counters now report attacker-supplied
values and nothing else. `bbs_tier()` remains public. `path_selection` still
reads the unverified Ed25519 tier, though a self-declared high tier does not
appear to gain anything there.

## Conditions for re-enabling

1. Generators derived by real hash-to-curve (RFC 9380; `bls12_381` provides SSWU
   behind its `experimental` feature), under a fixed domain separation tag.
2. Proof rebuilt in the standard ASM06/CDL form, with the second Schnorr
   relation binding the commitment to the randomised signature.
3. `deserialize_g1` fail-open removed.
4. Output matches published reference vectors / a reference implementation —
   not merely "our own tests are green".
5. The two forgery tests inverted into regression tests that assert rejection,
   plus adversarial coverage for identity/off-subgroup points, non-canonical
   scalars and context replay.
6. One external review.

Cryptographic correctness is necessary but not sufficient. The scheme must also
be *deployed* correctly, which it never has been:

7. Issuer public keys are transported and bound under the issuer's identity
   signature, not derived by the recipient from a value the peer publishes.
8. Presentations are verified when a descriptor is received, against a
   verifier-supplied nonce rather than the prover's own PeerId, before any tier
   influences admission or routing.
9. An issuer trust model that is not "every peer that completed one PoW".

And one architectural precondition, because without it the property BBS+ exists
to provide is unreachable regardless of implementation quality: descriptors are
signed by the long-term libp2p identity key and embed its verifying key, the
pseudonym is fixed per epoch, and recipients record PeerId↔pseudonym. Until that
carrier can hide identity, within-epoch unlinkability buys nothing — a point
both external reviewers reached independently.

Until all of the above hold, the scheme stays disconnected from trust
decisions.
