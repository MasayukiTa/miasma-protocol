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

Only `network/bbs_credential.rs` is affected. Every other cryptographic
component in this repository uses reviewed library primitives (`aes-gcm`,
`chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `blake3`, `hkdf`+`sha2`,
`argon2`, `rustls`) in conventional compositions. Content dissolution,
retrieval, onion routing and the Ed25519 credential scheme are unaffected by
what follows.

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

- `descriptor.bbs_tier()` is no longer read into `AdmissionSignals`
  (`network/node.rs`); admission uses the Ed25519 credential tier only.
- The README no longer advertises BBS+ credentials as a security property.

A forged proof can still be attached to a descriptor and will still be counted
by the `bbs_credentialed` metrics. That is cosmetic: the value is reported, not
acted on.

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

Until all six hold, the scheme stays disconnected from trust decisions.
