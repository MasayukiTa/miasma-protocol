# ADR-011: Replace `sharks` with `blahaj` for Shamir Secret Sharing

- **Status**: Accepted
- **Date**: 2026-09-07
- **Supersedes**: the long-standing `cargo audit --ignore RUSTSEC-2024-0398`
  entry in `.github/workflows/ci.yml`

## Context

`sharks` 0.5.0 implements the Shamir Secret Sharing used by
`miasma_core::crypto::sss` to split `K_enc` into the `n` shares that the whole
dissolution model is built on (`crates/miasma-core/src/crypto/sss.rs`,
`crates/miasma-wasm/src/lib.rs`).

RUSTSEC-2024-0398 / GHSA-jp37-5qhw-mffw ("Bias of Polynomial Coefficients in
Secret Sharing", reported by Cure53) says `sharks` drew the non-constant
polynomial coefficients from `[1, 255]` instead of `[0, 255]`. The advisory is
precise about the consequence: knowing that a coefficient cannot be zero lets a
holder of `k-1` shares exclude one byte value per shared byte, and Cure53
estimated that a secret reshared 500-1500 times becomes recoverable.

There is no patched `sharks` release; the maintainer did not respond. The
advisory names its own remediation: `blahaj`, a fork carrying the fix.

Miasma's exposure is bounded but real. A published MID's `K_enc` is split once,
so the "same secret reshared hundreds of times" precondition does not hold for
a single publish. It *does* hold for any workflow that republishes the same
content — the same plaintext yields the same content-derived key material, and
re-publishing is an ordinary operation.

## Decision

Replace `sharks` 0.5.0 with `blahaj` 0.6.0 in `miasma-core` and `miasma-wasm`,
and stop ignoring RUSTSEC-2024-0398 in CI.

## Why this is a safe swap (measured, not assumed)

`blahaj` 0.6.0 is a source-level fork of `sharks` 0.5.0. Diffing the two
vendored sources (636 lines across four files) gives the **complete** set of
differences:

| file | differences |
|---|---|
| `field.rs` | none — byte-identical |
| `share.rs` | one doc-comment `use sharks::` → `use blahaj::` |
| `lib.rs` | five doc-comment `use sharks::` → `use blahaj::` |
| `math.rs` | the fix, plus `u8::max_value()` → `u8::MAX` |

The fix itself:

```
-    let between = Uniform::new_inclusive(1, 255);   // sharks 0.5.0
+    let between = Uniform::new_inclusive(0, 255);   // blahaj 0.6.0
```

That is the entire delta. Nothing else in the arithmetic, the evaluator, the
share layout, or the API changed.

Verified before the swap:

1. **Public API is identical.** `Sharks(pub u8)`, `Share`,
   `dealer`/`dealer_rng`/`recover`, `From<&Share> for Vec<u8>` and
   `TryFrom<&[u8]> for Share` all match byte-for-byte. Only the `use` line and
   the crate name changed in this repo.
2. **Wire format is identical.** The serialized share layout (`[x, y_0, y_1,
   ...]`) is the same code in both crates. Confirmed empirically with a
   differential binary that links *both* crates: a secret split by `sharks`
   0.5.0 recovers correctly through `blahaj` 0.6.0. Shares already published
   under the old crate stay readable.
3. **The fix is observable.** With `k = 2` the polynomial is
   `f(x) = a1*x + s`, so the share at `x = 1` carries `y = a1 + s` (GF(256)
   addition is XOR) and `y == s` exactly when `a1 == 0`. Over 4000 splits of
   the same one-byte secret:

   | crate | `y == s` at `x = 1` |
   |---|---|
   | `sharks` 0.5.0 | **0 / 4000** (structurally impossible) |
   | `blahaj` 0.6.0 | 9 / 4000 (expected ~15.6 at p = 1/256) |

   `crypto::sss::tests::leading_coefficient_can_be_zero` encodes exactly this
   check. It fails deterministically against the biased implementation; its
   false-failure probability against the fixed one is `(255/256)^4000 ~ 2e-7`.
4. **Feature sets match.** Both crates declare `default = ["std",
   "zeroize_memory"]` and `std = ["rand/std", "rand/std_rng"]`, so the
   `miasma-wasm` build surface is unchanged.

## Consequences

- CI no longer carries an ignore for an advisory in the project's core
  cryptographic primitive.
- The dependency is still small and single-maintainer, and the maintainer has
  changed: `blahaj` is published by Distrust rather than by the original
  `sharks` author. That is a supply-chain change, not just a version bump. It
  is accepted here because the fork is 636 lines, its entire delta from the
  crate it replaces is enumerated above, and the crate it replaces has an
  unfixed advisory against it. (Cure53 reported the bias; neither crate has
  had a full third-party audit.)
- `docs/security/audit-checklist.md` and `docs/tasks/webapptasks.md` now name
  `blahaj` where they named `sharks`.
- Already-published shares are unaffected (point 2 above). Content that was
  published repeatedly *before* this change was split with the biased
  generator; that history cannot be retroactively fixed. It should be
  republished if the residual exclusion attack matters for it.
