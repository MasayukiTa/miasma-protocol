# Dependency review: ML-KEM-768 implementation

Status: review for the optional `pqc` feature of `miasma-core`.
Date of the data below: 2026-10-19 (crates.io metadata and project pages read that day).

## Goal

The hybrid key exchange (`protocol::hybrid`, behind the `pqc` cargo feature) needs a
key-encapsulation mechanism that implements ML-KEM-768 as standardised in FIPS 203.
The project does not implement any cryptographic primitive itself, so the choice is
which maintained library to depend on.

Requirements used for the comparison:

* implements the final FIPS 203 (not the earlier Kyber drafts)
* actively maintained, with a visible release history
* pure Rust or otherwise buildable for Windows, Linux, Android, iOS and wasm without
  extra toolchains
* `no_std`-capable, zeroisation of secrets, no `unsafe` where possible
* permissive licence compatible with the workspace (MIT / Apache-2.0)
* small transitive dependency set

## Candidates

| | `ml-kem` (RustCrypto) | `libcrux-ml-kem` | `fips203` | `pqcrypto-mlkem` |
|---|---|---|---|---|
| Version reviewed | 0.3.3 (2026-10-17) | 0.0.11 (2026-10-07) | 0.4.3 (2025-02-25) | 0.1.1 (2025-08-05) |
| Standard | FIPS 203 final | FIPS 203 (a separate unverified Kyber feature exists, off by default) | FIPS 203 final | FIPS 203 via C reference code |
| Implementation | pure Rust | pure Rust, portable plus AVX2 / Neon SIMD paths chosen by `build.rs` | pure Rust | Rust bindings to C code from a third-party collection |
| Licence | Apache-2.0 OR MIT | Apache-2.0 | MIT OR Apache-2.0 | MIT OR Apache-2.0 |
| Rust version | 1.85 (stated) | not stated in crates.io metadata | 1.85 (README); 1.70 in crates.io metadata | not stated |
| `no_std` | yes (`#![no_std]`) | yes (disable `std`) | yes, no heap use | not stated |
| Maintenance | very active: 0.3.0 (2026-04), 0.3.2 (2026-05), 0.3.3 (2026-10); about 11.5 million downloads | active: five releases since 2026-03; pre-1.0 (`0.0.x`) | one release per few months until 2025-02, none since | project README says it is unmaintained and recommends the RustCrypto crate |
| Audit | README: "never been independently audited" | verification claims (below), no audit statement found | no audit mentioned; fuzzing and timing measurements listed | none found |
| Timing behaviour | no claim in README; 0.3.3 changelog lists removal of secret-dependent table lookups in noise sampling; uses a constant-time helper crate for comparisons and selection | "best-effort" constant time; optional compile-time secret-independence checking (`check-secret-independence`) | source-level claim of no secret-dependent branching (sampling of the public matrix excepted); `dudect` measurements and cycle counts on one embedded target | inherited from the C code, not reviewed |
| Formal methods | none | portable and AVX2 field arithmetic, NTT, serialisation and generic algorithm code verified with hax / F*; Neon code not covered | none | none |
| `unsafe` | not reviewed (see below) | not stated | none, per README | C code |
| New transitive crates for this workspace | 7 (see below) | not resolved here | not resolved here | not resolved here |

## Evidence for `ml-kem` in this workspace

Resolved by `cargo` into `Cargo.lock` (ML-KEM-only additions): `ml-kem 0.3.3`, `kem 0.3.0`,
`module-lattice 0.2.3`, `sha3 0.12.0`, `shake 0.1.0`, `keccak 0.2.2`, `sponge-cursor 0.1.0`.
Already present and reused: `hybrid-array 0.4.15`, `rand_core 0.10.1`, `zeroize`, `ctutils`.
`cargo check --package miasma-core --features pqc` builds on the Windows host.

The crate is on the newer RustCrypto trait generation (`rand_core` 0.10, `sha3` 0.12). The
workspace uses `rand` 0.8 (`rand_core` 0.6), so `protocol::hybrid` carries a small adapter
that exposes the existing random source through the `rand_core` 0.10 traits. The adapter
only forwards bytes; it is not a random generator. The crate has no `rand_core` 0.6 mode.

Features used: `zeroize` only. `default-features = false`. The `hazmat` feature (which
exposes deterministic encapsulation) is not enabled.

## Recommendation

Use `ml-kem` (RustCrypto), version 0.3.3, behind the optional `pqc` feature.

Reasons:

1. It implements the final standard, is the most actively maintained candidate, and is the
   one the unmaintained `pqcrypto` project points to.
2. It is pure Rust and `no_std`, so it needs no C toolchain on Android, iOS or wasm.
3. Secrets are zeroised with the `zeroize` feature, and decapsulation keys are created
   from a 64-byte seed, so the stored form is small and always valid.
4. It shares `zeroize` and `hybrid-array` with crates already in the workspace and its
   other new dependencies are small and from the same project family.
5. The key validation in encapsulation-key parsing rejects non-canonical encodings (a test
   in `protocol::hybrid` exercises this).

Costs and risks to accept:

* No independent audit. The hybrid design limits the exposure: the session key also
  depends on X25519, so a flaw in ML-KEM alone does not remove the classical protection.
* A timing issue (secret-dependent table lookups in noise sampling) was fixed in 0.3.3,
  published two days before this review. Treat the timing behaviour of any pure-Rust ML-KEM
  as unproven until it has been measured on the target devices.
* The crate API changed substantially between 0.2 and 0.3. Pin through `Cargo.lock` and
  review each upgrade.

Second choice: `libcrux-ml-kem`. Its formal verification of the arithmetic core is a
stronger assurance story, but it is `0.0.x`, selects SIMD code in a build script per
target architecture, and was not evaluated for the Android and iOS cross builds here. It is
the right alternative if timing assurance becomes the main concern.

Not recommended: `pqcrypto-mlkem` (the project states it is unmaintained and it needs a C
toolchain). `fips203` is credible and attractive for its `rand_core` 0.6 compatibility and
`no_std` / no-heap design, but its last release is eight months old at the date of this
review.

## What could not be verified

* **Audits.** Only the statements in each project's README were read. A third-party audit
  may exist elsewhere; none was found for any candidate, and the `ml-kem` README states
  there is none.
* **Constant-time behaviour.** Nothing was measured here. The claims above are the
  projects' own. `ml-kem` makes no claim in its README.
* **`unsafe` usage in `ml-kem` and its dependencies** was not audited line by line.
* **Binary size.** Not measured. Needs a release build with and without the feature.
* **Android, iOS and wasm builds with the feature on.** The crate is `no_std`, pure Rust,
  and the targets `aarch64-linux-android`, `x86_64-linux-android` and
  `wasm32-unknown-unknown` are installed on the build host, but only a Windows host check
  was run for this change. Default builds do not include the dependency at all.
* **NIST ACVP and Wycheproof vectors.** The published crate archive does not contain the
  vector files (only a PKCS#8 example set), and they were not downloaded. The known-answer
  test uses the published example key (seed `00 01 .. 3f` to a fixed encapsulation key
  hash). Running the full upstream vectors is a follow-up.
* **Other candidates' dependency trees and Rust version requirements** were not resolved;
  the table repeats published metadata.
* **Release-date claims** come from crates.io on the review date and were not
  cross-checked against the source repositories' tags.
