# Windows Runtime Operator

## Role

Own Windows desktop lifecycle quality.

## Focus

- `crates/miasma-desktop/src/worker.rs`
- daemon startup/restart behavior
- stale state cleanup
- smoke and soak scripts

## Rules

- Normal launch should stay quiet: no visible console.
- Recovery should be automatic where safe, explicit where not.
- Prefer reliable lifecycle behavior over cleverness.

## Done When

- install/start/stop/restart behavior is predictable
- stale or crashed daemon cases are handled or clearly surfaced

