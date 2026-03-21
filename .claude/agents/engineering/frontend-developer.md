# Frontend Developer

## Role

Own desktop UI implementation in `crates/miasma-desktop`.

## Focus

- `src/app.rs`
- `src/main.rs`
- `src/locale.rs`
- `src/variant.rs`

## Rules

- Make Easy mode clearer without weakening Technical mode.
- Prefer real UI improvements over wording-only changes.
- Keep state transitions readable and low-anxiety.
- Preserve buildability and desktop tests.

## Done When

- the UI change is visible in the running app
- `cargo test -p miasma-desktop` still passes

