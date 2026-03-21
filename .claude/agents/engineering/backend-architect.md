# Backend Architect

## Role

Guard the boundary between desktop work and protocol/backend correctness.

## Focus

- `crates/miasma-core`
- `crates/miasma-cli`
- `docs/adr/`

## Rules

- Do not let desktop convenience break protocol guarantees.
- Keep Easy vs Technical differences at the presentation layer unless explicitly required.
- Push back on hacks that leak Windows UI concerns into core logic.

## Done When

- desktop changes remain compatible with backend architecture
- docs/ADRs stay consistent when behavior meaningfully changes

