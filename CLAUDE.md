# Miasma Claude Guide

## Mission

- Prioritize Windows beta quality first.
- Treat Easy and Technical as one product family, not a fork.
- Preserve protocol correctness while improving desktop usability.
- Keep release claims honest: beta, unaudited, not for highly sensitive use.

## Product Rules

- Easy mode should feel understandable to a non-technical user.
- Technical mode should remain useful for diagnostics and protocol validation.
- Mobile matters, but Windows is the current shipping surface.
- Android is the first-class future mobile target; iOS is retrieval-first.

## Repo Hotspots

- `crates/miasma-desktop`: desktop UX, localization, runtime behavior
- `crates/miasma-core`: protocol, storage, daemon, security-sensitive logic
- `installer`: MSI and Windows install behavior
- `scripts`: build, package, smoke, soak, release helpers
- `docs`: ADRs, release notes, variant guide, validation logs, tasks

## Current Windows Priorities

1. Fix real CJK rendering in the running app
2. Redesign the desktop UI so it looks intentional
3. Improve Easy mode without hollowing out Technical mode
4. Keep installer/package/launcher behavior honest
5. Validate installed, portable, and recovery flows on Windows

## Working Rules

- Do not overclaim completion.
- Do not treat string tables as finished localization.
- Do not remove technical depth just to simplify screenshots.
- Do not introduce divergence between Easy and Technical at the backend/protocol layer.
- Prefer code + validation + docs together when touching a subsystem.

## Common Commands

- `cargo test -p miasma-desktop`
- `cargo test -p miasma-core --tests`
- `.\scripts\build-release.ps1`
- `.\scripts\package-release.ps1 -Variant both`
- `.\scripts\build-installer.ps1`
- `.\scripts\smoke-windows.ps1`
- `.\scripts\validate-installer.ps1`

## Docs To Keep In Sync

- `readme.md`
- `RELEASE-NOTES.md`
- `docs/variant-guide.md`
- `docs/adr/`
- `docs/tasks/`
