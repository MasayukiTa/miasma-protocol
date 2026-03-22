# Miasma Claude Guide

## Mission

- Prioritize Windows beta quality first.
- Treat Easy and Technical as one product family, not a fork.
- Preserve protocol correctness while improving desktop usability.
- Keep release claims honest: beta, unaudited, not for highly sensitive use.
- Build Android as the next serious product surface after Windows, not as a throwaway demo.

## Product Rules

- Easy mode should feel understandable to a non-technical user.
- Technical mode should remain useful for diagnostics and protocol validation.
- Mobile matters, but Windows is the current shipping surface.
- Android is the first-class future mobile target; iOS is retrieval-first.
- Android work should preserve the same protocol guarantees where feasible, and clearly document where mobile constraints require reduced behavior.

## Repo Hotspots

- `crates/miasma-desktop`: desktop UX, localization, runtime behavior
- `crates/miasma-core`: protocol, storage, daemon, security-sensitive logic
- `crates/miasma-ffi`: UniFFI bridge between Rust core and mobile clients
- `android`: Android app, Gradle build, JNI libs, Kotlin UI
- `ios`: SwiftUI app, Swift package, XCFramework/UniFFI integration
- `installer`: MSI and Windows install behavior
- `scripts`: build, package, smoke, soak, release helpers
- `docs`: ADRs, release notes, variant guide, validation logs, tasks

## Current Windows Priorities

1. Fix real CJK rendering in the running app
2. Redesign the desktop UI so it looks intentional
3. Improve Easy mode without hollowing out Technical mode
4. Keep installer/package/launcher behavior honest
5. Validate installed, portable, and recovery flows on Windows

## Current Android Priorities

1. Turn the existing Android and UniFFI skeleton into a reproducible build
2. Keep Android aligned with `miasma-core`, not with desktop-only shortcuts
3. Make Android retrieval/save flows real before polishing
4. Treat background execution, storage permissions, and battery/network limits as first-class design constraints
5. Keep Android limitations explicit in docs and release language

## Current iOS Priorities

1. Keep iOS retrieval-first and honest about that scope
2. Turn the current SwiftUI/UniFFI shell into a reproducible macOS build
3. Replace stub-only assumptions with real Swift/XCFramework integration
4. Make the first real iOS loop about retrieve, save/export, and supportability
5. Keep iOS limitations explicit in docs and release language

## Working Rules

- Do not overclaim completion.
- Do not treat string tables as finished localization.
- Do not remove technical depth just to simplify screenshots.
- Do not introduce divergence between Easy and Technical at the backend/protocol layer.
- Prefer code + validation + docs together when touching a subsystem.

## Common Commands

- `cargo test -p miasma-desktop`
- `cargo test -p miasma-core --tests`
- `cargo test -p miasma-ffi`
- `.\scripts\build-release.ps1`
- `.\scripts\package-release.ps1 -Variant both`
- `.\scripts\build-installer.ps1`
- `.\scripts\smoke-windows.ps1`
- `.\scripts\validate-installer.ps1`
- `cd android; .\gradlew.bat assembleDebug`
- `cd android; .\gradlew.bat installDebug`

## Docs To Keep In Sync

- `readme.md`
- `RELEASE-NOTES.md`
- `docs/variant-guide.md`
- `docs/adr/`
- `docs/tasks/`
- Android-facing task docs and validation notes
- iOS-facing task docs and validation notes
