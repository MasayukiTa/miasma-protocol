## iOS Retrieval-First Client Foundation

### Purpose

Turn the existing `ios/` SwiftUI app and `miasma-ffi` bridge into a real iOS retrieval-first client foundation.

This is not a mockup task.
It should produce a buildable iOS client, a credible Rust/Swift integration path, and honest documentation of what still remains before any iOS beta.

### Important framing

- iOS is retrieval-first, not a first-class always-on mobile node.
- Android remains the first-class mobile node target.
- It is acceptable if this takes several hours.
- Do not stop at placeholder SwiftUI screens or IDE-only compilation.

### Current repo assumptions

- `ios/` already exists
- `crates/miasma-ffi` already exists
- the current Swift package and app shell are partial
- `MiasmaFFI.swift` still contains development stubs and must not be treated as release-ready integration
- Windows remains the current shipping platform, but iOS should become a serious retrieval client track

### Track A: Build and toolchain closure

1. Make iOS build steps reproducible from a fresh macOS machine
- Swift package/Xcode project setup is documented and runnable
- Rust Apple targets build cleanly
- UniFFI generation is documented and reproducible
- XCFramework production is documented and reproducible

2. Close the Rust-to-Swift integration loop
- generated Swift bindings replace stub-only behavior during real builds
- XCFramework placement is predictable
- the setup does not rely on hidden local machine assumptions

3. Make versioning and artifact naming sane
- app version should reflect current repo state
- docs and output artifacts should match reality

### Track B: Retrieval-first product shell

1. Establish the actual iOS app structure
- app startup
- retrieval-first navigation
- state management
- persistent settings/data-dir handling within iOS constraints

2. Define the first real iOS surfaces
- setup/init
- status/health
- retrieve/get back
- save/export/share retrieved content
- settings
- diagnostics/support

3. Keep wording mainstream
- avoid daemon-heavy or protocol-heavy language in default UI
- advanced detail can exist behind secondary screens if truly needed

### Track C: FFI-backed functionality

1. Make the core FFI calls real and testable for iOS scope
- initialize lightweight local state if required
- get node status
- retrieve bytes
- export/share retrieved payloads
- only expose dissolve/store if it is intentionally supported on iOS

2. Handle errors as product behavior
- missing initialization
- invalid MID
- insufficient shares
- FFI/XCFramework load failures
- unsupported features on iOS
- surface these as understandable iOS UI states

3. Be explicit about scope cuts
- if iOS remains retrieve-only for now, say so plainly
- do not imply equal always-on node behavior with desktop/Android unless proven

### Track D: iOS-specific runtime realities

1. Treat iOS constraints as first-class
- sandboxed storage
- app lifecycle and suspension
- background execution limits
- networking policy
- share sheet / file import / file export behavior

2. Decide what runs now vs later
- foreground retrieval is acceptable if honest
- persistent node behavior should not be implied unless proven on real devices

3. Make diagnostics possible
- logs, support export, or equivalent
- enough information to debug device-side failures without exposing too much jargon

### Track E: First-release usability

1. Basic user story must work
- install
- launch
- initialize if needed
- paste/open a MID or import supported retrieval input
- retrieve content
- save or share retrieved content

2. Keep the first iOS release small and real
- a smaller but working retrieval client is better than a broad fake mobile story

3. Do not overclaim
- no claims of full mobile-node parity
- no claims of reliable background participation unless validated
- no claims of production readiness

### Track F: Validation

1. Simulator validation
- build succeeds
- app launches
- major flows do not instantly fail

2. Real-device validation where possible
- at least one physical iPhone if available
- note exactly what was or was not verified

3. Rust-side validation
- `cargo test -p miasma-ffi`
- any targeted tests needed for new FFI behavior

### Track G: Documentation

Update or add:
- iOS build/setup notes
- iOS limitations
- release-facing wording if iOS status changes materially
- task/validation notes for the next pass

### Completion bar

Do not call this complete unless all of the following are true:

- iOS build steps are reproducible
- app installs and launches
- Rust/Swift integration is real, not stub-only
- the retrieval-first loop is wired or any missing slice is explicitly identified
- iOS constraints are documented honestly
- validation clearly separates simulator-tested vs device-tested vs unverified

### Final report format

1. What is newly real on iOS
2. What is still missing
3. Concrete code changes
4. Build and validation steps run
5. Whether iOS is ready for a first serious retrieval-client beta push or still only a dev foundation
