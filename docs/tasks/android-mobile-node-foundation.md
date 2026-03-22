## Android Mobile Node Foundation

### Purpose

Turn the existing `android/` app and `miasma-ffi` bridge into a real Android foundation we can iterate on outside the desk.

This is not a mockup task.
It should produce a buildable Android app, a credible Rust/Kotlin integration path, and honest documentation of what still remains before an Android beta.

### Important framing

- Android is the first-class mobile target.
- iOS remains retrieval-first and is out of scope here.
- It is acceptable if this takes several hours.
- Do not stop at placeholder UI or IDE-only compilation.

### Current repo assumptions

- `android/` already exists
- `crates/miasma-ffi` already exists
- UniFFI/JNI integration is partial and must be made reproducible
- Windows remains the current shipping platform, but Android is now the next serious product surface

### Track A: Build and toolchain closure

1. Make Android build steps reproducible from a fresh machine
- Gradle wrapper works
- Android app assembles in debug
- Rust mobile build steps are documented and runnable
- UniFFI generation is documented and reproducible

2. Close the Rust-to-Kotlin integration loop
- JNI libs actually land where Android expects them
- generated bindings are refreshed cleanly
- avoid a setup that only works on one dev machine by accident

3. Make versioning and package naming sane
- app version should reflect current project state
- output artifacts and docs should match reality

### Track B: Real app shell, not placeholder shell

1. Establish the actual Android app structure
- app startup
- navigation
- state management
- persistent settings/data dir handling

2. Define the first real Android surfaces
- setup/init
- health/status
- save/store
- retrieve/get back
- settings
- diagnostics/support

3. Keep wording mainstream
- avoid daemon-heavy or protocol-heavy language in default UI
- advanced protocol detail can exist behind secondary surfaces

### Track C: FFI-backed functionality

1. Make the core FFI calls real and testable
- initialize node
- get node status
- dissolve/store bytes
- retrieve bytes
- distress wipe if kept exposed

2. Handle errors as product behavior
- missing init
- invalid MID
- insufficient shares
- bridge/FFI load failures
- surface these as understandable Android UI states

3. Document any gaps between mobile and desktop capability
- if Android cannot yet match desktop behavior, say so plainly

### Track D: Android-specific runtime realities

1. Treat Android constraints as first-class
- storage location choices
- app lifecycle
- background execution limits
- battery/network policy
- permissions and modern Android behavior

2. Decide what runs now vs later
- foreground-only operations are acceptable if honest
- always-on node behavior should not be implied unless proven

3. Make diagnostics possible
- logs, status export, or equivalent support path
- enough information to debug device-side failures

### Track E: First-release usability

1. Basic user story must work
- install
- launch
- initialize
- save something
- retrieve something

2. Keep the first Android release small and real
- a smaller but working Android beta is better than a broad fake one

3. Do not overclaim
- no claims of mobile background reliability unless truly validated
- no claims of production readiness

### Track F: Validation

1. Emulator validation
- assembleDebug / installDebug
- app launch
- major flows do not instantly fail

2. Real-device validation where possible
- at least one physical Android device if available
- note exactly what was or was not verified

3. Rust-side validation
- `cargo test -p miasma-ffi`
- any targeted tests needed for new FFI behavior

### Track G: Documentation

Update or add:
- Android build/setup notes
- Android limitations
- release-facing wording if Android status changes materially
- task/validation notes for the next pass

### Completion bar

Do not call this complete unless all of the following are true:

- Android build steps are reproducible
- app installs and launches
- Rust/Kotlin integration is real, not stub-only
- at least the basic init/status/save/retrieve flow is wired or any missing slice is explicitly identified
- Android constraints are documented honestly
- validation clearly separates emulator-tested vs device-tested vs unverified

### Final report format

1. What is newly real on Android
2. What is still missing
3. Concrete code changes
4. Build and validation steps run
5. Whether Android is ready for a first serious beta push or still only a dev foundation
