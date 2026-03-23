Next task: turn the Android directed-sharing implementation from code-complete into real beta evidence through device validation and hardening.

Current state:
- The shared directed-sharing core is implemented and heavily tested.
- Android now has embedded daemon startup, Send, Inbox, Outbox, and WebView bridge paths.
- Windows already provides the strongest validation surface and should be used as the anchor peer.
- The main remaining gap is not architecture. It is proving the Android stack on a real ARM64 device and hardening whatever breaks there.

Important execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed to finish it properly.
- It is also acceptable to use multiple sub-agents aggressively if that improves speed or thoroughness.
- Do not call this complete based on emulator confidence alone if a real Android device is available.
- Prefer real observed behavior over optimistic interpretation of code paths.

Goal:
Prove that Android can participate in real directed sharing against another client, then harden the weak edges found during that validation.

Track A: ARM64 build and packaging proof
1. Build the Android app for a real ARM64 device.
- verify Rust FFI cross-compilation for `aarch64-linux-android`
- verify the APK/AAB includes the correct native library
- verify startup does not fail due to missing symbols, ABI mismatch, or packaging errors

2. Validate install and launch on a real device.
- app installs cleanly
- app launches cleanly
- embedded daemon can start
- app survives first-run setup without crashes

Track B: Real Android daemon and network validation
1. Confirm the embedded daemon actually runs on device.
- HTTP bridge port is reachable from the app
- node status is visible
- sharing contact is generated
- no silent fallback masks a real daemon-start failure

2. Validate network participation.
- same-network peer discovery if available
- manual bootstrap fallback if needed
- retrieve and status calls operate against a real networked daemon

3. Record exact device and network conditions.
- device model
- Android version
- app build
- Wi-Fi or other network path

Track C: Windows ↔ Android directed-sharing proof
1. Windows -> Android
- create directed share on Windows
- observe challenge on Android
- confirm on Windows
- retrieve on Android with password
- verify bytes/content match

2. Android -> Windows
- create directed share on Android
- observe challenge on Windows
- confirm on Android
- retrieve on Windows with password
- verify bytes/content match

3. If two Android devices are available, validate Android -> Android as a bonus path.

Track D: Android lifecycle and resilience
1. Background/foreground behavior
- app backgrounded during idle daemon
- app backgrounded during inbox/outbox refresh
- return to foreground with state still coherent

2. Process death and restart
- swipe-kill app and reopen
- verify clean daemon restart or honest recovery
- verify stale daemon/port state is handled correctly

3. Network interruption
- lose network and restore it
- verify app status recovers or fails honestly

Track E: Security and local storage validation
1. Validate Android Keystore behavior on a real device.
- wrapped key survives relaunch
- distress wipe clears access as intended
- secrets are not accidentally left in easy-to-recover storage paths

2. Validate directed-sharing fail-closed behavior from the Android UI.
- wrong challenge attempts
- wrong password attempts
- revoke then retrieval attempt
- delete then refresh behavior

Track F: UX hardening based on reality
1. Fix whatever breaks in real use.
- confusing challenge flow
- error message quality
- duplicate submits
- bad loading states
- missing success confirmation
- stale inbox/outbox rendering

2. Keep Android wording honest and non-developer-facing where practical.

Track G: Documentation and beta positioning
1. Update validation docs with real observed results.
- what really worked
- what only worked with fallback/manual bootstrap
- what failed
- what remains fragile

2. Update roadmap/connectivity docs only after reality is known.
- do not overclaim Android until the exchange is actually proven

3. Give a clear beta recommendation.
- acceptable for limited Android testers
- acceptable only for technical testers
- not ready yet

Completion bar:
Do not call this complete unless all of the following are true:
- the Android app has been installed and run on a real ARM64 device
- the embedded daemon has been observed running on-device
- at least one full Windows -> Android directed-sharing exchange has succeeded
- at least one full Android -> Windows directed-sharing exchange has succeeded
- lifecycle and restart behavior have been exercised and documented
- Android Keystore behavior has been checked on a real device
- the final recommendation clearly states whether Android is beta-ready and for whom

Expected final output:
1. Device/build/network environment used
2. What succeeded on a real Android device
3. What failed or stayed fragile
4. What hardening changes were made
5. Whether Android is ready for broader testing
6. What the next post-Android milestone should be
