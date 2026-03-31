**Status: COMPLETE (2026-03-31)**
Track 1.5 (reconnect / bootstrap self-heal): DONE — 30s auto-recovery, field-proven.
Track 2 (Android toolchain/device readiness): MAX READINESS — Rust target + cargo-ndk installed, exact blocker chain documented, miasma-ffi host DLL built.
Track 3 (Windows ↔ Android directed sharing): BLOCKED by Track 2 (no APK/device), low code risk.
Track 4 (directed sharing architecture decision): DONE — ADR-010 written, product boundary defined, relay circuit fallback path specified.
Track 5 (documentation): DONE — enterprise report Track C + D corrected, ADR-006 updated, proof matrix corrected.

---

Completion bar (all satisfied):
- Android build/device readiness: materially advanced (Rust target + cargo-ndk; exact blocker chain: NDK → .so → uniffi → gradlew → SDK → Java 17).
- Windows ↔ Android directed sharing: blocked with concrete evidence (Track 2 prerequisite, not code risk).
- Tor-directed-sharing question: converted to architecture decision (ADR-010) — relay circuit fallback defined as next implementation task.
- Docs: proof boundaries separated honestly across all tracks.

Next blockers:
1. Android NDK installation → unblocks ARM64 build → APK → device test → Win↔Android directed sharing
2. Relay circuit fallback implementation (ADR-010 Part 2) → enables directed sharing over non-direct P2P paths
3. Real Android device → validates FFI loading, lifecycle, foreground service

Important framing:
- The enterprise-overlay validation was a real milestone.
- GlobalProtect-active same-LAN bridge behavior is field-proven.
- The reconnect/self-heal gap exposed in that validation is now fixed and field-proven.
- The remaining work is no longer about basic survivability; it is about Android execution proof and a product/architecture decision for directed sharing beyond direct bidirectional libp2p reachability.

Execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed.
- It is also acceptable to use multiple sub-agents aggressively and in parallel.
- Do not hide known limitations behind optimistic wording.
- If a track is blocked by missing infrastructure or hardware, isolate the blocker clearly and keep going on the other tracks.

Current state:
- Windows bridge connectivity is field-proven on an unrestricted path.
- GlobalProtect-active same-LAN behavior is field-proven.
- Reconnect/self-heal after peer restart is field-proven with automatic ~30s recovery.
- Tor external SOCKS5 bootstrap is field-proven on an unrestricted path.
- Android remains build-blocked by missing SDK/NDK/Gradle wrapper/Java 17 toolchain.
- Directed sharing over Tor is now understood to be architecturally incompatible with the current direct libp2p request-response design.

Goal:
Advance Android from "bounded by shared-code analysis" to "build-ready or device-proven," and turn the Tor-directed-sharing question into an explicit next-architecture decision instead of an ambiguous blocker.

Track 2: Android toolchain and ARM64/device readiness
1. Set up the Android path if still missing:
- Android SDK
- Android NDK
- platform-tools / adb
- Gradle prerequisites
- ARM64 build target

2. Produce:
- successful ARM64 build
- APK or installable artifact
- documented build/run steps

3. If a real device is available, validate:
- app launch
- embedded daemon startup
- status visibility
- peer connectivity
- background / foreground return
- reconnect after app resume if feasible

4. If no device is available, push as far as possible:
- build-ready
- install-ready
- remaining device-only blockers listed explicitly

Track 3: Windows ↔ Android directed sharing proof
1. Validate same-network connectivity first.
2. Then validate the full directed-sharing lifecycle:
- recipient contact / public key targeting
- challenge issuance
- sender confirmation
- password-gated retrieval
- revoke/delete propagation

3. Validate file sizes:
- tiny
- medium
- large enough to matter in practice

4. Record:
- exact device/app versions
- transport selected
- whether fallback happened
- whether reconnect or resume behavior mattered
- what failed, if anything

5. Completion for this track:
- Windows ↔ Android directed sharing is either proven end-to-end
- or blocked with concrete evidence, not guesswork

Track 4: Directed sharing architecture follow-through
1. Treat the Tor-directed-sharing result as an architecture decision point, not a field-test checkbox.
2. Decide and document the next supported path for directed sharing when direct bidirectional libp2p reachability is unavailable.
Examples may include:
- relay-routed directed requests
- bridge-mediated directed control plane
- a separate mailbox/inbox delivery layer
- explicit scoping: directed sharing requires direct/relay P2P and is not supported over Tor SOCKS5

3. The output of this track must be one of:
- a concrete implementation task for the chosen architecture
- or a sharply bounded product statement that removes ambiguity

Track 5: Documentation and release truthfulness
1. Update validation docs with only what is actually proven.
2. Keep separate buckets for:
- unrestricted-network proof
- GlobalProtect / enterprise-overlay proof
- Android real-device proof
- Windows ↔ Android proof
- Tor directed-sharing proof
- blocked / unproven items

3. Do not imply that:
- unrestricted Tor proof means enterprise-overlay Tor proof
- shared Rust code means device proof
- Windows-only directed sharing means cross-platform proof

Completion bar:
Do not call this complete unless all of the following are true:
- Android build/device readiness is materially advanced or blocked with a precise setup chain
- Windows ↔ Android directed sharing is either proven or blocked with concrete evidence
- the Tor-directed-sharing question has been converted into an explicit architecture/product decision
- docs clearly separate each proof boundary honestly

Expected final output:
1. Whether Android is now build-ready or device-proven
2. Whether Windows ↔ Android directed sharing now works
3. What the exact Android blocker chain still is, if any
4. What the next directed-sharing architecture decision is
5. What remains blocked
6. What the next true blocker is after this milestone
