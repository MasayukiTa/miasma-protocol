Next task: finish the real-world mobile directed-sharing milestone with cross-device validation and honest platform closure.

Current state:
- Windows directed private sharing is materially implemented.
- Desktop and web connected-mode directed sharing are materially implemented.
- Android now has embedded-daemon startup plus send/inbox/outbox UI.
- iOS now has embedded-daemon startup plus retrieval-first inbox UI.
- FFI now exposes embedded daemon lifecycle for mobile hosts.
- The remaining work is no longer foundation work. It is validation, hardening, platform-closure, and honest release positioning.

Important execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed to finish it properly.
- It is also acceptable to use multiple sub-agents aggressively where that materially improves speed or thoroughness.
- Do not stop at partial code scaffolding or simulator-only confidence if a real device path is available.
- Do not call this complete just because the code compiles. The goal is cross-device proof.

Goal:
Prove that mobile-hosted Miasma directed sharing works in real cross-device conditions, clearly define what Android and iOS can truly do today, and close the remaining gaps needed for honest beta-level positioning.

Track A: Android real-device directed-sharing validation
1. Validate Android on a real device, not just code review.
- embedded daemon starts reliably
- HTTP bridge / hosted web path works if applicable
- Send screen can create a directed share
- Inbox and Outbox reflect live state transitions
- retrieval succeeds after confirmation/password flow
- revoke and delete work as expected

2. Validate Android against another real client.
Minimum matrix:
- Android -> Windows
- Windows -> Android
- Android -> Android if two devices are available

3. Validate lifecycle behavior.
- cold start
- app background / foreground
- service restart
- process death / relaunch
- network loss / restore

Track B: iOS real-device retrieval-first validation
1. Validate iOS on a real device if available, otherwise simulator plus explicit limitations.
- embedded daemon start path
- inbox visibility
- challenge display
- password-gated retrieval
- delete behavior

2. Validate iOS against another real client.
Minimum matrix:
- Windows -> iOS retrieval
- Android -> iOS retrieval if Android is available

3. Be explicit about the iOS boundary.
- If iOS remains retrieval-first, keep that honest.
- Do not imply sender parity if it is not really there.
- If background execution is fragile, document it directly.

Track C: Cross-device protocol and security validation
1. Validate the directed-sharing state machine end to end.
- Pending
- ChallengeIssued
- Confirmed
- Retrieved
- SenderRevoked
- RecipientDeleted
- ChallengeFailed
- PasswordFailed
- Expired

2. Validate the hard security boundaries.
- three failed challenge attempts fail closed
- three failed password attempts fail closed
- terminal states remain terminal
- deleted/revoked items cannot be resurrected
- challenge files are cleaned up on terminal transitions

3. Validate retention and expiry.
- sender-selected retention is honored
- expired items stop being retrievable
- expiry behavior is visible and understandable in UI

Track D: UX closure on mobile
1. Finish the last mile of Android usability.
- sender flow is understandable
- recipient challenge flow is understandable
- retrieval result handling is understandable
- error messages are actionable rather than developer-oriented

2. Finish the last mile of iOS usability.
- inbox states are understandable
- password entry flow is clear
- retrieval success/failure is clearly presented
- delete action and its consequences are clear

3. Keep the wording honest.
- no claims of capabilities not yet validated
- if a feature is Android-only or retrieval-first only, say so

Track E: Connectivity reality and platform positioning
1. Reconcile actual mobile connectivity with the documented connectivity model.
- what is truly networked today
- what is hosted-bridge only
- what is local-only fallback

2. Update the docs so there is no ambiguity.
- connectivity-model.md
- platform-roadmap.md
- any mobile README/task/validation docs touched by the outcome

3. Produce an honest statement of platform maturity.
- Android: exact current capability
- iOS: exact current capability
- what still blocks broader release confidence

Track F: Validation artifacts and reporting
1. Produce a concrete validation report.
Include:
- devices tested
- OS versions
- exact client pairings
- which flows passed
- which flows failed
- screenshots or logs if useful

2. Record what remains unverified.
- simulator-only paths
- device-only gaps
- background execution caveats
- network conditions not yet tested

Track G: Decide the next implementation milestone after validation
After validation, give one clear recommendation for the next milestone.
Examples:
- Android beta hardening
- iOS retrieval polish
- mobile-to-mobile networking completion
- push/background notification architecture
- release packaging for Android/iOS

Completion bar:
Do not call this complete unless all of the following are true:
- Android has been validated on a real device or the exact blocker is stated explicitly
- iOS has been validated on a real device or the exact blocker is stated explicitly
- at least one real cross-device directed-sharing path has succeeded end to end
- the security-critical state transitions have been exercised and reported
- docs reflect the actual mobile capability level honestly
- one clear next milestone is recommended based on observed reality, not guesses

Expected final output:
1. What Android can really do now
2. What iOS can really do now
3. Which cross-device flows were actually proven
4. Which security and lifecycle cases were validated
5. What remains fragile or incomplete
6. What the next mobile milestone should be
