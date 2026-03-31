Next task: close the reconnect/self-heal gap, then push through Android device proof, Windows↔Android directed sharing, and Tor end-to-end directed sharing.

Important framing:
- The enterprise-overlay validation was a real milestone.
- GlobalProtect-active same-LAN bridge behavior is now field-proven.
- However, the validation also exposed a real operational weakness: after a peer is hard-killed and restarted, the surviving node does not reliably self-heal back to the bootstrap peer without extra help.
- That weakness matters for every harder next step: Android device validation, Tor end-to-end sharing, and unstable-network behavior.
- So this milestone is intentionally split into:
  - **Track 1.5**: reconnect / bootstrap self-heal hardening
  - **Track 2**: Android toolchain + ARM64/device readiness
  - **Track 3**: Windows ↔ Android directed sharing proof
  - **Track 4**: Tor directed sharing end-to-end proof

Execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed.
- It is also acceptable to use multiple sub-agents aggressively and in parallel.
- Do not hide known limitations behind optimistic wording.
- If a track is blocked by missing infrastructure or hardware, isolate the blocker clearly and keep going on the other tracks.

Current state:
- Windows bridge connectivity is field-proven on an unrestricted path.
- GlobalProtect-active same-LAN behavior is field-proven.
- Directed sharing on Windows is already strong.
- Tor external SOCKS5 bootstrap is field-proven on an unrestricted path.
- Android transport is still bounded mostly by shared-code analysis, not real-device proof.
- The main newly exposed weakness is reconnect/self-heal after peer loss and restart.

Goal:
Strengthen runtime self-healing enough that harder field tests are meaningful, then prove the next product-critical paths on Android and Tor.

Track 1.5: Reconnect / bootstrap self-heal hardening
1. Fix the gap observed in enterprise-overlay validation:
- when Node A is killed and restarted
- Node B should not remain stranded indefinitely if Node A is still a configured bootstrap peer

2. Implement and/or validate:
- periodic bootstrap re-dial
- re-seeding bootstrap peers after peer loss
- bounded retry behavior
- interaction with flap damping and reconnection scheduler
- stale routing-table or address-book recovery

3. Record:
- what the root cause was
- what was changed
- whether reconnect becomes automatic
- how long recovery takes
- whether any manual restart/bootstrap is still required

4. Completion for this track:
- peer loss + restart is either self-healed automatically with evidence
- or the remaining non-healed case is isolated precisely and documented honestly

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

Track 4: Tor directed sharing end-to-end proof
1. Go beyond SOCKS reachability and plain HTTPS proof.
2. Validate:
- envelope delivery
- challenge confirmation
- password-gated retrieval
- revoke/delete propagation
- latency and stability

3. If two nodes are required, use them.
4. If the chain fails, isolate whether the break is in:
- Tor SOCKS path
- WebSocket / WSS transport
- transport selection
- directed sharing control plane
- directed sharing data plane

5. Completion for this track:
- directed sharing over Tor is either proven end-to-end
- or reduced to a sharply bounded blocker

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
- reconnect/self-heal after peer restart is improved or precisely bounded with evidence
- Android build/device readiness is materially advanced
- Windows ↔ Android directed sharing is either proven or blocked with concrete evidence
- Tor directed sharing is either proven or blocked with concrete evidence
- docs clearly separate each proof boundary honestly

Expected final output:
1. What was fixed in reconnect/self-heal
2. Whether Android is now build-ready or device-proven
3. Whether Windows ↔ Android directed sharing now works
4. Whether directed sharing over Tor now works
5. What remains blocked
6. What the next true blocker is after this milestone
