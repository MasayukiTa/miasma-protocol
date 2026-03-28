Next task: prove bridge connectivity under enterprise overlays and close the remaining mobile field gaps.

Important framing:
- Unrestricted-network proof is now in place for Shadowsocks, Tor external SOCKS5, fallback behavior, streaming publish, and reconnection.
- That is a major milestone, but it is not the same thing as proving survivability under GlobalProtect, enterprise VPN steering, ZTNA interception, or mobile device constraints.
- This milestone is about turning those remaining gaps into either field proof or explicitly bounded limits.

Execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed.
- It is also acceptable to use multiple sub-agents aggressively and in parallel.
- Prefer real evidence over more implementation unless a field blocker clearly requires code changes.

Current state:
- Windows unrestricted-network bridge behavior is field-validated.
- Tor external SOCKS5 is field-validated only on an unrestricted path.
- VPN and GlobalProtect-class overlays are not field-validated.
- Android transport is only bounded by shared-code analysis, not real-device proof.
- iOS remains retrieval-first and unproven on device.

Goal:
Produce hard evidence for enterprise-overlay survivability and mobile-hosted bridge behavior, or isolate the blockers precisely enough that release claims remain honest.

Track A: GlobalProtect and enterprise-overlay proof
1. Validate bridge behavior with GlobalProtect enabled on the Windows host.
At minimum:
- daemon startup
- peer connectivity
- winning transport
- fallback path if direct transport fails
- directed sharing success or failure

2. Record:
- whether QUIC survives
- whether TCP survives
- whether WSS / Shadowsocks / Tor become necessary
- whether TLS inspection or proxying changes the selected transport
- exact diagnostics from DaemonStatus and CLI

3. If GlobalProtect breaks connectivity, isolate whether the blocker is:
- UDP suppression
- TCP reset or policy block
- TLS inspection / trust issue
- DNS interference
- localhost bridge unaffected but network path degraded

Track B: Real VPN and degraded-network proof
1. Run at least one real VPN-backed validation beyond unrestricted WSL2.
Options:
- one-sided VPN
- two-sided VPN
- alternate enterprise VPN if available
- degraded network / packet loss / forced transport failure

2. Record:
- time to first usable transport
- selected transport
- fallback trace
- reconnect quality after hard failure
- directed-sharing success or failure

Track C: Android real-device proof
1. Set up the Android toolchain if still missing.
- SDK
- NDK
- ADB
- ARM64 target build

2. Run a real ARM64 device validation.
At minimum:
- app launch
- embedded daemon startup
- peer connectivity
- background / foreground return
- directed sharing
- revoke/delete

3. Validate Windows ↔ Android directed sharing.
- same-network first
- challenge confirmation
- password-gated retrieval
- medium file
- large file

Track D: Directed sharing over Tor
1. Validate whether directed sharing works end-to-end over Tor external SOCKS5.
2. Use two nodes if needed.
3. Record:
- envelope delivery
- confirmation flow
- retrieval
- revoke/delete propagation
- performance and failure modes

Track E: iOS proof boundary
1. Re-check whether iOS can advance beyond retrieval-first planning.
2. If no real build/device path exists, write the limit crisply and stop there.

Track F: Release truthfulness
1. Update validation reports so they explicitly distinguish:
- unrestricted-network proof
- enterprise-overlay proof
- mobile device proof
- unproven or blocked claims

2. Do not imply that unrestricted Tor/SS success automatically means GlobalProtect survivability.

Completion bar:
Do not call this complete unless all of the following are true:
- GlobalProtect or comparable enterprise-overlay behavior is field-tested or explicitly isolated with evidence
- at least one real VPN/degraded-network run is documented
- Android real-device bridge behavior is documented honestly
- Windows ↔ Android directed sharing is either proven or blocked with evidence
- directed sharing over Tor is either proven or blocked with evidence
- docs clearly separate unrestricted proof from enterprise-overlay proof

Expected final output:
1. What happened with GlobalProtect enabled
2. What VPN/degraded-network evidence now exists
3. What Android real-device behavior is proven
4. Whether directed sharing over Tor works end-to-end
5. What remains blocked
6. Whether the bridge layer is ready for broader external testing under realistic hostile-network conditions
