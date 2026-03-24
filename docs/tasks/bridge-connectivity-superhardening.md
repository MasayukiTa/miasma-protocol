Next task: finish the real-network proof and native tunnel completion for Bridge Connectivity Superhardening.

Current state:
- The fallback ladder, diagnostics model, rate limiting, health monitoring, flap damping, and environment detection are now live.
- External Shadowsocks and external Tor paths make real proxy-backed network calls by reusing the proven WSS request/response path.
- Validation docs exist and are substantially more honest than before.
- The remaining work is now focused on field proof, native tunnel removal of external dependencies, and the last runtime signal gaps.

Important execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed to finish it properly.
- It is also acceptable to use multiple sub-agents aggressively if that improves speed or thoroughness.
- Do not present config-only or trait-only transport placeholders as complete network support.
- Do not overclaim censorship-resistance or hostile-network survivability without direct evidence.

Goal:
Turn the current bridge/connectivity layer from "implemented and test-heavy" into "field-proven and release-truthful" under harsh network conditions.

Track A: Real-network validation
1. Re-run the bridge/connectivity validation matrix on actual network conditions.
At minimum:
- same LAN
- cross-PC same LAN
- one-sided VPN
- two-sided VPN
- filtered or degraded network where practical
- real Shadowsocks server
- real Tor path

2. Record:
- which transport actually won
- latency to first connectivity
- whether fallback was required
- whether directed sharing still worked
- what broke

Track B: Native tunnel completion
1. Add native Shadowsocks tunnel support.
- remove the hard dependency on `ss-local` for the strongest supported path
- implement real AEAD tunnel establishment using the `shadowsocks` crate
- preserve the current external-proxy path as fallback if useful

2. Add embedded Tor support if viable.
- use `arti-client` only if it is stable enough for the supported targets
- if embedded Tor is not viable on all targets, document the supported matrix explicitly rather than pretending it is

3. Validate:
- wrong config fails cleanly
- correct config actually routes traffic
- fallback ladder uses native tunnels only when intended
- diagnostics show whether the path was external-proxy or native-tunnel

Track C: Runtime signal completion
1. Wire additional runtime quality signals that are still incomplete.
- dial success/failure callbacks where available
- transport outcome attribution
- relay dependence visibility
- reconnect quality after failure

2. Verify that status/diagnostics reflect runtime changes, not only coarse connection events.

Track D: Release-truthfulness and posture
1. Update validation docs with only what is truly proven.
2. Keep the censorship-resistance posture honest.
- what is proven
- what is plausible but unproven
- what still fails

3. Make sure release-facing language matches the actual test evidence.

Completion bar:
Do not call this complete unless all of the following are true:
- at least one real Shadowsocks validation run is documented
- at least one real Tor validation run is documented
- at least one VPN/degraded-network validation run is documented
- native Shadowsocks tunnel support is either implemented or explicitly rejected with a documented reason
- embedded Tor support is either implemented or explicitly rejected with a documented reason
- runtime diagnostics reflect the stronger live wiring truthfully
- docs make no unsupported claims about censorship-resistance or severe-network survivability

Expected final output:
1. What real-network conditions were actually validated
2. What native Shadowsocks support now does
3. What embedded or external Tor support now does
4. What runtime diagnostics became more truthful
5. What remains unproven or intentionally unsupported
6. Whether the bridge layer is ready for broader field testing
