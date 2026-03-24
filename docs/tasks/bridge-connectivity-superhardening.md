Next task: finish the remaining live transport integration and real-network proof for Bridge Connectivity Superhardening.

Current state:
- The architecture, fallback ladder, diagnostics types, environment model, rate limiting model, and transport placeholders are now materially implemented.
- Live status fields are populated.
- Bridge/connectivity validation docs exist.
- The remaining work is no longer broad architecture. It is the last mile of real transport integration, daemon-loop wiring, and harsh-condition proof.

Important execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed to finish it properly.
- It is also acceptable to use multiple sub-agents aggressively if that improves speed or thoroughness.
- Do not present config-only or trait-only transport placeholders as complete network support.
- Do not overclaim censorship-resistance or hostile-network survivability without direct evidence.

Goal:
Turn the current bridge/connectivity foundation into a genuinely validated transport layer under real network conditions.

Track A: Complete live daemon/node-loop wiring
1. Wire `ConnectionHealthMonitor` into real swarm events.
- dial success/failure
- disconnect
- reconnect
- transport outcome
- relay dependence

2. Wire `EnvironmentDetector` into a real periodic daemon task.
- refresh cadence
- snapshot replacement
- degraded-environment reactions
- diagnostics export

3. Verify that live status fields reflect actual runtime changes, not just boot-time snapshots.

Track B: Complete real Shadowsocks integration
1. Add the actual `shadowsocks` crate integration.
- feature surface if still needed
- runtime config parsing
- real tunnel establishment
- payload transport execution, not placeholder returns

2. Validate:
- wrong config fails cleanly
- correct config actually routes traffic
- fallback ladder uses Shadowsocks only when intended

Track C: Complete real Tor integration
1. Add the actual `arti-client` integration or the chosen real Tor path.
- embedded mode if supported
- external SOCKS5 mode if that is the practical baseline

2. Validate:
- Tor config works
- fallback ladder invokes Tor when intended
- diagnostics reflect Tor use honestly

Track D: Real-network validation
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

Track E: Release-truthfulness and posture
1. Update validation docs with only what is truly proven.
2. Keep the censorship-resistance posture honest.
- what is proven
- what is plausible but unproven
- what still fails

3. Make sure release-facing language matches the actual test evidence.

Completion bar:
Do not call this complete unless all of the following are true:
- ConnectionHealthMonitor is wired to real runtime events
- EnvironmentDetector runs as a live periodic daemon task
- Shadowsocks uses a real transport implementation, not only config/trait scaffolding
- Tor uses a real transport implementation, not only config/trait scaffolding
- at least one real Shadowsocks validation run is documented
- at least one real Tor validation run is documented
- docs make no unsupported claims about censorship-resistance or severe-network survivability

Expected final output:
1. What remaining live wiring was completed
2. What real Shadowsocks integration now does
3. What real Tor integration now does
4. What network conditions were actually validated
5. What remains unproven or fragile
6. Whether the bridge layer is ready for broader field testing
