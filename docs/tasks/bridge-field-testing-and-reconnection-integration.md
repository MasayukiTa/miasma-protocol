Next task: finish the post-superhardening bridge milestone by clearing the remaining infrastructure blockers, wiring the reconnection logic into the live runtime, and producing real field evidence.

Important framing:
- The hard architecture work is no longer the primary blocker.
- The remaining work is split between:
  1. infrastructure-dependent field validation, and
  2. bounded runtime integration that should now be straightforward.
- Do not reopen settled architecture questions unless a real blocker forces it.
- Move quickly and aggressively.

It is acceptable if this milestone takes a long time.
Spend as much time as needed.
It is also acceptable to use multiple sub-agents aggressively and in parallel.

Current state:
- Native Shadowsocks AEAD-2022 is implemented.
- External Tor mode is implemented.
- Streaming publish for very large files is implemented.
- Reconnection scheduler, recovery actions, and metrics exist as tested logic.
- The main remaining gaps are infrastructure-backed validation and final runtime wiring.

Goal:
Convert the current bridge/connectivity work from "well-tested implementation" into "runtime-integrated and field-proven transport behavior."

Track A: Unblock validation infrastructure
1. Establish at least one viable multi-node environment.
Use any practical path:
- offline WSL2 distro install
- Linux VM
- accessible VPS
- second physical device

2. Stand up the minimum external services required for proof:
- real Shadowsocks server
- real Tor daemon or Tor Browser SOCKS5 proxy

3. Do not stop at "infrastructure blocked" unless every realistic option has been exhausted and documented.

Track B: Wire reconnection logic into the live runtime
1. Integrate `ReconnectionScheduler` into the node event loop.
- record failures
- record successes
- periodically attempt due reconnects
- abandon peers when circuit breaker trips

2. Integrate `recovery_actions_for()` into daemon or coordinator-side recovery flow.
- redial bootstrap peers
- refresh descriptors
- escalate transports
- accept relay-only mode where appropriate

3. Expose `ReconnectionMetrics` in live diagnostics.
- DaemonStatus
- CLI diagnostics
- HTTP bridge status if appropriate

Track C: Finish the operator surfaces
1. Add publish progress visibility for large streaming publishes.
- CLI progress or bounded progress logs
- enough visibility that large-file publishes do not feel hung

2. Add any minimal diagnostics needed to understand:
- reconnect attempts
- circuit-breaker trips
- recovery actions taken

Track D: Real field validation
1. Run real bridge validation with evidence.
At minimum:
- Windows ↔ Linux or equivalent multi-node path
- real Shadowsocks validation
- real Tor validation
- fallback ladder under degraded conditions
- large-file publish without OOM

2. Record:
- transport selected
- fallback path
- time to first success
- directed sharing success/failure
- reconnect behavior after failure

Track E: Documentation and release truthfulness
1. Update validation reports with real field evidence.
2. Update censorship-resistance posture only where evidence supports it.
3. Keep unsupported claims out.

Completion bar:
Do not call this complete unless all of the following are true:
- a real multi-node environment was used, not only a single local daemon
- `ReconnectionScheduler` is wired into the live runtime
- recovery actions are dispatched from live failure conditions
- reconnection metrics are visible in runtime diagnostics
- at least one real Shadowsocks validation run is documented
- at least one real Tor validation run is documented
- at least one large-file field validation run is documented
- docs clearly separate proven, implemented-but-not-field-tested, and still-blocked items

Expected final output:
1. What infrastructure was used
2. What runtime wiring was completed
3. What reconnection behavior is now live
4. What real field validations passed or failed
5. What remains blocked
6. Whether bridge connectivity is ready for broader field testing
