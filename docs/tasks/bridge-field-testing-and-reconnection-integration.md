Next task: finish the remaining field-proof work for bridge connectivity after the WSL2 lab, native Shadowsocks validation, streaming publish, and reconnection integration milestone.

Important framing:
- The largest architecture and implementation unknowns are no longer the main problem.
- The remaining work is now mostly about real-world proof, bounded network-condition validation, and honest release positioning.
- Do not reopen settled architecture unless a real blocker forces it.
- Move quickly and aggressively, but keep the claims honest.

It is acceptable if this milestone takes a long time.
Spend as much time as needed.
It is also acceptable to use multiple sub-agents aggressively and in parallel.

Current state:
- WSL2 Alpine lab exists and has already been used for field validation.
- Native Shadowsocks AEAD-2022 is field-validated.
- External Shadowsocks SOCKS5 mode is field-validated.
- Streaming publish for very large files is field-validated.
- Reconnection scheduler, recovery actions, and metrics are live.
- The remaining work is now narrower:
  - full Tor bootstrap on an unrestricted network
  - VPN and degraded-network fallback proof
  - mobile platform transport proof
  - stronger field evidence for hostile-network claims

Goal:
Convert the remaining bridge/connectivity unknowns from "blocked or inferred" into "proven or explicitly bounded."

Track A: Tor field completion
1. Re-run Tor validation on a network that does not block Tor bootstrap.
- standalone Tor daemon
- Tor Browser SOCKS5 if useful
- confirm real bootstrap, not only port reachability

2. Record:
- bootstrap success or failure
- time to usable circuit
- whether bridge traffic succeeds through Tor
- diagnostics and fallback state

Track B: VPN and degraded-network proof
1. Run real bridge validation with evidence.
At minimum:
- one-sided VPN
- two-sided VPN where possible
- degraded or filtered network where practical
- forced transport failure to exercise fallback ladder
- reconnect behavior after hard failure

2. Record:
- transport selected
- fallback path
- time to first success
- directed sharing success or failure
- reconnect behavior after failure

Track C: Mobile transport proof
1. Validate that Android and iOS transport paths inherit the bridge improvements honestly.
- Android real device if available
- iOS simulator or device if available
- status and diagnostics path, not just UI launch

2. Record exactly what is proven versus inferred from shared core code.

Track D: Documentation and release truthfulness
1. Update validation reports with real field evidence.
2. Update censorship-resistance posture only where evidence supports it.
3. Keep unsupported claims out.

Completion bar:
Do not call this complete unless all of the following are true:
- at least one real Tor validation run is documented
- at least one VPN or degraded-network validation run is documented
- fallback behavior under forced transport failure is documented
- mobile transport status is either validated or explicitly bounded with reasons
- docs clearly separate proven, implemented-but-not-field-tested, and still-blocked items

Expected final output:
1. What additional field environments were used
2. What Tor evidence now exists
3. What VPN or degraded-network evidence now exists
4. What real field validations passed or failed
5. What remains blocked
6. Whether bridge connectivity is ready for broader field testing
