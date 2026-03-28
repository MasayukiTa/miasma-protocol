Next task: finish the remaining external proof work for bridge connectivity under unrestricted and mobile-hosted conditions.

Important framing:
- The core bridge/connectivity implementation is now substantially complete.
- Native Shadowsocks, external Tor mode, fallback diagnostics, streaming publish, and reconnection logic are already in place.
- The remaining gap is no longer architecture-first. It is proof-first.
- Do not reopen settled transport design unless a real field blocker forces it.
- Keep all release and censorship-resistance language brutally honest.

Execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed.
- It is also acceptable to use multiple sub-agents aggressively and in parallel.
- Prefer real evidence over more speculative implementation.

Current state:
- Native Shadowsocks AEAD-2022 is implemented and field-validated.
- External Shadowsocks SOCKS5 mode is field-validated.
- Tor external SOCKS5 mode is implemented, but full bootstrap proof is still blocked by the current corporate network.
- The fallback ladder is now backed by stronger automated evidence, including forced-failure fallback tests.
- Mobile transport behavior is bounded by shared Rust code analysis, but not yet proven on real devices.

Goal:
Convert the remaining bridge unknowns from “implemented or inferred” into “proven in the field” or “explicitly bounded with evidence.”

Track A: Tor proof on an unrestricted network
1. Run a real Tor-backed bridge validation outside the current blocked network.
- external Tor daemon or Tor Browser SOCKS5 is acceptable
- confirm bootstrap, circuit establishment, and real bridge traffic

2. Record:
- bootstrap success or failure
- time to first usable circuit
- whether directed sharing works over Tor
- what transport diagnostics report during the run

3. If Tor still fails, determine whether the blocker is:
- network policy
- DNS or directory fetch
- SOCKS path correctness
- websocket or WSS path behavior
- daemon integration

Track B: VPN and degraded-network proof
1. Validate the bridge layer on harsher real conditions.
At minimum:
- one-sided VPN
- two-sided VPN if available
- degraded or filtered network if available
- forced transport failure with real fallback
- reconnect after hard failure

2. Record:
- winning transport
- fallback path
- time to connectivity
- directed-sharing success or failure
- reconnect and recovery behavior

Track C: Android real-device transport proof
1. Build and run the Android app on a real ARM64 device.
2. Confirm the embedded daemon starts and remains usable long enough to test:
- status
- peer connectivity
- directed sharing
- reconnect behavior
- background and foreground transitions

3. Validate Windows ↔ Android directed sharing on a real network.
- same-network first
- challenge confirmation
- password-gated retrieval
- revoke/delete behavior
- at least one medium file and one large file

4. Record what is proven on real hardware versus what is still only inherited from shared Rust code.

Track D: iOS proof boundary
1. Determine whether iOS can be advanced from “retrieval-first foundation” to a stronger proven statement.
2. If real device or simulator proof is possible, run it and document it.
3. If not, write the exact boundary honestly and stop there.

Track E: Operator evidence and release truthfulness
1. Update validation reports with real evidence only.
2. Keep a clean separation between:
- proven by field validation
- proven by automated testing
- implemented but not field-proven
- blocked by environment

3. Update release-facing language only after evidence exists.

Completion bar:
Do not call this complete unless all of the following are true:
- at least one real unrestricted-network Tor run is documented, or the blocker is isolated with evidence
- at least one VPN or degraded-network run is documented
- Android real-device bridge behavior is documented with honest results
- Windows ↔ Android directed sharing is either proven or explicitly blocked with evidence
- iOS status is either advanced with proof or bounded honestly
- all related validation docs clearly separate proven, inferred, and blocked claims

Expected final output:
1. What external environments were used
2. What Tor evidence now exists
3. What VPN and degraded-network evidence now exists
4. What Android real-device behavior is now proven
5. What iOS boundary remains
6. Whether bridge connectivity is ready for broader external testing
