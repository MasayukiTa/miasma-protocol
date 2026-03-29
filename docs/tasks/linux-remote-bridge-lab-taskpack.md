Next task pack: use Claude's Linux-capable environment to build out a serious remote bridge validation lab and burn down the remaining external blockers.

Important framing:
- This task pack is intentionally broad and modular.
- It is designed for a Linux-capable Claude environment where local services, multiple processes, and network tooling can be driven more aggressively than on the current Windows machine.
- Do not treat this as a single narrow milestone. Treat it as a coordinated bundle of small but high-value tasks.
- It is acceptable if this work takes a long time.
- Spend as much time as needed.
- It is also acceptable to use multiple sub-agents aggressively and in parallel.

Current state:
- Windows unrestricted-network bridge proof exists for Shadowsocks, Tor external SOCKS5, fallback behavior, reconnection, and large streaming publish.
- GlobalProtect-class overlay proof does not yet exist.
- Android real-device proof does not yet exist.
- Directed sharing over Tor is not yet proven end-to-end.
- The remaining gap is now mostly field proof, lab automation, reproducibility, and release-truthfulness.

Primary objective:
Turn the remaining bridge/connectivity uncertainty into either:
- reproducible Linux-lab proof,
- cross-host proof,
- Android build/device readiness,
- or crisply bounded blockers with evidence.

Use this task pack opportunistically. Claude can take any sub-task that is feasible in its Linux environment and complete as many as possible.

Track A: Linux remote lab bootstrap
1. Create or document a reproducible Linux lab setup for Miasma bridge testing.
At minimum:
- clone the repo
- build required Rust targets
- install Tor
- install or build Shadowsocks server/client tooling
- install curl / jq / python if needed
- document exact package names and commands

2. Produce a reproducible lab note covering:
- distro
- kernel
- Rust toolchain version
- Tor version
- Shadowsocks version
- local ports used
- any firewall or sysctl changes

3. If the Linux environment is containerized or ephemeral, document how to recreate it quickly.

Track B: Multi-node Linux bridge validation
1. Stand up at least two real Miasma nodes on Linux if feasible.
2. Validate:
- direct connectivity
- fallback behavior
- directed sharing
- revoke/delete propagation
- reconnect after one node restart

3. Capture:
- selected transport
- fallback path
- reconnect metrics
- DaemonStatus fields

Track C: Tor end-to-end directed sharing
1. Go beyond SOCKS reachability and simple HTTPS checks.
2. Prove or block with evidence:
- directed sharing envelope delivery over Tor
- confirmation flow
- retrieval flow
- revoke/delete propagation
- failure modes and latency

3. If full proof is not possible, identify exactly where the chain breaks:
- SOCKS5 connectivity
- websocket/WSS path
- daemon transport selection
- directed sharing control plane
- data plane

Track D: Shadowsocks stress and failure testing
1. Run repeated directed-sharing and retrieval cycles through native Shadowsocks.
2. Test:
- wrong password / wrong key
- server restart during activity
- temporary network drop
- reconnect after hard break
- medium and large files

3. Record whether native and external Shadowsocks behave differently in practice.

Track E: Real fallback ladder proof
1. Expand the forced-failure/fallback evidence into a stronger field matrix.
2. Validate combinations such as:
- direct fail → WSS success
- direct fail → Shadowsocks success
- direct fail → relay success
- direct fail → Tor success
- repeated failure → backoff and circuit-breaker behavior

3. Capture:
- exact fallback order used
- time to successful transport
- metrics after repeated failures

Track F: ObfuscatedQuic / harsh-network prep
1. If real DPI hardware is unavailable, prepare the closest feasible Linux-side approximation.
2. This may include:
- packet loss / delay / throttling
- blocked UDP simulation
- forced TCP resets if feasible
- proxying or TLS interception approximations

3. The goal is not to fake censorship proof, but to increase confidence in recovery and fallback behavior before true hostile-network tests.

Track G: Android-on-Linux readiness
1. Use Linux to reduce the Android blocker as much as possible.
2. If feasible, install:
- Android SDK
- Android NDK
- platform tools / adb
- required Gradle prerequisites

3. Prove as much as possible from Linux:
- ARM64 build
- APK generation
- service packaging correctness
- UniFFI generation
- manifest/service/permission correctness

4. If no device is available, still push Android from "theoretical" to "build-ready with documented remaining device-only steps."

Track H: Tooling and scripts
1. Improve existing validation tooling so future runs are easier.
Candidates:
- `scripts/validate-bridge-connectivity.ps1`
- Linux equivalents or wrapper scripts
- result capture helpers
- transport log summarizers
- status snapshot collectors

2. If the current tooling is Windows-centric, add Linux-friendly execution paths rather than duplicating logic badly.

Track I: Evidence packaging
1. Write or update validation docs with crisp sections for:
- proven on Windows unrestricted network
- proven in Linux remote lab
- proven through Tor
- proven through Shadowsocks
- proven only by automation
- blocked by environment

2. Keep every claim evidence-backed.
3. Do not silently upgrade maturity language just because the code looks strong.

Track J: Remaining blocker ledger
1. Produce a short blocker ledger after all feasible Linux work is done.
Each remaining blocker should say:
- what is blocked
- whether it is code, environment, device, infra, or policy
- what exact asset is needed to unblock it
- whether it is critical for broader beta

Completion bar:
Do not call this task pack complete unless all feasible Linux-executable work has been exhausted and the repo reflects that progress clearly.

At minimum, the final result should include:
- a reproducible Linux lab setup or setup note
- at least one stronger multi-node or Tor/SS validation beyond the current Windows-only evidence
- improved automation or evidence capture if possible
- Android build-readiness progress if Linux can help
- updated docs that distinguish proven vs blocked items honestly
- a concise remaining-blockers ledger

Expected final output:
1. What Linux environment was used
2. Which sub-tasks were completed
3. What new bridge evidence now exists
4. What Android/mobile readiness improved
5. What scripts or tooling improved
6. What still remains blocked and why
