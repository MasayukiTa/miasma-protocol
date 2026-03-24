Next task: use the remaining high-capacity Opus budget to break through the hardest remaining bridge/connectivity blockers now, before implementation work shifts to a cheaper model later.

Important framing:
- We are in a time-critical window.
- Assume that after Thursday, implementation may move to a weaker / cheaper model.
- That means the hardest technical work should be done now, not postponed.
- Do not treat this as a normal incremental cleanup pass.
- Treat this as an aggressive hard-blocker burn-down milestone.

Current reality:
- Bridge/connectivity has advanced substantially.
- Native Shadowsocks AEAD-2022 is now implemented.
- External Tor mode is implemented.
- Live runtime signals are substantially wired.
- Honest docs and validation reports exist.
- But real multi-node / real-network proof is still bottlenecked by infrastructure.
- Right now the environment effectively behaves like a single-device setup, which is not enough.

Core objective:
Build whatever local or remote lab is required so that bridge/connectivity can be validated beyond a single-device setup, while simultaneously attacking the remaining technically hard bottlenecks.

This milestone is successful only if it materially reduces the number of unknowns that currently block broader field confidence.

Execution guidance:
- It is acceptable if this takes a long time.
- Spend as much time as needed.
- It is also acceptable to use multiple sub-agents aggressively and in parallel.
- Use Opus-level reasoning for the highest-risk and highest-complexity parts.
- Do not stop at analysis or design notes if implementation or environment setup is feasible.

Track A: Build a real multi-node validation lab even if only one physical device is available
1. Do not accept “single device only” as the end state.
2. Create a practical multi-node environment using any realistic path that works in the current setup:
- local Linux via WSL2
- local Linux VM
- Docker or containerized side nodes if viable
- remote Linux VPS or cloud instance if needed
- any combination that creates at least 2-3 independently addressable nodes

3. The lab must be sufficient to test:
- Windows host node
- at least one Linux node
- bridge transports under non-trivial topology
- directed sharing over actual inter-node paths

4. If some lab options are not viable, document exactly why and move to the next viable option immediately.

Track B: Real bridge/connectivity validation in that lab
1. Use the lab to validate:
- same-LAN / same-subnet connectivity
- Windows ↔ Linux node connectivity
- mDNS where relevant
- bootstrap fallback
- transport selection and fallback trace
- directed sharing over real inter-node paths

2. Run `scripts/validate-bridge-connectivity.ps1` where applicable and extend it if needed.

3. Add or improve automation so the lab can be re-run later without rebuilding everything manually.

Track C: External infrastructure validation
1. Stand up a real Shadowsocks validation path.
- real ss-server
- real client config
- real bridge path through native Shadowsocks
- compare native tunnel vs external SOCKS5 fallback if both remain supported

2. Stand up a real Tor validation path.
- real Tor daemon
- real SOCKS5 proxy path
- real bridge path through Tor

3. Record exactly:
- what transport won
- how long connectivity took
- whether fallback happened
- whether directed sharing still succeeded
- what failed and why

Track D: Burn down the hardest technical blockers while Opus budget exists
1. Attack high-complexity issues now, not later.
At minimum, evaluate and implement where feasible:
- streaming / chunked handling for very large files so >100MB does not require full in-memory buffering
- stronger transport outcome attribution
- relay dependence visibility in diagnostics
- reconnect quality after hard network failure
- daemon/node-loop edge cases under partial transport death
- long-running soak behavior

2. If a blocker is too large to finish fully in one pass, reduce uncertainty aggressively:
- create a narrowed implementation
- add instrumentation
- add tests
- document the exact remaining delta

Track E: Validation under degraded or adversarial conditions
1. Go beyond “works on an easy network.”
Validate where practical:
- one-sided VPN
- two-sided VPN
- degraded/high-loss or filtered conditions
- restart during active traffic
- transport flap / partial failure
- large-file directed sharing under non-ideal conditions

2. Be explicit about what was genuinely reproduced versus what remains inferred.

Track F: Release-truthfulness and confidence upgrade
1. Update validation docs with the new evidence.
2. Keep honesty strict:
- what is proven in a lab
- what is proven on a real hostile network
- what is still only plausible
- what remains blocked by missing infrastructure or scope

3. Tighten the censorship-resistance and transport posture docs so they match exactly what was demonstrated.

Track G: Produce the next concrete blocker list for cheaper follow-on implementation
1. At the end, leave a sharply reduced, implementation-ready backlog for the weaker/cheaper model that may follow later.
2. That backlog should contain only:
- bounded tasks
- clear acceptance criteria
- low ambiguity items
- no major architectural unknowns if avoidable

Completion bar:
Do not call this complete unless all of the following are true:
- a practical multi-node lab exists even without relying on multiple physical user devices
- at least one Windows ↔ Linux or equivalent multi-node path has been validated
- at least one real Shadowsocks validation run is documented
- at least one real Tor validation run is documented
- bridge validation evidence is materially stronger than before this milestone
- at least one major high-complexity technical blocker has been fully or partially burned down with concrete code/tests/docs
- the remaining backlog is significantly narrower and cheaper to execute

Expected final output:
1. What lab environment was built
2. What real multi-node validations were run
3. What real Shadowsocks/Tor evidence now exists
4. What high-complexity blockers were burned down
5. What still remains hard
6. What exact bounded tasks should be handed to the cheaper follow-on model
