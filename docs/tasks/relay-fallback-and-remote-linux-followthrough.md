Next task: implement relay-circuit fallback for the directed-sharing control plane and use it to recover the blocked Windows <-> remote Linux proof.

Important framing:
- The previous remote Linux proof was valuable, but it did not clear the main public-path blocker.
- A real non-local Linux peer was stood up, yet Windows <-> remote Linux connectivity was blocked by the current network path and transport reachability constraints.
- At the same time, ADR-010 already identified the next structural move: wire relay-circuit fallback into the directed-sharing control plane.
- This task is where those two threads converge.
- It is acceptable if this task takes a long time.
- Spend as much time as needed.
- It is also acceptable to use multiple sub-agents aggressively and in parallel.

Current state:
- Windows <-> WSL2 Linux interoperability is field-proven.
- Windows <-> non-local Claude/Linux proof reached a real blocker, not just a missing setup step.
- Directed sharing currently requires an established bidirectional libp2p path.
- ADR-010 Part 2 already defines the next implementation path:
  relay dial fallback in `DhtCommand::SendDirectedRequest`.
- Relay infrastructure already exists for the data plane. What is missing is control-plane wiring and then a renewed remote proof attempt.

Primary objective:
Move directed sharing beyond direct bidirectional reachability by wiring relay-circuit fallback into the control plane, then use that new path to retry the remote Linux proof in a stronger, less fragile way.

Track A: Implement ADR-010 Part 2 cleanly
1. Extend the directed-sharing control plane so that when the target peer is not already connected, the node can attempt relay-circuit dial fallback before giving up.

2. The implementation should follow ADR-010 closely:
- inspect available relay peers from the descriptor / trust store
- prefer stronger trust tiers first
- build circuit multiaddrs of the form:
  `/p2p/{relay}/p2p-circuit/p2p/{target}`
- dial via circuit
- wait for connection establishment with a bounded timeout
- only then call `send_request`

3. Scope the fallback carefully:
- if the target is already directly connected, do not force relay
- if direct path fails or is unavailable, relay fallback is allowed
- errors should clearly distinguish:
  - no relay candidates
  - relay dial failed
  - relay connected but request failed
  - timeout waiting for connection

4. Keep the protocol surface stable where possible.
Do not redesign directed sharing into a mailbox/store-and-forward model in this task.

Track B: Test the control-plane relay path thoroughly
1. Add unit/integration/adversarial coverage for:
- directed invite over relay fallback
- confirm over relay fallback
- revoke/delete over relay fallback
- no-relay-candidate behavior
- bad relay candidate behavior
- timeout behavior
- multiple relay candidates with priority ordering

2. Validate that the direct path is still preferred when available.
This task must not silently degrade everything into relay-first behavior.

3. Validate that relay fallback does not pollute the address book or leave stale circuit state behind.

Track C: Re-run the remote Linux proof with the new capability
1. Revisit the blocked Windows <-> remote Linux proof after relay fallback is implemented.
2. Try again to establish:
- peer connectivity
- publish/retrieve
- directed sharing

3. Be explicit about what path actually succeeded:
- direct
- relay-assisted
- partially connected but not enough for directed sharing
- still blocked

4. If it still fails, classify the blocker precisely:
- GlobalProtect outbound policy
- relay reachability
- remote host firewall/NAT
- transport selection issue
- control-plane bug

Track D: Strengthen non-local proof quality
1. If a relay-assisted path succeeds, prove more than "the peers can see each other."
Validate:
- remote Linux publish -> Windows retrieve
- Windows publish -> remote Linux retrieve
- directed sharing both directions if supported
- revoke/delete propagation

2. Include at least:
- one tiny file
- one medium file
- one meaningfully large file

3. Record:
- transfer times
- selected transport
- relay used or not
- whether reconnect or retries occurred

Track E: Reconnect and recovery over the relay/non-local path
1. After initial success, break the path intentionally:
- restart remote Linux daemon
- drop the direct path if one exists
- force the system to recover via the relay path if feasible

2. Verify:
- stale state is cleaned
- reconnect happens automatically if supported
- relay fallback can be re-used after failure
- diagnostics expose what happened

3. Record:
- recovery timing
- whether path changed from direct to relay or vice versa

Track F: Diagnostics and operator visibility
1. Improve the operator story if needed so it is obvious:
- whether a directed request used direct or relay path
- which relay was selected
- why relay fallback was or was not attempted
- why the attempt failed

2. Expose this in:
- CLI diagnostics
- DaemonStatus / bridge diagnostics
- validation logs or report tables

3. The goal is that future debugging of public-path failures is much faster.

Track G: Documentation and proof boundaries
1. Update:
- ADR-010 follow-through status
- validation reports
- any transport/directed-sharing docs that still imply direct-only behavior

2. Keep the claims honest:
- if relay-assisted directed sharing is now proven, say that
- if remote Linux proof is still blocked, say exactly why
- do not silently upgrade this to "Tor directed sharing solved" unless the evidence truly supports that

3. Make the post-task boundary explicit:
- what directed sharing now supports
- what still requires future architecture work

Track H: Remaining blocker ledger
1. At the end, produce a short remaining-blockers ledger.
Each blocker should say:
- what remains unproven
- whether it is code, environment, infra, or policy
- what exact asset would unblock it
- whether it materially blocks broader beta confidence

Completion bar:
Do not call this complete unless all of the following are true:
- relay-circuit fallback is implemented in the directed-sharing control plane
- automated coverage exists for invite/confirm/revoke over relay fallback
- direct path is still preferred when healthy
- the remote Linux proof has been retried with the new capability
- the result of that retry is documented honestly
- diagnostics make direct vs relay behavior visible enough to debug future failures

Expected final output:
1. What changed in the directed-sharing control plane
2. How relay fallback now works
3. What tests were added
4. Whether the remote Linux proof now succeeds
5. Whether directed sharing over a non-local path now succeeds
6. What diagnostics improved
7. What still remains blocked and why
