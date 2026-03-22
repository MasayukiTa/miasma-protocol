## Windows Staged Cross-Device Validation

### Purpose

This task is the execution plan for cross-device Windows validation.
It is narrower and more operational than `windows-broader-tester-expansion.md`.

Use this task when a second Windows device is actually available and the goal is to validate the current beta build across increasingly hostile or restrictive network conditions.

### Current Build Assumption

Use the current locally prepared `0.3.1` Windows beta artifacts for this pass.

Preferred artifact:

- `dist\MiasmaSetup-0.3.1-x64.exe`

Optional portable artifacts:

- `dist\miasma-0.3.1-windows-x64-easy.zip`
- `dist\miasma-0.3.1-windows-x64.zip`

### Important Execution Rule

This task is **stage-gated**.

After each stage:

1. stop work
2. summarize what passed, what failed, and what remains unclear
3. recommend the next stage
4. explicitly ask the user whether to proceed

Do **not** continue automatically from Stage 1 to Stage 2 or from Stage 2 to Stage 3.
Each stage requires explicit user confirmation before moving on.

### Validation Topology

Run the stages in this exact order.

#### Stage 1

Same network:

- this PC on its normal network
- second Windows PC on the same network

#### Stage 2

Mixed network, moderate difficulty:

- this PC on its normal network
- second Windows PC connected through Kaspersky VPN

#### Stage 3

Mixed network, harder path:

- this PC connected through GlobalProtect
- second Windows PC connected through Kaspersky VPN

If an environment prerequisite is missing, say so clearly and stop at the end of the current stage.

### Common Rules For All Stages

At every stage, validate both:

- installed flow via `MiasmaSetup-0.3.1-x64.exe`
- practical user flow in the desktop app

Prefer Easy mode for mainstream-user validation and Technical mode for diagnostics when something fails.

At every stage, capture:

- whether install succeeded
- whether first launch succeeded
- whether the backend started reliably
- whether peers appeared
- whether save/retrieve worked
- whether diagnostics export worked
- what the user-facing errors looked like

### Stage 1: Same-Network Baseline

#### Goal

Prove the current `0.3.1` Windows beta behaves correctly across two separate devices under the easiest realistic network condition.

#### What to validate

1. Install and first launch on the second device
- run `MiasmaSetup-0.3.1-x64.exe`
- verify SmartScreen instructions if shown
- verify Start Menu shortcuts and icon appearance
- launch Easy mode
- verify first-run/setup flow is understandable

2. Basic app behavior on the second device
- mode switching
- locale switching and persistence
- Save Report path and output
- Easy mode health indicators
- Technical mode diagnostics visibility

3. Two-device connectivity on the same network
- configure bootstrap information as needed
- verify the second device can see at least one peer
- verify "no peers yet" vs connected states are understandable

4. Save/retrieve flow across devices
- save content on one device
- retrieve from the other device
- test both text and file flow if practical
- confirm resulting content integrity

5. Shell integration on the second device
- test `magnet:` opening from a real browser if practical
- test `.torrent` opening from Explorer / Open With
- verify import UI is understandable

6. Supportability
- Save Report works on the second device
- troubleshooting wording matches what the app says
- failure messages are actionable

#### Stage 1 success bar

Do not call Stage 1 successful unless:

- install succeeds on the second device
- the app launches cleanly
- the backend starts
- peer discovery succeeds on the same network
- at least one cross-device save/retrieve flow succeeds
- diagnostics export works

#### Stage 1 report format

At the end of Stage 1, report:

1. what passed
2. what failed
3. what was confusing for a user
4. whether Stage 2 should proceed

Then ask:

`Stage 1 is complete. Proceed to Stage 2 (second PC on Kaspersky VPN)?`

### Stage 2: Second PC Through Kaspersky VPN

#### Goal

Measure what breaks or degrades when the second device is behind Kaspersky VPN while this PC remains on its normal network.

#### What to validate

1. Basic launch under VPN condition
- verify the second device still installs and launches normally
- verify the backend still starts
- verify local app status is clear

2. Peer visibility and recovery behavior
- whether peers are discovered at all
- whether the app remains stuck at "starting" / "no peers" / "offline"
- whether recovery hints are still useful

3. Cross-device save/retrieve attempt
- save on PC A, retrieve on PC B
- save on PC B, retrieve on PC A
- if retrieval fails, capture exact behavior in Easy and Technical mode

4. Transport and trust behavior
- use Technical mode diagnostics to determine whether failure is:
  - no peer discovery
  - transport blocked
  - shell import unrelated
  - backend healthy but network path degraded

5. Diagnostics and logs
- export Save Report from the failing side if there is a failure
- capture whether logs / report make the problem legible enough for debugging

#### Stage 2 success bar

Stage 2 can be considered successful in either of these ways:

- full cross-device save/retrieve works under Kaspersky VPN
- or failure is reproduced clearly enough that the cause is diagnosable and user-facing behavior remains understandable

This stage is still valuable even if connectivity fails, provided the failure is captured honestly and clearly.

#### Stage 2 report format

At the end of Stage 2, report:

1. whether connectivity still worked
2. if not, exactly where it failed
3. what diagnostics revealed
4. whether the app experience remained understandable
5. whether Stage 3 should proceed

Then ask:

`Stage 2 is complete. Proceed to Stage 3 (second PC on Kaspersky VPN, this PC on GlobalProtect)?`

### Stage 3: Kaspersky VPN vs GlobalProtect

#### Goal

Validate the hardest currently planned tester environment:

- second PC on Kaspersky VPN
- this PC on GlobalProtect

This stage is expected to be the most failure-prone and is specifically meant to expose trust, connectivity, and user-facing recovery weaknesses.

#### What to validate

1. Launch and local health on both devices
- app startup
- backend startup
- health indicators
- Easy mode wording under degraded network conditions

2. Peer discovery across both VPN environments
- whether nodes discover each other at all
- how long discovery is attempted
- whether failure mode is "offline", "starting", or "no peers"

3. Cross-device save/retrieve attempt
- repeat the same two-way attempts from Stage 2
- capture whether the problem is symmetric or one-sided

4. Diagnostics depth
- compare Easy mode surface vs Technical mode diagnostics
- confirm whether Technical mode gives enough information to triage VPN-related failure

5. Product judgment under harsh conditions
- if this topology fails, assess whether the app still behaves acceptably for a beta
- distinguish product weakness from network impossibility

#### Stage 3 success bar

This stage is successful if either:

- cross-device retrieval works
- or failure is honest, diagnosable, and non-chaotic for the user and tester

#### Stage 3 report format

At the end of Stage 3, report:

1. what worked
2. what failed
3. whether the failure looks product-side, network-side, or mixed
4. what changes are now highest priority
5. whether the Windows beta is acceptable for broader tester expansion

### Cross-Stage Checklist

At each stage, explicitly note:

- install path used: Setup EXE or portable ZIP
- OS version on second device
- whether SmartScreen appeared
- whether icons looked correct
- whether non-English text still rendered correctly
- whether shell integration was tested
- whether Save Report was exported
- whether the user could tell what to do next

### Completion Bar

This task is complete only when:

1. Stage 1 was completed and reported
2. Stage 2 was completed and reported
3. Stage 3 was completed and reported
4. a final cross-stage summary exists
5. the remaining blockers, if any, are prioritized clearly

### Final Output Required After All Three Stages

After all stages are complete, provide:

1. A per-stage summary
2. A per-stage pass/fail matrix
3. The most important observed UX problems
4. The most important observed network/runtime problems
5. A recommendation:
- acceptable for broader tester expansion
- acceptable only for limited tester expansion
- not ready yet, blocked by specific issues
