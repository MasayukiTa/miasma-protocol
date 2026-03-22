## Platform Convergence Roadmap

### Why this task exists

Miasma has moved beyond a single-surface prototype.

We now have meaningful work across:

- Windows desktop beta
- Web/PWA client
- Android foundation
- iOS retrieval-first foundation

That is strong progress, but it also creates a new risk:

- each surface can continue moving independently
- release claims can drift apart
- protocol assumptions can fragment
- validation can remain too local to each platform

The next major task should therefore not be "add another isolated feature."
It should be "bring the current surfaces into a coherent product roadmap and execution order."

### Goal

Define and execute the next serious phase after the initial Windows/Web/Android/iOS expansion:

- converge platform scope
- decide what is truly beta-ready
- identify what remains foundation-only
- prioritize the next milestones in an order that reduces confusion and release risk

### Current state to assume

- Windows is the current shipping beta surface
- Web exists and is meaningful, but needs clear scope and security boundaries
- Android exists as a serious next surface, but is still foundation-stage
- iOS exists as retrieval-first groundwork, not as a parity client
- protocol/anonymity/storage work has progressed materially, but productization is uneven across platforms

### This task is not

- not a "build one more platform quickly" task
- not a "rewrite everything" task
- not a speculative architecture exercise

This is a concrete roadmap-and-execution task meant to clarify what we should do next and in what order.

### Track A: Product-line clarity

1. Write down the real product line as it exists now
- Windows Technical/Easy beta
- Web/PWA browser client
- Android mobile foundation
- iOS retrieval-first client foundation

2. State what each surface is for
- primary user
- maturity level
- what it can do now
- what it should not yet claim

3. Remove ambiguity
- do not let docs imply all surfaces are equally mature
- do not let mobile or web appear production-ready if they are not

### Track B: Capability matrix

Build a capability matrix across all active surfaces.

At minimum compare:

- initialize
- status/health
- dissolve/store
- retrieve/get
- diagnostics/support export
- localization
- import flows
- shell/share integration
- background behavior
- same-network discovery
- external peer retrieval
- release packaging
- security posture

For each surface, classify each capability as:

- real and validated
- partial
- stub/foundation only
- intentionally unsupported

This matrix should become the basis for milestone prioritization.

### Track C: Decide the next milestone order

After the capability matrix is clear, choose the next milestone order explicitly.

Recommended framing:

1. Windows broader-tester readiness
2. Android first serious mobile milestone
3. Web scope hardening and honest positioning
4. iOS retrieval-first closure
5. shared protocol/support/release convergence

But this should be re-evaluated based on actual repo state, not assumed blindly.

For each milestone, state:

- why it comes now
- what it unlocks
- what it deliberately postpones

### Track D: Shared backend and protocol convergence

Make sure platform work is not drifting into incompatible product stories.

Review:

- `miasma-core`
- `miasma-ffi`
- `miasma-wasm`
- mobile-facing assumptions
- desktop-specific assumptions that have leaked into shared layers

Call out:

- what is truly shared
- what is platform-specific by design
- what should be unified next

### Track E: Validation strategy by platform

Define a realistic validation ladder for each surface.

Examples:

- Windows: install/upgrade/uninstall, same-network, separate-machine, VPN, support export
- Web: browser compatibility, WASM support, security boundaries, offline/PWA behavior
- Android: fresh build, emulator, real device, retrieval/save loop, lifecycle behavior
- iOS: build, simulator, real device, retrieval-first loop, export/share behavior

Do not mix these together into one vague "tested" claim.

### Track F: Release and versioning strategy

The project now has enough surfaces that release/versioning strategy must be explicit.

Define:

- what gets versioned together
- what counts as a platform-specific beta
- how Windows/Web/Android/iOS status should appear in README and release notes
- how to avoid misleading installer/update behavior like the earlier Windows same-version beta issue

### Track G: Documentation consolidation

Current task docs are useful, but fragmented.

This task should result in:

- one higher-level roadmap document
- clear links to the platform-specific tasks
- a concise "current maturity by platform" summary

Do not delete the platform-specific task files.
Instead, make them easier to place in the bigger picture.

### Track H: Immediate next actionable tasks

This task must end by producing concrete next tasks, not only analysis.

Expected outputs:

1. one top-level roadmap
2. one platform capability matrix
3. one prioritized milestone order
4. one immediate next milestone task for each active surface:
- Windows
- Web
- Android
- iOS

If an existing task already serves that role, say so clearly instead of creating duplicate task files.

### Completion bar

Do not call this complete unless all of the following are true:

- platform maturity is explicit and honest
- the next milestone order is prioritized, not just listed
- platform-specific tasks are tied into one coherent roadmap
- release-positioning ambiguity is reduced
- there is a clear answer to "what do we do next, and why"

### Final report format

1. Current maturity by platform
2. Capability matrix summary
3. Recommended milestone order
4. Immediate next task for each platform
5. What should not be worked on yet
