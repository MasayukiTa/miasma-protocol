Next task: produce a brutally honest implementation-effort estimate, cost model, and productization gap assessment for the current Miasma codebase.

Important framing:
- This is not a feature-building task.
- This is a decision-quality assessment task.
- The goal is to answer, with evidence from the repository as it exists now:
  1. how much work remains,
  2. how much that work is likely to cost,
  3. what is still missing before Miasma can be treated as a serious product instead of an advanced development build.

Use the repository as the source of truth:
- README.md
- docs/platform-roadmap.md
- docs/connectivity-model.md
- docs/validation/*
- docs/adr/*
- current platform code and tests

Do not give a shallow "a few months" answer.
Do not give a hype answer.
Do not assume all implemented code is production-ready just because tests pass.
Be strict, conservative, and explicit about uncertainty.

It is acceptable if this takes a long time.
Spend as much time as needed.
It is also acceptable to use multiple sub-agents aggressively for parallel analysis.

Work in these tracks:

Track A: Current-state inventory
1. Establish the real state of each surface:
- Windows
- Web/PWA
- Android
- iOS
- shared protocol/core

2. For each surface, state clearly:
- what is implemented
- what is validated
- what is only foundation work
- what is still unproven
- what should not be claimed yet

3. Be explicit about the current release reality:
- what can reasonably be called beta
- what is still pre-beta
- what is still foundation only

Track B: Productization gap analysis
1. Identify what is still missing before this can be treated as a real product.
At minimum, evaluate:
- real-network validation depth
- mobile real-device validation
- large-file robustness
- directed sharing maturity
- bridge/connectivity resilience
- installer/update/signing story
- observability and diagnostics
- support and troubleshooting readiness
- release/versioning discipline
- crash recovery and lifecycle behavior
- security hardening
- external audit readiness
- documentation and onboarding quality

2. Group gaps by severity:
- must-have before serious external beta
- must-have before broader public beta
- must-have before production claim
- important but can wait

Track C: Effort estimate
1. Estimate remaining effort in engineer-weeks for at least these targets:
- closed technical beta
- broader external beta
- first credible product release

2. Break effort down by workstream:
- protocol/core/networking
- Windows desktop/runtime
- Android
- iOS
- web
- QA/validation
- security
- release/packaging
- docs/support/product polish

3. Use ranges, not fake precision.
Example style:
- optimistic
- realistic
- conservative

4. State assumptions behind every estimate.

Track D: Cost estimate
1. Convert effort into rough cost using at least two staffing models:
- lean founder/small team execution
- contractor/agency-heavy execution

2. Give cost ranges in:
- JPY
- USD

3. Separate:
- engineering cost
- QA/device validation cost
- security/audit cost
- code signing / operational overhead if relevant

4. Be honest about cost drivers:
- mobile real-device work
- hostile-network validation
- security review
- support burden
- platform-specific packaging/distribution

Track E: Release-readiness judgment
1. Answer clearly:
- What can be shipped now?
- What can be shipped only to technical testers?
- What should not yet be publicly positioned as ready?

2. Give a recommended release order.

3. State what the next single highest-leverage milestone should be after this assessment.

Track F: Evidence-backed final deliverable
1. Produce a concise but serious assessment document.
2. Tie claims back to repository evidence where possible.
3. Prefer tables for:
- platform maturity
- missing capabilities
- effort ranges
- cost ranges
- release gates

Completion bar:
Do not call this complete unless all of the following are true:
- current platform maturity is stated honestly
- major productization gaps are identified and prioritized
- effort is estimated in engineer-weeks with assumptions
- costs are estimated in JPY and USD with staffing-model context
- release readiness is judged explicitly
- the final recommendation clearly answers "what do we do next, and why"

Expected final output:
1. Current maturity by platform
2. What is still missing
3. Effort estimate by milestone
4. Cost estimate by staffing model
5. What can be shipped now vs later
6. Recommended next milestone
