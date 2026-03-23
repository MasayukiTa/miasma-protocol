# Directed Private Sharing and Connectivity Completion

## Remaining Work Only

This file intentionally lists only what is still incomplete after the first
implementation pass.

The following foundations are already in the codebase and are NOT repeated
here:

- directed envelope crypto and inbox/outbox storage
- CLI commands for sharing key, send, confirm, receive, revoke, inbox, outbox
- daemon IPC / HTTP bridge support for directed sharing
- desktop GUI first-pass send/inbox/retrieve/revoke support
- desktop web bridge first-pass send/inbox/retrieve/revoke support
- ADR coverage for the directed sharing protocol

This task starts from that point and focuses only on the gaps still blocking a
credible milestone.

## Goal

Close the remaining gaps so directed private sharing becomes a real,
validated, user-complete feature on Windows first, with an honest path for web,
Android, and iOS.

## Current honest state

- Windows core plumbing exists, but the end-to-end user flow is not yet fully
  finished or fully validated.
- Desktop browser web can talk to a local daemon through the HTTP bridge, but
  the connected-mode user flow is still incomplete.
- Android and iOS still do not have a completed, validated network-capable
  path for directed sharing.
- Documentation and platform positioning need one more consistency pass after
  the recent implementation jump.

## Track A: Finish the Windows end-to-end product flow

### A1. Sender confirmation UX is still incomplete

The sender must be able to finish the challenge-confirmation step without
falling back to the CLI unless that is explicitly marked as an advanced path.

Required:

- desktop GUI must expose challenge submission clearly
- web bridge UI must expose challenge submission clearly
- sender should be able to see pending outgoing shares and their current state
- outbox state should make it obvious whether the share is:
  - waiting for recipient challenge
  - confirmed
  - expired
  - revoked
  - failed due to too many attempts

### A2. Recipient-side flow must feel complete

The recipient flow needs to be explicit and product-usable.

Required:

- incoming share notification/banner or equivalent obvious inbox visibility
- clear password entry flow
- clear error states:
  - wrong password
  - password attempts exhausted
  - expired share
  - sender revoked
  - recipient deleted
- explicit save/download behavior after successful retrieval

### A3. Outbox and inbox completeness

The first pass added inbox and send surfaces, but the full lifecycle still
needs to be visible.

Required:

- explicit outbox UI where applicable
- clear timestamps / expiry information
- clear retention display
- sender-side revoke from UI
- recipient-side delete/revoke from UI

## Track B: Real Windows validation, not just code-level confidence

### B1. Same-network validation

Run and document real same-network Windows validation for:

- sharing key exchange
- directed send
- recipient challenge display
- sender confirmation
- password-gated retrieval
- sender revoke
- recipient delete
- expiry behavior

### B2. Cross-network validation

Run and document the same flow for at least one supported cross-network path,
if available in this environment.

If cross-network cannot be completed in one pass, document exactly what was
blocked and keep the Windows same-network path as the release baseline.

### B3. Failure-path validation

The following must be tested explicitly:

- wrong challenge once, twice, three times
- wrong password once, twice, three times
- challenge TTL expiry
- retention expiry
- recipient offline at invite time
- sender offline after invite
- daemon restart during pending share

## Track C: Web surface completion for directed sharing

Desktop-hosted web is no longer purely local-only, but the product flow is
still incomplete.

Required:

- connected-mode web UX must clearly distinguish:
  - local-only fallback
  - connected via local daemon
  - backend unavailable
  - no peers / no network path
- web must expose sender confirmation flow, not only send and inbox
- web must expose outbox or equivalent sender-state visibility
- prompt-based temporary UI should be replaced where it is too weak for a real
  feature
- browser validation against a running daemon must be documented honestly

## Track D: Android and iOS supported path

The recent work does NOT complete mobile directed sharing.

### D1. Android

Define and implement the narrowest real supported Android path:

- native screen flow
- hosted web flow
- or another supported route

But it must be real, not implied.

At minimum, answer clearly:

- can Android receive a directed share?
- can Android display the challenge?
- can Android submit confirmation?
- can Android retrieve with password?
- can Android revoke/delete?

### D2. iOS

iOS may remain retrieval-first, but the supported scope must be explicit and
real.

At minimum, answer clearly:

- can iOS receive a directed share?
- can iOS display the challenge?
- can iOS retrieve with password?
- can iOS delete/revoke local access?

If any of these remain unsupported, document them explicitly rather than
implying parity.

## Track E: Security and lifecycle hardening

The core design is in place, but the surrounding lifecycle needs one more pass.

Required:

- verify password is never persisted in plaintext anywhere
- verify challenge material is handled safely and removed when no longer needed
- verify terminal states are really terminal
- verify revoke/delete/expiry survive daemon restarts
- verify cryptographic deletion semantics are consistent in UI and docs
- verify inbox/outbox cleanup behavior over time

## Track F: Documentation and release alignment

Several docs now need to catch up to the new reality.

Update and align:

- `README.md`
- `docs/platform-roadmap.md`
- `docs/connectivity-model.md`
- troubleshooting docs
- release notes / validation notes where relevant

The docs must reflect the real state after this pass:

- Windows directed sharing: target milestone
- desktop web: host-assisted and partially complete until fully validated
- Android: not complete unless actually validated
- iOS: retrieval-first unless actually advanced

## Immediate next task

Do this in order:

1. Finish the Windows sender/recipient UX so confirmation, retrieval, revoke,
   and outbox are all usable without CLI fallback.
2. Run real same-network Windows validation of the full directed-share flow.
3. Close web bridge UX gaps for connected mode and sender confirmation.
4. Re-assess Android and iOS honestly and implement the narrowest real
   supported path that can actually be validated.
5. Update docs only after the above is true.

## Completion bar

Do not call this milestone complete unless all of the following are true:

- Windows desktop can complete the full directed-share lifecycle end to end
  without requiring the CLI for the normal path
- same-network validation has been run for the full flow
- failure paths have been tested and recorded
- desktop web connected mode is honest and usable
- Android and iOS supported scope is explicit and validated, or explicitly
  documented as still unsupported
- docs match the real current behavior

## Expected final output

1. What still required CLI before this pass, and what no longer does
2. What Windows end-to-end flow now works
3. What was validated on same-network and cross-network paths
4. What web, Android, and iOS can honestly do now
5. What still remains intentionally deferred
