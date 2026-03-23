# Mobile Directed Sharing Network Path

## Purpose

Use the now-complete Windows and desktop-web directed sharing flow as the
reference implementation, and close the next major product gap:

- Android must gain a real supported network path for directed sharing
- iOS must gain an honest, validated retrieval-first path for directed sharing
- hosted web surfaces on mobile must reflect the same reality clearly

This is the next milestone after Windows / desktop-web completion.

## Current baseline

Already complete and should be treated as the reference:

- Windows CLI directed sharing
- Windows desktop GUI directed sharing
- Desktop web directed sharing via local HTTP bridge
- Directed envelope protocol, inbox/outbox storage, confirmation challenge,
  password gate, retention/expiry, revoke/delete, and core validation

Do not re-do those surfaces unless a mobile requirement exposes a real bug.

## Goal

Deliver the narrowest honest cross-surface milestone where:

- Android can participate in real directed sharing over the Miasma network
- iOS can complete an honest retrieval-first directed share flow
- hosted web on Android/iOS reflects the native capability correctly
- Windows can send to mobile and mobile can receive from Windows

## Track A: Choose the mobile network architecture and commit to it

### A1. Android

Choose one primary supported Android path and carry it through:

- embedded daemon with app-managed lifecycle
- FFI-exposed network operations
- HTTP bridge backed by a local native service
- another realistic, supportable option

The chosen path must support real directed sharing, not only local envelope
listing.

### A2. iOS

Choose the honest iOS scope and implement it accordingly.

iOS does not need full-node parity if that is unrealistic. It does need a real
retrieval-first path, including:

- seeing incoming directed shares
- challenge visibility if applicable
- password-gated retrieval
- revoke/delete of local access

### A3. Hosted web alignment

Android-hosted web and iOS-hosted web must not imply more than the native host
can really do.

If hosted web is just a presentation shell over native retrieval/network
operations, say so clearly and make the UX match that model.

## Track B: Android directed sharing support

Android must answer "yes" to the following with real validation:

- can it receive an incoming directed share from Windows?
- can it show the confirmation challenge?
- can it complete sender confirmation if the flow requires Android-side action?
- can it retrieve content with the sender password?
- can it revoke/delete?
- can it survive app/background lifecycle interruptions without corrupting the
  share state?

Required implementation areas:

- native or hosted-web inbox
- recipient challenge display
- password-gated retrieval
- outbox / sender-state visibility if Android sending is supported in this
  milestone
- daemon/service lifecycle management
- storage and persistence behavior

## Track C: iOS retrieval-first support

iOS must answer "yes" to the following with real validation:

- can it receive and list incoming directed shares?
- can it display enough metadata to make retrieval understandable?
- can it retrieve with password?
- can it delete/revoke local access?

If sender-side directed sharing is still out of scope on iOS, state that
explicitly and do not blur the line.

## Track D: Cross-surface validation

Run real validation across at least these pairs:

- Windows sender → Android recipient
- Windows sender → iOS recipient
- Android sender/recipient if supported in this milestone
- hosted web on mobile where applicable

Validate:

- inbox delivery
- challenge confirmation path
- wrong challenge failure behavior
- password-gated retrieval
- wrong password failure behavior
- expiry
- revoke/delete
- restart / background / reconnect behavior

## Track E: UX and product honesty

The mobile experience must make capability boundaries obvious.

Required:

- clear connected / unavailable / local-only / retrieval-only states
- no fake parity wording
- no hidden dependence on Windows desktop unless the product explicitly says so
- clear failure and retry guidance

## Track F: Documentation and release positioning

Update:

- `README.md`
- `docs/platform-roadmap.md`
- `docs/connectivity-model.md`
- platform-specific mobile task docs
- troubleshooting / validation docs

The docs must explicitly answer:

- what Android can now do
- what iOS can now do
- what hosted web on mobile can now do
- what still remains Windows-only

## Completion bar

Do not call this complete unless all of the following are true:

- Android has a real validated directed-sharing path over the network
- iOS has a real validated retrieval-first directed-sharing path
- hosted web surfaces on mobile match native capability honestly
- Windows-to-mobile directed share exchange has been validated
- lifecycle and failure behavior have been tested
- docs reflect the real state without overclaiming parity

## Expected final output

1. Which mobile network architecture was chosen and why
2. What Android can now do end to end
3. What iOS can now do end to end
4. What hosted web on Android/iOS really does
5. What cross-device validation was run
6. What still remains intentionally deferred
