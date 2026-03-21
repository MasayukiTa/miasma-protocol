# Windows Dual-Release Variants: Remaining Work For Full Completion

## Purpose

This file contains only the work that is still unfinished or newly required.

Do not reopen already-finished work unless it is necessary to complete one of the remaining items below.
Do not mark this effort complete unless the completion bar at the end is fully satisfied.

It is acceptable if this takes several hours.
I prefer one slower pass that truly closes the remaining gaps over another fast pass that overstates completion.

## Current Honest Status

The current desktop work is a strong first pass, not a finished dual-release system.

What is already materially landed:

- hidden console behavior is improved
- basic Technical vs Easy presentation split exists
- localization scaffolding exists
- English, Japanese, and Simplified Chinese string tables exist
- desktop-specific tests exist
- release scripts started to grow variant awareness

What is still not good enough to call "complete":

- end-user variant behavior still depends too much on `MIASMA_MODE`
- mode switching is not yet a trustworthy end-user release mechanism
- locale selection does not yet clearly behave like a product feature across restarts/upgrades
- Technical and Easy are not yet fully honest, distinct, end-user-releasable Windows outputs
- build/package/install flows still overclaim how distinct the variants really are
- Easy mode still needs another pass to feel safe and obvious for non-technical users
- localization needs real rendering and quality validation, not only string-table presence

## Goal Of The Next Pass

Finish the remaining Windows dual-release work completely enough that both of these can honestly exist from the same codebase:

1. Technical Beta RC
2. Easy Trial Build

These are release variants, not separate products and not a fork.

They must share:

- backend
- protocol stack
- storage/encryption/key management
- daemon IPC
- installer foundation
- diagnostics backend

They may differ in:

- default mode
- launcher behavior
- shortcut naming
- package naming
- information density
- wording
- onboarding tone
- release notes / audience positioning

## Non-Negotiable Rules

1. Do not rely on environment variables as the normal-user mechanism.
`MIASMA_MODE` may remain as a developer override only.

2. Do not present runtime toggles alone as "dual release".
If the release outputs are not meaningfully distinct to a tester, the work is not complete.

3. Do not sacrifice Technical mode usefulness to simplify Easy mode.
Technical must remain clearly better for validation, debugging, and protocol testing.

4. Do not stop at string tables.
Localization is not complete unless the UI is actually usable in the shipped languages.

5. Do not overclaim in scripts, docs, README, installer text, or release notes.

## Required Remaining Work

### A. Make Variant Selection Real For End Users

#### A1. Remove end-user dependence on `MIASMA_MODE`

Implement a real default-selection mechanism for normal users.
Acceptable mechanisms include one or more of:

- persisted product mode in app state/config
- explicit launcher arguments
- variant-specific shortcuts
- installer-created launch entries
- packaged launch wrappers

`MIASMA_MODE` may stay as a developer/testing override, but it must not be the primary user path.

Required outcome:

- a normal user can launch the intended variant without setting environment variables
- the intended variant is obvious from how it is launched
- developer override behavior is documented separately

#### A2. Persist product mode across restart and upgrade

If a user switches between Technical and Easy in Settings, that choice must survive:

- restart
- normal update/upgrade
- ordinary relaunch from the installed shortcut

Define and implement a clear precedence order.
Recommended order:

1. explicit launch argument / launcher choice
2. persisted user choice
3. developer env override
4. built-in default

If you choose a different order, document it clearly and keep it testable.

Required outcome:

- the chosen mode survives restart
- the chosen mode survives upgrade
- precedence rules are explicit and tested

#### A3. Persist locale across restart and upgrade

Language selection must behave like a real desktop-app setting.

Requirements:

- chosen locale persists
- locale restores correctly on next launch
- unknown/removed locale values fall back safely
- upgrade does not reset language unexpectedly

Required outcome:

- language survives restart
- language survives upgrade
- fallback behavior is explicit and tested

### B. Make The Release Variants Honest And Real

#### B1. Produce actually distinct release outputs

The release process must generate outputs that are meaningfully different for testers and end users.

Acceptable examples:

- one shared binary plus two distinct launchers/shortcuts and two clearly different packages
- one installer that installs both launch paths clearly
- two packages/installers with different defaults but shared internals

The distinction must be real in release terms:

- name
- launch behavior
- default mode
- package/readme content
- audience positioning

Required outcome:

- `technical`, `easy`, and `both` each produce something meaningfully distinct
- a tester can tell which variant they launched without guessing
- package contents and instructions match actual behavior

#### B2. Make `build-release.ps1` and `package-release.ps1` truthful

Fix any overclaiming or fake separation in:

- `scripts/build-release.ps1`
- `scripts/package-release.ps1`
- any release helper scripts touched by the variant model

Required outcome:

- script help text matches reality
- script output messages match reality
- generated artifact names match reality
- no script comment claims "baked-in mode" unless that is truly implemented

#### B3. Add variant-aware installer and shortcut behavior

The Windows installed experience should make the variants understandable.

Acceptable examples:

- Start Menu entries for both variants
- one main shortcut and one advanced shortcut
- installer selection flow with clear wording

Required outcome:

- installed shortcuts clearly communicate intent
- launching the intended variant does not require technical knowledge
- install, upgrade, and uninstall remain clean

#### B4. Add variant-aware portable behavior

Portable ZIP users also need a real story.

Required outcome:

- portable instructions explain how to launch each variant
- portable usage does not depend on users inventing environment-variable tricks

### C. Finish Easy Mode As A Real Non-Technical Product Surface

#### C1. Second-pass terminology scrub

Audit Easy-mode primary surfaces again and remove remaining engineering leakage.

Examples to avoid in primary Easy-mode UX where possible:

- daemon
- bootstrap
- relay
- descriptor
- admission
- topology
- replication queue
- transport fallback
- protocol

Audit:

- onboarding
- buttons
- empty states
- status messages
- success/failure messages
- settings descriptions
- save/retrieve confirmations

Required outcome:

- Easy mode reads like a mainstream product
- advanced terms appear only in clearly secondary/advanced surfaces where necessary

#### C2. Reduce Easy-mode information density further

Easy mode should not merely rename tabs.

Improve:

- default status screen
- startup state clarity
- next-action guidance
- error recovery prompts
- visibility hierarchy

Keep:

- diagnostics export
- advanced support paths

But do not center the experience on diagnostics.

Required outcome:

- a non-technical user can understand the default status screen quickly
- readiness and next actions are visually dominant
- advanced detail remains available without being the main experience

#### C3. Improve first-run and recovery UX

Polish:

- first setup language
- "not ready yet" language
- background-service recovery wording
- save success wording
- retrieve success wording
- common failure recovery hints

Required outcome:

- a non-technical user can recover from common problems without understanding architecture
- startup/recovery states feel guided rather than brittle

### D. Preserve Technical Mode As A Real Validation Tool

#### D1. Audit Technical mode for diagnostic richness

Make sure simplification work does not hollow out Technical mode.

Review:

- backend state visibility
- transport detail
- connection/routing visibility
- support usefulness
- diagnostics export usefulness
- troubleshooting clarity

Required outcome:

- Technical mode remains clearly better for protocol testing and debugging
- technical users can still inspect meaningful system state

#### D2. Clearly explain the audience split

Update release-facing text so the distinction is obvious:

- who should use Technical Beta RC
- who should use Easy Trial Build
- what differs
- what remains shared
- what does not differ at the protocol layer

Required outcome:

- no ambiguity about why two variants exist
- no implication of protocol incompatibility

### E. Finish Localization Properly

#### E1. Validate real rendering on Windows

Do not stop at localized strings.

Validate at minimum:

- Japanese rendering
- Simplified Chinese rendering
- line wrapping
- button widths
- heading overflow
- status-card overflow
- settings-panel readability
- mixed-language edge cases where relevant

Required outcome:

- no mojibake
- no obviously broken layouts
- critical controls remain readable in all shipped languages

#### E2. Expand translation coverage

Find any remaining hardcoded English user-facing strings and move them into localization if they belong in primary UX.

Required outcome:

- mainstream UI strings are localization-backed
- any intentional English-only leftovers are limited to advanced diagnostics/support artifacts and are documented

#### E3. Do a translation quality pass

Make sure translations feel natural, not literal or engineer-heavy.

Required outcome:

- Japanese reads naturally for ordinary users
- Simplified Chinese reads naturally for ordinary users
- terminology is consistent across languages

### F. Validate Both Variants Against Their Real Use Cases

#### F1. Add a variant-specific validation matrix

Technical Beta RC validation should cover:

- install
- launch
- backend lifecycle
- restart/recovery
- diagnostics
- retrieval/connectivity behavior

Easy Trial Build validation should cover:

- install
- first-run comprehension
- ability to save
- ability to retrieve
- ability to understand status
- ability to recover from common issues without technical knowledge

Required outcome:

- both variants have written validation criteria
- both variants are tested against their intended use case

#### F2. Add a beginner usability checklist

Create a simple non-technical trial checklist:

1. install the app
2. launch it
3. understand the first screen
4. save one file or text item
5. retrieve it
6. understand whether the app is ready or needs attention

Required outcome:

- Easy Trial Build is evaluated like a consumer-facing app, not just a developer tool

#### F3. Add or update desktop tests where practical

Tests should cover the remaining product-mechanics work where reasonable, including:

- mode persistence
- locale persistence
- precedence behavior
- variant naming/default behavior
- script/package invariants if practical

Required outcome:

- the most failure-prone remaining mechanics are regression-tested

### G. Keep Docs, Packaging, and Claims Honest

#### G1. Align docs with the real implementation

Update, where relevant:

- README
- release notes
- variant-specific package README text
- task docs
- installer text

Required outcome:

- docs do not get ahead of implementation
- release positioning stays honest

#### G2. Keep repo-vs-local doc hygiene deliberate

As these tasks grow, continue deciding intentionally what belongs in:

- repo-tracked `docs/tasks/`
- canonical release docs
- local-only notes

Required outcome:

- repo docs remain curated rather than noisy

## Suggested Execution Order

1. mode persistence
2. locale persistence
3. real end-user variant launch/default mechanism
4. truthful build/package/installer behavior
5. Easy-mode second-pass UX cleanup
6. Technical-mode richness audit
7. real Windows JA / ZH-CN rendering validation
8. variant-specific validation + docs cleanup

## Required Completion Bar

Do not mark the dual-release effort complete unless all of the following are true:

- mode persists across restart
- locale persists across restart
- users do not need env vars to get the intended variant behavior
- Technical and Easy both have a real launcher/package/release story
- script help text and output are truthful
- installer/shortcuts clearly support the intended variants
- Easy mode is genuinely easier, not merely renamed
- Technical mode remains genuinely better for protocol validation
- localization works in practice and has been visually validated
- docs and release positioning match reality
- validation results are reported separately for Technical and Easy

If any of the above remain open, the correct status is:

- strong first pass landed
- remaining work still in progress

## Expected Output From The Next Pass

1. What is newly fully complete
2. What still remains, if anything
3. The concrete code and script changes
4. The validation run for Technical Beta RC
5. The validation run for Easy Trial Build
6. A clear judgment on whether the dual-release Windows story is actually complete
