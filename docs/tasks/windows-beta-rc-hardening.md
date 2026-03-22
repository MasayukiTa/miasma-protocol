# Windows Beta RC Hardening

## Purpose

The desktop UI and localization are now in much better shape.
The next milestone is not another design pass.
The next milestone is to make the Windows beta behave like a serious release candidate in real use.

This task should push the Windows build toward something that can be installed, launched, recovered, validated, and supported with much less friction.

It is acceptable if this takes several hours.
I prefer a smaller number of fully closed Windows beta gaps over broad partial progress.

## Scope

This is a Windows-focused release-candidate hardening pass.

It should cover as much of the following as practical:

- installer and upgrade reliability
- installed vs portable behavior consistency
- Windows shell integration
- app icon and identity quality
- daemon lifecycle and recovery quality
- support and diagnostics flows
- real-world validation on multiple machines or networks where feasible
- Windows release ergonomics
- honest release-readiness documentation

Do not spend this milestone on mobile runtime work.
Do not reopen deep protocol redesign unless it is necessary for Windows beta quality.

## Current Honest State

What is already materially improved:

- Easy and Technical variants exist from one binary
- mode and locale persist
- launcher and shortcut stories are much clearer
- hidden console behavior is fixed
- desktop UI and localization are in a much better place

What is still likely weak or under-validated:

- installed, upgraded, and uninstalled behavior under real Windows conditions
- shell integration for `magnet:` links and `.torrent` files
- lack of a proper icon or visual identity in installed Windows surfaces
- startup and recovery behavior outside ideal local dev conditions
- diagnostics and support workflows for ordinary testers
- confidence from separate-PC and separate-network validation
- final release-candidate gating and known-issues discipline
- release ergonomics such as code-signing preparation, crash/support handling, and packaging clarity

## Top-Level Goal

Make the current Windows beta good enough to function like a real release candidate for broader technical testing and selected non-technical trials.

That means:

- fewer surprises during install, launch, and everyday use
- clearer recovery when something goes wrong
- better supportability
- better validation evidence
- more honest and actionable release docs

## Non-Negotiable Rules

1. Do not overclaim.
If something is only locally tested or only manually tested, say so clearly.

2. Prefer real installed-behavior fixes over more cosmetic UI work.

3. Do not let Easy-mode polish break Technical-mode usefulness.

4. If a Windows problem can only be mitigated, document the mitigation honestly.

5. End this milestone with a clear release judgment, not just a changelog.

## Required Work

### A. Installer, Upgrade, and Uninstall Quality

#### A1. Re-validate MSI install behavior end to end

Check and improve where needed:

- fresh install
- Start Menu entries
- launch after install
- PATH behavior for CLI shortcut
- install location assumptions
- docs packaged with the app

Required outcome:

- a fresh install behaves as documented
- both Easy and Technical launch paths are discoverable

#### A2. Validate upgrade behavior

Test and harden:

- installing over an older version
- preserving data directory
- preserving `desktop-prefs.toml`
- preserving launcher and shortcut behavior
- avoiding broken shortcut or PATH state after upgrade

Required outcome:

- upgrade works without confusing mode or locale resets or broken launchers

#### A3. Validate uninstall behavior

Check:

- shortcuts removed cleanly
- binaries removed cleanly
- data-preservation behavior matches docs
- no confusing residue in obvious install locations

Required outcome:

- uninstall behavior is predictable and documented

### B. Windows Shell Integration and App Identity

#### B1. Add a real app icon across Windows surfaces

The installed app should no longer look like an icon-less unknown utility.

Implement a coherent icon story for at least:

- `miasma-desktop.exe`
- Start Menu shortcuts
- installer-facing surfaces where practical
- file and protocol associations added in this milestone

The icon does not need to be perfect final branding, but it must look intentional and non-suspicious.

Required outcome:

- installed Miasma no longer looks icon-less or generic
- launcher and shortcut surfaces show a coherent app identity

#### B2. Add `magnet:` protocol handling

Make it possible for Windows users to choose Miasma as a handler for `magnet:` links.

This should include:

- installer registration for the `magnet:` protocol
- a clear open-command path into Miasma
- desktop-side argument handling for incoming magnet URIs
- an in-app flow for what happens after Miasma is launched this way

Do not stop at registry wiring only.
The app must do something coherent once it receives the magnet URI.

Required outcome:

- a tester can choose Miasma for `magnet:` links
- launching from a magnet link lands in a sensible Miasma flow

#### B3. Add `.torrent` open support, but keep association behavior careful

Make `.torrent` files openable with Miasma, but do not aggressively hijack existing torrent workflows by default.

Preferred behavior:

- `.torrent` file opening is supported
- default-association behavior is opt-in or clearly intentional
- users are not surprised if they already use another torrent client

This should include:

- desktop argument handling for `.torrent` file paths
- a clear import or dissolve flow after opening a torrent file
- installer and package behavior that is explicit and user-respectful

Required outcome:

- `.torrent` files can be opened with Miasma
- association behavior is intentional and not overly aggressive

#### B4. Define the actual import flow for magnets and torrent files

Do not leave shell integration as raw parameter parsing only.

When Miasma is launched with a `magnet:` URI or `.torrent` file, define:

- where the user lands
- what confirmation or safety step appears
- how bridge or dissolve behavior is explained
- how cancellation works
- whether Easy and Technical differ in presentation

Required outcome:

- shell integration feels like a product feature, not a debug hook

### C. Daemon Lifecycle and Recovery Hardening

#### C1. Recheck desktop-to-daemon lifecycle end to end

Audit and harden:

- first launch
- daemon already running
- stale port file
- daemon crash while desktop is open
- daemon restart behavior
- desktop restart after daemon failure

Required outcome:

- common lifecycle failures are handled or clearly surfaced

#### C2. Improve recovery messaging

When the app cannot start, reconnect, or reach the backend, the user should see:

- what failed
- what the app already tried
- what to do next

Do this without dumping raw internal jargon on Easy-mode users.

Required outcome:

- recovery states are clearer and less brittle

#### C3. Revisit startup timing and retry policy

Review:

- startup timeout
- auto-relaunch attempt count
- detection of stale versus healthy running daemon
- behavior under slower machines or antivirus drag

Required outcome:

- startup and recovery policy feel deliberate rather than accidental

### D. Installed vs Portable Consistency

#### D1. Compare installed and ZIP flows directly

Make sure the following are still coherent across both:

- variant launch behavior
- prefs persistence
- shell integration behavior if implemented
- documentation quality
- support and export behavior
- file layout assumptions

Required outcome:

- installed and portable stories are both usable and clearly documented

#### D2. Remove avoidable divergence

If the installed and ZIP experiences differ for no good reason, reduce that divergence where practical.

Required outcome:

- fewer surprising differences between install modes

### E. Diagnostics, Support, and Field Debuggability

#### E1. Improve diagnostics export usefulness

Review and improve:

- what gets exported
- how it is named
- where it lands
- whether an ordinary tester can find and share it
- whether it contains enough signal for support

Required outcome:

- support export is easier to use and still useful to developers

#### E2. Add or improve troubleshooting guidance

Create or tighten practical guidance for:

- app does not start
- backend does not connect
- no peers found
- save or retrieve confusion
- language or mode confusion
- install or upgrade confusion
- shell integration confusion if magnets or torrents are added

Required outcome:

- common tester problems have a documented path forward

#### E3. Improve support-ready status visibility

Make it easier to answer:

- is the app running?
- is the backend reachable?
- is the node connected?
- is this just "no peers yet" versus "broken"?

Required outcome:

- users and testers can distinguish basic health states more easily

### F. Real-World Validation

#### F1. Validate on at least one non-dev machine or non-dev environment where practical

Prefer evidence from:

- separate PC
- different Windows user profile
- installed MSI rather than only local debug run
- different network condition if available

Required outcome:

- confidence is not based only on one dev box

#### F2. Validate across key scenarios

At minimum try to cover:

- first install and first launch
- Easy mode basic flow
- Technical mode diagnostics visibility
- magnet-link handling if implemented
- `.torrent` open flow if implemented
- save and retrieve
- restart after close
- recovery after daemon interruption

Required outcome:

- the release candidate has scenario-based validation evidence

#### F3. Run longer-lived stability where practical

If feasible in this pass, run or improve:

- smoke-installed
- smoke-windows
- soak behavior
- reconnect behavior after idle time

Required outcome:

- at least some evidence beyond instant local success

### G. Windows Release Ergonomics

#### G1. Prepare for code signing even if the cert is not available yet

If real signing cannot be completed in this pass, at least tighten:

- script flow for signing
- where signed artifacts would slot in
- docs around unsigned prerelease limitations

Required outcome:

- code-signing remains an explicit next step, not vague future work

#### G2. Review packaging clarity

Check:

- artifact naming
- package README wording
- variant guide wording
- icon clarity
- which file an ordinary user should open first

Required outcome:

- release artifacts are easier to understand at a glance

#### G3. Review supportability of distributed builds

Think about:

- what a tester needs to report an issue
- how they identify the build or version
- how they attach useful diagnostics

Required outcome:

- distributed beta testing is easier to manage

### H. Docs and Release Readiness

#### H1. Tighten the variant guide and release docs

Update as needed:

- `docs/variant-guide.md`
- `readme.md`
- `RELEASE-NOTES.md`
- packaged README text
- validation logs or troubleshooting notes

Required outcome:

- docs match what the Windows build really does now

#### H2. Produce a clear release judgment

End the task with a specific call:

- acceptable for current beta continuation
- acceptable for broader tester expansion
- needs another hardening pass first

Do not stop at "lots was improved."

Required outcome:

- there is an explicit release recommendation with reasons

## Validation Expectations

Run the strongest practical validation you can in this pass, including:

- `cargo test -p miasma-desktop`
- `cargo test --workspace`
- installer validation where feasible
- installed and portable launch checks
- icon and shell-integration checks if implemented
- manual Windows scenario checks
- support-export checks

If something cannot be validated in this environment, say exactly what remains unverified.

## Completion Bar

Do not mark this task complete unless all of the following are true:

- fresh install behavior is verified
- upgrade behavior is verified or its remaining gap is explicitly documented
- uninstall behavior is verified or its remaining gap is explicitly documented
- icon behavior is verified across installed Windows surfaces if touched
- `magnet:` handling is verified if implemented
- `.torrent` handling is verified if implemented
- daemon lifecycle and recovery behavior were re-checked in real use
- diagnostics and support flow is materially better or at least clearly validated
- installed and portable variant behavior is clearly understood
- release docs match actual Windows behavior
- a clear release judgment is given

If several of the above remain open, the correct status is:

- Windows beta RC hardening in progress

## Expected Output

1. What was improved in installer and packaging behavior
2. What was improved in shell integration and icon behavior
3. What was improved in runtime and recovery behavior
4. What was improved in diagnostics and supportability
5. What real-world validation was run
6. What docs were updated
7. What still remains, if anything
8. A direct recommendation on Windows beta release readiness
