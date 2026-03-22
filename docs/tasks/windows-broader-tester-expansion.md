## Windows Broader Tester Expansion

### Intent

This milestone is the next step after `windows-beta-rc-hardening.md`.
The current Windows beta is acceptable to continue internally and with technically comfortable testers, but it is not yet proven ready for broader tester expansion.

This task is meant to close that gap.

Do not treat this as a polish-only pass.
This is a release-readiness, operational-quality, and real-user-validation pass for Windows.

It is acceptable if this takes several hours.
I prefer one deep pass with real validation over many shallow partial edits.

### Current State

The project now has:

- a materially implemented anonymity/reachability stack
- a Windows desktop GUI with Easy and Technical modes
- hidden-console startup behavior
- persisted mode and locale
- English, Japanese, and Simplified Chinese
- shell integration wiring for `magnet:` and `.torrent`
- diagnostics export and troubleshooting docs
- app icon embedding and packaging groundwork

However, several important areas are still not proven strongly enough for broader tester expansion:

- no separate-machine validation
- no real upgrade-path validation against an older installed version
- no real browser/Explorer validation for `magnet:` and `.torrent`
- no code signing
- SmartScreen experience is still only documented, not fully rehearsed with non-technical expectations
- import flow cancellation and some recovery/edge cases remain weak

### Goal

Make the Windows beta credible for broader tester expansion.

That means:

- installed and portable behavior is trustworthy
- first-run and restart behavior are understandable
- shell integration works in the real Windows environment
- support/recovery flows are good enough for non-developers
- documentation and release language are honest and precise
- remaining risk is clearly bounded

### Scope

This milestone is Windows-only.
Do not spend time on mobile runtime or unrelated protocol expansion here.

### Track A: Separate-Machine Validation

Validate on at least one non-dev Windows environment.

Minimum expectations:

- use a different Windows user profile or a separate PC
- verify both Easy and Technical entry points
- verify first launch without a dev shell nearby
- verify non-English locale selection and persistence
- verify app icon appearance in Start Menu, taskbar, Explorer, and shortcuts

Validation scenarios:

1. Fresh MSI install on a clean-ish machine/profile
2. Fresh portable ZIP extraction and launch
3. Launch Easy mode from shortcut / launcher
4. Launch Technical mode from shortcut / launcher
5. Restart after closing and after backend restart
6. Save Report and inspect output location
7. Switch language and restart
8. Validate visual quality in EN / JA / ZH-CN on a real Windows desktop

Important:
Do not call this done based only on automated tests.
Manual validation evidence is required.

### Track B: Install / Upgrade / Uninstall / Repair

The installer story must be stronger than “it installs on the dev box.”

Implement and validate:

1. Fresh install
- shortcuts created correctly
- icons visible correctly
- correct Easy / Technical launch behavior
- CLI remains accessible without confusing normal users

2. Upgrade behavior
- validate upgrade from the current prior beta package if available
- confirm settings/data survive where intended
- confirm stale files and shortcuts are cleaned up correctly
- confirm shell integration remains correct after upgrade

3. Uninstall behavior
- uninstall removes app files cleanly
- shortcuts removed correctly
- shell integration entries do not remain broken
- data retention behavior is documented honestly

4. Repair / reinstall behavior
- reinstall over a broken or partial install
- ensure launcher scripts, icons, and shortcuts recover cleanly

5. Portable ZIP behavior
- portable package remains coherent and honest
- launcher scripts work without requiring the user to know CLI flags
- README and troubleshooting text match real package contents

### Track C: Real Shell Integration Validation

The current wiring is promising, but broader tester expansion requires real Windows behavior validation.

Implement and validate:

1. `magnet:` flow from a real browser
- click a real `magnet:` link
- verify Windows prompt / app selection behavior
- verify Miasma receives the URI correctly
- verify import UI flow is understandable
- verify failure messaging if bridge is unavailable or import fails

2. `.torrent` flow from Explorer
- double-click or use “Open with”
- verify Miasma appears appropriately
- verify Miasma receives the file path correctly
- verify import flow and result messaging

3. Edge cases
- duplicate imports
- malformed magnet URIs
- missing `.torrent` files
- bridge executable missing
- bridge returns invalid or empty output

4. User-facing behavior
- no scary jargon in Easy mode
- progress and completion are understandable
- retry guidance is specific

5. Import cancellation / interruption
- if full cancellation can be implemented cleanly, do it
- if not, at minimum:
  - document the limitation clearly
  - make in-progress state honest
  - make “close / retry later” behavior understandable

### Track D: First-Run and Recovery Experience

Strengthen the product feel for broader testers.

Implement or improve:

1. First-run clarity
- users should know what to do first
- clarify “ready / starting / offline / no peers yet”
- surface next action when the app is not usable yet

2. Recovery messaging
- backend offline
- startup timeout
- shell import failure
- no peers discovered
- saved report success/failure

3. Support path
- Save Report should be easy to find when needed
- troubleshooting docs should map to the exact wording shown in the app
- non-technical testers should have a simple “what to send us” path

4. Technical mode support value
- do not gut diagnostics
- keep it clearly better for issue triage and protocol validation

### Track E: SmartScreen, Trust, and Packaging Honesty

Code signing may still be unavailable, but the experience around that cannot stay vague.

Do the following:

1. Make SmartScreen handling explicit and humane
- verify current instructions match the real Windows flow
- check wording for non-technical clarity
- ensure README / release notes / package README / troubleshooting all agree

2. Code signing preparation
- if a real certificate is not available, prepare the repo and docs so signing can be slotted in cleanly
- identify exactly what changes when signing is introduced
- keep release steps ready for that future path

3. Packaging identity
- ensure app naming, shortcut naming, README naming, and release artifact naming all align
- avoid confusing “technical” language on normal-user surfaces

### Track F: Runtime and Operational Robustness

Push Windows runtime behavior further before broadening testers.

Focus on:

1. Daemon lifecycle robustness
- repeated start/stop
- already-running detection
- crashed-backend recovery
- stale port cleanup

2. Logging and diagnostics
- log file location is understandable
- diagnostics report contains enough support detail
- no obviously missing data when backend is down

3. Antivirus / path / missing-binary tolerance
- if binaries are missing or blocked, error messages must be specific
- avoid generic “failed to start” dead ends

4. Portable vs installed consistency
- key actions should behave similarly enough that support does not become chaotic

### Track G: Documentation and Release Positioning

Docs must stay honest and operationally useful.

Update as needed:

- `RELEASE-NOTES.md`
- `docs/variant-guide.md`
- `docs/TROUBLESHOOTING.md`
- package README text
- any installer/release checklist docs

Ensure docs clearly distinguish:

- what is validated only on the dev box
- what has now been validated on a separate machine
- what remains unverified
- what broader testers should and should not expect

### Track H: Final Validation Package

At the end of this milestone, provide a clean validation report with these sections:

1. Automated validation
- exact commands run
- results

2. Manual Windows validation
- machine/profile used
- scenarios tested
- pass/fail and notes

3. Installer/package validation
- fresh install
- portable ZIP
- upgrade
- uninstall

4. Shell integration validation
- browser `magnet:` test
- Explorer `.torrent` test

5. Remaining limitations
- only real remaining limits, not hand-wavy future ideas

### Completion Bar

Do not mark this milestone complete unless all of the following are true:

1. A separate-machine or separate-profile manual validation pass has been completed and documented
2. Fresh install, portable ZIP, and at least one real upgrade/uninstall path have been validated
3. `magnet:` opening has been tested from a real browser
4. `.torrent` opening has been tested from Explorer / Open With
5. Support and troubleshooting flows are coherent for non-technical testers
6. Documentation matches the actual validated state
7. Release readiness is judged explicitly as one of:
- still internal only
- acceptable for broader tester expansion with caveats
- blocked by specific remaining issues

### Important Execution Rule

Do not stop at code wiring or “should work” reasoning.
This milestone requires real Windows behavior validation.

If something cannot be completed in one pass:

- say exactly what blocked it
- say exactly what evidence is still missing
- say exactly what smallest next step remains

Do not present unvalidated installer, shell, or cross-machine behavior as complete.

### Expected Output

1. What was implemented
2. What was validated automatically
3. What was validated manually on Windows
4. What still remains unverified
5. A clear recommendation on whether the beta is ready for broader tester expansion
