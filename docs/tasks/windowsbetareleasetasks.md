# Windows Beta Overnight Overdrive

## Purpose

This is an all-in Windows milestone for an overnight push.

The goal is not to make one narrow improvement.
The goal is to push the Windows beta forward across as many remaining important areas as possible in one serious pass.

This is intentionally broad and heavy.
It is acceptable if this takes several hours.
I expect deep implementation work, not shallow cleanup.

## Scope

This task covers the remaining Windows-side work as broadly as practical, including:

- desktop UX and visual design
- localization rendering and translation quality
- Easy vs Technical variant quality
- launcher / packaging / installer honesty
- background-service lifecycle quality
- diagnostics / supportability
- release-facing documentation
- practical Windows validation

This task does **not** require mobile runtime work.
Keep the focus on Windows beta quality and usability.

## Current Honest State

What is already materially landed:

- no visible terminal/console during normal desktop launch
- runtime Technical / Easy variant split exists
- mode persistence exists
- locale persistence exists
- launcher / shortcut foundation exists
- localized string tables exist for EN / JA / ZH-CN
- desktop-specific automated tests exist
- packaging scripts are more honest than before

What is still clearly not good enough:

- Japanese and Chinese rendering is visibly broken in the real app
- the desktop UI still looks underdesigned and too developer-ish
- Easy mode is still not polished enough for a non-technical user
- some Windows productization details still need work
- real installed / portable / validation flows need tightening
- docs and release positioning may still lag behind implementation changes

## Top-Level Goal

Push the Windows project as far as reasonably possible toward two credible outputs from one codebase:

1. Technical Beta RC
2. Easy Trial Build

These remain one product family with one backend and one protocol stack.
The work should improve both variants without forking the codebase.

## Non-Negotiable Rules

1. Do not overclaim.
If something is only partly finished, say so clearly.

2. Do not stop at wording cleanup.
This pass must materially improve the running app.

3. Do not stop at string tables.
Localization is not complete unless the running Windows app renders correctly.

4. Do not sacrifice Technical mode usefulness to make Easy mode simpler.

5. Do not let build/package/install scripts pretend to do more than they really do.

6. Prefer working end to end.
If you touch a subsystem in this milestone, try to carry it through code, validation, and docs.

7. If something truly cannot be finished in one pass, state exactly:
- what is blocked
- what is already improved
- what concrete minimum remains

## Priority Order

1. Real CJK rendering fix
2. Visual/UI redesign
3. Easy-mode mainstream usability
4. Installer / launcher / packaging polish
5. Background-service and runtime quality
6. Validation and supportability
7. Docs / release truthfulness

## Track A: Localization Rendering Must Actually Work

### A1. Fix Japanese and Simplified Chinese rendering in the running Windows app

The current broken-box / mojibake state is unacceptable.

Implement a real font/rendering strategy, for example:

- bundled CJK-capable fonts
- explicit egui font families and fallback configuration
- Windows-aware font loading
- a combination of the above

Do not rely on hope or default behavior if it is already failing.

Required outcome:

- no tofu boxes in core UI screens
- no mojibake in primary controls
- English still looks coherent
- Easy and Technical both render correctly

### A2. Build an intentional font system

Define:

- primary UI font
- CJK fallback font
- monospace / diagnostics font
- size hierarchy
- heading/body/button style rules

Required outcome:

- typography feels consistent
- mixed Latin + CJK text remains readable
- diagnostics still look usable

### A3. Fix translated layout problems

After rendering is fixed, audit and repair:

- button widths
- tab labels
- section headings
- status cards
- settings panels
- path rows
- welcome/setup copy
- error and warning banners

Required outcome:

- no obvious clipping or overflow on key screens
- translated layouts remain readable and intentional

## Track B: Redesign The Desktop App So It Looks Like A Product

### B1. Establish a clear visual direction

The app currently lacks an intentional design language.

Introduce a coherent visual system for:

- layout spacing
- cards / panels
- button styles
- accent colors
- status colors
- headings / section structure
- visual density

Do not settle for default-looking egui with minor tweaks.

Required outcome:

- the app looks designed
- the app no longer feels like a rough internal tool

### B2. Improve information hierarchy

Easy mode should clearly foreground:

- whether the app is ready
- what to do next
- how to save content
- how to get content back
- whether anything needs attention

Technical mode should foreground:

- the same core clarity
- plus useful detailed diagnostics

Required outcome:

- the first screen is easier to scan
- the primary action is obvious
- the current state is easier to understand

### B3. Upgrade component quality across the app

Improve:

- top navigation
- welcome/setup panel
- stopped / starting / connected states
- status cards
- action buttons
- text fields
- notifications and alerts
- settings sections
- footer / build/status metadata

Required outcome:

- components feel coherent
- spacing and grouping feel deliberate
- visual noise is lower

## Track C: Make Easy Mode Actually Work For A Non-Technical User

### C1. Rework Easy mode around plain-language actions

Easy mode must feel like a mainstream app, not a softened dev tool.

Prioritize:

- one clear main action
- plain-language state
- low-anxiety wording
- clear next step
- simple recovery guidance

Required outcome:

- a non-technical user can understand what the app wants from them
- the screen does not feel intimidating

### C2. Do another terminology and copy pass

Audit Easy-mode primary surfaces and keep engineering leakage out wherever possible.

Pay special attention to:

- onboarding
- startup states
- save/retrieve confirmations
- warning/error messages
- settings labels
- support/help copy

Required outcome:

- Easy mode reads like a consumer-facing product
- backend/protocol jargon is pushed into secondary or technical surfaces

### C3. Improve first-run and common failure recovery

Polish:

- setup progress
- not-ready-yet state
- service restart language
- save success
- get-back success
- likely user mistakes
- practical next-step hints

Required outcome:

- first-run is less confusing
- common problems are easier to recover from

## Track D: Keep Technical Mode Strong, But Better Organized

### D1. Retain diagnostic richness

Technical mode must remain valuable for:

- protocol testing
- support
- diagnostics export
- routing/transport inspection
- node-health inspection

Required outcome:

- Technical mode still exposes useful system state
- useful information has not been removed just to simplify the UI

### D2. Organize Technical mode better

Improve grouping and scanability of:

- health summary
- transport details
- identity/listening info
- storage/replication info
- diagnostics export actions

Required outcome:

- Technical mode feels like a professional tool
- it is easier to scan than before

## Track E: Finish Variant Packaging And Installer Quality

### E1. Make Easy and Technical launches feel intentional

Recheck:

- MSI Start Menu shortcuts
- launcher scripts
- package README text
- variant naming
- default launch behavior

Required outcome:

- a user can tell what each launch option is for
- the launch path matches the variant story honestly

### E2. Polish installer / installed experience

Audit:

- shortcut names
- shortcut descriptions
- install location expectations
- upgrade behavior
- uninstall behavior
- whether both variants remain easy to find after install

Required outcome:

- installed behavior feels deliberate
- installed launch paths remain understandable

### E3. Polish portable ZIP experience

Audit:

- launcher discoverability
- README clarity
- folder expectations
- what a non-technical user sees first

Required outcome:

- portable trial usage is also understandable

## Track F: Improve Windows Runtime Quality

### F1. Recheck background-service lifecycle quality

Audit and improve where practical:

- startup timeout behavior
- daemon crash recovery
- stale state cleanup
- already-running daemon handling
- restart after failure

Required outcome:

- background-service behavior remains quiet but reliable
- common lifecycle problems are better handled or better explained

### F2. Improve support and diagnostics usability

Keep diagnostics strong, but make support flows easier.

Consider:

- clearer diagnostics export wording
- better support bundle explanation
- more helpful failure summaries
- more obvious “what should I do now?” messaging

Required outcome:

- diagnostics are still useful to developers
- support actions are easier for ordinary testers to use

### F3. Check Windows-specific rough edges

Where practical, review:

- firewall friendliness
- proxy messaging
- AV-sensitive behavior
- path handling
- stale temp/artifact behavior

If you cannot fully fix these, at least improve messaging and notes where needed.

## Track G: Validate Like A Real Windows Product

### G1. Keep automated checks green

Run the strongest practical targeted validation for desktop changes, including:

- desktop unit tests
- any touched packaging/runtime tests
- the broader suite if practical

Required outcome:

- desktop/UI changes do not silently regress prior work

### G2. Perform real Windows visual validation

This is mandatory.

Actually run the app on Windows and validate at minimum:

- Easy EN
- Easy JA
- Easy ZH-CN
- Technical EN
- at least one non-English Technical screen

Validate:

- no tofu/mojibake
- no obvious clipping
- no obviously broken layout
- app looks materially better than before

If screenshots are possible, take them.
If not, provide concrete manual validation notes.

### G3. Do a basic non-technical-user sanity pass

Evaluate Easy mode as if it is for a family member with no IT background.

At minimum check:

1. launch the app
2. understand the opening screen
3. complete setup
4. save something
5. get it back
6. understand ready/not-ready state
7. understand what to do when something goes wrong

Required outcome:

- Easy mode passes a basic sanity check for a non-technical person

## Track H: Keep Documentation Honest And Useful

Update anything that becomes stale because of this pass, especially:

- `docs/variant-guide.md`
- package README text
- release-facing README text if needed
- task docs if remaining scope changes

The docs must match reality, especially about:

- variant differences
- current Windows strengths
- known limitations
- what is still rough

## Stretch Goals If Time Allows

Only do these after the core problems above are materially improved:

- better screenshots / visuals for release notes
- small onboarding illustrations or clearer empty states
- light polish to package/readme branding
- stronger validation notes for support/testing

## Completion Bar

Do not mark this overnight task complete unless all of the following are true:

- Japanese renders correctly in the real Windows app
- Simplified Chinese renders correctly in the real Windows app
- the running app no longer obviously looks like an underdesigned dev tool
- Easy mode is materially more approachable for non-technical users
- Technical mode still retains useful diagnostic depth
- launcher / installer / package behavior still matches the variant story
- automated desktop tests pass
- real Windows visual validation was actually performed and reported
- docs were updated to match the new reality

If some of the above still remain open by the end of the overnight pass, report that honestly.

## Expected Output

1. What was improved in localization rendering
2. What was improved in visual design
3. What changed in Easy mode
4. What changed in Technical mode
5. What changed in packaging / installer / launcher behavior
6. What tests were run
7. What real Windows visual validation was performed
8. What still remains, if anything
