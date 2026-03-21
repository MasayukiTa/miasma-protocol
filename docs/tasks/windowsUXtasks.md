# Windows Desktop UX + Localization Overhaul

## Purpose

This task exists because the current Windows desktop app is still not good enough for ordinary users.

The hidden-console work is a good improvement, but the current desktop experience still has two major problems:

1. Japanese and Chinese UI rendering is visibly broken in practice.
2. The app still looks and feels like a rough developer tool rather than a real desktop product.

This next pass should focus on fixing those problems properly.

Do not treat string-table presence as localization completion.
Do not treat "the console no longer pops up" as UX completion.

It is acceptable if this takes several hours.
I want a real end-to-end desktop-product pass, not another shallow first pass.

## Current Honest State

What is already good enough to keep:

- no visible terminal/console during normal desktop launch
- Technical vs Easy mode split exists
- mode persistence exists
- locale persistence exists
- launcher/shortcut foundation exists
- desktop tests exist

What is still not good enough:

- Japanese and Chinese are visibly rendering as tofu/mojibake boxes in the real running app
- current font handling is not acceptable for shipped non-English UI
- the current UI has weak visual hierarchy and weak typography
- the current UI still looks like a generic engineering panel
- Easy mode still does not feel polished enough for a non-technical trial user
- the desktop app does not yet communicate a clear design direction

## Goal

Make the Windows desktop app feel like a real product for both:

1. Technical Beta RC users
2. Easy Trial Build users

without forking the codebase or weakening the backend/protocol work.

This milestone is specifically about:

- fixing localization rendering in practice
- giving the desktop app an intentional, mainstream visual design
- making Easy mode genuinely usable by a non-technical person
- keeping Technical mode useful while making it visually coherent

## Non-Negotiable Rules

1. Do not stop at "fonts exist in code".
The shipped app must actually render Japanese and Chinese correctly in a running Windows build.

2. Do not ship another UI pass that is only wording cleanup.
This pass must improve visual design, hierarchy, spacing, typography, and overall feel.

3. Do not flatten Technical mode into a toy UI.
Technical mode must remain useful for protocol validation and diagnostics.

4. Do not overclaim completion without screenshot-level validation.
If the running app still has broken text or obviously weak layout, the work is not complete.

5. Do not reopen unrelated protocol work unless strictly necessary for the desktop experience.
This is a desktop product-quality and localization pass.

## Required Work

### A. Fix Real Localization Rendering

#### A1. Eliminate tofu / mojibake in JA and ZH-CN

The app must render Japanese and Simplified Chinese correctly in the actual Windows app.

Do not rely on hope or default font behavior if it is already failing.
Use a real font strategy, for example:

- bundled CJK-capable fonts with proper licensing
- explicit egui font definitions and fallback families
- Windows-aware font loading if that is more reliable

Whichever approach you choose, it must actually solve the problem in the running app.

Requirements:

- no tofu boxes in ordinary UI
- no mojibake in buttons, headings, body text, or settings
- English still looks good
- Technical and Easy mode both render correctly

#### A2. Make the font stack intentional

Do not just make the text "appear".
Define a real font system:

- primary UI font(s)
- fallback font(s)
- monospace/diagnostics font strategy
- size hierarchy
- weight hierarchy if supported

Requirements:

- text looks coherent across EN / JA / ZH-CN
- diagnostics remain readable
- mixed Latin + CJK text does not look broken

#### A3. Handle text layout and wrapping properly

After fixing fonts, make sure layout still works:

- headings
- buttons
- status cards
- settings labels
- path display
- alert/warning text
- welcome/setup text

Requirements:

- translated text does not overflow obviously
- buttons are sized for translated text
- line wrapping feels intentional rather than broken

### B. Redesign The Desktop App Visually

#### B1. Establish a real design direction

The app needs an intentional visual language.

Do not leave it as the current default-ish egui look with minimal styling.
Choose a clear product direction and carry it through:

- typography
- spacing
- panel structure
- colors
- cards
- buttons
- status indicators
- empty states

Requirements:

- the app looks like a designed product
- the design feels coherent rather than pieced together
- it does not look like a debug utility by default

#### B2. Improve global hierarchy and layout

The app should visually communicate what matters first.

Easy mode should prioritize:

- whether the app is ready
- what the user can do next
- how to save something
- how to get something back
- whether anything needs attention

Technical mode should prioritize:

- the same core clarity
- plus meaningful diagnostics and protocol detail

Requirements:

- the first screen is easier to scan
- the main action is visually obvious
- status and next steps are easier to understand

#### B3. Improve component quality

Upgrade the quality of:

- top navigation / tab bar
- welcome/setup panel
- stopped/starting/running states
- status cards
- buttons
- form inputs
- alerts
- settings sections
- footer / metadata area

Requirements:

- controls feel consistent
- spacing is deliberate
- cards and sections are easier to parse
- visual noise is reduced

### C. Make Easy Mode Genuinely Mainstream

#### C1. Rework Easy mode information architecture

Easy mode should not feel like Technical mode with softer words.

Reorganize Easy mode around:

- one obvious primary action
- plain-language state
- clear next step
- simple recovery messaging

Requirements:

- a non-technical user can tell what to do next
- the screen does not feel intimidating
- the app feels approachable at first launch

#### C2. Polish the copy again with product voice

Do another pass over Easy-mode text.

Focus on:

- warmth
- clarity
- plain language
- lower anxiety
- shorter labels where appropriate

Avoid:

- backend jargon
- protocol framing
- infrastructure-heavy explanations in primary surfaces

Requirements:

- Easy mode reads like a consumer-facing app
- common states and actions are self-explanatory

#### C3. Improve common state flows

Polish:

- first setup
- not yet ready
- background service starting
- save success
- get-back success
- recoverable failure
- next action after failure

Requirements:

- state transitions feel guided
- common problems are less confusing

### D. Keep Technical Mode Strong While Making It Look Better

#### D1. Redesign Technical mode without removing useful detail

Technical mode should still expose:

- transport details
- peer/routing visibility
- diagnostics
- replication/storage detail
- support/export value

But it should do so in a better layout and with better grouping.

Requirements:

- Technical mode remains clearly better for dev/test work
- diagnostic surfaces are easier to scan, not weaker

#### D2. Separate primary and secondary detail better

Even in Technical mode, not every detail should fight for attention equally.

Requirements:

- health/status summary is still easy to spot
- deep detail is grouped cleanly
- the screen feels like a professional tool, not clutter

### E. Variant-Specific Product Polish

#### E1. Make Easy and Technical look intentionally related but distinct

They should feel like two faces of the same app:

- same brand/system
- different density and tone

Requirements:

- Easy does not feel childish
- Technical does not feel neglected
- both feel like one product family

#### E2. Revisit titles, package copy, and launcher wording if needed

If visual/product polish changes the tone, update:

- launcher text
- package README text
- variant guide wording
- window-title wording if needed

Requirements:

- release-facing language matches the improved product feel

### F. Validation Must Be Real, Not Assumed

#### F1. Run desktop automated validation

Keep or add the strongest practical automated checks for:

- locale completeness
- mode persistence
- locale persistence
- launcher / variant invariants where practical
- any new UI/state logic with meaningful unit coverage

Requirements:

- no regression in desktop tests

#### F2. Perform real Windows visual validation

This is mandatory for this task.

Launch the app on Windows and verify at minimum:

- Easy mode in English
- Easy mode in Japanese
- Easy mode in Simplified Chinese
- Technical mode in English
- at least one non-English Technical-mode screen

Capture or summarize concrete visual validation results.
If screenshots are possible in your environment, take them.
If not, still perform the manual run and report exactly what was checked.

Requirements:

- no broken CJK rendering remains
- no obvious clipping/overflow remains on key screens
- results are reported explicitly, not assumed

#### F3. Do a non-technical-user sanity check

Evaluate the Easy build as if it is for a family member with no IT background.

At minimum check:

1. launch the app
2. understand the first screen
3. complete setup
4. save something
5. get it back
6. understand when the app is ready
7. understand what to do if it is not ready

Requirements:

- Easy mode passes a basic non-technical-user sanity check

## Documentation Work

Update any docs that become stale because of this pass, especially:

- `docs/variant-guide.md`
- release-facing README/package text if visuals or wording materially change
- task docs if the remaining gaps become narrower afterward

Do not claim localization is complete unless real rendering has been visually verified.

## Completion Bar

Do not mark this task complete unless all of the following are true:

- Japanese renders correctly in the running Windows app
- Simplified Chinese renders correctly in the running Windows app
- no obvious tofu/mojibake remains in primary surfaces
- the app has a clear and coherent visual design direction
- Easy mode feels materially more polished and approachable
- Technical mode still retains useful diagnostic depth
- translated text fits key controls and layouts
- automated desktop tests still pass
- manual Windows visual validation was actually performed and reported
- docs match the new reality

If any of the above are still open, the correct status is:

- desktop UI/localization overhaul in progress

## Execution Standard

Do not stop at:

- string-table edits only
- theme color tweaks only
- mockup-like code that still looks broken in the running app
- "manual validation needed" without actually doing it if you can run the app

This task is successful only if the running Windows desktop app looks and behaves significantly better.

## Expected Output

1. What changed in the font/rendering system
2. What changed in the visual design and layout
3. What changed in Easy mode UX
4. What changed in Technical mode organization
5. What automated tests were run
6. What real Windows visual validation was performed
7. What still remains, if anything
