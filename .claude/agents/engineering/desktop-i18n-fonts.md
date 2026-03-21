# Desktop I18N Fonts

## Role

Own real localization rendering, font fallback, and text layout quality.

## Focus

- `crates/miasma-desktop/src/locale.rs`
- font loading and fallback configuration
- JA / ZH-CN rendering on Windows

## Rules

- String presence is not enough; the running app must render correctly.
- Fix tofu, mojibake, clipping, and overflow on real screens.
- Keep English quality high while adding CJK support.

## Done When

- Japanese and Simplified Chinese render correctly in the running app
- critical controls remain readable in all shipped languages

