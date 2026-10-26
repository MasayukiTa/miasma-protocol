//! Which build is running: crate version plus the short commit hash that
//! `build.rs` embeds (`unknown` when the build had no git checkout).

use crate::locale::Locale;

/// The short commit hash this binary was built from.
pub const BUILD_ID: &str = env!("MIASMA_BUILD_ID");

/// `0.3.2 · 1a2b3c4d5`: version and build id.
pub fn version_with_build(version: &str, build_id: &str) -> String {
    format!("{version} \u{b7} {build_id}")
}

/// The product label in the release channel's own words.
pub fn channel_label(locale: Locale) -> &'static str {
    match locale {
        Locale::En => "Beta",
        Locale::Ja => "\u{30d9}\u{30fc}\u{30bf}\u{7248}",
        Locale::ZhCn => "\u{6d4b}\u{8bd5}\u{7248}",
    }
}

/// Window title: `Miasma v0.3.2 (Beta)`. The build id stays out of the
/// title to avoid clashing with the "Technical" display mode; it is shown
/// in Settings (Update and About) via `build_row_value`.
pub fn title_for(version: &str, locale: Locale) -> String {
    format!("Miasma v{} ({})", version, channel_label(locale))
}

/// Title of the running build.
pub fn window_title(locale: Locale) -> String {
    title_for(env!("MIASMA_VERSION"), locale)
}

/// Label of the "Build" row in Settings.
pub fn build_row_label(locale: Locale) -> &'static str {
    match locale {
        Locale::En => "Build:",
        Locale::Ja => "\u{30d3}\u{30eb}\u{30c9}:",
        Locale::ZhCn => "\u{6784}\u{5efa}\u{ff1a}",
    }
}

/// Value of the "Build" row: `0.3.2 · 1a2b3c4d5`.
pub fn build_row_value() -> String {
    version_with_build(env!("MIASMA_VERSION"), BUILD_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_shows_version_and_channel_without_the_build_id() {
        assert_eq!(
            title_for("0.3.2", Locale::En),
            "Miasma v0.3.2 (Beta)"
        );
        // The build id is deliberately kept out of the title.
        assert!(!title_for("0.3.2", Locale::En).contains("1a2b3c4d5"));
        let ja = title_for("0.3.2", Locale::Ja);
        assert!(ja.starts_with("Miasma v0.3.2 ("), "{ja}");
        assert!(ja.ends_with("\u{7248})"), "{ja}");
        // "Technical" must not appear in the channel label (it is a display mode).
        assert!(!title_for("0.3.2", Locale::En).contains("Technical"));
    }

    #[test]
    fn every_locale_has_a_channel_and_build_label() {
        for l in Locale::ALL {
            assert!(!channel_label(l).is_empty());
            assert!(build_row_label(l).ends_with([':', '\u{ff1a}']));
        }
    }

    #[test]
    fn running_build_has_a_nonempty_id_and_the_crate_version() {
        assert!(!BUILD_ID.trim().is_empty());
        assert!(BUILD_ID.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(build_row_value().starts_with(env!("MIASMA_VERSION")));
        // The build id is shown in Settings (the Build row), not in the title.
        assert!(build_row_value().contains(BUILD_ID));
        assert!(!window_title(Locale::En).contains(BUILD_ID));
    }

    // The build id left the window title, so it must still reach the user
    // somewhere. It is carried by `build_row_value`, which has to stay wired
    // into both Settings screens that show the running build: About and
    // Update. If either call is removed, the hash silently disappears from the
    // UI, so pin the wiring here (at the source level, without spinning up the
    // whole egui app).
    #[test]
    fn the_build_row_value_is_shown_on_the_about_and_update_screens() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let about = std::fs::read_to_string(format!("{dir}/src/app.rs"))
            .expect("read app.rs");
        let updates = std::fs::read_to_string(format!("{dir}/src/updates.rs"))
            .expect("read updates.rs");
        assert!(
            about.contains("build_row_value()"),
            "the About screen (app.rs) no longer shows build_row_value, so the \
             build hash is gone from Settings > About"
        );
        assert!(
            about.contains("build_row_label("),
            "the About screen (app.rs) no longer labels the build row"
        );
        assert!(
            updates.contains("build_row_value()"),
            "the Update screen (updates.rs) no longer shows build_row_value, so \
             the build hash is gone from Settings > Update"
        );
    }
}
