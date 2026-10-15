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
        Locale::En => "Technical Beta",
        Locale::Ja => "\u{30c6}\u{30af}\u{30cb}\u{30ab}\u{30eb}\u{30d9}\u{30fc}\u{30bf}\u{7248}",
        Locale::ZhCn => "\u{6280}\u{672f}\u{6d4b}\u{8bd5}\u{7248}",
    }
}

/// Window title: `Miasma v0.3.2 · 1a2b3c4d5 (Technical Beta)`.
pub fn title_for(version: &str, build_id: &str, locale: Locale) -> String {
    format!(
        "Miasma v{} ({})",
        version_with_build(version, build_id),
        channel_label(locale)
    )
}

/// Title of the running build.
pub fn window_title(locale: Locale) -> String {
    title_for(env!("CARGO_PKG_VERSION"), BUILD_ID, locale)
}

/// Label of the "Build" row in Settings.
pub fn build_row_label(locale: Locale) -> &'static str {
    match locale {
        Locale::En => "Build:",
        Locale::Ja => "\u{30d3}\u{30eb}\u{30c9}:",
        Locale::ZhCn => "\u{6784}\u{5efa}:",
    }
}

/// Value of the "Build" row: `0.3.2 · 1a2b3c4d5`.
pub fn build_row_value() -> String {
    version_with_build(env!("CARGO_PKG_VERSION"), BUILD_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_shows_version_hash_and_channel() {
        assert_eq!(
            title_for("0.3.2", "1a2b3c4d5", Locale::En),
            "Miasma v0.3.2 \u{b7} 1a2b3c4d5 (Technical Beta)"
        );
        let ja = title_for("0.3.2", "unknown", Locale::Ja);
        assert!(ja.starts_with("Miasma v0.3.2 \u{b7} unknown ("), "{ja}");
        assert!(ja.ends_with("\u{7248})"), "{ja}");
    }

    #[test]
    fn every_locale_has_a_channel_and_build_label() {
        for l in Locale::ALL {
            assert!(!channel_label(l).is_empty());
            assert!(build_row_label(l).ends_with(':'));
        }
    }

    #[test]
    fn running_build_has_a_nonempty_id_and_the_crate_version() {
        assert!(!BUILD_ID.trim().is_empty());
        assert!(BUILD_ID.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(build_row_value().starts_with(env!("CARGO_PKG_VERSION")));
        assert!(window_title(Locale::En).contains(BUILD_ID));
    }
}
