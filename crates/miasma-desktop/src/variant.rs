/// Product mode — controls UI density and terminology.
///
/// Both modes share the same backend, protocol, storage, and daemon.
/// The only differences are presentation, defaults, and information density.
///
/// ## Precedence (highest to lowest)
///
/// 1. Explicit launch argument (`--mode easy` or `--mode technical`)
/// 2. `MIASMA_MODE` environment variable (developer/testing override only)
/// 3. Persisted user preference in `desktop-prefs.toml`
/// 4. Built-in default: `Easy`
use std::path::{Path, PathBuf};

use crate::locale::Locale;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProductMode {
    /// Full diagnostics, transport details, protocol terminology.
    Technical,
    /// Simplified language, hidden internals, product-like UX.
    Easy,
}

impl Default for ProductMode {
    fn default() -> Self {
        Self::Easy
    }
}

impl ProductMode {
    pub fn is_easy(self) -> bool {
        self == Self::Easy
    }

    pub fn is_technical(self) -> bool {
        self == Self::Technical
    }
}

// ─── Persisted desktop preferences ──────────────────────────────────────────

const PREFS_FILE: &str = "desktop-prefs.toml";

/// Persisted desktop preferences (mode + locale).
///
/// Stored as `desktop-prefs.toml` in the data directory.
/// Survives restart, upgrade, and reinstall (data dir is preserved).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct DesktopPrefs {
    pub mode: ProductMode,
    pub locale: Locale,
}

impl Default for DesktopPrefs {
    fn default() -> Self {
        Self {
            mode: ProductMode::default(),
            locale: Locale::default(),
        }
    }
}

impl DesktopPrefs {
    /// Load from data directory. Returns defaults if file is missing or corrupt.
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(PREFS_FILE);
        match std::fs::read_to_string(&path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save to data directory. Errors are logged but not fatal.
    pub fn save(&self, data_dir: &Path) {
        let path = data_dir.join(PREFS_FILE);
        match toml::to_string_pretty(self) {
            Ok(contents) => {
                if let Err(e) = std::fs::write(&path, contents) {
                    tracing::warn!("Failed to save desktop prefs: {e}");
                }
            }
            Err(e) => tracing::warn!("Failed to serialize desktop prefs: {e}"),
        }
    }

    /// Path to the prefs file.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(PREFS_FILE)
    }
}

/// Resolve the effective product mode from all sources.
///
/// Precedence (highest to lowest):
/// 1. `cli_mode` — explicit `--mode` argument
/// 2. `MIASMA_MODE` env var — developer/testing override
/// 3. `persisted` — user's saved preference from Settings
/// 4. Built-in default: Easy
pub fn resolve_mode(cli_mode: Option<ProductMode>, persisted: &DesktopPrefs) -> ProductMode {
    // 1. CLI argument
    if let Some(m) = cli_mode {
        return m;
    }
    // 2. Environment variable (developer override)
    if let Ok(val) = std::env::var("MIASMA_MODE") {
        match val.to_lowercase().as_str() {
            "technical" | "tech" => return ProductMode::Technical,
            "easy" | "simple" => return ProductMode::Easy,
            _ => {}
        }
    }
    // 3. Persisted user preference
    persisted.mode
}

/// Parse `--mode <value>` from command-line arguments.
pub fn parse_cli_mode() -> Option<ProductMode> {
    let args: Vec<String> = std::env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == "--mode" {
            if let Some(val) = args.get(i + 1) {
                match val.to_lowercase().as_str() {
                    "technical" | "tech" => return Some(ProductMode::Technical),
                    "easy" | "simple" => return Some(ProductMode::Easy),
                    _ => {}
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_easy() {
        assert_eq!(ProductMode::default(), ProductMode::Easy);
    }

    #[test]
    fn is_easy_and_is_technical_are_exclusive() {
        assert!(ProductMode::Easy.is_easy());
        assert!(!ProductMode::Easy.is_technical());
        assert!(ProductMode::Technical.is_technical());
        assert!(!ProductMode::Technical.is_easy());
    }

    #[test]
    fn serde_roundtrip() {
        let easy_json = serde_json::to_string(&ProductMode::Easy).unwrap();
        assert_eq!(easy_json, "\"easy\"");
        let tech_json = serde_json::to_string(&ProductMode::Technical).unwrap();
        assert_eq!(tech_json, "\"technical\"");
        let easy: ProductMode = serde_json::from_str(&easy_json).unwrap();
        assert_eq!(easy, ProductMode::Easy);
        let tech: ProductMode = serde_json::from_str(&tech_json).unwrap();
        assert_eq!(tech, ProductMode::Technical);
    }

    #[test]
    fn prefs_default_values() {
        let prefs = DesktopPrefs::default();
        assert_eq!(prefs.mode, ProductMode::Easy);
        assert_eq!(prefs.locale, Locale::En);
    }

    #[test]
    fn prefs_toml_roundtrip() {
        let prefs = DesktopPrefs {
            mode: ProductMode::Technical,
            locale: Locale::Ja,
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        let back: DesktopPrefs = toml::from_str(&toml_str).unwrap();
        assert_eq!(back.mode, ProductMode::Technical);
        assert_eq!(back.locale, Locale::Ja);
    }

    #[test]
    fn prefs_load_missing_file_returns_defaults() {
        let tmp = std::env::temp_dir().join("miasma-test-prefs-missing");
        let _ = std::fs::create_dir_all(&tmp);
        let prefs = DesktopPrefs::load(&tmp);
        assert_eq!(prefs.mode, ProductMode::Easy);
        assert_eq!(prefs.locale, Locale::En);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn prefs_save_and_load_roundtrip() {
        let tmp = std::env::temp_dir().join("miasma-test-prefs-roundtrip");
        let _ = std::fs::create_dir_all(&tmp);
        let prefs = DesktopPrefs {
            mode: ProductMode::Technical,
            locale: Locale::ZhCn,
        };
        prefs.save(&tmp);
        let loaded = DesktopPrefs::load(&tmp);
        assert_eq!(loaded.mode, ProductMode::Technical);
        assert_eq!(loaded.locale, Locale::ZhCn);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn prefs_corrupt_file_returns_defaults() {
        let tmp = std::env::temp_dir().join("miasma-test-prefs-corrupt");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join(PREFS_FILE), "not valid toml {{{").unwrap();
        let prefs = DesktopPrefs::load(&tmp);
        assert_eq!(prefs.mode, ProductMode::Easy);
        assert_eq!(prefs.locale, Locale::En);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn prefs_partial_file_fills_defaults() {
        let tmp = std::env::temp_dir().join("miasma-test-prefs-partial");
        let _ = std::fs::create_dir_all(&tmp);
        // Only mode, no locale
        std::fs::write(tmp.join(PREFS_FILE), "mode = \"technical\"\n").unwrap();
        let prefs = DesktopPrefs::load(&tmp);
        assert_eq!(prefs.mode, ProductMode::Technical);
        assert_eq!(prefs.locale, Locale::En); // default
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_mode_precedence() {
        let prefs_easy = DesktopPrefs {
            mode: ProductMode::Easy,
            locale: Locale::En,
        };
        let prefs_tech = DesktopPrefs {
            mode: ProductMode::Technical,
            locale: Locale::En,
        };

        // CLI wins over everything
        assert_eq!(
            resolve_mode(Some(ProductMode::Technical), &prefs_easy),
            ProductMode::Technical
        );

        // No CLI → persisted wins (env var not set in this test context)
        // Note: can't fully test env var precedence without setting it,
        // but we test that persisted is used when CLI is None.
        std::env::remove_var("MIASMA_MODE");
        assert_eq!(resolve_mode(None, &prefs_tech), ProductMode::Technical);
        assert_eq!(resolve_mode(None, &prefs_easy), ProductMode::Easy);
    }
}
