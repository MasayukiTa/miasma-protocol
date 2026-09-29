//! Font discovery: read Japanese-capable system fonts on Windows, macOS and (best effort) Linux.
//!
//! Meiryo is the owner's preferred UI font. It ships with Windows and cannot be redistributed,
//! so it is read from the system and never bundled. macOS has no Meiryo by default (Office may
//! install one), so the macOS chain falls back to Hiragino Sans and PingFang.
//!
//! `discover` is a pure function of (search directories, candidate list), so the per-OS tables
//! below are just data and the lookup is tested against a temp directory.

use std::path::PathBuf;

use eframe::egui;

/// One font we would like to load.
#[derive(Debug, Clone, Copy)]
pub struct FontSpec {
    /// Name under which the font is registered with egui (also used in diagnostics).
    pub name: &'static str,
    /// Exact file names, tried in order in every search directory.
    pub files: &'static [&'static str],
    /// If no exact file exists, any font file whose name starts with one of these
    /// (case-insensitive) is accepted. For macOS names that differ between OS versions.
    pub prefixes: &'static [&'static str],
}

/// A font that was found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundFont {
    pub name: &'static str,
    pub path: PathBuf,
}

/// Which specs exist on this OS and in which order they form each family's chain.
pub struct Platform {
    pub dirs: Vec<PathBuf>,
    pub specs: &'static [FontSpec],
    /// Names from `specs`, in priority order (first = primary UI font).
    pub proportional: &'static [&'static str],
    pub monospace: &'static [&'static str],
}

// ─── Candidate tables (data) ────────────────────────────────────────────────

pub const WINDOWS_SPECS: &[FontSpec] = &[
    FontSpec {
        name: "Meiryo",
        files: &["meiryo.ttc"],
        prefixes: &[],
    },
    FontSpec {
        name: "Yu Gothic",
        files: &["YuGothR.ttc"],
        prefixes: &[],
    },
    FontSpec {
        name: "Microsoft YaHei",
        files: &["msyh.ttc"],
        prefixes: &[],
    },
    FontSpec {
        name: "MS Gothic",
        files: &["msgothic.ttc"],
        prefixes: &[],
    },
    FontSpec {
        name: "Consolas",
        files: &["consola.ttf"],
        prefixes: &[],
    },
];
pub const WINDOWS_PROPORTIONAL: &[&str] = &["Meiryo", "Yu Gothic", "Microsoft YaHei", "MS Gothic"];
pub const WINDOWS_MONOSPACE: &[&str] = &["Consolas", "MS Gothic", "Yu Gothic", "Microsoft YaHei"];

// macOS file names are Unicode. `ヒラギノ角ゴシック` is spelled with escapes (composed form
// first, then the decomposed form the file system may hand back from a directory listing).
pub const MACOS_SPECS: &[FontSpec] = &[
    FontSpec {
        name: "Meiryo",
        files: &["Meiryo.ttc", "meiryo.ttc"],
        prefixes: &["meiryo"],
    },
    FontSpec {
        name: "Hiragino Sans",
        files: &[
            "\u{30D2}\u{30E9}\u{30AE}\u{30CE}\u{89D2}\u{30B4}\u{30B7}\u{30C3}\u{30AF} W3.ttc",
            "Hiragino Sans W3.ttc",
            "Hiragino Sans GB.ttc",
        ],
        prefixes: &[
            "\u{30D2}\u{30E9}\u{30AE}\u{30CE}\u{89D2}\u{30B4}",
            "\u{30D2}\u{30E9}\u{30AD}\u{3099}\u{30CE}\u{89D2}\u{30B3}\u{3099}",
            "Hiragino Sans",
        ],
    },
    FontSpec {
        name: "PingFang",
        files: &["PingFang.ttc"],
        prefixes: &["PingFang"],
    },
    FontSpec {
        name: "Menlo",
        files: &["Menlo.ttc"],
        prefixes: &[],
    },
];
pub const MACOS_PROPORTIONAL: &[&str] = &["Meiryo", "Hiragino Sans", "PingFang"];
pub const MACOS_MONOSPACE: &[&str] = &["Menlo", "Hiragino Sans", "PingFang"];

pub const LINUX_SPECS: &[FontSpec] = &[FontSpec {
    name: "Noto Sans CJK",
    files: &[
        "NotoSansCJK-Regular.ttc",
        "NotoSansCJKjp-Regular.otf",
        "NotoSansCJKjp-Regular.ttf",
    ],
    prefixes: &["NotoSansCJK", "NotoSansJP", "NotoSansJapanese"],
}];
pub const LINUX_PROPORTIONAL: &[&str] = &["Noto Sans CJK"];
pub const LINUX_MONOSPACE: &[&str] = &["Noto Sans CJK"];

/// Search directories for this OS (only the tables above are OS specific; existence is checked
/// later by `discover`).
pub fn platform() -> Platform {
    if cfg!(target_os = "windows") {
        // Honour %WINDIR% (Windows may not live on C:), then the stock location.
        let mut dirs = Vec::new();
        for var in ["WINDIR", "SystemRoot"] {
            if let Some(w) = std::env::var_os(var) {
                let d = PathBuf::from(w).join("Fonts");
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        }
        let stock = PathBuf::from(r"C:\Windows\Fonts");
        if !dirs.contains(&stock) {
            dirs.push(stock);
        }
        // Per-user installs (Windows 10 1809+).
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            dirs.push(PathBuf::from(local).join(r"Microsoft\Windows\Fonts"));
        }
        Platform {
            dirs,
            specs: WINDOWS_SPECS,
            proportional: WINDOWS_PROPORTIONAL,
            monospace: WINDOWS_MONOSPACE,
        }
    } else if cfg!(target_os = "macos") {
        let mut dirs = vec![
            PathBuf::from("/Library/Fonts"),
            // Office puts Meiryo here when it is installed.
            PathBuf::from("/Library/Fonts/Microsoft"),
            PathBuf::from("/Applications/Microsoft Word.app/Contents/Resources/DFonts"),
        ];
        if let Some(home) = std::env::var_os("HOME") {
            dirs.push(PathBuf::from(home).join("Library/Fonts"));
        }
        dirs.push(PathBuf::from("/System/Library/Fonts"));
        dirs.push(PathBuf::from("/System/Library/Fonts/Supplemental"));
        Platform {
            dirs,
            specs: MACOS_SPECS,
            proportional: MACOS_PROPORTIONAL,
            monospace: MACOS_MONOSPACE,
        }
    } else {
        Platform {
            dirs: [
                "/usr/share/fonts/opentype/noto",
                "/usr/share/fonts/truetype/noto",
                "/usr/share/fonts/noto-cjk",
                "/usr/share/fonts/google-noto-cjk",
                "/usr/share/fonts/google-noto",
                "/usr/share/fonts/OTF",
                "/usr/share/fonts/TTF",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            specs: LINUX_SPECS,
            proportional: LINUX_PROPORTIONAL,
            monospace: LINUX_MONOSPACE,
        }
    }
}

// ─── Discovery (pure) ───────────────────────────────────────────────────────

fn is_font_file(name: &str) -> bool {
    let n = name.to_lowercase();
    n.ends_with(".ttc") || n.ends_with(".ttf") || n.ends_with(".otf")
}

/// Find `spec` in `dirs`: exact file names first (all dirs), then prefix matches in a directory
/// listing (sorted, so the result does not depend on directory order).
fn find_one(dirs: &[PathBuf], spec: &FontSpec) -> Option<PathBuf> {
    for dir in dirs {
        for file in spec.files {
            let p = dir.join(file);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    if spec.prefixes.is_empty() {
        return None;
    }
    for dir in dirs {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| is_font_file(n))
            .collect();
        names.sort();
        for prefix in spec.prefixes {
            let lp = prefix.to_lowercase();
            if let Some(n) = names.iter().find(|n| n.to_lowercase().starts_with(&lp)) {
                return Some(dir.join(n));
            }
        }
    }
    None
}

/// Look every candidate up. Returns the fonts found (in `specs` order) and the names missing.
pub fn discover(dirs: &[PathBuf], specs: &[FontSpec]) -> (Vec<FoundFont>, Vec<&'static str>) {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for spec in specs {
        match find_one(dirs, spec) {
            Some(path) => found.push(FoundFont {
                name: spec.name,
                path,
            }),
            None => missing.push(spec.name),
        }
    }
    (found, missing)
}

/// The names of `chain` that were actually found, in chain order.
pub fn chain_of(chain: &[&str], found: &[FoundFont]) -> Vec<&'static str> {
    chain
        .iter()
        .filter_map(|want| found.iter().find(|f| f.name == *want).map(|f| f.name))
        .collect()
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

/// Font detection results for the diagnostics text (Settings > copy diagnostics).
pub struct FontDetectionResult {
    pub loaded: Vec<String>,
    pub missing: Vec<String>,
}

static FONT_DETECTION: std::sync::OnceLock<FontDetectionResult> = std::sync::OnceLock::new();

pub fn detection() -> Option<&'static FontDetectionResult> {
    FONT_DETECTION.get()
}

/// Read the fonts for this OS, put them in front of egui's built-in fonts (Latin only), and
/// record what loaded. Never fails: with no system fonts the built-ins remain and CJK shows as
/// tofu, which the diagnostics say.
pub fn install(ctx: &egui::Context) {
    let platform = platform();
    let (found, missing) = discover(&platform.dirs, platform.specs);

    let mut fonts = egui::FontDefinitions::default();
    let mut loaded = Vec::new();
    let mut missing: Vec<String> = missing.into_iter().map(str::to_owned).collect();
    let mut usable: Vec<FoundFont> = Vec::new();
    for f in found {
        match std::fs::read(&f.path) {
            Ok(data) => {
                fonts
                    .font_data
                    .insert(f.name.to_owned(), egui::FontData::from_owned(data));
                let file = f.path.file_name().map(|n| n.to_string_lossy().into_owned());
                loaded.push(format!("{} ({})", f.name, file.unwrap_or_default()));
                tracing::info!("Font loaded: {} from {}", f.name, f.path.display());
                usable.push(f);
            }
            Err(e) => {
                tracing::warn!("Font unreadable: {}: {e}", f.path.display());
                missing.push(f.name.to_owned());
            }
        }
    }

    // In front of egui's built-ins, which stay at the end as the last resort.
    let chain_p = chain_of(platform.proportional, &usable);
    let chain_m = chain_of(platform.monospace, &usable);
    for (i, name) in chain_p.iter().enumerate() {
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(i, (*name).to_owned());
    }
    for (i, name) in chain_m.iter().enumerate() {
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .insert(i, (*name).to_owned());
    }

    if chain_p.is_empty() {
        tracing::warn!(
            "No Japanese-capable system font found (looked in {:?}); Japanese text will show as boxes",
            platform.dirs
        );
    } else {
        tracing::info!("Proportional font chain: {chain_p:?}; monospace: {chain_m:?}");
    }

    let _ = FONT_DETECTION.set(FontDetectionResult { loaded, missing });
    ctx.set_fonts(fonts);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("miasma-fonts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    #[test]
    fn finds_exact_names_and_reports_missing() {
        let d = tmpdir("exact");
        touch(&d, "meiryo.ttc");
        touch(&d, "consola.ttf");
        let (found, missing) = discover(std::slice::from_ref(&d), WINDOWS_SPECS);
        let names: Vec<_> = found.iter().map(|f| f.name).collect();
        assert_eq!(names, ["Meiryo", "Consolas"]);
        assert_eq!(missing, ["Yu Gothic", "Microsoft YaHei", "MS Gothic"]);
        assert_eq!(found[0].path, d.join("meiryo.ttc"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn searches_every_directory_in_order() {
        let a = tmpdir("dir-a");
        let b = tmpdir("dir-b");
        touch(&b, "Meiryo.ttc");
        touch(&a, "PingFang.ttc");
        // Meiryo only in the second directory, PingFang only in the first.
        let (found, _) = discover(&[a.clone(), b.clone()], MACOS_SPECS);
        let names: Vec<_> = found.iter().map(|f| f.name).collect();
        assert_eq!(names, ["Meiryo", "PingFang"]);
        assert_eq!(found[0].path, b.join("Meiryo.ttc"));
        // Same font in both: the earlier directory wins.
        touch(&a, "Meiryo.ttc");
        let (found, _) = discover(&[a.clone(), b.clone()], MACOS_SPECS);
        assert_eq!(found[0].path, a.join("Meiryo.ttc"));
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn falls_back_to_prefix_when_the_exact_name_differs() {
        let d = tmpdir("prefix");
        // A future macOS names the file differently from every exact candidate.
        touch(&d, "Hiragino Sans W6.ttc");
        touch(&d, "notes.txt");
        let (found, missing) = discover(std::slice::from_ref(&d), MACOS_SPECS);
        let hira = found.iter().find(|f| f.name == "Hiragino Sans").unwrap();
        assert_eq!(hira.path, d.join("Hiragino Sans W6.ttc"));
        assert!(missing.contains(&"Meiryo"));
        assert!(missing.contains(&"PingFang"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn prefix_ignores_non_font_files_and_is_case_insensitive() {
        let d = tmpdir("prefix-case");
        touch(&d, "notosanscjk-notes.txt");
        touch(&d, "NOTOSANSCJKJP-Bold.otf");
        let (found, _) = discover(std::slice::from_ref(&d), LINUX_SPECS);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, d.join("NOTOSANSCJKJP-Bold.otf"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn japanese_named_hiragino_file_is_found() {
        let d = tmpdir("hiragino-ja");
        touch(&d, "\u{30D2}\u{30E9}\u{30AE}\u{30CE}\u{89D2}\u{30B4}\u{30B7}\u{30C3}\u{30AF} W3.ttc");
        let (found, _) = discover(std::slice::from_ref(&d), MACOS_SPECS);
        assert!(found.iter().any(|f| f.name == "Hiragino Sans"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_or_unreadable_directory_is_not_an_error() {
        let nowhere = std::env::temp_dir().join("miasma-fonts-does-not-exist-xyz");
        let (found, missing) = discover(&[nowhere], MACOS_SPECS);
        assert!(found.is_empty());
        assert_eq!(missing.len(), MACOS_SPECS.len());
    }

    #[test]
    fn chain_keeps_chain_order_not_discovery_order() {
        let found = vec![
            FoundFont {
                name: "Consolas",
                path: PathBuf::from("c"),
            },
            FoundFont {
                name: "MS Gothic",
                path: PathBuf::from("m"),
            },
            FoundFont {
                name: "Meiryo",
                path: PathBuf::from("y"),
            },
        ];
        assert_eq!(
            chain_of(WINDOWS_PROPORTIONAL, &found),
            ["Meiryo", "MS Gothic"]
        );
        assert_eq!(chain_of(WINDOWS_MONOSPACE, &found), ["Consolas", "MS Gothic"]);
    }

    #[test]
    fn tables_put_meiryo_first_and_segoe_is_gone() {
        assert_eq!(WINDOWS_PROPORTIONAL[0], "Meiryo");
        assert_eq!(MACOS_PROPORTIONAL[0], "Meiryo");
        assert_eq!(
            WINDOWS_PROPORTIONAL,
            ["Meiryo", "Yu Gothic", "Microsoft YaHei", "MS Gothic"]
        );
        assert_eq!(MACOS_PROPORTIONAL, ["Meiryo", "Hiragino Sans", "PingFang"]);
        assert!(WINDOWS_SPECS.iter().all(|s| s.name != "Segoe UI"));
        // every chain entry is a spec
        for (specs, chains) in [
            (WINDOWS_SPECS, [WINDOWS_PROPORTIONAL, WINDOWS_MONOSPACE]),
            (MACOS_SPECS, [MACOS_PROPORTIONAL, MACOS_MONOSPACE]),
            (LINUX_SPECS, [LINUX_PROPORTIONAL, LINUX_MONOSPACE]),
        ] {
            for chain in chains {
                for n in chain {
                    assert!(specs.iter().any(|s| s.name == *n), "{n} has no spec");
                }
            }
        }
    }
}
