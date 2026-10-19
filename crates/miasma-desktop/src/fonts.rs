//! Font discovery: read Japanese-capable system fonts on Windows, macOS and (best effort) Linux.
//!
//! Meiryo is the owner's preferred UI font. It ships with Windows and cannot be redistributed,
//! so it is read from the system and never bundled. macOS has no Meiryo by default (Office may
//! install one), so the macOS chain falls back to Hiragino Sans and PingFang.
//!
//! `discover` is a pure function of (search directories, candidate list), so the per-OS tables
//! below are just data and the lookup is tested against a temp directory.
//!
//! Loading is lazy. The CJK system fonts are large (five files, about 50 MiB on Windows), so only
//! the fonts the active language needs are read at start (`required_for`): one UI font that
//! covers the language, plus a small Latin monospace font where the OS has one. The others are
//! read the first time a CJK character is painted that no loaded font can draw (`ensure_glyphs`),
//! or when the language is switched (`set_locale`). Fonts that were read stay loaded.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use eframe::egui;

use crate::locale::Locale;

/// A writing system a font covers well enough to be the UI font for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Latin,
    Ja,
    ZhHans,
}

/// The CJK script a UI language is written in (`None` for English).
pub fn script_of(locale: Locale) -> Option<Script> {
    match locale {
        Locale::En => None,
        Locale::Ja => Some(Script::Ja),
        Locale::ZhCn => Some(Script::ZhHans),
    }
}

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
    /// What the font covers. A font whose only script is `Latin` is small and is loaded for every
    /// language; the others are CJK fonts.
    pub scripts: &'static [Script],
}

impl FontSpec {
    fn covers(&self, script: Script) -> bool {
        self.scripts.contains(&script)
    }

    fn latin_only(&self) -> bool {
        self.scripts == [Script::Latin]
    }
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
        scripts: &[Script::Ja, Script::Latin],
    },
    FontSpec {
        name: "Yu Gothic",
        files: &["YuGothR.ttc"],
        prefixes: &[],
        scripts: &[Script::Ja, Script::Latin],
    },
    FontSpec {
        name: "Microsoft YaHei",
        files: &["msyh.ttc"],
        prefixes: &[],
        scripts: &[Script::ZhHans, Script::Latin],
    },
    FontSpec {
        name: "MS Gothic",
        files: &["msgothic.ttc"],
        prefixes: &[],
        scripts: &[Script::Ja],
    },
    FontSpec {
        name: "Consolas",
        files: &["consola.ttf"],
        prefixes: &[],
        scripts: &[Script::Latin],
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
        scripts: &[Script::Ja, Script::Latin],
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
        scripts: &[Script::Ja, Script::Latin],
    },
    FontSpec {
        name: "PingFang",
        files: &["PingFang.ttc"],
        prefixes: &["PingFang"],
        scripts: &[Script::ZhHans, Script::Latin],
    },
    FontSpec {
        name: "Menlo",
        files: &["Menlo.ttc"],
        prefixes: &[],
        scripts: &[Script::Latin],
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
    scripts: &[Script::Ja, Script::ZhHans, Script::Latin],
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

// ─── Which fonts a language needs (pure) ────────────────────────────────────

fn spec_of<'a>(specs: &'a [FontSpec], name: &str) -> Option<&'a FontSpec> {
    specs.iter().find(|s| s.name == name)
}

/// `chain` as it applies to `locale`: fonts that cover the language's script come first (in the
/// chain's own order), then the rest. Latin-only fonts (a small monospace face) stay at the very
/// front. English keeps the table order.
pub fn ordered_chain(
    locale: Locale,
    chain: &[&'static str],
    specs: &[FontSpec],
) -> Vec<&'static str> {
    let script = script_of(locale);
    let (mut latin, mut first, mut rest) = (Vec::new(), Vec::new(), Vec::new());
    for &name in chain {
        match spec_of(specs, name) {
            Some(s) if s.latin_only() => latin.push(name),
            Some(s) if script.is_some_and(|sc| s.covers(sc)) => first.push(name),
            _ => rest.push(name),
        }
    }
    latin.extend(first);
    latin.extend(rest);
    latin
}

/// The fonts to read at start for `locale`: the first font in the language's chain that covers its
/// script (any font of the chain when none does), and the first Latin-only monospace font. English
/// needs no CJK font. Only fonts present in `found` are chosen.
pub fn required_for(
    locale: Locale,
    proportional: &[&'static str],
    monospace: &[&'static str],
    specs: &[FontSpec],
    found: &[FoundFont],
) -> Vec<&'static str> {
    let have = |n: &str| found.iter().any(|f| f.name == n);
    let mut out: Vec<&'static str> = Vec::new();
    if let Some(script) = script_of(locale) {
        let chain = ordered_chain(locale, proportional, specs);
        let covering = chain
            .iter()
            .copied()
            .find(|n| have(n) && spec_of(specs, n).is_some_and(|s| s.covers(script)));
        out.extend(covering.or_else(|| chain.iter().copied().find(|n| have(n))));
    }
    let mono = monospace
        .iter()
        .copied()
        .find(|n| have(n) && spec_of(specs, n).is_some_and(FontSpec::latin_only));
    if let Some(n) = mono {
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

/// Characters that need a CJK font: kana, CJK punctuation, ideographs, fullwidth forms. (Hangul is
/// not in any font table, so it is left out rather than loading every font for nothing.)
pub fn is_cjk_char(c: char) -> bool {
    matches!(
        c as u32,
        0x3000..=0x303F
            | 0x3040..=0x30FF
            | 0x31F0..=0x31FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xF900..=0xFAFF
            | 0xFF00..=0xFFEF
            | 0x2_0000..=0x2_FA1F
    )
}

// ─── Loading ────────────────────────────────────────────────────────────────

/// Which fonts are on disk, which are read, and what the egui font set looks like for the active
/// language. One lives in a process-wide slot (`install`, `set_locale`, `ensure_glyphs`); tests make
/// their own.
pub struct FontManager {
    platform: Platform,
    found: Vec<FoundFont>,
    /// Not found on disk, or found but unreadable.
    missing: Vec<String>,
    locale: Locale,
    /// Read so far, in the order they were read.
    loaded: Vec<&'static str>,
    /// File contents. Leaked on purpose: each font is read at most once and stays for the life of
    /// the process, and a `'static` slice lets egui share it instead of copying 10 to 20 MiB every
    /// time the font set is rebuilt.
    data: HashMap<&'static str, &'static [u8]>,
    /// Characters already known to be drawable (or hopeless: every font is loaded), per family
    /// (`[proportional, monospace]`), so each is looked up once.
    checked: [HashSet<char>; 2],
}

impl FontManager {
    pub fn new(locale: Locale) -> Self {
        Self::with_platform(platform(), locale)
    }

    pub fn with_platform(platform: Platform, locale: Locale) -> Self {
        let (found, missing) = discover(&platform.dirs, platform.specs);
        Self {
            platform,
            found,
            missing: missing.into_iter().map(str::to_owned).collect(),
            locale,
            loaded: Vec::new(),
            data: HashMap::new(),
            checked: [HashSet::new(), HashSet::new()],
        }
    }

    pub fn loaded(&self) -> &[&'static str] {
        &self.loaded
    }

    /// Read one font from disk (once). True when it is loaded afterwards.
    fn read(&mut self, name: &'static str) -> bool {
        if self.loaded.contains(&name) {
            return true;
        }
        let Some(path) = self
            .found
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.path.clone())
        else {
            return false;
        };
        match std::fs::read(&path) {
            Ok(bytes) => {
                tracing::info!(
                    "Font loaded: {name} from {} ({} KiB)",
                    miasma_core::logging::redact::path(&path),
                    bytes.len() / 1024
                );
                let leaked: &'static [u8] = Box::leak(bytes.into_boxed_slice());
                self.data.insert(name, leaked);
                self.loaded.push(name);
                true
            }
            Err(_) => {
                tracing::warn!(
                    "Font unreadable: {name}: {}",
                    miasma_core::logging::redact::path(&path)
                );
                self.missing.push(name.to_owned());
                self.found.retain(|f| f.name != name);
                false
            }
        }
    }

    /// Read the fonts the active language needs. True when something new was read.
    pub fn load_required(&mut self) -> bool {
        let before = self.loaded.len();
        // A file that cannot be read drops out of `found`, so the choice is made again
        // (a few times at most) and falls to the next font in the chain.
        for _ in 0..3 {
            let want = required_for(
                self.locale,
                self.platform.proportional,
                self.platform.monospace,
                self.platform.specs,
                &self.found,
            );
            let mut all_read = true;
            for name in want {
                all_read &= self.read(name);
            }
            if all_read {
                break;
            }
        }
        self.loaded.len() != before
    }

    /// Switch the language: read what it needs. True when something new was read.
    pub fn set_locale(&mut self, locale: Locale) -> bool {
        self.locale = locale;
        self.load_required()
    }

    /// Fonts found on disk but not read yet, in the order they would be tried for one family.
    pub fn candidates(&self, monospace: bool) -> Vec<&'static str> {
        let chain = if monospace {
            self.platform.monospace
        } else {
            self.platform.proportional
        };
        ordered_chain(self.locale, chain, self.platform.specs)
            .into_iter()
            .filter(|n| {
                !self.loaded.contains(n)
                    && self.found.iter().any(|f| f.name == *n)
                    && spec_of(self.platform.specs, n).is_some_and(|s| !s.latin_only())
            })
            .collect()
    }

    /// Read the next font that could draw more characters in a family. True when one was read.
    fn load_next(&mut self, monospace: bool) -> bool {
        for name in self.candidates(monospace) {
            if self.read(name) {
                return true;
            }
        }
        false
    }

    /// The egui font set for what is loaded now. Fonts that cover the active language go in front
    /// of egui's built-ins (as before); a CJK font read only because some text needed it while the
    /// UI is in English goes behind them, so the Latin look of the UI does not change.
    pub fn definitions(&self) -> egui::FontDefinitions {
        let mut fonts = egui::FontDefinitions::default();
        let usable: Vec<FoundFont> = self
            .loaded
            .iter()
            .filter_map(|n| self.found.iter().find(|f| f.name == *n).cloned())
            .collect();
        for name in &self.loaded {
            if let Some(&bytes) = self.data.get(name) {
                fonts
                    .font_data
                    .insert((*name).to_owned(), egui::FontData::from_static(bytes));
            }
        }
        let cjk_in_front = script_of(self.locale).is_some();
        for (family, chain) in [
            (egui::FontFamily::Proportional, self.platform.proportional),
            (egui::FontFamily::Monospace, self.platform.monospace),
        ] {
            let ordered = ordered_chain(self.locale, chain, self.platform.specs);
            let names = chain_of(&ordered, &usable);
            let list = fonts.families.entry(family).or_default();
            let mut front = 0;
            for name in names {
                let latin = spec_of(self.platform.specs, name).is_some_and(FontSpec::latin_only);
                if latin || cjk_in_front {
                    list.insert(front, name.to_owned());
                    front += 1;
                } else {
                    list.push(name.to_owned());
                }
            }
        }
        fonts
    }

    /// What the diagnostics text reports.
    pub fn detection(&self) -> FontDetectionResult {
        let describe = |name: &str| {
            let file = self
                .found
                .iter()
                .find(|f| f.name == name)
                .and_then(|f| f.path.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            format!("{name} ({file})")
        };
        FontDetectionResult {
            loaded: self.loaded.iter().map(|n| describe(n)).collect(),
            missing: self.missing.clone(),
            deferred: self
                .found
                .iter()
                .filter(|f| !self.loaded.contains(&f.name))
                .map(|f| describe(f.name))
                .collect(),
        }
    }

    /// Look at the text painted so far in this frame. When a CJK character is there that the
    /// loaded fonts cannot draw, read the next font that might. True when one was read (the caller
    /// then installs `definitions()`; the text shows correctly one frame later).
    pub fn ensure_glyphs(&mut self, ctx: &egui::Context) -> bool {
        if self.candidates(false).is_empty() && self.candidates(true).is_empty() {
            return false;
        }
        let wanted = cjk_text_in_frame(ctx, &self.checked);
        if wanted.is_empty() {
            return false;
        }
        let mut missing: [Vec<char>; 2] = [Vec::new(), Vec::new()];
        for (mono, ch, font_id) in wanted {
            if ctx.fonts(|f| f.has_glyph(&font_id, ch)) {
                self.checked[usize::from(mono)].insert(ch);
            } else {
                missing[usize::from(mono)].push(ch);
            }
        }
        let mut changed = false;
        for mono in [false, true] {
            let i = usize::from(mono);
            if missing[i].is_empty() {
                continue;
            }
            if self.load_next(mono) {
                changed = true;
            } else {
                // Nothing left to try for this family: stop asking about these.
                self.checked[i].extend(missing[i].iter().copied());
            }
        }
        changed
    }
}

/// CJK characters painted in this frame that are not yet in `checked`, with the family and font
/// they were laid out in. The text is read from the paint lists, so everything on screen counts
/// whatever widget drew it (labels, text edits, hand-painted rows).
fn cjk_text_in_frame(
    ctx: &egui::Context,
    checked: &[HashSet<char>; 2],
) -> Vec<(bool, char, egui::FontId)> {
    fn visit(
        shape: &egui::Shape,
        checked: &[HashSet<char>; 2],
        seen: &mut HashSet<(bool, char)>,
        out: &mut Vec<(bool, char, egui::FontId)>,
    ) {
        match shape {
            egui::Shape::Text(t) => {
                let job = &t.galley.job;
                if job.text.is_ascii() {
                    return;
                }
                for section in &job.sections {
                    let Some(text) = job.text.get(section.byte_range.clone()) else {
                        continue;
                    };
                    let font_id = &section.format.font_id;
                    let mono = font_id.family == egui::FontFamily::Monospace;
                    for ch in text.chars() {
                        if is_cjk_char(ch)
                            && !checked[usize::from(mono)].contains(&ch)
                            && seen.insert((mono, ch))
                        {
                            out.push((mono, ch, font_id.clone()));
                        }
                    }
                }
            }
            egui::Shape::Vec(v) => {
                for s in v {
                    visit(s, checked, seen, out);
                }
            }
            _ => {}
        }
    }

    // Collect first and look the glyphs up afterwards: the paint lists and the fonts sit behind
    // the same context lock.
    let mut layers: Vec<egui::LayerId> = ctx.memory(|m| m.layer_ids().collect());
    layers.push(egui::LayerId::background());
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    ctx.graphics(|g| {
        for layer in &layers {
            if let Some(list) = g.get(*layer) {
                for clipped in list.all_entries() {
                    visit(&clipped.shape, checked, &mut seen, &mut out);
                }
            }
        }
    });
    out
}

// ─── Diagnostics and the process-wide slot ──────────────────────────────────

/// Font detection results for the diagnostics text (Settings > copy diagnostics).
#[derive(Clone)]
pub struct FontDetectionResult {
    pub loaded: Vec<String>,
    pub missing: Vec<String>,
    /// On disk, not read yet: read when some text needs them.
    pub deferred: Vec<String>,
}

static MANAGER: Mutex<Option<FontManager>> = Mutex::new(None);
static FONT_DETECTION: Mutex<Option<FontDetectionResult>> = Mutex::new(None);

pub fn detection() -> Option<FontDetectionResult> {
    FONT_DETECTION
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn with_manager<R>(f: impl FnOnce(&mut FontManager) -> R) -> Option<R> {
    let mut slot = MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    slot.as_mut().map(f)
}

/// Publish what is loaded to the diagnostics text.
fn publish_detection(m: &FontManager) {
    *FONT_DETECTION.lock().unwrap_or_else(|e| e.into_inner()) = Some(m.detection());
}

/// Read the fonts the language needs, put them in front of egui's built-in fonts (Latin only), and
/// record what loaded. Never fails: with no system fonts the built-ins remain and CJK shows as
/// tofu, which the diagnostics say.
pub fn install(ctx: &egui::Context, locale: Locale) {
    let mut m = FontManager::new(locale);
    m.load_required();
    if script_of(locale).is_some() && m.loaded().is_empty() {
        tracing::warn!(
            "No CJK-capable system font found ({} folders searched); CJK text will show as boxes",
            m.platform.dirs.len()
        );
    }
    tracing::info!("Fonts read at start for {locale:?}: {:?}", m.loaded());
    ctx.set_fonts(m.definitions());
    publish_detection(&m);
    *MANAGER.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
}

/// The language was switched: read the fonts it needs.
pub fn set_locale(ctx: &egui::Context, locale: Locale) {
    let fonts = with_manager(|m| {
        m.set_locale(locale);
        publish_detection(m);
        m.definitions()
    });
    if let Some(fonts) = fonts {
        ctx.set_fonts(fonts);
    }
}

/// Call once per frame, after the screen is drawn: reads a further font when the frame holds a
/// CJK character that no loaded font can draw.
pub fn ensure_glyphs(ctx: &egui::Context) {
    let fonts = with_manager(|m| {
        m.ensure_glyphs(ctx).then(|| {
            publish_detection(m);
            m.definitions()
        })
    })
    .flatten();
    if let Some(fonts) = fonts {
        ctx.set_fonts(fonts);
        ctx.request_repaint();
    }
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
        touch(
            &d,
            "\u{30D2}\u{30E9}\u{30AE}\u{30CE}\u{89D2}\u{30B4}\u{30B7}\u{30C3}\u{30AF} W3.ttc",
        );
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
        assert_eq!(
            chain_of(WINDOWS_MONOSPACE, &found),
            ["Consolas", "MS Gothic"]
        );
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

/// Which fonts each language reads at start, and lazy loading. The table tests need no font files;
/// the ones that draw text use the system fonts and skip themselves where the OS has none.
#[cfg(test)]
mod lazy_tests {
    use super::*;

    const SETS: [(&str, &[FontSpec], &[&str], &[&str]); 3] = [
        (
            "windows",
            WINDOWS_SPECS,
            WINDOWS_PROPORTIONAL,
            WINDOWS_MONOSPACE,
        ),
        ("macos", MACOS_SPECS, MACOS_PROPORTIONAL, MACOS_MONOSPACE),
        ("linux", LINUX_SPECS, LINUX_PROPORTIONAL, LINUX_MONOSPACE),
    ];

    fn all_found(specs: &[FontSpec]) -> Vec<FoundFont> {
        specs
            .iter()
            .map(|s| FoundFont {
                name: s.name,
                path: PathBuf::from(s.name),
            })
            .collect()
    }

    /// Ja, ZhCn: kana/ideographs for each language, written with escapes.
    fn sample(locale: Locale) -> &'static str {
        match locale {
            Locale::En => "Settings Contacts Transfers",
            Locale::Ja => "\u{8a2d}\u{5b9a} \u{9023}\u{7d61}\u{5148} \u{8ee2}\u{9001} \u{30c6}\u{30b9}\u{30c8}",
            Locale::ZhCn => "\u{8bbe}\u{7f6e} \u{8054}\u{7cfb}\u{4eba} \u{4f20}\u{8f93}",
        }
    }

    #[test]
    fn every_font_table_entry_declares_what_it_covers() {
        for (os, specs, _, _) in SETS {
            for s in specs {
                assert!(!s.scripts.is_empty(), "{os}: {} covers nothing", s.name);
            }
        }
    }

    #[test]
    fn each_language_reads_a_font_that_covers_it_and_at_most_one_other() {
        for (os, specs, prop, mono) in SETS {
            let found = all_found(specs);
            for locale in Locale::ALL {
                let want = required_for(locale, prop, mono, specs, &found);
                assert!(want.len() <= 2, "{os} {locale:?}: reads {want:?}");
                if let Some(script) = script_of(locale) {
                    assert!(
                        want.iter()
                            .any(|n| spec_of(specs, n).is_some_and(|s| s.covers(script))),
                        "{os} {locale:?}: {want:?} covers {script:?} in no font"
                    );
                    // Exactly one CJK font is read at start, not the whole chain.
                    let cjk = want
                        .iter()
                        .filter(|n| spec_of(specs, n).is_some_and(|s| !s.latin_only()))
                        .count();
                    assert_eq!(cjk, 1, "{os} {locale:?}: {want:?}");
                } else {
                    // English: nothing but a small Latin face.
                    assert!(
                        want.iter()
                            .all(|n| spec_of(specs, n).is_some_and(FontSpec::latin_only)),
                        "{os} {locale:?}: {want:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn windows_reads_one_cjk_font_per_language() {
        let found = all_found(WINDOWS_SPECS);
        let want = |l| {
            required_for(
                l,
                WINDOWS_PROPORTIONAL,
                WINDOWS_MONOSPACE,
                WINDOWS_SPECS,
                &found,
            )
        };
        assert_eq!(want(Locale::En), ["Consolas"]);
        assert_eq!(want(Locale::Ja), ["Meiryo", "Consolas"]);
        assert_eq!(want(Locale::ZhCn), ["Microsoft YaHei", "Consolas"]);
    }

    #[test]
    fn a_language_falls_back_to_the_next_font_when_its_first_is_missing() {
        let mut found = all_found(WINDOWS_SPECS);
        found.retain(|f| f.name != "Meiryo");
        let want = required_for(
            Locale::Ja,
            WINDOWS_PROPORTIONAL,
            WINDOWS_MONOSPACE,
            WINDOWS_SPECS,
            &found,
        );
        assert_eq!(want, ["Yu Gothic", "Consolas"]);
        // No font covers Chinese: the first available one is better than none.
        let only_ja: Vec<_> = all_found(WINDOWS_SPECS)
            .into_iter()
            .filter(|f| f.name == "MS Gothic")
            .collect();
        let want = required_for(
            Locale::ZhCn,
            WINDOWS_PROPORTIONAL,
            WINDOWS_MONOSPACE,
            WINDOWS_SPECS,
            &only_ja,
        );
        assert_eq!(want, ["MS Gothic"]);
    }

    #[test]
    fn chain_order_puts_the_languages_own_font_first() {
        // Japanese keeps Meiryo first; the Japanese fallbacks now come before the Chinese one.
        assert_eq!(
            ordered_chain(Locale::Ja, WINDOWS_PROPORTIONAL, WINDOWS_SPECS),
            ["Meiryo", "Yu Gothic", "MS Gothic", "Microsoft YaHei"]
        );
        // English keeps the table order.
        assert_eq!(
            ordered_chain(Locale::En, WINDOWS_PROPORTIONAL, WINDOWS_SPECS),
            WINDOWS_PROPORTIONAL
        );
        // Simplified Chinese moves YaHei to the front; the Latin face stays ahead of the CJK ones.
        assert_eq!(
            ordered_chain(Locale::ZhCn, WINDOWS_PROPORTIONAL, WINDOWS_SPECS),
            ["Microsoft YaHei", "Meiryo", "Yu Gothic", "MS Gothic"]
        );
        assert_eq!(
            ordered_chain(Locale::ZhCn, WINDOWS_MONOSPACE, WINDOWS_SPECS),
            ["Consolas", "Microsoft YaHei", "MS Gothic", "Yu Gothic"]
        );
        assert_eq!(
            ordered_chain(Locale::ZhCn, MACOS_PROPORTIONAL, MACOS_SPECS),
            ["PingFang", "Meiryo", "Hiragino Sans"]
        );
    }

    #[test]
    fn cjk_characters_are_told_apart_from_the_rest() {
        for c in "\u{3042}\u{30a2}\u{4e2d}\u{3001}\u{ff01}".chars() {
            assert!(is_cjk_char(c), "{c:?}");
        }
        for c in "aZ0 \u{e9}\u{2192}\u{1f600}\u{ac00}".chars() {
            assert!(!is_cjk_char(c), "{c:?}");
        }
    }

    // ── With the system's own fonts ───────────────────────────────────────

    fn screen() -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 600.0),
            )),
            ..Default::default()
        }
    }

    /// A manager for the real OS with the given language, if the OS has a font that covers it.
    fn real_manager(locale: Locale) -> Option<FontManager> {
        let mut m = FontManager::new(locale);
        m.load_required();
        let script = script_of(locale);
        let covered = script.is_none_or(|sc| {
            m.loaded()
                .iter()
                .any(|n| spec_of(m.platform.specs, n).is_some_and(|s| s.covers(sc)))
        });
        if !covered {
            eprintln!("skipped {locale:?}: no covering font on this system");
            return None;
        }
        Some(m)
    }

    fn draws(ctx: &egui::Context, text: &str) -> bool {
        ctx.fonts(|f| f.has_glyphs(&egui::FontId::proportional(14.0), text))
    }

    #[test]
    fn the_loaded_fonts_draw_each_languages_own_text() {
        for locale in Locale::ALL {
            let Some(m) = real_manager(locale) else {
                continue;
            };
            let ctx = egui::Context::default();
            ctx.set_fonts(m.definitions());
            let _ = ctx.run(screen(), |_| {});
            assert!(draws(&ctx, sample(locale)), "{locale:?}: {:?}", m.loaded());
        }
    }

    #[test]
    fn english_reads_no_cjk_font_until_a_cjk_character_is_painted() {
        if real_manager(Locale::Ja).is_none() {
            return;
        }
        // Same OS, English UI.
        let mut en = FontManager::new(Locale::En);
        en.load_required();
        assert!(
            en.loaded()
                .iter()
                .all(|n| spec_of(en.platform.specs, n).is_some_and(FontSpec::latin_only)),
            "English reads {:?}",
            en.loaded()
        );
        let ctx = egui::Context::default();
        ctx.set_fonts(en.definitions());
        // A frame of Latin text: nothing to read.
        let mut changed = true;
        let _ = ctx.run(screen(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label("Settings");
            });
            changed = en.ensure_glyphs(ctx);
        });
        assert!(!changed, "Latin text reads no font");
        // A frame with Japanese text: the next CJK font is read.
        let before = en.loaded().len();
        let _ = ctx.run(screen(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label(sample(Locale::Ja));
            });
            changed = en.ensure_glyphs(ctx);
        });
        assert!(changed, "Japanese text reads a font");
        assert_eq!(en.loaded().len(), before + 1);
        ctx.set_fonts(en.definitions());
        let _ = ctx.run(screen(), |_| {});
        let _ = ctx.run(screen(), |_| {});
        assert!(draws(&ctx, sample(Locale::Ja)), "{:?}", en.loaded());
        // Once everything on screen can be drawn, nothing more is read.
        let mut again = true;
        let _ = ctx.run(screen(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label(sample(Locale::Ja));
            });
            again = en.ensure_glyphs(ctx);
        });
        assert!(!again);
    }

    #[test]
    fn switching_the_language_reads_the_new_languages_font() {
        let Some(zh) = real_manager(Locale::ZhCn) else {
            return;
        };
        let zh_fonts = zh.loaded().to_vec();
        let mut m = FontManager::new(Locale::En);
        m.load_required();
        m.set_locale(Locale::ZhCn);
        for n in &zh_fonts {
            assert!(m.loaded().contains(n), "{n} after switching to zh");
        }
        // Switching back keeps what was read.
        let n_before = m.loaded().len();
        m.set_locale(Locale::En);
        assert_eq!(m.loaded().len(), n_before);
    }
}

/// Working-set measurement of font setup. Ignored by default: it reads the real system fonts and
/// prints numbers. Run with `cargo test -p miasma-desktop font_memory_probe -- --ignored --nocapture`.
#[cfg(test)]
mod mem_probe {
    use super::*;
    use crate::locale::Locale;

    #[cfg(windows)]
    fn working_set() -> Option<u64> {
        #[repr(C)]
        struct Counters {
            cb: u32,
            page_fault_count: u32,
            peak_working_set_size: usize,
            working_set_size: usize,
            quota_peak_paged_pool_usage: usize,
            quota_paged_pool_usage: usize,
            quota_peak_non_paged_pool_usage: usize,
            quota_non_paged_pool_usage: usize,
            pagefile_usage: usize,
            peak_pagefile_usage: usize,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(p: isize, c: *mut Counters, cb: u32) -> i32;
        }
        // SAFETY: valid pointer to a correctly laid out struct of the stated size.
        unsafe {
            let mut c: Counters = std::mem::zeroed();
            c.cb = std::mem::size_of::<Counters>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) == 0 {
                return None;
            }
            Some(c.working_set_size as u64)
        }
    }

    #[cfg(not(windows))]
    fn working_set() -> Option<u64> {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let kb: u64 = s
            .lines()
            .find(|l| l.starts_with("VmRSS:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb * 1024)
    }

    fn sample(loc: Locale) -> &'static str {
        match loc {
            Locale::En => "Settings Contacts Transfers",
            Locale::Ja => {
                "\u{8a2d}\u{5b9a}\u{3000}\u{9023}\u{7d61}\u{5148}\u{3000}\u{8ee2}\u{9001}"
            }
            Locale::ZhCn => {
                "\u{8bbe}\u{7f6e}\u{3000}\u{8054}\u{7cfb}\u{4eba}\u{3000}\u{4f20}\u{8f93}"
            }
        }
    }

    /// Child process: one locale, fresh working set.
    #[test]
    #[ignore]
    fn font_probe_one() {
        let Ok(tag) = std::env::var("MIASMA_FONT_PROBE_LOCALE") else {
            return;
        };
        let loc = match tag.as_str() {
            "ja" => Locale::Ja,
            "zh" => Locale::ZhCn,
            _ => Locale::En,
        };
        let ctx = egui::Context::default();
        let base = working_set().unwrap_or(0);
        install(&ctx, loc);
        for _ in 0..2 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 600.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.label(sample(loc));
                    });
                },
            );
        }
        let after = working_set().unwrap_or(0);
        let mb = |b: u64| b as f64 / 1048576.0;
        println!(
            "PROBE locale={tag} base_mib={:.1} after_mib={:.1} delta_mib={:.1}",
            mb(base),
            mb(after),
            mb(after.saturating_sub(base))
        );
    }

    /// Parent: run the child once per locale so each measurement has its own process.
    #[test]
    #[ignore]
    fn font_memory_probe() {
        let exe = std::env::current_exe().unwrap();
        for tag in ["en", "ja", "zh"] {
            let out = std::process::Command::new(&exe)
                .args([
                    "fonts::mem_probe::font_probe_one",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MIASMA_FONT_PROBE_LOCALE", tag)
                .output()
                .unwrap();
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if line.starts_with("PROBE") {
                    println!("{line}");
                }
            }
        }
    }
}
