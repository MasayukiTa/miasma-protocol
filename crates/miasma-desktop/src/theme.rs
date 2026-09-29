//! Whole-app colour theme: one light and one dark palette, selectable in Settings.
//!
//! The values are the design tokens of the owner's other product (warm neutrals, one accent
//! that is reserved for the single primary action). Only the colour values are used.
//!
//! Rules that the call sites in `app.rs` follow:
//! - Status is shown as a small chip and as coloured *text*. Never as a coloured rail down the
//!   edge of a block and never as a full-card fill in a status colour.
//! - `accent` / `accent_fill` belong to the one primary action of a screen. Everything else is
//!   neutral (`text`, `muted`, `faint`, `border`, ...).
//!
//! The current palette lives in a process-wide flag so any drawing code can read it cheaply with
//! [`palette`]. It is switched by [`set_dark`], which the app calls when the resolved theme
//! changes (mode change in Settings, or the OS theme changing while the mode is `System`).

use std::sync::atomic::{AtomicBool, Ordering};

use eframe::egui::{self, Color32};

/// User choice, persisted in `desktop-prefs.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    /// Follow the operating system (falls back to dark when the OS does not say).
    #[default]
    System,
    Light,
    Dark,
}

/// Colour tokens. See the module docs for how each one is meant to be used.
/// The full table is kept even where a token is not drawn yet (the transfers screen will use
/// `faint`, `border_strong` and `accent`).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// App background.
    pub bg: Color32,
    /// Cards and panels.
    pub surface: Color32,
    /// Inputs and the base of selected rows.
    pub surface_subtle: Color32,
    /// Selected row.
    pub selected: Color32,
    /// 1 px borders.
    pub border: Color32,
    /// Hover / active borders.
    pub border_strong: Color32,
    /// Body text.
    pub text: Color32,
    /// Secondary text.
    pub muted: Color32,
    /// Meta text (timestamps, hints). Lower contrast than `muted`: never for anything needed to act.
    pub faint: Color32,
    /// Text/outline colour of the primary action.
    pub accent: Color32,
    /// Fill of the primary action; carries white text.
    pub accent_fill: Color32,
    /// Done.
    pub success: Color32,
    /// Paused / needs attention.
    pub warning: Color32,
    /// Error.
    pub danger: Color32,
    /// Running / in progress.
    pub info: Color32,
}

/// `0xRRGGBB` to an opaque colour.
const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

impl Palette {
    pub const fn light() -> Self {
        Self {
            bg: hex(0xF7F6F2),
            surface: hex(0xFFFFFF),
            surface_subtle: hex(0xF4F4F2),
            selected: hex(0xE7E5DE),
            border: hex(0xD8D6CF),
            border_strong: hex(0xD4D4D0),
            text: hex(0x18181B),
            muted: hex(0x5F5F66),
            faint: hex(0x6B6B73),
            accent: hex(0xC4400D),
            accent_fill: hex(0xC4400D),
            success: hex(0x15803D),
            warning: hex(0xB45309),
            danger: hex(0xB91C1C),
            info: hex(0x2563EB),
        }
    }

    pub const fn dark() -> Self {
        Self {
            bg: hex(0x111111),
            surface: hex(0x181818),
            surface_subtle: hex(0x202020),
            selected: hex(0x2C2C2C),
            border: hex(0x2E2E2E),
            border_strong: hex(0x3A3A3A),
            text: hex(0xF4F4F5),
            muted: hex(0xA1A1AA),
            faint: hex(0x71717A),
            accent: hex(0xF97316),
            accent_fill: hex(0xC2410C),
            success: hex(0x22C55E),
            warning: hex(0xF59E0B),
            danger: hex(0xEF4444),
            info: hex(0x60A5FA),
        }
    }

    /// Text colour to put on `accent_fill` (both modes: white).
    pub const fn on_accent(&self) -> Color32 {
        Color32::WHITE
    }

    /// Build the egui visuals for this palette.
    pub fn visuals(&self, dark: bool) -> egui::Visuals {
        let mut v = if dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        v.dark_mode = dark;
        v.override_text_color = None;

        v.panel_fill = self.bg;
        v.window_fill = self.surface;
        v.window_stroke = egui::Stroke::new(1.0, self.border);
        v.extreme_bg_color = self.surface_subtle; // text edit / scroll area background
        v.faint_bg_color = self.surface_subtle; // striped rows
        v.code_bg_color = self.surface_subtle;
        v.hyperlink_color = self.info;
        v.warn_fg_color = self.warning;
        v.error_fg_color = self.danger;

        // Selection is neutral: the accent belongs to the primary action only.
        v.selection.bg_fill = self.selected;
        v.selection.stroke = egui::Stroke::new(1.0, self.text);

        let w = &mut v.widgets;
        w.noninteractive.bg_fill = self.surface;
        w.noninteractive.weak_bg_fill = self.surface;
        w.noninteractive.bg_stroke = egui::Stroke::new(1.0, self.border); // also separators
        w.noninteractive.fg_stroke = egui::Stroke::new(1.0, self.text);

        w.inactive.bg_fill = self.surface_subtle;
        w.inactive.weak_bg_fill = self.surface_subtle;
        w.inactive.bg_stroke = egui::Stroke::new(1.0, self.border);
        w.inactive.fg_stroke = egui::Stroke::new(1.0, self.text);

        w.hovered.bg_fill = self.selected;
        w.hovered.weak_bg_fill = self.selected;
        w.hovered.bg_stroke = egui::Stroke::new(1.0, self.border_strong);
        w.hovered.fg_stroke = egui::Stroke::new(1.5, self.text);

        w.active.bg_fill = self.selected;
        w.active.weak_bg_fill = self.selected;
        w.active.bg_stroke = egui::Stroke::new(1.0, self.border_strong);
        w.active.fg_stroke = egui::Stroke::new(2.0, self.text);

        w.open.bg_fill = self.selected;
        w.open.weak_bg_fill = self.selected;
        w.open.bg_stroke = egui::Stroke::new(1.0, self.border_strong);
        w.open.fg_stroke = egui::Stroke::new(1.0, self.text);

        // Rounder controls.
        w.inactive.rounding = egui::Rounding::same(6.0);
        w.hovered.rounding = egui::Rounding::same(6.0);
        w.active.rounding = egui::Rounding::same(6.0);
        w.open.rounding = egui::Rounding::same(6.0);
        w.noninteractive.rounding = egui::Rounding::same(4.0);
        v.window_rounding = egui::Rounding::same(8.0);

        // Softer shadows on the light theme (the egui default is tuned for dark).
        if !dark {
            v.window_shadow.color = Color32::from_black_alpha(28);
            v.popup_shadow.color = Color32::from_black_alpha(28);
        }
        v
    }
}

static DARK: AtomicBool = AtomicBool::new(true);

/// The palette currently in force. Cheap: one relaxed atomic load.
pub fn palette() -> Palette {
    if DARK.load(Ordering::Relaxed) {
        Palette::dark()
    } else {
        Palette::light()
    }
}

/// Whether the dark palette is in force.
#[allow(dead_code)]
pub fn is_dark() -> bool {
    DARK.load(Ordering::Relaxed)
}

/// Switch the process-wide palette. The caller must also `ctx.set_visuals(...)`; use [`apply`].
pub fn set_dark(dark: bool) {
    DARK.store(dark, Ordering::Relaxed);
}

/// Decide dark/light from the user's choice and what the OS reports.
/// `system == None` (the OS gave no answer) resolves to dark.
pub fn resolve_dark(mode: ThemeMode, system: Option<eframe::Theme>) -> bool {
    match mode {
        ThemeMode::Dark => true,
        ThemeMode::Light => false,
        ThemeMode::System => !matches!(system, Some(eframe::Theme::Light)),
    }
}

/// Make `dark` the current palette and rebuild the egui visuals from it.
pub fn apply(ctx: &egui::Context, dark: bool) {
    set_dark(dark);
    ctx.set_visuals(palette().visuals(dark));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb(c: Color32) -> u32 {
        ((c.r() as u32) << 16) | ((c.g() as u32) << 8) | c.b() as u32
    }

    /// WCAG 2.x relative luminance.
    fn luminance(c: Color32) -> f64 {
        let f = |v: u8| {
            let x = v as f64 / 255.0;
            if x <= 0.03928 {
                x / 12.92
            } else {
                ((x + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn light_tokens_match_the_plan_table() {
        let p = Palette::light();
        let want = [
            (p.bg, 0xF7F6F2),
            (p.surface, 0xFFFFFF),
            (p.surface_subtle, 0xF4F4F2),
            (p.selected, 0xE7E5DE),
            (p.border, 0xD8D6CF),
            (p.border_strong, 0xD4D4D0),
            (p.text, 0x18181B),
            (p.muted, 0x5F5F66),
            (p.faint, 0x6B6B73),
            (p.accent, 0xC4400D),
            (p.accent_fill, 0xC4400D),
            (p.success, 0x15803D),
            (p.warning, 0xB45309),
            (p.danger, 0xB91C1C),
            (p.info, 0x2563EB),
        ];
        for (i, (got, exp)) in want.iter().enumerate() {
            assert_eq!(rgb(*got), *exp, "light token #{i}");
        }
    }

    #[test]
    fn dark_tokens_match_the_plan_table() {
        let p = Palette::dark();
        let want = [
            (p.bg, 0x111111),
            (p.surface, 0x181818),
            (p.surface_subtle, 0x202020),
            (p.selected, 0x2C2C2C),
            (p.border, 0x2E2E2E),
            (p.border_strong, 0x3A3A3A),
            (p.text, 0xF4F4F5),
            (p.muted, 0xA1A1AA),
            (p.faint, 0x71717A),
            (p.accent, 0xF97316),
            (p.accent_fill, 0xC2410C),
            (p.success, 0x22C55E),
            (p.warning, 0xF59E0B),
            (p.danger, 0xEF4444),
            (p.info, 0x60A5FA),
        ];
        for (i, (got, exp)) in want.iter().enumerate() {
            assert_eq!(rgb(*got), *exp, "dark token #{i}");
        }
    }

    #[test]
    fn text_and_muted_meet_wcag_aa_on_every_surface_in_both_modes() {
        for (name, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            for (bg_name, bg) in [
                ("bg", p.bg),
                ("surface", p.surface),
                ("surface_subtle", p.surface_subtle),
                ("selected", p.selected),
            ] {
                let t = contrast(p.text, bg);
                let m = contrast(p.muted, bg);
                assert!(t >= 4.5, "{name}: text on {bg_name} = {t:.2}");
                assert!(m >= 4.5, "{name}: muted on {bg_name} = {m:.2}");
            }
        }
    }

    #[test]
    fn white_on_accent_fill_is_readable_in_both_modes() {
        for (name, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            let c = contrast(p.on_accent(), p.accent_fill);
            assert!(c >= 4.5, "{name}: white on accent_fill = {c:.2}");
        }
    }

    #[test]
    fn status_text_is_readable_on_bg_and_surface() {
        // Status colours are used as text and as small chips: hold them to the AA bar for
        // large / bold text (3.0) on the two surfaces they are drawn on.
        for (name, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            for (tok, c) in [
                ("success", p.success),
                ("warning", p.warning),
                ("danger", p.danger),
                ("info", p.info),
            ] {
                for (bg_name, bg) in [("bg", p.bg), ("surface", p.surface)] {
                    let r = contrast(c, bg);
                    assert!(r >= 3.0, "{name}: {tok} on {bg_name} = {r:.2}");
                }
            }
        }
    }

    #[test]
    fn theme_mode_serde_roundtrip() {
        for (m, s) in [
            (ThemeMode::System, "system"),
            (ThemeMode::Light, "light"),
            (ThemeMode::Dark, "dark"),
        ] {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(json, format!("\"{s}\""));
            let back: ThemeMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, m);
        }
        assert_eq!(ThemeMode::default(), ThemeMode::System);
    }

    #[test]
    fn resolve_follows_choice_then_system_then_dark() {
        use eframe::Theme;
        assert!(resolve_dark(ThemeMode::Dark, Some(Theme::Light)));
        assert!(!resolve_dark(ThemeMode::Light, Some(Theme::Dark)));
        assert!(!resolve_dark(ThemeMode::System, Some(Theme::Light)));
        assert!(resolve_dark(ThemeMode::System, Some(Theme::Dark)));
        // OS gave no answer: dark.
        assert!(resolve_dark(ThemeMode::System, None));
    }

    #[test]
    fn visuals_follow_the_palette() {
        for dark in [true, false] {
            let p = if dark { Palette::dark() } else { Palette::light() };
            let v = p.visuals(dark);
            assert_eq!(v.dark_mode, dark);
            assert_eq!(v.panel_fill, p.bg);
            assert_eq!(v.window_fill, p.surface);
            assert_eq!(v.widgets.noninteractive.fg_stroke.color, p.text);
            assert_eq!(v.hyperlink_color, p.info);
        }
    }
}
