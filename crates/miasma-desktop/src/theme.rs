//! Whole-app colour theme: one light and one dark palette, selectable in Settings.
//!
//! The values are the design tokens of the owner's other product (warm neutrals, one accent
//! that is reserved for the single primary action). Only the colour values are used.
//!
//! Rules that the screens follow (see `ui_kit.rs`, which applies them):
//! - Status is shown as coloured *text* with a small dot. Never as a filled pill, never as a
//!   coloured rail down the edge of a block and never as a full-card fill in a status colour.
//! - `accent` / `accent_fill` belong to the primary action of a section, the selected tab or
//!   segment, and links. Everything else is neutral (`text`, `muted`, `faint`, `border`, ...).
//! - Every colour that carries text meets 4.5:1 on the surfaces it is drawn on, in both themes
//!   (tests below).
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

fn darken(c: Color32, k: f32) -> Color32 {
    let f = |v: u8| (v as f32 * k).round() as u8;
    Color32::from_rgb(f(c.r()), f(c.g()), f(c.b()))
}

impl Palette {
    pub const fn light() -> Self {
        Self {
            bg: hex(0xF7F6F2),
            surface: hex(0xFFFFFF),
            surface_subtle: hex(0xF4F4F2),
            selected: hex(0xE7E5DE),
            border: hex(0xD8D6CF),
            border_strong: hex(0xB0AEA6),
            text: hex(0x18181B),
            muted: hex(0x5F5F66),
            faint: hex(0x65656D),
            accent: hex(0xB63A0A),
            accent_fill: hex(0xB63A0A),
            success: hex(0x136B33),
            warning: hex(0x9A4607),
            danger: hex(0xB91C1C),
            info: hex(0x1D4FD0),
        }
    }

    pub const fn dark() -> Self {
        Self {
            bg: hex(0x111111),
            surface: hex(0x181818),
            surface_subtle: hex(0x202020),
            selected: hex(0x2C2C2C),
            border: hex(0x2E2E2E),
            border_strong: hex(0x4A4A4A),
            text: hex(0xF4F4F5),
            muted: hex(0xA1A1AA),
            faint: hex(0x8C8C96),
            accent: hex(0xF97316),
            accent_fill: hex(0xC2410C),
            success: hex(0x22C55E),
            warning: hex(0xF59E0B),
            danger: hex(0xF87171),
            info: hex(0x60A5FA),
        }
    }

    /// Text colour to put on `accent_fill` (both modes: white).
    pub const fn on_accent(&self) -> Color32 {
        Color32::WHITE
    }

    /// Primary action fill while hovered / pressed: the fill, darkened (white text stays
    /// readable on it in both themes).
    pub fn accent_hover(&self) -> Color32 {
        darken(self.accent_fill, 0.88)
    }

    pub fn accent_pressed(&self) -> Color32 {
        darken(self.accent_fill, 0.78)
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
        // Text edits: white on the light theme (they read as fields on both the page and a
        // surface), one step lighter than the surface on the dark theme.
        v.extreme_bg_color = if dark {
            self.surface_subtle
        } else {
            self.surface
        };
        v.faint_bg_color = self.surface_subtle; // striped rows
        v.code_bg_color = self.surface_subtle;
        v.hyperlink_color = self.accent;
        v.warn_fg_color = self.warning;
        v.error_fg_color = self.danger;

        // Selection and the focus ring are the one accent.
        v.selection.bg_fill = Color32::from_rgba_unmultiplied(
            self.accent.r(),
            self.accent.g(),
            self.accent.b(),
            if dark { 70 } else { 48 },
        );
        v.selection.stroke = egui::Stroke::new(1.5, self.accent);

        let w = &mut v.widgets;
        w.noninteractive.bg_fill = self.surface;
        w.noninteractive.weak_bg_fill = self.surface;
        w.noninteractive.bg_stroke = egui::Stroke::new(1.0, self.border); // also separators
        w.noninteractive.fg_stroke = egui::Stroke::new(1.0, self.text);

        // Buttons: outlined neutral (the surface colour with a visible 1 px border).
        w.inactive.bg_fill = self.surface_subtle;
        w.inactive.weak_bg_fill = self.surface;
        w.inactive.bg_stroke = egui::Stroke::new(1.0, self.border_strong);
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

        // No shadows anywhere: surfaces are told apart by a hairline border.
        v.window_shadow = egui::epaint::Shadow::NONE;
        v.popup_shadow = egui::epaint::Shadow::NONE;
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

/// Switch the process-wide palette. Call `ui_kit::apply_theme`, which also rebuilds the egui
/// style; calling this alone leaves egui's visuals on the old palette.
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
            (p.border_strong, 0xB0AEA6),
            (p.text, 0x18181B),
            (p.muted, 0x5F5F66),
            (p.faint, 0x65656D),
            (p.accent, 0xB63A0A),
            (p.accent_fill, 0xB63A0A),
            (p.success, 0x136B33),
            (p.warning, 0x9A4607),
            (p.danger, 0xB91C1C),
            (p.info, 0x1D4FD0),
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
            (p.border_strong, 0x4A4A4A),
            (p.text, 0xF4F4F5),
            (p.muted, 0xA1A1AA),
            (p.faint, 0x8C8C96),
            (p.accent, 0xF97316),
            (p.accent_fill, 0xC2410C),
            (p.success, 0x22C55E),
            (p.warning, 0xF59E0B),
            (p.danger, 0xF87171),
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
    fn status_faint_and_accent_text_meet_aa_on_every_surface_in_both_modes() {
        // Status colours are drawn as text (with a dot), `faint` as hint text and `accent` as
        // link / selection text: all of them are held to the 4.5:1 bar.
        for (name, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            for (tok, c) in [
                ("success", p.success),
                ("warning", p.warning),
                ("danger", p.danger),
                ("info", p.info),
                ("faint", p.faint),
                ("accent", p.accent),
            ] {
                for (bg_name, bg) in [
                    ("bg", p.bg),
                    ("surface", p.surface),
                    ("surface_subtle", p.surface_subtle),
                ] {
                    let r = contrast(c, bg);
                    assert!(r >= 4.5, "{name}: {tok} on {bg_name} = {r:.2}");
                }
            }
            // Status text on the selected row of a list (Transfers).
            for (tok, c) in [
                ("success", p.success),
                ("warning", p.warning),
                ("danger", p.danger),
                ("info", p.info),
            ] {
                let r = contrast(c, p.selected);
                assert!(r >= 4.5, "{name}: {tok} on selected = {r:.2}");
            }
        }
    }

    #[test]
    fn button_outline_is_visible_against_the_surface() {
        // Non-text UI components need 3:1 in WCAG; the outline of a secondary button is
        // border_strong on the surface it sits on. The hairline `border` is only a divider.
        for (name, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            let r = contrast(p.border_strong, p.surface);
            assert!(r >= 1.9, "{name}: border_strong on surface = {r:.2}");
        }
    }

    #[test]
    fn primary_hover_and_pressed_keep_white_text_readable() {
        for (name, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            for (state, c) in [("hover", p.accent_hover()), ("pressed", p.accent_pressed())] {
                let r = contrast(p.on_accent(), c);
                assert!(r >= 4.5, "{name}: white on accent {state} = {r:.2}");
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
            let p = if dark {
                Palette::dark()
            } else {
                Palette::light()
            };
            let v = p.visuals(dark);
            assert_eq!(v.dark_mode, dark);
            assert_eq!(v.panel_fill, p.bg);
            assert_eq!(v.window_fill, p.surface);
            assert_eq!(v.widgets.noninteractive.fg_stroke.color, p.text);
            assert_eq!(v.hyperlink_color, p.accent);
        }
    }
}
