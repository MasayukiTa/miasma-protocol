//! The desktop UI kit: one place that decides how Miasma looks.
//!
//! Every screen is built from these pieces, so widths, spacing, type sizes and colours cannot
//! drift from tab to tab. Colour *values* live in `theme.rs`; this module decides how they are
//! used. The rules (also in the PR description):
//!
//! 1. **One column.** A page is one column, at most [`COLUMN_MAX`] wide, centred when the window
//!    is wider. Every section, surface, row and table fills that column exactly, so left and
//!    right edges line up down the whole page. Nothing shrinks to its content.
//! 2. **Structure.** Plain sections (title, hairline, content). The only framed container is
//!    [`surface`] and it is for the one primary task of a page (a form). No nesting, no shadows.
//! 3. **Type scale.** Page title 22, section title 16, body 14, hint/label 12.5, mono 13. egui
//!    cannot synthesise a bold weight, so hierarchy is size and colour only.
//! 4. **Colour.** Neutral surfaces. One accent, for the primary action, the selected tab or
//!    segment and links. Status colours appear only as text and a small dot ([`status_dot`]).
//! 5. **Controls.** One primary button per section ([`primary`]); everything else is outlined
//!    ([`secondary_button`]); destructive is neutral with danger text ([`danger_button`]).
//!    Buttons and text edits are all [`CONTROL_H`] tall.
//! 6. **Spacing.** 4 / 8 / 12 / 16 / 24 only ([`SP_1`] to [`SP_5`]).

use std::sync::OnceLock;

use eframe::egui::{
    self, vec2, Color32, FontId, InnerResponse, Label, Layout, Response, RichText, Sense, Stroke,
    TextStyle, Ui, WidgetText,
};

use crate::theme::{self, Palette};

// ─── Tokens ─────────────────────────────────────────────────────────────────

/// Spacing scale (px).
pub const SP_1: f32 = 4.0;
pub const SP_2: f32 = 8.0;
pub const SP_3: f32 = 12.0;
pub const SP_4: f32 = 16.0;
pub const SP_5: f32 = 24.0;

/// Widest a page column gets. Wider windows centre it.
pub const COLUMN_MAX: f32 = 920.0;
/// Space between the window edge and the column.
pub const PAGE_MARGIN_X: f32 = SP_5;
/// Width of the label column of key-value grids and forms.
pub const LABEL_W: f32 = 168.0;
/// Height of every button and single-line text edit.
pub const CONTROL_H: f32 = 30.0;
/// Height of an inline (compact) button such as Copy.
pub const COMPACT_H: f32 = 24.0;
/// Narrowest a regular button gets, so a row of buttons looks like a row.
pub const BTN_MIN_W: f32 = 96.0;

const SURFACE_ROUNDING: f32 = 8.0;

/// The palette in force.
pub fn pal() -> Palette {
    theme::palette()
}

// ─── Theme and text styles ──────────────────────────────────────────────────

fn section_style() -> TextStyle {
    static S: OnceLock<TextStyle> = OnceLock::new();
    S.get_or_init(|| TextStyle::Name("Section".into())).clone()
}

/// Make `dark` the colour palette in force and (re)build visuals, type scale and spacing.
/// The single place where egui's global style is set.
pub fn apply_theme(ctx: &egui::Context, dark: bool) {
    theme::set_dark(dark);
    let p = theme::palette();
    let mut style = (*ctx.style()).clone();
    style.visuals = p.visuals(dark);

    // Type scale. Meiryo (see fonts.rs) is tall with a generous line gap, which already gives
    // Japanese text its ~1.5 line height; sizes are chosen so nothing is below 12.5 px.
    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(22.0)),
        (section_style(), FontId::proportional(16.0)),
        (TextStyle::Body, FontId::proportional(14.0)),
        (TextStyle::Button, FontId::proportional(14.0)),
        (TextStyle::Small, FontId::proportional(12.5)),
        (TextStyle::Monospace, FontId::monospace(13.0)),
    ]
    .into();

    style.spacing.item_spacing = vec2(SP_2, SP_2);
    style.spacing.button_padding = vec2(SP_4, 6.0);
    style.spacing.window_margin = egui::Margin::same(SP_4);
    style.spacing.interact_size = vec2(40.0, CONTROL_H);
    style.spacing.indent = SP_4;
    ctx.set_style(style);
}

// ─── Status levels ──────────────────────────────────────────────────────────

/// What a status means. Drawn as coloured text and a small dot, never as a filled pill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Error,
    /// In progress.
    Info,
    /// Neutral / inactive.
    Muted,
}

pub fn level_color(level: Level) -> Color32 {
    let p = pal();
    match level {
        Level::Ok => p.success,
        Level::Warn => p.warning,
        Level::Error => p.danger,
        Level::Info => p.info,
        Level::Muted => p.muted,
    }
}

// ─── Text ───────────────────────────────────────────────────────────────────

/// Secondary text (labels, descriptions) at body size.
pub fn muted_text(text: impl Into<String>) -> RichText {
    RichText::new(text).color(pal().muted)
}

/// A hint under a control or a block: small, muted, wraps.
pub fn hint(ui: &mut Ui, text: &str) -> Response {
    ui.add(Label::new(RichText::new(text).small().color(pal().muted)).wrap(true))
}

/// A wrapped body paragraph in `muted`.
pub fn paragraph_muted(ui: &mut Ui, text: &str) -> Response {
    ui.add(Label::new(muted_text(text)).wrap(true))
}

/// A wrapped body paragraph in the normal text colour.
pub fn paragraph(ui: &mut Ui, text: &str) -> Response {
    ui.add(Label::new(RichText::new(text).color(pal().text)).wrap(true))
}

/// An identifier, path or hash: monospace, wraps instead of overflowing, selectable.
pub fn mono(ui: &mut Ui, text: &str) -> Response {
    ui.add(Label::new(RichText::new(text).monospace().color(pal().text)).wrap(true))
}

/// An identifier with a Copy button after it (wrapping to the next line when it must).
/// Puts `text` on the clipboard and returns true when the button was pressed.
pub fn mono_copy(ui: &mut Ui, text: &str, copy_label: &str) -> bool {
    mono_copy_labelled(ui, text, text, copy_label)
}

/// [`mono_copy`] where the text shown differs from the text copied.
pub fn mono_copy_labelled(ui: &mut Ui, shown: &str, copied: &str, copy_label: &str) -> bool {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(shown).monospace().color(pal().text));
        let clicked = ui.add(compact_button(copy_label)).clicked();
        if clicked {
            ui.output_mut(|o| o.copied_text = copied.to_owned());
        }
        clicked
    })
    .inner
}

/// Like [`mono`] but on one line, cut with an ellipsis; the whole text is the tooltip.
pub fn mono_elided(ui: &mut Ui, text: &str) -> Response {
    ui.add(Label::new(RichText::new(text).monospace().color(pal().text)).truncate(true))
        .on_hover_text(text)
}

/// Section-title text (16 px, normal colour), for places that lay the title out themselves.
pub fn section_text(text: impl Into<String>) -> RichText {
    RichText::new(text)
        .text_style(section_style())
        .color(pal().text)
}

/// A small dot followed by text, both in the status colour.
pub fn status_dot(ui: &mut Ui, level: Level, text: &str) -> Response {
    // Text is coloured only when it asks for attention (warning, error); "fine", "in
    // progress" and "inactive" keep the normal text colour and let the dot carry the status.
    let text_color = match level {
        Level::Warn | Level::Error => level_color(level),
        Level::Ok | Level::Info | Level::Muted => pal().text,
    };
    dot_line(ui, level_color(level), text_color, text)
}

/// [`status_dot`] for a colour that is already chosen. Drawn in one piece (not as a
/// `horizontal`), so it is as tall as its text, lines up with a label beside it, and keeps its
/// dot-then-text order inside a right-to-left layout too.
pub fn dot_text(ui: &mut Ui, color: Color32, text: &str) -> Response {
    dot_line(ui, color, color, text)
}

fn dot_line(ui: &mut Ui, dot: Color32, text_color: Color32, text: &str) -> Response {
    const DOT_W: f32 = 14.0;
    let font = TextStyle::Body.resolve(ui.style());
    let wrap = (ui.available_width() - DOT_W).max(40.0);
    let galley = ui.fonts(|f| f.layout(text.to_owned(), font, text_color, wrap));
    let (rect, resp) = ui.allocate_exact_size(
        vec2(DOT_W + galley.size().x, galley.size().y),
        Sense::hover(),
    );
    if ui.is_rect_visible(rect) {
        let first_line = galley
            .rows
            .first()
            .map_or(galley.size().y, |r| r.rect.height());
        ui.painter().circle_filled(
            egui::pos2(rect.left() + 4.0, rect.top() + first_line * 0.5),
            4.0,
            dot,
        );
        ui.painter().galley(
            egui::pos2(rect.left() + DOT_W, rect.top()),
            galley,
            text_color,
        );
    }
    resp
}

/// A big status line: a larger dot and a title-sized sentence.
pub fn status_headline(ui: &mut Ui, level: Level, text: &str) {
    let color = level_color(level);
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(12.0, 12.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 6.0, color);
        ui.add(
            Label::new(
                RichText::new(text)
                    .text_style(TextStyle::Heading)
                    .color(color),
            )
            .wrap(true),
        );
    });
}

/// A status sentence with the dot aligned to its first line. Wraps.
pub fn notice(ui: &mut Ui, level: Level, text: &str) {
    let color = level_color(level);
    ui.horizontal_top(|ui| {
        let h = ui.text_style_height(&TextStyle::Body);
        let (rect, _) = ui.allocate_exact_size(vec2(8.0, h), Sense::hover());
        ui.painter()
            .circle_filled(egui::pos2(rect.center().x, rect.center().y), 4.0, color);
        ui.add(Label::new(RichText::new(text).color(color)).wrap(true));
    });
}

// ─── Layout ─────────────────────────────────────────────────────────────────

/// A hairline across the column.
pub fn divider(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0.0, pal().border);
}

/// Distance from the window edge to the page column at a window `width` (side margin, or more
/// when the window is wider than the column).
pub fn column_edge(width: f32) -> f32 {
    ((width - COLUMN_MAX) * 0.5).max(PAGE_MARGIN_X).floor()
}

/// The page column: [`COLUMN_MAX`] wide at most, centred, with side margins and a top and bottom
/// margin. Everything a tab draws goes inside it.
pub fn column(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    let avail = ui.available_width();
    let w = (avail - 2.0 * PAGE_MARGIN_X).clamp(0.0, COLUMN_MAX);
    let pad = ((avail - w) * 0.5).floor();
    let spacing = ui.spacing().item_spacing;
    ui.add_space(SP_5);
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.add_space(pad);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing = spacing;
            ui.set_width(w);
            add(ui);
        });
    });
    ui.add_space(SP_5);
}

/// A page: title, optional description, then the body.
pub fn page<R>(
    ui: &mut Ui,
    title: &str,
    subtitle: Option<&str>,
    body: impl FnOnce(&mut Ui) -> R,
) -> R {
    page_actions(ui, title, subtitle, |_| {}, body)
}

/// A page whose title row carries actions on the right.
pub fn page_actions<R>(
    ui: &mut Ui,
    title: &str,
    subtitle: Option<&str>,
    actions: impl FnOnce(&mut Ui),
    body: impl FnOnce(&mut Ui) -> R,
) -> R {
    ui.horizontal(|ui| {
        ui.add(
            Label::new(
                RichText::new(title)
                    .text_style(TextStyle::Heading)
                    .color(pal().text),
            )
            .truncate(true),
        );
        ui.with_layout(Layout::right_to_left(egui::Align::Center), actions);
    });
    if let Some(sub) = subtitle {
        paragraph_muted(ui, sub);
    }
    ui.add_space(SP_3);
    body(ui)
}

/// A plain section: title, hairline, content, and the gap to the next section.
pub fn section<R>(ui: &mut Ui, title: &str, body: impl FnOnce(&mut Ui) -> R) -> R {
    section_actions(ui, title, |_| {}, body)
}

/// A section whose title row carries actions on the right.
pub fn section_actions<R>(
    ui: &mut Ui,
    title: &str,
    actions: impl FnOnce(&mut Ui),
    body: impl FnOnce(&mut Ui) -> R,
) -> R {
    ui.horizontal(|ui| {
        ui.add(
            Label::new(
                RichText::new(title)
                    .text_style(section_style())
                    .color(pal().text),
            )
            .truncate(true),
        );
        ui.with_layout(Layout::right_to_left(egui::Align::Center), actions);
    });
    divider(ui);
    ui.add_space(SP_1);
    let r = body(ui);
    ui.add_space(SP_4);
    r
}

/// The one framed container: the primary task of a page. Fills the column width. Callers that
/// need a custom frame (contacts, until it adopts the kit) get the same one via
/// [`card_frame`].
pub fn surface<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> InnerResponse<R> {
    surface_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui)
    })
}

fn surface_frame() -> egui::Frame {
    egui::Frame::none()
        .inner_margin(egui::Margin::same(SP_4))
        .rounding(SURFACE_ROUNDING)
        .fill(pal().surface)
        .stroke(Stroke::new(1.0, pal().border))
}

/// Compatibility for screens that still say `card_frame().show(ui, ..)`: the same as
/// [`surface`] (full column width), with the old builder-style entry point.
pub fn card_frame() -> Surface {
    Surface
}

/// See [`card_frame`].
pub struct Surface;

impl Surface {
    pub fn show<R>(self, ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> InnerResponse<R> {
        surface(ui, add)
    }
}

/// A page heading for screens that draw their own body: the same as a page title row plus the
/// hairline the old screens had.
pub fn section_heading(ui: &mut Ui, text: &str) {
    ui.add(
        Label::new(
            RichText::new(text)
                .text_style(TextStyle::Heading)
                .color(pal().text),
        )
        .truncate(true),
    );
}

/// A list item: hairline above, content, breathing room below.
pub fn list_item<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    divider(ui);
    ui.add_space(SP_1);
    let r = add(ui);
    ui.add_space(SP_1);
    r
}

/// A row of buttons: consistent gap, left aligned.
pub fn button_row<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(SP_2, SP_2);
        add(ui)
    })
    .inner
}

// ─── Key-value grid and forms ───────────────────────────────────────────────

/// Aligned label / value rows with a fixed label column ([`LABEL_W`]). The value column takes
/// the rest of the width, so long values wrap and never push the page sideways.
pub struct Kv<'a> {
    ui: &'a mut Ui,
}

/// Key-value rows. `grid.row("Label:", |ui| ...)`.
pub fn kv_grid<R>(ui: &mut Ui, add: impl FnOnce(&mut Kv) -> R) -> R {
    let mut kv = Kv { ui };
    add(&mut kv)
}

impl Kv<'_> {
    pub fn row<R>(&mut self, label: &str, value: impl FnOnce(&mut Ui) -> R) -> R {
        labelled_row(self.ui, label, true, value)
    }

    /// A row whose value is plain text.
    pub fn text(&mut self, label: &str, value: &str) {
        self.row(label, |ui| paragraph(ui, value));
    }

    /// A row whose value is an identifier or a path.
    pub fn mono(&mut self, label: &str, value: &str) {
        self.row(label, |ui| mono(ui, value));
    }
}

/// Label column plus value column, top aligned. `muted_label` is for read-only values.
fn labelled_row<R>(
    ui: &mut Ui,
    label: &str,
    muted_label: bool,
    value: impl FnOnce(&mut Ui) -> R,
) -> R {
    let total = ui.available_width();
    let value_w = (total - LABEL_W).max(80.0);
    let spacing = ui.spacing().item_spacing;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.allocate_ui_with_layout(
            vec2(LABEL_W, 0.0),
            Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_width(LABEL_W - SP_3);
                if !label.is_empty() {
                    let color = if muted_label { pal().muted } else { pal().text };
                    ui.add(Label::new(RichText::new(label).color(color)).wrap(true));
                }
            },
        );
        ui.add_space(SP_3);
        ui.allocate_ui_with_layout(
            vec2(value_w, 0.0),
            Layout::top_down(egui::Align::Min),
            |ui| {
                ui.spacing_mut().item_spacing = spacing;
                ui.set_width(value_w);
                value(ui)
            },
        )
        .inner
    })
    .inner
}

/// A form row: label column, control, and an optional hint under the control. The label is
/// centred on the first control line so it sits next to the control, not above it.
pub fn form_row<R>(
    ui: &mut Ui,
    label: &str,
    hint_text: Option<&str>,
    control: impl FnOnce(&mut Ui) -> R,
) -> R {
    let total = ui.available_width();
    let value_w = (total - LABEL_W).max(80.0);
    let spacing = ui.spacing().item_spacing;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.allocate_ui_with_layout(
            vec2(LABEL_W, 0.0),
            Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_width(LABEL_W - SP_3);
                if !label.is_empty() {
                    let line = ui.text_style_height(&TextStyle::Body);
                    ui.add_space(((CONTROL_H - line) * 0.5).max(0.0));
                    ui.add(Label::new(RichText::new(label).color(pal().text)).wrap(true));
                }
            },
        );
        ui.add_space(SP_3);
        ui.allocate_ui_with_layout(
            vec2(value_w, 0.0),
            Layout::top_down(egui::Align::Min),
            |ui| {
                ui.spacing_mut().item_spacing = spacing;
                ui.set_width(value_w);
                let r = control(ui);
                if let Some(h) = hint_text {
                    hint(ui, h);
                }
                r
            },
        )
        .inner
    })
    .inner
}

/// The action row under a form, aligned with the controls (not with the labels).
pub fn form_actions<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.add_space(LABEL_W);
        ui.spacing_mut().item_spacing.x = SP_2;
        add(ui)
    })
    .inner
}

// ─── Controls ───────────────────────────────────────────────────────────────

/// A single-line text edit at the standard height. Chain `.desired_width(..)` /
/// `.hint_text(..)` / `.password(true)` as usual; the default fills the available width.
pub fn input(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text)
        .margin(vec2(SP_2, 5.0))
        .min_size(vec2(0.0, CONTROL_H))
        .desired_width(f32::INFINITY)
}

/// [`input`] in the monospace font (identifiers, addresses). The vertical margin is larger
/// because the monospace line is shorter, so the box is still [`CONTROL_H`] tall.
pub fn input_mono(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text)
        .font(TextStyle::Monospace)
        .margin(vec2(SP_2, 6.5))
        .min_size(vec2(0.0, CONTROL_H))
        .desired_width(f32::INFINITY)
}

/// A multi-line text edit with the same look.
pub fn input_multiline(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::multiline(text)
        .margin(vec2(SP_2, SP_2))
        .desired_width(f32::INFINITY)
}

/// Width for a text edit that shares its row with one regular button: what is left after the
/// button, the gap and the edit's own horizontal margins (egui does not count those in
/// `desired_width`).
pub fn input_width_beside_button(ui: &Ui) -> f32 {
    (ui.available_width() - BTN_MIN_W - SP_2 - 2.0 * SP_2).max(120.0)
}

/// The primary action button, as a widget (accent fill, white text). Prefer [`primary`], which
/// also handles the disabled look and hover colour.
pub fn primary_button<'a>(text: impl Into<WidgetText>) -> egui::Button<'a> {
    let text: WidgetText = text.into();
    egui::Button::new(text.color(pal().on_accent()))
        .fill(pal().accent_fill)
        .stroke(Stroke::NONE)
        .min_size(vec2(BTN_MIN_W, CONTROL_H))
}

/// The one primary action of a section. Disabled, it falls back to the neutral outlined style
/// instead of a washed-out accent.
pub fn primary(ui: &mut Ui, enabled: bool, text: &str) -> Response {
    if !enabled {
        return ui.add_enabled(false, secondary_button(text));
    }
    let p = pal();
    ui.scope(|ui| {
        let w = &mut ui.visuals_mut().widgets;
        for (state, fill) in [
            (&mut w.inactive, p.accent_fill),
            (&mut w.hovered, p.accent_hover()),
            (&mut w.active, p.accent_pressed()),
        ] {
            state.weak_bg_fill = fill;
            state.bg_fill = fill;
            state.bg_stroke = Stroke::NONE;
            state.fg_stroke = Stroke::new(1.0, p.on_accent());
        }
        ui.add(egui::Button::new(text).min_size(vec2(BTN_MIN_W, CONTROL_H)))
    })
    .inner
}

/// An outlined neutral button.
pub fn secondary_button<'a>(text: impl Into<WidgetText>) -> egui::Button<'a> {
    egui::Button::new(text).min_size(vec2(BTN_MIN_W, CONTROL_H))
}

/// A destructive action: neutral button, danger-coloured text. Callers confirm first.
pub fn danger_button<'a>(text: impl Into<String>) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).color(pal().danger)).min_size(vec2(BTN_MIN_W, CONTROL_H))
}

/// A small inline button (Copy, Refresh next to a title).
pub fn compact_button<'a>(text: impl Into<String>) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).small())
        .small()
        .min_size(vec2(56.0, COMPACT_H))
}

/// Segmented choice: a row of mutually exclusive options; the selected one gets an accent
/// outline. Returns true when the choice changed.
pub fn segmented<T: Copy + PartialEq>(ui: &mut Ui, current: &mut T, options: &[(T, &str)]) -> bool {
    let p = pal();
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = SP_1;
        for (value, label) in options {
            let selected = *current == *value;
            let mut button = egui::Button::new(RichText::new(*label).color(p.text))
                .min_size(vec2(72.0, CONTROL_H));
            if selected {
                button = button.fill(p.selected).stroke(Stroke::new(1.5, p.accent));
            }
            if ui.add(button).clicked() && !selected {
                *current = *value;
                changed = true;
            }
        }
    });
    changed
}

/// A top-level navigation tab: muted text, the selected one in the text colour with an accent
/// underline.
pub fn nav_tab(ui: &mut Ui, selected: bool, label: &str) -> Response {
    let p = pal();
    let font = TextStyle::Body.resolve(ui.style());
    let color = if selected { p.text } else { p.muted };
    let galley = ui.fonts(|f| f.layout_no_wrap(label.to_owned(), font, color));
    let size = vec2(galley.size().x + 2.0 * SP_3, 34.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if resp.hovered() && !selected {
            painter.rect_filled(
                rect.shrink2(vec2(0.0, 3.0)),
                6.0,
                p.text.gamma_multiply(0.06),
            );
        }
        painter.galley(
            egui::pos2(
                rect.center().x - galley.size().x * 0.5,
                rect.center().y - galley.size().y * 0.5,
            ),
            galley,
            color,
        );
        if selected {
            let underline = egui::Rect::from_min_max(
                egui::pos2(rect.left() + SP_2, rect.bottom() - 2.0),
                egui::pos2(rect.right() - SP_2, rect.bottom()),
            );
            painter.rect_filled(underline, 1.0, p.accent);
        }
    }
    resp
}

/// A thin determinate bar across the available width. Neutral; turns to the warning colour when
/// `warn`.
pub fn progress(ui: &mut Ui, fraction: f32, warn: bool) {
    let p = pal();
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 6.0), Sense::hover());
    ui.painter().rect_filled(rect, 3.0, p.border);
    let w = rect.width() * fraction.clamp(0.0, 1.0);
    if w > 0.5 {
        let fill = egui::Rect::from_min_size(rect.min, vec2(w.max(3.0), rect.height()));
        ui.painter()
            .rect_filled(fill, 3.0, if warn { p.warning } else { p.muted });
    }
}

/// A row of big numbers with small captions, equal columns across the column width.
pub fn stats(ui: &mut Ui, items: &[(&str, String, Level)]) {
    let n = items.len().max(1) as f32;
    let w = ui.available_width() / n;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (label, value, level) in items {
            ui.allocate_ui_with_layout(vec2(w, 0.0), Layout::top_down(egui::Align::Min), |ui| {
                ui.set_width(w - SP_2);
                hint(ui, label);
                let color = if *level == Level::Muted {
                    pal().text
                } else {
                    level_color(*level)
                };
                ui.label(
                    RichText::new(value)
                        .text_style(TextStyle::Heading)
                        .color(color),
                );
            });
        }
    });
}

// ─── Tables ─────────────────────────────────────────────────────────────────

/// Column widths for a table, as fractions of the available width.
pub struct Table {
    widths: Vec<f32>,
}

/// Start a table whose columns take `fractions` of the width (they should sum to 1).
pub fn table(ui: &Ui, fractions: &[f32]) -> Table {
    let total = ui.available_width();
    Table {
        widths: fractions.iter().map(|f| (total * f).floor()).collect(),
    }
}

/// The cells of one table row.
pub struct Cells<'a> {
    ui: &'a mut Ui,
    widths: &'a [f32],
    spacing: egui::Vec2,
    index: usize,
}

impl Table {
    /// Header row: small muted captions.
    pub fn header(&self, ui: &mut Ui, captions: &[&str]) {
        self.row(ui, false, |cells| {
            for c in captions {
                cells.add(|ui| {
                    ui.label(RichText::new(*c).small().color(pal().muted));
                });
            }
        });
    }

    /// A body row, with a hairline above it.
    pub fn row(&self, ui: &mut Ui, separator: bool, add: impl FnOnce(&mut Cells)) {
        if separator {
            divider(ui);
        }
        let spacing = ui.spacing().item_spacing;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            let mut cells = Cells {
                ui,
                widths: &self.widths,
                spacing,
                index: 0,
            };
            add(&mut cells);
        });
    }
}

impl Cells<'_> {
    /// Next cell.
    pub fn add(&mut self, content: impl FnOnce(&mut Ui)) {
        let w = self.widths.get(self.index).copied().unwrap_or(80.0);
        self.index += 1;
        let spacing = self.spacing;
        self.ui
            .allocate_ui_with_layout(vec2(w, 0.0), Layout::top_down(egui::Align::Min), |ui| {
                ui.spacing_mut().item_spacing = spacing;
                ui.set_width((w - SP_2).max(10.0));
                content(ui);
            });
    }

    pub fn text(&mut self, text: &str) {
        self.add(|ui| {
            ui.add(Label::new(RichText::new(text).color(pal().text)).truncate(true))
                .on_hover_text(text);
        });
    }

    pub fn status(&mut self, level: Level, text: &str) {
        self.add(|ui| {
            status_dot(ui, level, text);
        });
    }

    pub fn muted(&mut self, text: &str) {
        self.add(|ui| {
            ui.add(Label::new(RichText::new(text).small().color(pal().muted)).truncate(true))
                .on_hover_text(text);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `apply_theme` switches a process-wide palette flag, so the tests that call it take turns.
    static THEME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn theme_guard() -> std::sync::MutexGuard<'static, ()> {
        THEME_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn spacing_scale_is_the_agreed_one() {
        assert_eq!([SP_1, SP_2, SP_3, SP_4, SP_5], [4.0, 8.0, 12.0, 16.0, 24.0]);
    }

    #[test]
    fn type_scale_has_no_text_below_12_5_px() {
        let _guard = theme_guard();
        let ctx = egui::Context::default();
        apply_theme(&ctx, false);
        let style = ctx.style();
        for (name, font) in &style.text_styles {
            assert!(font.size >= 12.5, "{name:?} is {} px", font.size);
        }
        assert!(style.text_styles[&TextStyle::Body].size >= 13.0);
        assert!(
            style.text_styles[&section_style()].size > style.text_styles[&TextStyle::Body].size
        );
        assert!(
            style.text_styles[&TextStyle::Heading].size > style.text_styles[&section_style()].size
        );
    }

    #[test]
    fn apply_theme_switches_the_palette_and_the_visuals_together() {
        let _guard = theme_guard();
        let ctx = egui::Context::default();
        apply_theme(&ctx, true);
        assert_eq!(ctx.style().visuals.panel_fill, Palette::dark().bg);
        assert!(theme::is_dark());
        apply_theme(&ctx, false);
        assert_eq!(ctx.style().visuals.panel_fill, Palette::light().bg);
        assert!(!theme::is_dark());
    }

    #[test]
    fn the_column_is_capped_and_centred() {
        let _guard = theme_guard();
        // Run the layout once and read where the column landed.
        let ctx = egui::Context::default();
        apply_theme(&ctx, false);
        for (screen_w, expect_w) in [(700.0_f32, 652.0_f32), (976.0, 920.0), (1400.0, 920.0)] {
            let mut got = None;
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    vec2(screen_w, 800.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::none())
                    .show(ctx, |ui| {
                        column(ui, |ui| {
                            let r = surface(ui, |ui| {
                                ui.label("x");
                            });
                            got = Some(r.response.rect);
                        });
                    });
            });
            let rect = got.unwrap();
            assert!(
                (rect.width() - expect_w).abs() < 1.0,
                "surface is {} wide at window {screen_w}",
                rect.width()
            );
            // Centred: equal margins on both sides.
            assert!(((rect.left()) - (screen_w - rect.right())).abs() < 1.5);
        }
    }

    #[test]
    fn a_surface_fills_the_column_whatever_it_contains() {
        let _guard = theme_guard();
        let ctx = egui::Context::default();
        apply_theme(&ctx, true);
        let mut widths = Vec::new();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                vec2(900.0, 800.0),
            )),
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| {
            egui::CentralPanel::default()
                .frame(egui::Frame::none())
                .show(ctx, |ui| {
                    column(ui, |ui| {
                        widths.push(surface(ui, |ui| ui.label("short")).response.rect.width());
                        widths.push(
                            surface(ui, |ui| {
                                ui.label("a much longer line of text inside the second surface");
                            })
                            .response
                            .rect
                            .width(),
                        );
                        widths.push(card_frame().show(ui, |_| {}).response.rect.width());
                    });
                });
        });
        assert!(
            widths.windows(2).all(|w| (w[0] - w[1]).abs() < 0.5),
            "{widths:?}"
        );
    }
}
