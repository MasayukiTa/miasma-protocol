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

/// Smallest text size anywhere (hints, labels): egui's `Small`.
pub const MIN_TEXT_PX: f32 = 12.5;
/// Size of secondary lines that people read to know what is going on (message state, time,
/// system lines): between hint and body, so they never read as fine print.
pub const META_PX: f32 = 13.5;

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

/// The type scale: nothing is smaller than [`MIN_TEXT_PX`].
pub fn type_scale() -> [(TextStyle, FontId); 6] {
    [
        (TextStyle::Heading, FontId::proportional(22.0)),
        (section_style(), FontId::proportional(16.0)),
        (TextStyle::Body, FontId::proportional(14.0)),
        (TextStyle::Button, FontId::proportional(14.0)),
        (TextStyle::Small, FontId::proportional(MIN_TEXT_PX)),
        (TextStyle::Monospace, FontId::monospace(13.0)),
    ]
}

/// Secondary text that must be read (message state, times, system lines): [`META_PX`] in `color`.
pub fn meta_text(text: impl Into<String>, color: Color32) -> RichText {
    RichText::new(text).size(META_PX).color(color)
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
    style.text_styles = type_scale().into();

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
    // The text is painted, not a Label: give it to screen readers as the widget's name.
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, text));
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
            let resp = ui.add(button);
            // A choice among several: report which one is selected.
            resp.widget_info(|| {
                egui::WidgetInfo::selected(egui::WidgetType::RadioButton, selected, *label)
            });
            if resp.clicked() && !selected {
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
    // Screen readers: a selectable item named by its label (which carries any count of new items).
    resp.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, selected, label)
    });
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
        if resp.has_focus() {
            focus_ring(painter, rect.shrink2(vec2(1.0, 3.0)), 6.0);
        }
    }
    resp
}

/// Thickness of the keyboard focus ring on hand-painted controls.
pub const FOCUS_RING_PX: f32 = 2.0;

/// The focus ring colour: the accent, which is held to 4.5:1 on every surface (and so clears the
/// 3:1 that non-text indicators need).
pub fn focus_ring_color(p: &Palette) -> Color32 {
    p.accent
}

/// Outline a hand-painted control that has keyboard focus. Stock widgets get egui's own focus
/// look; call this from any control drawn with the painter.
pub fn focus_ring(painter: &egui::Painter, rect: egui::Rect, rounding: f32) {
    painter.rect_stroke(
        rect,
        rounding,
        Stroke::new(FOCUS_RING_PX, focus_ring_color(&pal())),
    );
}

// ─── Icon buttons and the conversation header ───────────────────────────────

/// The pictures an icon button can show. They are painted with lines and circles, so no icon
/// font is needed (and no emoji, which not every system font can draw).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// An arrow pointing left: back to the list.
    Back,
    /// Three dots: the menu with the rare actions.
    More,
    /// A paperclip: attach a file.
    Attach,
}

/// Side of an icon button (px). Large enough to hit; no frame is drawn around it.
pub const ICON_BTN: f32 = 32.0;

/// Points of a paperclip in a 24 x 24 box (a polyline through two straight runs and three
/// half circles).
fn paperclip_points() -> Vec<(f32, f32)> {
    fn arc(c: (f32, f32), r: f32, from: f32, to: f32, out: &mut Vec<(f32, f32)>) {
        const STEPS: usize = 14;
        for i in 1..=STEPS {
            let a = (from + (to - from) * i as f32 / STEPS as f32).to_radians();
            out.push((c.0 + r * a.cos(), c.1 + r * a.sin()));
        }
    }
    let mut v = vec![(21.44, 11.05), (12.25, 20.24)];
    arc((8.005, 15.995), 6.0, 45.0, 225.0, &mut v);
    v.push((12.95, 2.56));
    arc((15.78, 5.39), 4.0, 225.0, 405.0, &mut v);
    v.push((9.41, 17.41));
    arc((8.0, 16.0), 2.0, 45.0, 225.0, &mut v);
    v.push((15.07, 6.10));
    v
}

/// A borderless icon button. `name` is what a screen reader says and the tooltip. A disabled
/// one is drawn faint and does not react.
pub fn icon_button(ui: &mut Ui, icon: Icon, name: &str, enabled: bool) -> Response {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(vec2(ICON_BTN, ICON_BTN), sense);
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, name));
    if ui.is_rect_visible(rect) {
        let p = pal();
        let color = if enabled { p.text } else { p.faint };
        let painter = ui.painter();
        if enabled && (resp.hovered() || resp.has_focus()) {
            painter.rect_filled(rect, 6.0, p.text.gamma_multiply(0.08));
        }
        let c = rect.center();
        let stroke = Stroke::new(1.8, color);
        match icon {
            Icon::Back => {
                let (x0, x1) = (c.x - 7.0, c.x + 7.0);
                painter.line_segment([egui::pos2(x0, c.y), egui::pos2(x1, c.y)], stroke);
                painter.line_segment(
                    [egui::pos2(x0, c.y), egui::pos2(x0 + 5.5, c.y - 5.5)],
                    stroke,
                );
                painter.line_segment(
                    [egui::pos2(x0, c.y), egui::pos2(x0 + 5.5, c.y + 5.5)],
                    stroke,
                );
            }
            Icon::More => {
                for dx in [-6.0, 0.0, 6.0] {
                    painter.circle_filled(egui::pos2(c.x + dx, c.y), 2.0, color);
                }
            }
            Icon::Attach => {
                let side = 20.0;
                let s = side / 24.0;
                let origin = egui::pos2(c.x - side * 0.5, c.y - side * 0.5);
                let pts: Vec<egui::Pos2> = paperclip_points()
                    .into_iter()
                    .map(|(x, y)| origin + vec2(x * s, y * s))
                    .collect();
                painter.add(egui::Shape::line(pts, stroke));
            }
        }
        if resp.has_focus() {
            focus_ring(painter, rect.shrink(1.0), 6.0);
        }
    }
    resp.on_hover_text(name)
}

/// One row of a menu: the whole row is the button. True when it was pressed.
pub fn menu_item(ui: &mut Ui, label: &str, danger: bool) -> bool {
    let p = pal();
    let text = RichText::new(label).color(if danger { p.danger } else { p.text });
    let w = ui.available_width();
    ui.add(
        egui::Button::new(text)
            .frame(false)
            .min_size(vec2(w, CONTROL_H)),
    )
    .clicked()
}

/// A menu row with a check box (a setting that is on or off). Check `changed()` on the result.
pub fn menu_check(ui: &mut Ui, on: &mut bool, label: &str) -> Response {
    ui.checkbox(on, label)
}

/// What the composer shows for the text in it right now.
pub struct ComposerView {
    /// Send is available.
    pub can_send: bool,
    /// A small line under the composer (the length, when it is close to the limit or over it).
    pub note: Option<(String, Color32)>,
    /// What the disabled Send button says when hovered.
    pub disabled_hover: String,
}

/// The fixed parts of a composer.
pub struct ComposerSpec<'a> {
    /// Id of the text field (also what focus is asked for).
    pub id: &'static str,
    pub hint: &'a str,
    /// Names for a screen reader.
    pub a11y_input: &'a str,
    pub a11y_send: &'a str,
    pub send_label: &'a str,
    /// What the field says when hovered: the keys.
    pub keys_hint: &'a str,
    /// A paperclip on the left: its name, and whether it can be pressed. `None`: no paperclip.
    pub attach: Option<(&'a str, bool)>,
}

/// What a frame of the composer did.
#[derive(Default)]
pub struct ComposerOut {
    /// Enter was pressed (and it was not confirming an input-method conversion), or Send was.
    pub submit: bool,
    pub attach: bool,
    pub changed: bool,
    pub can_send: bool,
}

/// The composer of a conversation, as in the common messengers: one row with the paperclip on the
/// left, a text field that grows with what is typed (up to a few lines, then it scrolls), and Send
/// on the right (disabled while there is nothing to send). Enter sends, Shift+Enter starts a new
/// line. `view` says, for the text as it is after this frame's typing, whether Send is available.
pub fn composer(
    ui: &mut Ui,
    spec: &ComposerSpec,
    text: &mut String,
    ime_composing: &mut bool,
    focus: &mut bool,
    view: &dyn Fn(&str) -> ComposerView,
) -> ComposerOut {
    // Japanese input: Enter that confirms a conversion must not send.
    let composing = ui.input(|i| {
        i.events.iter().fold(*ime_composing, |now, e| match e {
            egui::Event::CompositionStart => true,
            egui::Event::CompositionUpdate(s) => !s.is_empty(),
            egui::Event::CompositionEnd(_) => false,
            _ => now,
        })
    });
    *ime_composing = composing;
    let id = egui::Id::new(spec.id);
    let focused = ui.memory(|m| m.has_focus(id));
    let mut out = ComposerOut::default();
    if focused
        && !composing
        && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
    {
        out.submit = true;
    }
    let mut note = None;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = SP_2;
        if let Some((name, enabled)) = spec.attach {
            out.attach = icon_button(ui, Icon::Attach, name, enabled).clicked();
        }
        let field_w = (ui.available_width() - BTN_MIN_W - SP_2).max(120.0);
        let resp = ui
            .allocate_ui(vec2(field_w, 0.0), |ui| {
                egui::ScrollArea::vertical()
                    .id_source((spec.id, "scroll"))
                    .max_height(112.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.add(
                            input_multiline(text)
                                .id(id)
                                .desired_rows(1)
                                .desired_width(field_w - 2.0 * SP_2)
                                .hint_text(spec.hint),
                        )
                    })
                    .inner
            })
            .inner;
        resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, spec.a11y_input));
        out.changed = resp.changed();
        if *focus {
            resp.request_focus();
            *focus = false;
        }
        resp.on_hover_text(spec.keys_hint);
        let v = view(text);
        let btn = primary(ui, v.can_send, spec.send_label);
        btn.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, spec.a11y_send));
        let btn = if v.can_send {
            btn
        } else {
            btn.on_disabled_hover_text(v.disabled_hover.clone())
        };
        if btn.clicked() {
            out.submit = true;
        }
        out.can_send = v.can_send;
        note = v.note;
    });
    if let Some((text, color)) = note {
        ui.label(meta_text(text, color));
    }
    out
}

/// The header of a conversation, in the manner of the common messengers: a small back arrow, the
/// name with one muted line under it, and one menu button on the right. `menu` draws the rows of
/// the menu (the rare actions); `None` shows no menu button. Returns true when back was pressed.
pub fn conversation_header(
    ui: &mut Ui,
    back_name: &str,
    title: &str,
    subtitle: Option<(&str, Color32)>,
    menu_name: &str,
    menu_key: &str,
    open_menu: bool,
    menu: Option<&mut dyn FnMut(&mut Ui)>,
) -> bool {
    let mut back = false;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = SP_2;
        back = icon_button(ui, Icon::Back, back_name, true).clicked();
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.add(
                Label::new(
                    RichText::new(title)
                        .font(FontId::proportional(17.0))
                        .color(pal().text),
                )
                .truncate(true),
            )
            .on_hover_text(title);
            if let Some((text, color)) = subtitle {
                ui.add(Label::new(meta_text(text, color)).truncate(true));
            }
        });
        if let Some(menu) = menu {
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                let resp = icon_button(ui, Icon::More, menu_name, true);
                let id = ui.make_persistent_id(("conversation_menu", menu_key));
                if resp.clicked() {
                    ui.memory_mut(|m| m.toggle_popup(id));
                }
                if open_menu {
                    ui.memory_mut(|m| m.open_popup(id));
                }
                egui::popup::popup_below_widget(ui, id, &resp, |ui| {
                    ui.set_width(260.0);
                    menu(ui);
                });
            });
        }
    });
    ui.add_space(SP_1);
    back
}

/// A thin determinate bar across the available width. Neutral; turns to the warning colour when
/// `warn`. `name` is what a screen reader calls it ("Storage"); `fraction` is its value.
pub fn progress(ui: &mut Ui, name: &str, fraction: f32, warn: bool) {
    let p = pal();
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 6.0), Sense::hover());
    resp.widget_info(|| crate::a11y::progress_info(name, fraction));
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

    /// Every named text colour the kit draws with, against each background it is drawn on.
    /// Printed with `--nocapture` to record before/after numbers.
    #[test]
    fn every_named_text_colour_is_at_least_4_5_to_1_on_its_backgrounds() {
        use crate::theme::{contrast, Palette};
        for (mode, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            let backgrounds = [
                ("bg", p.bg),
                ("surface", p.surface),
                ("surface_subtle", p.surface_subtle),
                ("selected", p.selected),
            ];
            let texts = [
                ("text", p.text),
                ("muted", p.muted),
                ("faint", p.faint),
                ("success", p.success),
                ("warning", p.warning),
                ("danger", p.danger),
                ("info", p.info),
                ("accent", p.accent),
            ];
            for (tn, t) in texts {
                for (bn, b) in backgrounds {
                    let r = contrast(t, b);
                    println!("{mode}: {tn} on {bn} = {r:.2}");
                    assert!(r >= 4.5, "{mode}: {tn} on {bn} = {r:.2}");
                }
            }
            // Secondary text that people read to act (state lines, times, system lines) is
            // `muted` or better, which is held to 7:1 on the page and card backgrounds.
            for (bn, b) in &backgrounds[..3] {
                let r = contrast(p.muted, *b);
                assert!(r >= 7.0, "{mode}: muted on {bn} = {r:.2}");
            }
            // The chat bubbles: text on the own-message and the received-message fill.
            for (bn, b) in [("own bubble", p.selected), ("their bubble", p.surface)] {
                let r = contrast(p.text, b);
                assert!(r >= 7.0, "{mode}: text on {bn} = {r:.2}");
            }
            assert!(contrast(p.on_accent(), p.accent_fill) >= 4.5, "{mode}");
        }
    }

    #[test]
    fn nothing_is_set_smaller_than_the_minimum_text_size() {
        for (style, font) in type_scale() {
            assert!(font.size >= MIN_TEXT_PX, "{style:?} = {}", font.size);
        }
        assert!(META_PX >= MIN_TEXT_PX);
        assert!(META_PX < 14.0, "meta text stays below body size");
    }

    /// Literal font sizes in the chat, contacts and transfers screens: none below the minimum.
    #[test]
    fn no_screen_hard_codes_a_size_below_the_minimum() {
        let files = [
            ("chat_ui.rs", include_str!("chat_ui.rs")),
            ("contacts.rs", include_str!("contacts.rs")),
            ("transfers.rs", include_str!("transfers.rs")),
        ];
        for (name, src) in files {
            for pat in [".size(", "proportional(", "single_line(ui, "] {
                for (at, _) in src.match_indices(pat) {
                    if src[..at].ends_with("Spinner::new()") {
                        continue; // a spinner's diameter, not text
                    }
                    let rest = &src[at + pat.len()..];
                    let rest = if pat.starts_with("single_line") {
                        // `pat` already ate "single_line(ui, ", so the next field is the text and
                        // the one after it is the size.
                        match rest.splitn(3, ',').nth(1) {
                            Some(r) => r,
                            None => continue,
                        }
                    } else {
                        rest
                    };
                    let num: String = rest
                        .trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    if let Ok(px) = num.parse::<f32>() {
                        assert!(px >= MIN_TEXT_PX, "{name}: {pat}{px}");
                    }
                }
            }
        }
    }
}
