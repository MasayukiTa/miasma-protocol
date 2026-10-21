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
//! 5. **Controls.** A button hierarchy, one pattern each: primary ([`primary`], at most one per
//!    screen or dialog, never per list row); secondary, outlined ([`secondary_button`], the next
//!    likely action); quiet, text only ([`quiet_button`]); icon, 28 px with a tooltip and an
//!    accessible name ([`icon_button`]); destructive, never on the main surface: it lives in a
//!    "..." menu ([`row_menu`]) as red text and asks in a dialog, where the confirm button is
//!    [`danger_button`]. Buttons and text edits are all [`CONTROL_H`] tall.
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

/// Gap between a page title and its content.
pub const GAP_TITLE: f32 = SP_3;
/// Gap between two groups on a page.
pub const GAP_GROUP: f32 = SP_4;
/// Vertical padding inside a list row.
pub const ROW_PAD_V: f32 = SP_2;

/// Type scale (px). Page titles use [`TITLE_PX`] and only when the page needs a title; a section
/// title ([`SECTION_PX`]) goes only above a group of two or more rows. The largest text on a
/// screen is its title.
pub const TITLE_PX: f32 = 22.0;
pub const SECTION_PX: f32 = 16.0;
pub const BODY_PX: f32 = 14.0;
pub const MONO_PX: f32 = 13.0;

/// Height of a list row with two lines of text (and of a large action button).
pub const ROW_H: f32 = 56.0;
/// Height of a list row with one line.
pub const ROW_H_ONE_LINE: f32 = 40.0;

/// Diameter of the initial circle in a list row.
pub const AVATAR_PX: f32 = 36.0;
/// Height of the big actions on the home screen.
pub const LARGE_ACTION_H: f32 = 56.0;

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
        (TextStyle::Heading, FontId::proportional(TITLE_PX)),
        (section_style(), FontId::proportional(SECTION_PX)),
        (TextStyle::Body, FontId::proportional(BODY_PX)),
        (TextStyle::Button, FontId::proportional(BODY_PX)),
        (TextStyle::Small, FontId::proportional(MIN_TEXT_PX)),
        (TextStyle::Monospace, FontId::monospace(MONO_PX)),
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
    column_max(ui, COLUMN_MAX, add);
}

/// [`column`] with its own widest width: a screen that is two panes side by side (the Chat list
/// beside a conversation) uses more of a wide window than a page of text does.
pub fn column_max(ui: &mut Ui, max: f32, add: impl FnOnce(&mut Ui)) {
    let avail = ui.available_width();
    let w = (avail - 2.0 * PAGE_MARGIN_X).clamp(0.0, max);
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

/// The buttons of a dialog: one cluster at the bottom right. Add the button that goes furthest right
/// first (the confirming one), then the others: the cancel button ends up to its left. Forms and
/// inline actions keep [`button_row`], which stays left aligned.
pub fn dialog_actions<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
        ui.spacing_mut().item_spacing = vec2(SP_2, SP_2);
        add(ui)
    })
    .inner
}

/// Width of the page column below which a banner's actions go under its text.
const BANNER_NARROW_W: f32 = 560.0;

/// A banner: the text on the left and its decision on the right (add the main action first: the
/// others end up to its left, so "Later / Skip / Update" reads secondary to primary). Below
/// [`BANNER_NARROW_W`] the actions go under the text, still at the right.
pub fn banner_actions(ui: &mut Ui, level: Level, text: &str, actions: impl FnOnce(&mut Ui)) {
    let right = Layout::right_to_left(egui::Align::Center);
    if ui.available_width() < BANNER_NARROW_W {
        notice(ui, level, text);
        ui.with_layout(right, |ui| {
            ui.spacing_mut().item_spacing = vec2(SP_2, SP_2);
            actions(ui);
        });
    } else {
        ui.with_layout(right, |ui| {
            ui.spacing_mut().item_spacing = vec2(SP_2, SP_2);
            actions(ui);
            ui.with_layout(Layout::left_to_right(egui::Align::Center), |ui| {
                notice(ui, level, text);
            });
        });
    }
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

/// Below this width a form row stacks its label above the control.
const STACK_FORM_BELOW: f32 = 440.0;

/// A form row: label column, control, and an optional hint under the control. The label is
/// centred on the first control line so it sits next to the control, not above it.
pub fn form_row<R>(
    ui: &mut Ui,
    label: &str,
    hint_text: Option<&str>,
    control: impl FnOnce(&mut Ui) -> R,
) -> R {
    let total = ui.available_width();
    let spacing = ui.spacing().item_spacing;
    // A narrow window: no room for a label column beside the control, so the label goes above
    // it and the control takes the full width (nothing runs past the right edge).
    if total < STACK_FORM_BELOW {
        return ui
            .vertical(|ui| {
                ui.spacing_mut().item_spacing = spacing;
                if !label.is_empty() {
                    ui.add(Label::new(RichText::new(label).color(pal().text)).wrap(true));
                }
                ui.set_width(total);
                let r = control(ui);
                if let Some(h) = hint_text {
                    hint(ui, h);
                }
                r
            })
            .inner;
    }
    let value_w = (total - LABEL_W).max(80.0);
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
        let off = crate::form_check::add_enabled(ui, false, secondary_button(text));
        crate::form_check::mark_disabled(&off);
        return off;
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

// ─── Button hierarchy: quiet and icon buttons ───────────────────────────────

/// A borderless text button (Refresh, Clear finished, Back, an inline Retry): accent text, no
/// frame. For the action that is not the point of the screen.
pub fn quiet_button<'a>(text: impl Into<String>) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).color(pal().accent))
        .frame(false)
        .min_size(vec2(0.0, ICON_BTN))
}

/// A "< Back" text link above a title.
#[allow(dead_code)]
pub fn back_link(ui: &mut Ui, label: &str) -> bool {
    ui.add(quiet_button(format!("< {label}"))).clicked()
}

/// A big action (Home): [`LARGE_ACTION_H`] tall, `width` wide, section-size text. `primary_style`
/// is the accent fill; a disabled primary falls back to outlined like [`primary`].
pub fn large_action(
    ui: &mut Ui,
    primary_style: bool,
    enabled: bool,
    text: &str,
    width: f32,
) -> Response {
    let size = vec2(width, LARGE_ACTION_H);
    let label = RichText::new(text).text_style(section_style());
    if !primary_style || !enabled {
        return crate::form_check::add_enabled(
            ui,
            enabled,
            egui::Button::new(label).min_size(size),
        );
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
        ui.add(egui::Button::new(label).min_size(size))
    })
    .inner
}

// ─── Avatar, list rows, "..." menu, dialogs, empty and error states ─────────

/// The letter an initial circle shows for `name`: its first letter or digit, upper-cased, or
/// `?` when there is none.
pub fn initial_of(name: &str) -> String {
    name.chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "?".to_owned())
}

/// Which kind of conversation an avatar stands for. The kinds differ in shape (circle or rounded
/// square) and in tint, and the list that shows them also has a heading per kind, so colour is
/// never the only carrier of the meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarKind {
    Person,
    Group,
}

/// Fill and letter colour of an avatar. A person is neutral; a group is tinted with the `info`
/// colour mixed into the surface, with the letter in `info` itself.
pub fn avatar_colors(p: &Palette, kind: AvatarKind) -> (Color32, Color32) {
    match kind {
        AvatarKind::Person => (p.selected, p.text),
        AvatarKind::Group => {
            let mix = |a: u8, b: u8| (f32::from(a) * 0.16 + f32::from(b) * 0.84).round() as u8;
            let fill = Color32::from_rgb(
                mix(p.info.r(), p.surface.r()),
                mix(p.info.g(), p.surface.g()),
                mix(p.info.b(), p.surface.b()),
            );
            (fill, p.info)
        }
    }
}

/// Draw an avatar of `kind` with the initial of `name` into `rect` (a square).
pub fn paint_avatar(painter: &egui::Painter, rect: egui::Rect, name: &str, kind: AvatarKind) {
    let p = pal();
    let (fill, letter) = avatar_colors(&p, kind);
    match kind {
        AvatarKind::Person => {
            painter.circle_filled(rect.center(), rect.width() * 0.5, fill);
        }
        AvatarKind::Group => {
            painter.rect_filled(rect, rect.width() * 0.28, fill);
        }
    }
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initial_of(name),
        FontId::proportional(SECTION_PX),
        letter,
    );
}

/// A circle with the initial of `name`. Decoration: the name is always written beside it.
pub fn avatar(ui: &mut Ui, name: &str, diameter: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(diameter, diameter), Sense::hover());
    if ui.is_rect_visible(rect) {
        paint_avatar(ui.painter(), rect, name, AvatarKind::Person);
    }
    resp
}

/// What a [`list_row`] shows on its left.
pub struct ListRow<'a> {
    /// Name for the initial circle; `None` for a row without one.
    pub avatar: Option<&'a str>,
    pub title: &'a str,
    /// A muted second line with a status colour (text colour for `Level::Muted`).
    pub subtitle: Option<(&'a str, Level)>,
}

/// What [`list_row`] gives back.
pub struct ListRowOut<R> {
    /// The row's rectangle (not counting the hairline above it).
    pub rect: egui::Rect,
    /// Whatever the trailing closure returned.
    #[allow(dead_code)]
    pub inner: R,
}

/// A compact list row: hairline above, then [`ROW_H`] (two lines or an initial circle) or
/// [`ROW_H_ONE_LINE`] of avatar, title, muted subtitle and, on the right, a trailing slot (a quiet
/// action and a "..." menu). The title and subtitle are cut with an ellipsis, never wrapped, so
/// every row is the same height. The row is tinted while the pointer is over it.
pub fn list_row<R>(
    ui: &mut Ui,
    row: ListRow<'_>,
    trailing: impl FnOnce(&mut Ui) -> R,
) -> ListRowOut<R> {
    // Rows touch: no gap between the hairline, the row and the next hairline.
    let saved_gap = ui.spacing().item_spacing.y;
    ui.spacing_mut().item_spacing.y = 0.0;
    let out = {
        divider(ui);
        let h = if row.avatar.is_some() || row.subtitle.is_some() {
            ROW_H
        } else {
            ROW_H_ONE_LINE
        };
        let w = ui.available_width();
        let tint = ui.painter().add(egui::Shape::Noop);
        let out = ui.allocate_ui_with_layout(
            vec2(w, h),
            Layout::right_to_left(egui::Align::Center),
            |ui| {
                ui.set_min_size(vec2(w, h));
                ui.spacing_mut().item_spacing.x = SP_2;
                let inner = trailing(ui);
                ui.with_layout(Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = SP_3;
                    if let Some(name) = row.avatar {
                        avatar(ui, name, AVATAR_PX);
                    }
                    ui.allocate_ui_with_layout(
                        vec2(ui.available_width(), h),
                        Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            // Centre the one or two lines of text in the row.
                            let lines = if row.subtitle.is_some() { 2.0 } else { 1.0 };
                            let block = lines * ui.text_style_height(&TextStyle::Body);
                            ui.add_space(((h - block) * 0.5).max(0.0));
                            ui.add(
                                Label::new(RichText::new(row.title).color(pal().text))
                                    .truncate(true),
                            )
                            .on_hover_text(row.title);
                            if let Some((sub, level)) = row.subtitle {
                                let color = if level == Level::Muted {
                                    pal().muted
                                } else {
                                    level_color(level)
                                };
                                ui.add(Label::new(RichText::new(sub).color(color)).truncate(true))
                                    .on_hover_text(sub);
                            }
                        },
                    );
                });
                inner
            },
        );
        let rect = out.response.rect;
        if ui.rect_contains_pointer(rect) {
            ui.painter().set(
                tint,
                egui::epaint::RectShape::filled(rect, 0.0, pal().text.gamma_multiply(0.04)),
            );
        }
        ListRowOut {
            rect,
            inner: out.inner,
        }
    };
    ui.spacing_mut().item_spacing.y = saved_gap;
    out
}

/// A confirmation a destructive menu item asks for.
pub struct Confirm<'a> {
    pub title: &'a str,
    pub body: &'a str,
    /// The red confirm button.
    pub confirm: &'a str,
    pub cancel: &'a str,
}

/// An item of a [`row_menu`].
pub struct MenuItem<'a> {
    pub label: &'a str,
    pub enabled: bool,
    /// `Some` for a destructive item: drawn as red text, and chosen only after the person
    /// confirms in a dialog.
    pub confirm: Option<Confirm<'a>>,
    /// Drawn as red text without asking in a dialog here (the caller asks itself).
    pub danger: bool,
}

impl<'a> MenuItem<'a> {
    pub fn new(label: &'a str) -> Self {
        Self {
            label,
            enabled: true,
            confirm: None,
            danger: false,
        }
    }

    /// Red text, chosen at once: for an item whose caller opens its own confirmation.
    pub fn danger(label: &'a str) -> Self {
        Self {
            danger: true,
            ..Self::new(label)
        }
    }

    /// A destructive item: red text, asks first.
    pub fn destructive(label: &'a str, confirm: Confirm<'a>) -> Self {
        Self {
            label,
            enabled: true,
            confirm: Some(confirm),
            danger: true,
        }
    }

    #[allow(dead_code)]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Narrowest the popup of a [`row_menu`] gets.
const MENU_MIN_W: f32 = 180.0;
const MENU_CONFIRM_KEY: &str = "row_menu_confirm";

/// A "..." icon button that opens a popup of `items`. Returns the index of the item the person
/// chose: at once for a plain item, and for a destructive one only after they press its confirm
/// button in the dialog. `name` is the button's tooltip and accessible name ("More actions");
/// `id_source` tells the menus of different rows apart.
pub fn row_menu(
    ui: &mut Ui,
    id_source: impl std::hash::Hash,
    name: &str,
    items: &[MenuItem<'_>],
) -> Option<usize> {
    let id = ui.make_persistent_id(("row_menu", id_source));
    let popup_id = id.with("popup");
    let pending_id = id.with("pending");
    let button = icon_button(ui, Icon::More, name, true).on_hover_text(name);
    if button.clicked() {
        ui.memory_mut(|m| m.toggle_popup(popup_id));
    }
    let mut chosen = None;
    egui::popup::popup_below_widget(ui, popup_id, &button, |ui| {
        ui.set_min_width(MENU_MIN_W);
        for (i, item) in items.iter().enumerate() {
            let r = ui
                .add_enabled_ui(item.enabled, |ui| menu_item(ui, item.label, item.danger))
                .inner;
            if r {
                chosen = Some(i);
                ui.memory_mut(|m| m.close_popup());
            }
        }
    });
    let mut result = None;
    if chosen.is_some() {
        // Whatever opens next (a confirmation, or a dialog of the caller) hands focus back to
        // this button, which stays, and not to the menu item, which goes with the popup.
        crate::a11y::set_opener(ui.ctx(), button.id);
    }
    if let Some(i) = chosen {
        if items.get(i).is_some_and(|it| it.confirm.is_some()) {
            ui.ctx().data_mut(|d| d.insert_temp(pending_id, i));
        } else {
            result = Some(i);
        }
    }
    let pending: Option<usize> = ui.ctx().data(|d| d.get_temp(pending_id));
    if let Some(i) = pending {
        match items.get(i).and_then(|it| it.confirm.as_ref()) {
            Some(conf) => {
                let mut decided: Option<bool> = None;
                let shown = dialog(ui.ctx(), MENU_CONFIRM_KEY, conf.title, |ui| {
                    paragraph(ui, conf.body);
                    ui.add_space(SP_2);
                    dialog_actions(ui, |ui| {
                        if ui.add(danger_button(conf.confirm)).clicked() {
                            decided = Some(true);
                        }
                        let cancel = ui.add(secondary_button(conf.cancel));
                        crate::a11y::dialog_focus_safe_button(ui.ctx(), MENU_CONFIRM_KEY, &cancel);
                        if cancel.clicked() {
                            decided = Some(false);
                        }
                    });
                });
                match (shown, decided) {
                    // Esc: the dialog closed itself.
                    (None, _) => {
                        ui.ctx().data_mut(|d| d.remove::<usize>(pending_id));
                    }
                    (Some(()), Some(yes)) => {
                        crate::a11y::dialog_leave(ui.ctx(), MENU_CONFIRM_KEY);
                        ui.ctx().data_mut(|d| d.remove::<usize>(pending_id));
                        if yes {
                            result = Some(i);
                        }
                    }
                    (Some(()), None) => {}
                }
            }
            None => ui.ctx().data_mut(|d| d.remove::<usize>(pending_id)),
        }
    }
    result
}

/// (window width, content width) of a dialog on a screen `screen_w` wide: the usual 460 / 440,
/// or less when the screen is narrow (a margin of 16 px on each side, and the window's own
/// frame inside it).
pub fn dialog_widths(screen_w: f32) -> (f32, f32) {
    let win = (screen_w - 32.0).clamp(200.0, 460.0);
    let inner = if win >= 460.0 {
        440.0
    } else {
        (win - 2.0 * SP_4 - 2.0).clamp(150.0, 440.0)
    };
    (win, inner)
}

/// A modal-looking dialog window, centred, with the focus and Esc handling of `a11y`. Returns
/// `None` when Esc closed it (the caller then drops its "open" state); otherwise the value
/// `body` returned. A caller that closes it by a button calls
/// [`crate::a11y::dialog_leave`] with the same `key`.
pub fn dialog<R>(
    ctx: &egui::Context,
    key: &'static str,
    title: &str,
    body: impl FnOnce(&mut Ui) -> R,
) -> Option<R> {
    crate::a11y::dialog_enter(ctx, key);
    if crate::a11y::esc_pressed(ctx) {
        crate::a11y::dialog_leave(ctx, key);
        return None;
    }
    // Never wider than the window (less a margin on each side): at 320 px the dialog used to
    // keep its 440 px and ran off both edges.
    let (win_w, inner_w) = dialog_widths(ctx.screen_rect().width());
    crate::a11y::dialog_title(ctx, title);
    let shown = egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .default_width(win_w.min(420.0))
        .max_width(win_w)
        .show(ctx, |ui| {
            ui.set_max_width(inner_w);
            body(ui)
        })
        .and_then(|r| r.inner);
    crate::a11y::dialog_end(ctx);
    shown
}

/// An empty list: one sentence and one primary action, centred. Returns true when the action was
/// pressed.
pub fn empty_state(ui: &mut Ui, text: &str, primary_label: &str) -> bool {
    empty_state_with(ui, text, primary_label, |_| {})
}

/// [`empty_state`] with something quiet under the primary action.
pub fn empty_state_with(
    ui: &mut Ui,
    text: &str,
    primary_label: &str,
    below: impl FnOnce(&mut Ui),
) -> bool {
    let mut pressed = false;
    ui.vertical_centered(|ui| {
        ui.add_space(SP_5 + SP_5);
        ui.add(Label::new(muted_text(text)).wrap(true));
        ui.add_space(SP_3);
        pressed = primary(ui, true, primary_label).clicked();
        below(ui);
        ui.add_space(SP_5);
    });
    pressed
}

/// A one-line problem next to its cause, with at most one quiet action under it ("Try again").
/// Returns true when the action was pressed. Not a card, not a Dismiss button.
pub fn inline_message(ui: &mut Ui, level: Level, text: &str, action: Option<&str>) -> bool {
    notice(ui, level, text);
    match action {
        Some(label) => ui.add(quiet_button(label)).clicked(),
        None => false,
    }
}

/// A read-only, selectable code (a contact code) in monospace at the standard control height.
pub fn code_display(ui: &mut Ui, text: &str) -> Response {
    let mut shown: &str = text;
    ui.add(
        egui::TextEdit::singleline(&mut shown)
            .font(TextStyle::Monospace)
            .margin(vec2(SP_2, 6.5))
            .min_size(vec2(0.0, CONTROL_H))
            .desired_width(f32::INFINITY),
    )
}

/// Segmented choice: a row of mutually exclusive options; the selected one gets an accent
/// outline. Returns true when the choice changed.
pub fn segmented<T: Copy + PartialEq>(ui: &mut Ui, current: &mut T, options: &[(T, &str)]) -> bool {
    let p = pal();
    let mut changed = false;
    ui.horizontal_wrapped(|ui| {
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
    // A tab that says whether it is the selected one.
    let _ = resp.ctx.accesskit_node_builder(resp.id, |b| {
        b.set_role(egui::accesskit::Role::Tab);
        b.set_selected(selected);
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
    /// A circle with an "i": show the information of this conversation.
    Info,
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
            Icon::Info => {
                painter.circle_stroke(c, 9.0, stroke);
                painter.circle_filled(egui::pos2(c.x, c.y - 4.0), 1.2, color);
                painter.line_segment(
                    [egui::pos2(c.x, c.y - 0.5), egui::pos2(c.x, c.y + 4.5)],
                    stroke,
                );
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
    .then(|| ui.memory_mut(|m| m.close_popup()))
    .is_some()
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
#[allow(dead_code)]
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
    let end = match menu {
        Some(menu) => HeaderEnd::Menu {
            name: menu_name,
            key: menu_key,
            open: open_menu,
            menu,
        },
        None => HeaderEnd::None,
    };
    conversation_header_ex(ui, Some(back_name), title, subtitle, end).back
}

/// What the right end of a conversation header holds.
pub enum HeaderEnd<'a> {
    /// Nothing.
    None,
    /// A "..." button with a popup of rare actions (only worth it with two or more).
    Menu {
        name: &'a str,
        key: &'a str,
        open: bool,
        menu: &'a mut dyn FnMut(&mut Ui),
    },
    /// One direct "i" button (named `name`): for a conversation whose only extra is its
    /// information, so no popup covers the messages.
    Info { name: &'a str },
}

/// What a press in a conversation header did.
#[derive(Debug, Default, Clone, Copy)]
pub struct HeaderOut {
    pub back: bool,
    pub info: bool,
}

/// [`conversation_header`] with a choice of the right end, and without the back arrow when
/// `back_name` is `None` (a two-pane screen, where the list is always beside the conversation).
pub fn conversation_header_ex(
    ui: &mut Ui,
    back_name: Option<&str>,
    title: &str,
    subtitle: Option<(&str, Color32)>,
    end: HeaderEnd<'_>,
) -> HeaderOut {
    let mut out = HeaderOut::default();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = SP_2;
        if let Some(back_name) = back_name {
            out.back = icon_button(ui, Icon::Back, back_name, true).clicked();
        }
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
        match end {
            HeaderEnd::None => {}
            HeaderEnd::Menu {
                name,
                key,
                open,
                menu,
            } => {
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    let resp = icon_button(ui, Icon::More, name, true);
                    let id = ui.make_persistent_id(("conversation_menu", key));
                    if resp.clicked() {
                        ui.memory_mut(|m| m.toggle_popup(id));
                    }
                    if open {
                        ui.memory_mut(|m| m.open_popup(id));
                    }
                    egui::popup::popup_below_widget(ui, id, &resp, |ui| {
                        ui.set_width(260.0);
                        menu(ui);
                    });
                });
            }
            HeaderEnd::Info { name } => {
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    out.info = icon_button(ui, Icon::Info, name, true).clicked();
                });
            }
        }
    });
    ui.add_space(SP_1);
    out
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
    fn the_letter_of_each_avatar_kind_is_readable_and_the_kinds_differ() {
        use crate::theme::{contrast, Palette};
        for (mode, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            for kind in [AvatarKind::Person, AvatarKind::Group] {
                let (fill, letter) = avatar_colors(&p, kind);
                let r = contrast(letter, fill);
                assert!(r >= 4.5, "{mode}: {kind:?} letter on its fill = {r:.2}");
            }
            let person = avatar_colors(&p, AvatarKind::Person);
            let group = avatar_colors(&p, AvatarKind::Group);
            assert_ne!(person.0, group.0, "{mode}: the fills differ");
            // A group's tint still reads as a shape against the page and the selected row.
            for (bn, b) in [
                ("bg", p.bg),
                ("surface", p.surface),
                ("selected", p.selected),
            ] {
                assert_ne!(group.0, b, "{mode}: the group fill is the {bn} colour");
            }
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

    fn run_page(w: f32, h: f32, add: impl FnOnce(&mut Ui)) {
        run_page_with(egui::RawInput::default(), w, h, add);
    }

    fn run_page_with(mut input: egui::RawInput, w: f32, h: f32, add: impl FnOnce(&mut Ui)) {
        let ctx = egui::Context::default();
        apply_theme(&ctx, false);
        input.screen_rect = Some(egui::Rect::from_min_size(egui::pos2(0.0, 0.0), vec2(w, h)));
        let mut add = Some(add);
        let _ = ctx.run(input, |ctx| {
            egui::CentralPanel::default()
                .frame(egui::Frame::none())
                .show(ctx, |ui| {
                    if let Some(f) = add.take() {
                        f(ui);
                    }
                });
        });
    }

    #[test]
    fn the_scales_are_the_agreed_ones() {
        assert_eq!([TITLE_PX, SECTION_PX, BODY_PX], [22.0, 16.0, 14.0]);
        assert!(TITLE_PX > SECTION_PX && SECTION_PX > BODY_PX && BODY_PX > MIN_TEXT_PX);
        assert_eq!([GAP_TITLE, GAP_GROUP, ROW_PAD_V], [SP_3, SP_4, SP_2]);
        assert_eq!((ROW_H, ROW_H_ONE_LINE, ICON_BTN), (56.0, 40.0, 32.0));
        // A row has room for the circle plus its vertical padding.
        assert!(ROW_H >= AVATAR_PX + 2.0 * ROW_PAD_V);
        assert!(ICON_BTN >= COMPACT_H);
        let _guard = theme_guard();
        let ctx = egui::Context::default();
        apply_theme(&ctx, false);
        let style = ctx.style();
        assert_eq!(style.text_styles[&TextStyle::Heading].size, TITLE_PX);
        assert_eq!(style.text_styles[&section_style()].size, SECTION_PX);
        assert_eq!(style.text_styles[&TextStyle::Body].size, BODY_PX);
    }

    #[test]
    fn the_initial_is_the_first_letter_upper_cased() {
        assert_eq!(initial_of("taro"), "T");
        assert_eq!(initial_of("  Ken"), "K");
        assert_eq!(initial_of("田中"), "田");
        assert_eq!(initial_of("(work) anna"), "W");
        assert_eq!(initial_of("ßeta"), "SS");
        assert_eq!(initial_of(""), "?");
        assert_eq!(initial_of("--"), "?");
    }

    #[test]
    fn a_list_row_has_a_fixed_height_whatever_the_text() {
        let _guard = theme_guard();
        for width in [652.0_f32, 920.0] {
            let mut heights = Vec::new();
            run_page(width + 2.0 * PAGE_MARGIN_X, 600.0, |ui| {
                column(ui, |ui| {
                    let long = "x".repeat(400);
                    for (name, sub) in [
                        ("Taro", Some(("Ready", Level::Muted))),
                        (long.as_str(), Some((long.as_str(), Level::Warn))),
                        ("Ken", None),
                    ] {
                        let out = list_row(
                            ui,
                            ListRow {
                                avatar: Some(name),
                                title: name,
                                subtitle: sub,
                            },
                            |ui| {
                                ui.add(quiet_button("Send"));
                                ui.label("...");
                            },
                        );
                        heights.push((out.rect.height(), out.rect.width()));
                    }
                    // Without a circle and a second line it is the one-line height.
                    let out = list_row(
                        ui,
                        ListRow {
                            avatar: None,
                            title: "Only a title",
                            subtitle: None,
                        },
                        |_| {},
                    );
                    heights.push((out.rect.height(), out.rect.width()));
                });
            });
            assert_eq!(heights.len(), 4);
            for (h, w) in &heights[..3] {
                assert_eq!(*h, ROW_H, "two-line row at {width}");
                assert!(
                    (w - width).abs() < 1.5,
                    "row is {w} wide in a {width} column"
                );
            }
            assert_eq!(heights[3].0, ROW_H_ONE_LINE);
        }
    }

    #[test]
    fn rows_stack_without_extra_gaps() {
        let _guard = theme_guard();
        let mut tops = Vec::new();
        run_page(700.0, 600.0, |ui| {
            for name in ["a", "b", "c"] {
                let out = list_row(
                    ui,
                    ListRow {
                        avatar: Some(name),
                        title: name,
                        subtitle: Some(("x", Level::Muted)),
                    },
                    |_| {},
                );
                tops.push(out.rect.top());
            }
        });
        // The hairline is 1 px; item spacing inside a row list is zero.
        assert_eq!(tops[1] - tops[0], ROW_H + 1.0);
        assert_eq!(tops[2] - tops[1], ROW_H + 1.0);
    }

    #[test]
    fn the_menu_button_is_the_shared_icon_button() {
        let _guard = theme_guard();
        let mut size = None;
        run_page(700.0, 300.0, |ui| {
            let r = icon_button(ui, Icon::More, "More actions", true);
            size = Some(r.rect.size());
        });
        let size = size.unwrap();
        assert!(size.x >= ICON_BTN && size.y >= ICON_BTN, "{size:?}");
        assert!(size.y <= ICON_BTN + 1.0 && size.x <= ICON_BTN + 1.0);
    }

    #[test]
    fn an_unconfirmed_destructive_choice_is_not_returned_and_esc_cancels_it() {
        let _guard = theme_guard();
        let ctx = egui::Context::default();
        apply_theme(&ctx, false);
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), vec2(700.0, 400.0));
        let mut seen_pending = Vec::new();
        let mut results = Vec::new();
        for (frame, esc) in [false, false, true, false].into_iter().enumerate() {
            let mut input = egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            };
            if esc {
                input.events.push(egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                });
            }
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let pending_id = ui.make_persistent_id(("row_menu", "t")).with("pending");
                    if frame == 0 {
                        // As if the red item had just been chosen.
                        ui.ctx().data_mut(|d| d.insert_temp(pending_id, 1usize));
                    }
                    let items = [
                        MenuItem::new("Rename"),
                        MenuItem::destructive(
                            "Remove",
                            Confirm {
                                title: "Remove this contact?",
                                body: "It cannot be undone.",
                                confirm: "Remove",
                                cancel: "Cancel",
                            },
                        ),
                    ];
                    results.push(row_menu(ui, "t", "More actions", &items));
                    seen_pending.push(ui.ctx().data(|d| d.get_temp::<usize>(pending_id)));
                });
            });
        }
        assert_eq!(
            results,
            [None, None, None, None],
            "nothing is chosen unasked"
        );
        assert_eq!(seen_pending[0], Some(1), "the dialog is waiting");
        assert_eq!(seen_pending[1], Some(1));
        assert_eq!(seen_pending[2], None, "Esc cancelled the question");
        assert_eq!(seen_pending[3], None);
    }

    #[test]
    fn the_empty_state_is_centred_and_asks_for_one_action() {
        let _guard = theme_guard();
        let mut out = None;
        run_page(800.0, 600.0, |ui| {
            let pressed = empty_state(ui, "No contacts yet.", "Add a contact");
            out = Some((pressed, ui.min_rect()));
        });
        let (pressed, used) = out.unwrap();
        assert!(!pressed);
        assert!(used.height() > 60.0);
        assert!(((used.center().x) - 400.0).abs() < 2.0, "{used:?}");
    }

    #[test]
    fn the_code_display_is_as_tall_as_every_other_control() {
        let _guard = theme_guard();
        let mut heights = Vec::new();
        run_page(700.0, 300.0, |ui| {
            let code = "miasma-contact:3pg8nKBJuripJfrJxMKBKFY6JSBPhTP266EJPq6Q8RDVL2ymxw";
            heights.push(code_display(ui, code).rect.height());
            let mut t = String::new();
            heights.push(ui.add(input(&mut t)).rect.height());
            heights.push(ui.add(input_mono(&mut t)).rect.height());
        });
        for h in &heights {
            assert!((h - CONTROL_H).abs() < 0.6, "{heights:?}");
        }
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
    /// Right edge of the content column and the rectangles of the buttons that `add` draws, in a
    /// column `width` px wide (two frames: the first one settles the layout).
    fn action_rects(
        width: f32,
        add: impl Fn(&mut Ui, &mut Vec<(String, egui::Rect)>),
    ) -> (f32, Vec<(String, egui::Rect)>) {
        let ctx = egui::Context::default();
        let mut rects = Vec::new();
        let mut right = 0.0;
        for _ in 0..2 {
            rects.clear();
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 600.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(raw, |ctx| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::none())
                    .show(ctx, |ui| {
                        right = ui.max_rect().right();
                        add(ui, &mut rects);
                    });
            });
        }
        (right, rects)
    }

    #[test]
    fn dialog_buttons_sit_at_the_bottom_right_with_cancel_left_of_confirm() {
        let (right, rects) = action_rects(440.0, |ui, rects| {
            dialog_actions(ui, |ui| {
                let confirm = ui.add(danger_button("Erase"));
                let cancel = ui.add(secondary_button("Cancel"));
                rects.push(("confirm".into(), confirm.rect));
                rects.push(("cancel".into(), cancel.rect));
            });
        });
        let get = |n: &str| rects.iter().find(|(k, _)| k == n).unwrap().1;
        assert!(
            (get("confirm").right() - right).abs() <= 1.0,
            "{rects:?} {right}"
        );
        assert!(
            get("cancel").right() < get("confirm").left(),
            "cancel is left of confirm"
        );
    }

    #[test]
    fn banner_actions_are_right_aligned_and_stack_under_the_text_when_narrow() {
        for (width, stacked) in [(900.0_f32, false), (400.0, true)] {
            let (right, rects) = action_rects(width, |ui, rects| {
                banner_actions(
                    ui,
                    Level::Info,
                    "A new version is ready to install.",
                    |ui| {
                        let update = ui.add(primary_button("Update"));
                        let skip = ui.add(secondary_button("Skip this version"));
                        let later = ui.add(secondary_button("Later"));
                        rects.push(("update".into(), update.rect));
                        rects.push(("skip".into(), skip.rect));
                        rects.push(("later".into(), later.rect));
                    },
                );
            });
            let get = |n: &str| rects.iter().find(|(k, _)| k == n).unwrap().1;
            assert!(
                (get("update").right() - right).abs() <= 1.0,
                "{width}: {rects:?} {right}"
            );
            assert!(
                get("later").right() < get("skip").left(),
                "{width}: Later, Skip, Update"
            );
            assert!(
                get("skip").right() < get("update").left(),
                "{width}: Later, Skip, Update"
            );
            if stacked {
                assert!(
                    get("update").top() > 20.0,
                    "{width}: the actions are under the text"
                );
            }
        }
    }
}
