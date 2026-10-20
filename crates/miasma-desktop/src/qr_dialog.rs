//! The contact QR code as a small dialog.
//!
//! It used to open inline and push the rest of the page down. As a dialog it floats above the
//! page: Esc and a click outside close it, the copy button sits next to the image, the image has
//! one accessible name, and the description is read once.
//!
//! The caller owns the "is it open" flag and calls [`show`] every frame while it is set.

use eframe::egui;

use crate::ui_kit as kit;

/// The sentences of the dialog, all from the locale tables.
pub struct QrTexts<'a> {
    pub title: &'a str,
    /// What the image is, for a screen reader.
    pub image_name: &'a str,
    /// One sentence under the image: what the code does when it is scanned.
    pub note: &'a str,
    /// Shown instead of the image when the text does not fit a QR code.
    pub too_long: &'a str,
    pub copy: &'a str,
    pub close: &'a str,
}

/// What happened in this frame.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// The dialog stays open.
    pub keep_open: bool,
    /// The copy button was pressed.
    pub copy_pressed: bool,
}

/// Draw the dialog for `payload` (the text inside the QR code). The key is the one the other
/// dialogs use for focus: the first call after a pause counts as the opening, which moves focus
/// to the close button; the last call gives focus back to the control that opened it.
pub fn show(ctx: &egui::Context, texts: &QrTexts<'_>, payload: &str) -> Outcome {
    const KEY: &str = "contact_qr";
    let fresh = crate::a11y::dialog_enter(ctx, KEY);
    if crate::a11y::esc_pressed(ctx) {
        crate::a11y::dialog_leave(ctx, KEY);
        return Outcome::default();
    }
    let mut out = Outcome {
        keep_open: true,
        copy_pressed: false,
    };
    let shown = egui::Window::new(texts.title)
        .id(egui::Id::new(KEY))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .max_width(300.0)
        .show(ctx, |ui| {
            ui.set_max_width(280.0);
            ui.vertical_centered(|ui| {
                if !crate::transfers::draw_qr(ui, payload, 220.0, texts.image_name) {
                    ui.label(egui::RichText::new(texts.too_long).color(kit::pal().danger));
                }
            });
            ui.add_space(kit::SP_1);
            kit::hint(ui, texts.note);
            ui.add_space(kit::SP_1);
            kit::button_row(ui, |ui| {
                if ui.add(kit::secondary_button(texts.copy)).clicked() {
                    out.copy_pressed = true;
                }
                let close = ui.add(kit::secondary_button(texts.close));
                crate::a11y::dialog_focus_safe_button(ui.ctx(), KEY, &close);
                if close.clicked() {
                    out.keep_open = false;
                }
            });
        });
    // A click outside the dialog closes it (not on the frame that opened it: the click that
    // pressed the button which opened the dialog is still in this frame's input).
    if let Some(window) = shown {
        let rect = window.response.rect;
        let outside = ctx.input(|i| {
            i.pointer.primary_clicked()
                && i.pointer
                    .interact_pos()
                    .is_some_and(|p| !rect.expand(2.0).contains(p))
        });
        if outside && !fresh {
            out.keep_open = false;
        }
    }
    if !out.keep_open {
        crate::a11y::dialog_leave(ctx, KEY);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXTS: QrTexts<'static> = QrTexts {
        title: "Your contact QR code",
        image_name: "QR code of your contact code",
        note: "Scan it with the phone camera.",
        too_long: "Too long for a QR code.",
        copy: "Copy code",
        close: "Close",
    };

    fn screen() -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 560.0),
            )),
            ..Default::default()
        }
    }

    fn key(k: egui::Key) -> egui::RawInput {
        let mut input = screen();
        input.events.push(egui::Event::Key {
            key: k,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        input
    }

    fn click_at(pos: egui::Pos2) -> egui::RawInput {
        let mut input = screen();
        input.events.push(egui::Event::PointerMoved(pos));
        for pressed in [true, false] {
            input.events.push(egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            });
        }
        input
    }

    fn frame(ctx: &egui::Context, input: egui::RawInput) -> (Outcome, egui::Rect) {
        let mut out = Outcome::default();
        let _ = ctx.run(input, |ctx| {
            out = show(ctx, &TEXTS, "Miasma Contact\nabc");
        });
        let rect = ctx
            .memory(|m| m.area_rect(egui::Id::new("contact_qr")))
            .unwrap_or(egui::Rect::NOTHING);
        (out, rect)
    }

    fn opened(ctx: &egui::Context) -> egui::Rect {
        for _ in 0..3 {
            let (out, _) = frame(ctx, screen());
            assert!(out.keep_open);
        }
        frame(ctx, screen()).1
    }

    #[test]
    fn it_stays_open_without_input() {
        let ctx = egui::Context::default();
        let rect = opened(&ctx);
        assert!(rect.width() > 100.0, "the dialog has a size: {rect:?}");
    }

    #[test]
    fn escape_closes_it() {
        let ctx = egui::Context::default();
        opened(&ctx);
        let (out, _) = frame(&ctx, key(egui::Key::Escape));
        assert!(!out.keep_open);
    }

    #[test]
    fn a_click_outside_closes_it_and_a_click_inside_does_not() {
        let ctx = egui::Context::default();
        let rect = opened(&ctx);
        let (out, _) = frame(&ctx, click_at(rect.center()));
        assert!(out.keep_open, "a click on the image keeps it open");
        let (out, _) = frame(&ctx, click_at(egui::pos2(4.0, 4.0)));
        assert!(!out.keep_open, "a click on the page closes it");
    }

    #[test]
    fn the_click_that_opened_it_does_not_close_it() {
        let ctx = egui::Context::default();
        // The very first frame already carries a click on the page (the opening click).
        let (out, _) = frame(&ctx, click_at(egui::pos2(4.0, 4.0)));
        assert!(out.keep_open);
    }
}
