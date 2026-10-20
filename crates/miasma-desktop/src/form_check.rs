//! Forms that say what is missing.
//!
//! Three small helpers used by every screen with a main button that needs input first:
//!
//! - [`name`] gives a text field, number field or drop-down an accessible name without touching
//!   its role or its value (a password field stays a password field for a screen reader).
//! - [`primary_with_reason`] draws the main button, disabled until every [`Need`] is met, with one
//!   short plain sentence beside it that says what to do first. An attempt anyway (Enter in a
//!   field of the form, or a click on the disabled button) moves the focus to the first field
//!   that is still missing.
//! - [`submitted`] tells whether Enter was pressed in a single-line field.
//!
//! Nothing here knows about a particular form; the screens pass their own fields and sentences.

use eframe::egui;

use crate::ui_kit as kit;

/// One condition of a form: the field it belongs to (when there is one), whether it is met, and
/// the sentence that says what to do when it is not.
#[derive(Clone, Copy)]
pub struct Need {
    /// The field to focus when the person tries to go on without it.
    pub field: Option<egui::Id>,
    pub ok: bool,
    pub reason: &'static str,
}

impl Need {
    pub fn new(field: &egui::Response, ok: bool, reason: &'static str) -> Self {
        Self {
            field: Some(field.id),
            ok,
            reason,
        }
    }

    /// A condition that is not about a field (the service is not connected yet).
    pub fn general(ok: bool, reason: &'static str) -> Self {
        Self {
            field: None,
            ok,
            reason,
        }
    }
}

/// The first condition that is not met, in the order the fields are on the screen.
pub fn first_missing(needs: &[Need]) -> Option<&Need> {
    needs.iter().find(|n| !n.ok)
}

/// Give the control behind `resp` an accessible name. The role (text input, password input,
/// spin button, ...) and the value that egui already published stay as they are.
pub fn name(resp: &egui::Response, label: &str) {
    let label = label.to_owned();
    let _ = resp.ctx.accesskit_node_builder(resp.id, |b| {
        b.set_name(label);
    });
}

/// Tell assistive technology that the control behind `resp` is switched off (egui draws a
/// disabled widget grey but does not publish that by itself).
pub fn mark_disabled(resp: &egui::Response) {
    let _ = resp.ctx.accesskit_node_builder(resp.id, |b| {
        b.set_disabled();
    });
}

/// True when Enter was pressed in this single-line field (it gave up focus because of it).
pub fn submitted(resp: &egui::Response) -> bool {
    resp.lost_focus() && resp.ctx.input(|i| i.key_pressed(egui::Key::Enter))
}

/// True when the primary mouse button was pressed on this (disabled) button this frame.
fn pressed_while_disabled(resp: &egui::Response) -> bool {
    resp.contains_pointer() && resp.ctx.input(|i| i.pointer.primary_clicked())
}

/// The main button of a form.
///
/// It is enabled when every need is met and `allowed` (not busy, and so on) holds. When something
/// is missing, the reason for the first missing need stands beside the button. `attempt` is true
/// when the person tried to go on from a field (Enter); together with a click on the disabled
/// button it moves the focus to the first missing field. Returns true when the button was pressed.
pub fn primary_with_reason(
    ui: &mut egui::Ui,
    label: &str,
    needs: &[Need],
    allowed: bool,
    attempt: bool,
) -> bool {
    let missing = first_missing(needs).copied();
    let resp = kit::primary(ui, missing.is_none() && allowed, label);
    if let Some(m) = missing {
        if attempt || pressed_while_disabled(&resp) {
            if let Some(id) = m.field {
                ui.ctx().memory_mut(|mem| mem.request_focus(id));
            }
        }
        // A note for assistive technology and for the eye: next to the button, wrapped.
        kit::hint(ui, m.reason);
    }
    resp.clicked()
}

/// What a key did in a small inline edit (the rename field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditKey {
    None,
    /// Enter: keep what was typed.
    Save,
    /// Esc: leave the field as it was.
    Cancel,
}

/// Enter saves and Esc cancels an inline single-line edit. The field gives up focus on both
/// keys, so this only looks at a field that has just lost it.
pub fn edit_keys(resp: &egui::Response) -> EditKey {
    if !resp.lost_focus() {
        return EditKey::None;
    }
    resp.ctx.input(|i| {
        if i.key_pressed(egui::Key::Escape) {
            EditKey::Cancel
        } else if i.key_pressed(egui::Key::Enter) {
            EditKey::Save
        } else {
            EditKey::None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(600.0, 300.0),
            )),
            ..Default::default()
        }
    }

    /// One frame of an inline rename field that has focus; returns the key result.
    fn rename_frame(ctx: &egui::Context, input: egui::RawInput, text: &mut String) -> EditKey {
        let mut key = EditKey::None;
        let _ = ctx.run(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let r = ui.add(egui::TextEdit::singleline(text));
                key = edit_keys(&r);
                if key == EditKey::None && !r.has_focus() && !ctx.memory(|m| m.focused().is_some())
                {
                    r.request_focus();
                }
            });
        });
        key
    }

    fn pressed(k: egui::Key) -> egui::RawInput {
        let mut input = raw();
        input.events.push(egui::Event::Key {
            key: k,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        input
    }

    #[test]
    fn enter_saves_and_escape_cancels_the_inline_rename() {
        for (k, want) in [
            (egui::Key::Enter, EditKey::Save),
            (egui::Key::Escape, EditKey::Cancel),
        ] {
            let ctx = egui::Context::default();
            let mut text = String::from("Anna");
            for _ in 0..3 {
                assert_eq!(rename_frame(&ctx, raw(), &mut text), EditKey::None);
            }
            assert_eq!(rename_frame(&ctx, pressed(k), &mut text), want, "{k:?}");
        }
    }

    #[test]
    fn typing_in_the_rename_field_is_neither_save_nor_cancel() {
        let ctx = egui::Context::default();
        let mut text = String::from("Anna");
        for _ in 0..3 {
            rename_frame(&ctx, raw(), &mut text);
        }
        let mut input = raw();
        input.events.push(egui::Event::Text("x".into()));
        assert_eq!(rename_frame(&ctx, input, &mut text), EditKey::None);
    }

    #[test]
    fn first_missing_follows_screen_order() {
        let id = |n: &str| Some(egui::Id::new(n));
        let needs = [
            Need {
                field: id("a"),
                ok: true,
                reason: "a",
            },
            Need {
                field: id("b"),
                ok: false,
                reason: "b",
            },
            Need {
                field: id("c"),
                ok: false,
                reason: "c",
            },
        ];
        assert_eq!(first_missing(&needs).map(|n| n.reason), Some("b"));
        assert!(first_missing(&needs[..1]).is_none());
        assert!(first_missing(&[]).is_none());
    }

    /// A form with two fields and a main button; returns (button pressed, first field id,
    /// second field id) for the frame.
    fn form_frame(
        ctx: &egui::Context,
        input: egui::RawInput,
        a: &mut String,
        b: &mut String,
    ) -> (bool, egui::Id, egui::Id) {
        let mut out = (false, egui::Id::NULL, egui::Id::NULL);
        let _ = ctx.run(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let ra = ui.add(kit::input(a));
                let rb = ui.add(kit::input(b));
                let needs = [
                    Need::new(&ra, !a.trim().is_empty(), "Choose a file first."),
                    Need::new(&rb, !b.trim().is_empty(), "Enter the code first."),
                ];
                let attempt = submitted(&ra) || submitted(&rb);
                let pressed = primary_with_reason(ui, "Go", &needs, true, attempt);
                out = (pressed, ra.id, rb.id);
            });
        });
        out
    }

    fn enter() -> egui::RawInput {
        let mut input = raw();
        input.events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        input
    }

    #[test]
    fn enter_in_a_field_of_an_incomplete_form_focuses_the_first_missing_field() {
        let ctx = egui::Context::default();
        let (mut a, mut b) = (String::new(), String::from("code"));
        let (_, ida, idb) = form_frame(&ctx, raw(), &mut a, &mut b);
        // The person is in the second field and presses Enter; the first one is empty.
        ctx.memory_mut(|m| m.request_focus(idb));
        form_frame(&ctx, raw(), &mut a, &mut b);
        form_frame(&ctx, enter(), &mut a, &mut b);
        form_frame(&ctx, raw(), &mut a, &mut b);
        assert_eq!(ctx.memory(|m| m.focused()), Some(ida));
    }

    #[test]
    fn a_disabled_main_button_is_published_as_disabled() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let (mut a, mut b) = (String::new(), String::from("x"));
        let full = ctx.run(raw(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let ra = ui.add(kit::input(&mut a));
                let rb = ui.add(kit::input(&mut b));
                let needs = [
                    Need::new(&ra, !a.is_empty(), "Choose a file first."),
                    Need::new(&rb, !b.is_empty(), "Enter the code first."),
                ];
                primary_with_reason(ui, "Go", &needs, true, false);
            });
        });
        let update = full.platform_output.accesskit_update.expect("tree");
        let go: Vec<bool> = update
            .nodes
            .iter()
            .filter(|(_, n)| n.name() == Some("Go"))
            .map(|(_, n)| n.is_disabled())
            .collect();
        assert_eq!(go, [true], "the Go button is published as disabled");
    }

    #[test]
    fn name_sets_the_accessible_name_and_keeps_the_text_input_role() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut text = String::new();
        let mut secret = String::new();
        let full = ctx.run(raw(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let r = ui.add(kit::input(&mut text));
                name(&r, "Text to store");
                let r = ui.add(kit::input(&mut secret).password(true));
                name(&r, "Password");
            });
        });
        let update = full
            .platform_output
            .accesskit_update
            .expect("accesskit tree");
        let named: Vec<(egui::accesskit::Role, String)> = update
            .nodes
            .iter()
            .filter_map(|(_, n)| n.name().map(|s| (n.role(), s.to_owned())))
            .collect();
        assert!(
            named.contains(&(egui::accesskit::Role::TextInput, "Text to store".into())),
            "{named:?}"
        );
        assert!(
            named.contains(&(egui::accesskit::Role::PasswordInput, "Password".into())),
            "a password field keeps its role: {named:?}"
        );
    }
}
