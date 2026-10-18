//! Accessibility helpers: names for custom-painted widgets, focus handling for dialogs, and the
//! inventory that keeps new custom widgets from shipping without a name.
//!
//! egui 0.27 publishes an AccessKit tree. Stock widgets (buttons, labels, text edits) describe
//! themselves; anything painted by hand (a status dot with a galley, a progress bar made of
//! rectangles, a QR code, a list row drawn with the painter) is invisible to a screen reader until
//! its `Response` gets `widget_info`. All names come from the existing locale tables (English,
//! Japanese, Simplified Chinese), so there is no separate string table to keep complete.
//!
//! Focus follows egui's own model: Tab visits widgets in the order they are created in a frame, and
//! Esc drops focus. This module adds only two small things on top: a dialog remembers which widget
//! opened it and gives focus back when it closes, and a dialog puts focus on its safe button when
//! it opens.

use eframe::egui;

/// Frames a dialog keeps asking for focus on its safe button (the window is laid out invisibly on
/// its first frame, so the first request may not stick).
const FOCUS_ATTEMPTS: u8 = 6;

#[derive(Clone, Copy, Default)]
struct DialogFocus {
    /// The widget that had focus when the dialog opened.
    opener: Option<egui::Id>,
    /// One more than the frame number of the last `dialog_enter` call (0 = never called).
    last_frame: u64,
    /// Remaining attempts to move focus into the dialog.
    attempts: u8,
}

fn state_id(key: &str) -> egui::Id {
    egui::Id::new(("a11y_dialog_focus", key))
}

/// Call every frame a dialog is shown, before drawing it. Returns true on the first frame of an
/// opening: that is when the widget that had focus (the control that opened the dialog) is
/// remembered. A dialog that was not drawn in the previous frame counts as newly opened.
pub fn dialog_enter(ctx: &egui::Context, key: &'static str) -> bool {
    let id = state_id(key);
    let frame = ctx.frame_nr() + 1;
    let mut state: DialogFocus = ctx.data_mut(|d| d.get_temp(id)).unwrap_or_default();
    let fresh = state.last_frame == 0 || state.last_frame + 1 < frame;
    if fresh {
        state = DialogFocus {
            opener: ctx.memory(|m| m.focused()),
            last_frame: frame,
            attempts: FOCUS_ATTEMPTS,
        };
    } else {
        state.last_frame = frame;
    }
    ctx.data_mut(|d| d.insert_temp(id, state));
    fresh
}

/// Call with the response of the dialog's safe button (cancel, close, keep) on every frame the
/// dialog is shown: focus moves there for the first frames after opening, then is left alone so
/// that Tab and the mouse behave normally.
pub fn dialog_focus_safe_button(ctx: &egui::Context, key: &'static str, safe: &egui::Response) {
    let id = state_id(key);
    let mut state: DialogFocus = ctx.data_mut(|d| d.get_temp(id)).unwrap_or_default();
    if state.attempts > 0 {
        if safe.has_focus() {
            state.attempts = 0;
        } else {
            safe.request_focus();
            state.attempts -= 1;
        }
        ctx.data_mut(|d| d.insert_temp(id, state));
    }
}

/// Call on the frame a dialog closes: focus goes back to the control that opened it.
pub fn dialog_leave(ctx: &egui::Context, key: &'static str) {
    let id = state_id(key);
    let state: Option<DialogFocus> = ctx.data_mut(|d| d.get_temp(id));
    if let Some(opener) = state.and_then(|s| s.opener) {
        ctx.memory_mut(|m| m.request_focus(opener));
    }
    ctx.data_mut(|d| d.remove::<DialogFocus>(id));
}

/// Consume an Esc key press (true when there was one). A dialog calls this while it is open.
pub fn esc_pressed(ctx: &egui::Context) -> bool {
    ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
}

/// Description of the segment bar: "Segments: 12 / 40" with the share done as its value.
pub fn segments_info(name: &str, done: u64, total: u64) -> egui::WidgetInfo {
    let mut info = egui::WidgetInfo::labeled(
        egui::WidgetType::ProgressIndicator,
        format!("{name}: {done} / {total}"),
    );
    let fraction = if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64) as f32
    };
    info.value = Some(percent_value(fraction));
    info
}

/// Name for one transfer row: direction, title, state, percent.
pub fn transfer_row_label(direction: &str, title: &str, state: &str, percent: &str) -> String {
    let mut s = format!("{direction}: {title}, {state}");
    if !percent.is_empty() {
        s.push_str(", ");
        s.push_str(percent);
    }
    s
}

/// The value a progress indicator reports to assistive technology: percent, 0 to 100.
pub fn percent_value(fraction: f32) -> f64 {
    (fraction.clamp(0.0, 1.0) as f64 * 100.0).round()
}

/// A progress bar's accessible description.
pub fn progress_info(name: &str, fraction: f32) -> egui::WidgetInfo {
    let mut info = egui::WidgetInfo::labeled(egui::WidgetType::ProgressIndicator, name);
    info.value = Some(percent_value(fraction));
    info
}

#[cfg(test)]
pub(crate) mod inventory {
    //! Every place that allocates a rectangle and paints it by hand, and what the screen reader
    //! hears. `custom_widgets_are_all_in_the_inventory` walks the source and fails when a new
    //! one appears that is not listed here: add it with a name (or say why it is decoration).

    use crate::locale::{self, Locale};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Role {
        /// Gets `widget_info` with a localized name.
        Named,
        /// Pure decoration next to text that already carries the meaning.
        Decoration,
    }

    pub struct Entry {
        pub file: &'static str,
        /// The function that allocates and paints the widget.
        pub func: &'static str,
        pub role: Role,
        /// The locale strings that make up its name, per locale (empty for decoration).
        pub names: fn(Locale) -> Vec<&'static str>,
    }

    fn none(_: Locale) -> Vec<&'static str> {
        Vec::new()
    }

    pub const INVENTORY: &[Entry] = &[
        Entry {
            file: "ui_kit.rs",
            func: "dot_line",
            role: Role::Named,
            // The text next to the dot is the name; it is whatever the caller passes.
            names: none,
        },
        Entry {
            file: "ui_kit.rs",
            func: "status_headline",
            role: Role::Decoration,
            names: none,
        },
        Entry {
            file: "ui_kit.rs",
            func: "notice",
            role: Role::Decoration,
            names: none,
        },
        Entry {
            file: "ui_kit.rs",
            func: "divider",
            role: Role::Decoration,
            names: none,
        },
        Entry {
            file: "ui_kit.rs",
            func: "nav_tab",
            role: Role::Named,
            // The tab label is passed in by the caller from the tab strings.
            names: |l| {
                let s = locale::strings(l);
                vec![s.tab_status, s.tab_settings]
            },
        },
        Entry {
            file: "ui_kit.rs",
            func: "progress",
            role: Role::Named,
            names: |l| vec![locale::strings(l).status_storage],
        },
        Entry {
            file: "group_ui.rs",
            func: "group_row",
            role: Role::Named,
            // "<group name>, <n> members", plus unread count and preview built by the caller.
            names: |l| vec![locale::group_strings(l).a11y_row],
        },
        Entry {
            file: "speed.rs",
            func: "paint_spark",
            // The sparkline repeats the speed that the text line beside it states.
            role: Role::Decoration,
            names: none,
        },
        Entry {
            file: "chat_ui.rs",
            func: "conversation_row",
            role: Role::Named,
            names: |l| {
                let c = locale::chat_strings(l);
                vec![c.a11y_row, c.a11y_unread]
            },
        },
        Entry {
            file: "contacts.rs",
            func: "row_ui",
            role: Role::Named,
            names: |l| {
                let c = locale::contact_strings(l);
                vec![c.dir_out, c.dir_in]
            },
        },
        Entry {
            file: "transfers.rs",
            func: "strip_section",
            role: Role::Named,
            names: |l| {
                let t = locale::transfer_strings(l);
                vec![t.segments_label]
            },
        },
        Entry {
            file: "transfers.rs",
            func: "draw_qr",
            role: Role::Named,
            names: |l| vec![locale::transfer_strings(l).qr_note],
        },
        Entry {
            file: "transfers.rs",
            func: "job_row",
            role: Role::Named,
            names: |l| {
                let t = locale::transfer_strings(l);
                vec![t.send, t.receive]
            },
        },
    ];

    /// Calls that put a hand-painted rectangle in the layout.
    pub const PATTERNS: &[&str] = &[
        "allocate_exact_size(",
        "allocate_painter(",
        "allocate_response(",
        "allocate_rect(",
        ".interact(",
    ];
}

#[cfg(test)]
mod tests {
    use super::inventory::*;
    use super::*;
    use crate::locale::Locale;
    use std::path::{Path, PathBuf};

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                rust_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// Name of the last `fn` that starts before byte offset `at`.
    fn enclosing_fn(src: &str, at: usize) -> Option<String> {
        let head = &src[..at];
        let i = head.rfind("fn ")?;
        let name: String = head[i + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        Some(name)
    }

    /// Source text of function `name` (from its `fn` line to the next `fn` at the same or a lower
    /// indentation).
    fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
        let needle = format!("fn {name}");
        let start = src.match_indices(&needle).find_map(|(i, _)| {
            let after = src[i + needle.len()..].chars().next()?;
            (after == '(' || after == '<').then_some(i)
        })?;
        let line_start = src[..start].rfind('\n').map_or(0, |n| n + 1);
        let indent = src[line_start..].chars().take_while(|c| *c == ' ').count();
        let mut end = src.len();
        let mut pos = start;
        for line in src[start..].split_inclusive('\n').skip(1) {
            pos += src[pos..].find('\n').map_or(0, |n| n + 1);
            let ind = line.chars().take_while(|c| *c == ' ').count();
            let t = line.trim_start();
            let is_fn =
                t.starts_with("fn ") || t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ");
            if ind <= indent && is_fn {
                end = pos;
                break;
            }
        }
        Some(&src[line_start..end])
    }

    #[test]
    fn custom_widgets_are_all_in_the_inventory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        assert!(files.len() > 10, "source walk found {} files", files.len());
        let mut found: Vec<(String, String)> = Vec::new();
        for f in &files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "a11y.rs" {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            // Only the code above the test module counts.
            let code_end = src
                .find("\n#[cfg(test)]\nmod ")
                .or_else(|| src.find("\r\n#[cfg(test)]\r\nmod "))
                .unwrap_or(src.len());
            let code = &src[..code_end];
            for pat in PATTERNS {
                for (at, _) in code.match_indices(pat) {
                    let func = enclosing_fn(code, at).unwrap_or_default();
                    let key = (rel.rsplit('/').next().unwrap().to_owned(), func);
                    if !found.contains(&key) {
                        found.push(key);
                    }
                }
            }
        }
        for (file, func) in &found {
            assert!(
                INVENTORY.iter().any(|e| e.file == file && e.func == func),
                "{file}: fn {func} paints a custom widget but is not in a11y::inventory::INVENTORY; \
                 give its response widget_info(...) with a localized name and list it"
            );
        }
        for e in INVENTORY {
            assert!(
                found.iter().any(|(f, n)| f == e.file && n == e.func),
                "{} fn {} is in the inventory but no longer allocates a custom widget; remove it",
                e.file,
                e.func
            );
        }
    }

    #[test]
    fn every_named_widget_sets_widget_info_in_its_function() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for e in INVENTORY.iter().filter(|e| e.role == Role::Named) {
            let src = std::fs::read_to_string(root.join(e.file)).unwrap();
            let body = fn_body(&src, e.func)
                .unwrap_or_else(|| panic!("{}: fn {} not found", e.file, e.func));
            assert!(
                body.contains("widget_info") || body.contains("progress_info"),
                // progress_info / segments_info build the WidgetInfo handed to widget_info
                "{}: fn {} is Named but never calls widget_info",
                e.file,
                e.func
            );
        }
    }

    #[test]
    fn names_exist_in_every_locale_and_are_translated() {
        for e in INVENTORY {
            let en = (e.names)(Locale::En);
            for lang in [Locale::Ja, Locale::ZhCn] {
                let other = (e.names)(lang);
                assert_eq!(en.len(), other.len(), "{} {}", e.file, e.func);
                for (a, b) in en.iter().zip(&other) {
                    assert!(!a.trim().is_empty(), "{} {} {lang:?}", e.file, e.func);
                    assert!(!b.trim().is_empty(), "{} {} {lang:?}", e.file, e.func);
                    assert!(
                        !b.is_ascii(),
                        "{} {}: {lang:?} name {b:?} is not translated",
                        e.file,
                        e.func
                    );
                }
            }
            if e.role == Role::Named && e.func != "dot_line" {
                assert!(
                    !en.is_empty(),
                    "{} {}: a named widget lists no strings",
                    e.file,
                    e.func
                );
            }
        }
    }

    #[test]
    fn labels_are_built_from_their_parts() {
        let info = segments_info("Segments", 10, 40);
        assert_eq!(info.label.as_deref(), Some("Segments: 10 / 40"));
        assert_eq!(info.value, Some(25.0));
        assert_eq!(segments_info("Segments", 0, 0).value, Some(0.0));
        assert_eq!(
            transfer_row_label("Send", "a.bin", "Running", "42%"),
            "Send: a.bin, Running, 42%"
        );
        assert_eq!(
            transfer_row_label("Send", "a.bin", "Done", ""),
            "Send: a.bin, Done"
        );
    }

    #[test]
    fn progress_value_is_a_clamped_percent() {
        assert_eq!(percent_value(0.0), 0.0);
        assert_eq!(percent_value(0.426), 43.0);
        assert_eq!(percent_value(1.0), 100.0);
        assert_eq!(percent_value(-3.0), 0.0);
        assert_eq!(percent_value(7.0), 100.0);
        let info = progress_info("Storage", 0.5);
        assert_eq!(info.label.as_deref(), Some("Storage"));
        assert_eq!(info.value, Some(50.0));
        assert_eq!(info.typ, egui::WidgetType::ProgressIndicator);
    }

    #[test]
    fn focus_ring_meets_three_to_one_on_every_surface() {
        use crate::theme::{contrast, Palette};
        for (mode, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            for (name, bg) in [
                ("bg", p.bg),
                ("surface", p.surface),
                ("surface_subtle", p.surface_subtle),
                ("selected", p.selected),
            ] {
                let r = contrast(crate::ui_kit::focus_ring_color(&p), bg);
                assert!(r >= 3.0, "{mode}: focus ring on {name} = {r:.2}");
            }
        }
    }

    // ── Dialog focus, without a window ────────────────────────────────────

    fn screen() -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 480.0),
            )),
            ..Default::default()
        }
    }

    fn esc() -> egui::RawInput {
        let mut input = screen();
        input.events.push(egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        input
    }

    /// One frame of a page with an "open" button and, while `open`, a dialog. Returns the opener's
    /// id and whether the dialog was closed (by Esc) in this frame.
    fn frame(
        ctx: &egui::Context,
        input: egui::RawInput,
        open: bool,
        focus_opener: bool,
    ) -> (egui::Id, bool) {
        let mut opener = egui::Id::NULL;
        let mut closed = false;
        let _ = ctx.run(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let b = ui.button("open");
                opener = b.id;
                if focus_opener {
                    b.request_focus();
                }
            });
            if open {
                dialog_enter(ctx, "t_dialog");
                if esc_pressed(ctx) {
                    dialog_leave(ctx, "t_dialog");
                    closed = true;
                    return;
                }
                egui::Window::new("d").show(ctx, |ui| {
                    let safe = ui.button("cancel");
                    dialog_focus_safe_button(ctx, "t_dialog", &safe);
                });
            }
        });
        (opener, closed)
    }

    #[test]
    fn closing_a_dialog_returns_focus_to_the_control_that_opened_it() {
        let ctx = egui::Context::default();
        // The opener has focus (as after a keyboard press on it).
        let (opener, _) = frame(&ctx, screen(), false, true);
        frame(&ctx, screen(), false, false);
        assert_eq!(ctx.memory(|m| m.focused()), Some(opener));
        // The dialog opens and takes focus on its safe button within a few frames.
        for _ in 0..4 {
            frame(&ctx, screen(), true, false);
        }
        let inside = ctx.memory(|m| m.focused());
        assert!(inside.is_some(), "focus is inside the dialog");
        assert_ne!(inside, Some(opener));
        // Esc closes it, and focus is back on the opener.
        let (_, closed) = frame(&ctx, esc(), true, false);
        assert!(closed, "Esc closes the dialog");
        frame(&ctx, screen(), false, false);
        assert_eq!(ctx.memory(|m| m.focused()), Some(opener));
    }

    #[test]
    fn a_dialog_that_was_not_drawn_in_between_counts_as_new() {
        let ctx = egui::Context::default();
        let mut results = Vec::new();
        for frame_has_dialog in [true, true, false, false, true] {
            let _ = ctx.run(screen(), |ctx| {
                if frame_has_dialog {
                    results.push(dialog_enter(ctx, "t_fresh"));
                }
            });
        }
        assert_eq!(results, [true, false, true]);
    }
}
