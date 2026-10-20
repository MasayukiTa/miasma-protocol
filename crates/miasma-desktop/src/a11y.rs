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
use egui::accesskit;

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
        // A control that named itself as the opener (a row menu's button) wins over whatever has
        // focus, which may be a menu item that is about to disappear.
        let named: Option<(egui::Id, u64)> = ctx.data_mut(|d| d.get_temp(opener_id()));
        let named = named
            .filter(|(_, at)| frame <= at + OPENER_FRAMES)
            .map(|(id, _)| id);
        ctx.data_mut(|d| d.remove::<(egui::Id, u64)>(opener_id()));
        state = DialogFocus {
            opener: named.or_else(|| ctx.memory(|m| m.focused())),
            last_frame: frame,
            attempts: FOCUS_ATTEMPTS,
        };
    } else {
        state.last_frame = frame;
    }
    ctx.data_mut(|d| d.insert_temp(id, state));
    segment_begin(ctx, key);
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
    // An opener that is gone is not asked for focus: the accessibility tree would point at it.
    if let Some(opener) = state.and_then(|s| s.opener).filter(|o| on_screen(ctx, *o)) {
        ctx.memory_mut(|m| m.request_focus(opener));
        // The page behind a dialog is switched off while it is open, and focus on a switched-off
        // widget is dropped at the end of the frame. Ask again in the next frame.
        ctx.data_mut(|d| d.insert_temp(restore_id(), opener));
    }
    ctx.data_mut(|d| d.remove::<DialogFocus>(id));
}

/// Frames during which a named opener is still taken by the next dialog that opens.
const OPENER_FRAMES: u64 = 3;

fn opener_id() -> egui::Id {
    egui::Id::new("a11y_dialog_named_opener")
}

/// A control that is about to open a dialog says that focus goes back to it when the dialog
/// closes.
pub fn set_opener(ctx: &egui::Context, opener: egui::Id) {
    let frame = ctx.frame_nr();
    ctx.data_mut(|d| d.insert_temp(opener_id(), (opener, frame)));
}

/// Whether a widget with this id was on screen this frame or the one before.
fn on_screen(ctx: &egui::Context, id: egui::Id) -> bool {
    ctx.read_response(id).is_some()
}

// ── Dialog boundary in the accessibility tree ─────────────────────────────

/// One dialog drawn in this frame: the range of top-level tree nodes it created.
#[derive(Clone, Debug, Default)]
struct Segment {
    start: usize,
    end: Option<usize>,
    title: String,
    /// The dialog's key: its tree node keeps the same id from frame to frame.
    key: &'static str,
}

#[derive(Clone, Default)]
struct FrameSegments {
    frame: u64,
    list: Vec<Segment>,
}

fn segments_id() -> egui::Id {
    egui::Id::new("a11y_dialog_segments")
}

/// Number of top-level nodes of the accessibility tree built so far (None when no accessibility
/// client is attached: nothing is built then, and nothing here costs anything).
fn top_level_count(ctx: &egui::Context) -> Option<usize> {
    ctx.accesskit_node_builder(egui::accesskit_root_id(), |b| b.children().len())
}

fn with_segments(ctx: &egui::Context, f: impl FnOnce(&mut Vec<Segment>)) {
    let frame = ctx.frame_nr();
    ctx.data_mut(|d| {
        let s = d.get_temp_mut_or_default::<FrameSegments>(segments_id());
        if s.frame != frame {
            s.frame = frame;
            s.list.clear();
        }
        f(&mut s.list);
    });
}

/// Called by `dialog_enter` in every frame a dialog is drawn: the dialog's nodes start here.
fn segment_begin(ctx: &egui::Context, key: &'static str) {
    let Some(at) = top_level_count(ctx) else {
        return;
    };
    with_segments(ctx, |list| {
        if let Some(prev) = list.last_mut() {
            prev.end.get_or_insert(at);
        }
        list.push(Segment {
            start: at,
            end: None,
            title: String::new(),
            key,
        });
    });
}

/// Name the dialog that is being drawn. Call it right before the dialog's window, with the same
/// text as the window title: it becomes the accessible name of the dialog.
pub fn dialog_title(ctx: &egui::Context, title: &str) {
    with_segments(ctx, |list| {
        if let Some(last) = list.last_mut() {
            last.title = title.to_owned();
        }
    });
}

/// Optional: marks the end of the dialog that is being drawn. Without it a dialog ends where the
/// next one starts, or at the end of the frame.
pub fn dialog_end(ctx: &egui::Context) {
    let Some(at) = top_level_count(ctx) else {
        return;
    };
    with_segments(ctx, |list| {
        if let Some(last) = list.last_mut() {
            last.end.get_or_insert(at);
        }
    });
}

/// Shape the top level of the accessibility tree around the dialogs drawn in this frame: every
/// dialog becomes one node with role Dialog, its title as name and the modal flag, holding the
/// dialog's controls; everything else on screen moves under one node that is hidden from
/// assistive technology, so nothing behind an open dialog can be reached through the tree. Only
/// the newest dialog stays visible when several are open. Called from [`drop_orphan_focus`].
fn seal_dialogs(ctx: &egui::Context) {
    let frame = ctx.frame_nr();
    let segments: Vec<Segment> = ctx.data_mut(|d| {
        d.get_temp::<FrameSegments>(segments_id())
            .filter(|s| s.frame == frame)
            .map(|s| s.list)
            .unwrap_or_default()
    });
    let root = egui::accesskit_root_id();
    let Some(all) = ctx.accesskit_node_builder(root, |b| b.children().to_vec()) else {
        return;
    };
    // Resolve the ranges against what the root really holds.
    let mut ranges: Vec<(usize, usize, String, &'static str)> = Vec::new();
    for (i, s) in segments.iter().enumerate() {
        let next = segments.get(i + 1).map_or(all.len(), |n| n.start);
        let end = s.end.unwrap_or(next).min(all.len());
        let start = s.start.min(end);
        if start < end {
            ranges.push((start, end, s.title.clone(), s.key));
        }
    }
    // The page always sits under the same wrapper node, with or without a dialog: the platform
    // side keeps its own copy of the tree and applies each frame as an update, and an update
    // that moves nodes from one parent to another (root -> wrapper when a dialog opens, back
    // when it closes) is not applied correctly (see `traverse_orphan` in accesskit_consumer: it
    // looks up a node it has already dropped and panics). Only the wrapper's hidden flag and the
    // dialog nodes (new nodes with new children) change.
    let in_dialog = |i: usize| ranges.iter().any(|(a, b, _, _)| i >= *a && i < *b);
    let page: Vec<accesskit::NodeId> = all
        .iter()
        .enumerate()
        .filter(|(i, _)| !in_dialog(*i))
        .map(|(_, n)| *n)
        .collect();

    let bg = egui::Id::new("a11y_inert_background");
    let any_dialog = !ranges.is_empty();
    let _ = ctx.accesskit_node_builder(bg, |b| {
        b.set_role(accesskit::Role::GenericContainer);
        if any_dialog {
            b.set_hidden();
        }
        b.set_children(page);
    });
    let last = ranges.len().saturating_sub(1);
    for (k, (start, end, title, key)) in ranges.iter().enumerate() {
        // One id per dialog (not per position), so a dialog that stays open keeps its node when
        // another one opens or closes.
        let id = egui::Id::new(("a11y_dialog_node", *key));
        let kids: Vec<accesskit::NodeId> = all[*start..*end].to_vec();
        let _ = ctx.accesskit_node_builder(id, |b| {
            b.set_role(accesskit::Role::Dialog);
            if !title.is_empty() {
                b.set_name(title.clone());
            }
            b.set_modal();
            if k != last {
                b.set_hidden();
            }
            b.set_children(kids);
        });
    }
    // The new nodes were appended to the root as they were made; the root now lists exactly the
    // inert background (if any) and the dialogs, in drawing order.
    let _ = ctx.accesskit_node_builder(root, |b| {
        let kids: Vec<accesskit::NodeId> = b.children().iter().skip(all.len()).copied().collect();
        b.set_children(kids);
    });
}

// ── Password fields ───────────────────────────────────────────────────────

/// Call with the response of every `TextEdit::password(true)`. egui already marks such a field
/// with role PasswordInput and masks the text it publishes; this removes the rest: the value
/// and the per-character text runs (which would let a client read the length and move a caret
/// through the field), so nothing but the name and the role is left for a client to read.
pub fn secret_field(resp: &egui::Response) {
    let ctx = &resp.ctx;
    let rows = ctx
        .accesskit_node_builder(resp.id, |b| {
            b.set_role(accesskit::Role::PasswordInput);
            b.clear_value();
            b.clear_text_selection();
            b.children().len()
        })
        .unwrap_or(0);
    for i in 0..rows {
        // The text runs are children of the field, numbered by row (see egui's
        // `update_accesskit_for_text_widget`). They stay in the tree (the tree needs them to be
        // reachable) but are no longer text.
        let _ = ctx.accesskit_node_builder(resp.id.with(i), |b| {
            b.set_role(accesskit::Role::GenericContainer);
            b.set_hidden();
            b.clear_value();
            b.clear_character_lengths();
            b.clear_character_positions();
            b.clear_character_widths();
            b.clear_word_lengths();
            b.clear_text_direction();
        });
    }
}

// ── Collapsing headers ────────────────────────────────────────────────────

/// `CollapsingHeader::show` that also publishes whether the section is open.
pub trait CollapsingExt {
    fn show_a11y<R>(
        self,
        ui: &mut egui::Ui,
        add_body: impl FnOnce(&mut egui::Ui) -> R,
    ) -> egui::CollapsingResponse<R>;
}

impl CollapsingExt for egui::CollapsingHeader {
    fn show_a11y<R>(
        self,
        ui: &mut egui::Ui,
        add_body: impl FnOnce(&mut egui::Ui) -> R,
    ) -> egui::CollapsingResponse<R> {
        let r = self.show(ui, add_body);
        mark_expanded(&r.header_response, !r.fully_closed());
        r
    }
}

/// Publish the open/closed state of a collapsing header. AccessKit has an `expanded` flag; the
/// Windows adapter in the version egui 0.27 uses does not map it, so the same state is also
/// published as a toggle (On = open), which that adapter does map (UIA TogglePattern).
pub fn mark_expanded(header: &egui::Response, open: bool) {
    let _ = header.ctx.accesskit_node_builder(header.id, |b| {
        b.set_role(accesskit::Role::DisclosureTriangle);
        b.set_expanded(open);
        b.set_checked(if open {
            accesskit::Checked::True
        } else {
            accesskit::Checked::False
        });
    });
}

/// Call at the end of every frame. The accessibility tree names the focused widget; when that
/// widget is not on screen (a menu item that went with its popup, a field of a closed dialog)
/// the tree points at nothing and the platform side can bring the whole program down. Focus is
/// dropped instead.
pub fn drop_orphan_focus(ctx: &egui::Context) {
    seal_dialogs(ctx);
    if let Some(id) = ctx.memory(|m| m.focused()) {
        if !on_screen(ctx, id) {
            ctx.memory_mut(|m| m.surrender_focus(id));
        }
    }
}

fn restore_id() -> egui::Id {
    egui::Id::new("a11y_dialog_restore_focus")
}

/// Call once at the start of every frame: when a dialog closed in the last frame, focus goes to
/// the control that opened it, unless the person has already moved it somewhere else.
pub fn restore_pending_focus(ctx: &egui::Context) {
    let id = restore_id();
    let pending: Option<egui::Id> = ctx.data_mut(|d| d.get_temp(id));
    if let Some(opener) = pending {
        ctx.data_mut(|d| d.remove::<egui::Id>(id));
        if ctx.memory(|m| m.focused()).is_none() && on_screen(ctx, opener) {
            ctx.memory_mut(|m| m.request_focus(opener));
        }
    }
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
            // The initial circle: the person's name is always written beside it.
            func: "avatar",
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
            func: "icon_button",
            role: Role::Named,
            // The name is passed in by the caller: back, attach and the conversation menu.
            names: |l| {
                let c = locale::chat_strings(l);
                let k = locale::compose_strings(l);
                vec![c.a11y_back, c.a11y_attach, k.a11y_menu]
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
pub(crate) mod tests {
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

    /// Controls that take input and need a name a screen reader can say. Whoever adds one
    /// gives it a name within the next lines: `form_check::name(..)` or a `widget_info` of the
    /// matching type.
    const NAMED_INPUTS: &[&str] = &[
        "kit::input(",
        "kit::input_mono(",
        "kit::input_multiline(",
        "egui::TextEdit::",
        "egui::DragValue::new(",
        "egui::ComboBox::",
    ];

    #[test]
    fn every_text_field_number_field_and_drop_down_is_given_a_name() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        let mut unnamed = Vec::new();
        let mut seen = 0usize;
        for f in &files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            // The helpers that build the controls, and this file's own list.
            if rel == "a11y.rs" || rel.starts_with("locale") || rel == "form_check.rs" {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let code_end = src
                .find("\n#[cfg(test)]\nmod ")
                .or_else(|| src.find("\r\n#[cfg(test)]\r\nmod "))
                .unwrap_or(src.len());
            let lines: Vec<&str> = src[..code_end].lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") || t.starts_with("pub fn ") || t.starts_with("fn ") {
                    continue;
                }
                if !NAMED_INPUTS.iter().any(|p| line.contains(p)) {
                    continue;
                }
                // A builder chain that continues the previous line is part of that statement.
                if t.starts_with('.') || (rel == "ui_kit.rs" && t.starts_with("egui::TextEdit::")) {
                    continue;
                }
                seen += 1;
                let window = &lines[i..(i + 40).min(lines.len())];
                let named = window.iter().any(|l| {
                    l.contains("form_check::name(")
                        || l.contains("WidgetType::TextEdit")
                        || l.contains("WidgetType::ComboBox")
                });
                if !named {
                    unnamed.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
        assert!(seen > 15, "the scan found only {seen} input controls");
        assert!(
            unnamed.is_empty(),
            "input controls without an accessible name (use form_check::name):\n{}",
            unnamed.join("\n")
        );
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

    /// A page with an "item" button (a menu item that goes away with its popup) and a dialog
    /// that was opened from it.
    fn orphan_frame(ctx: &egui::Context, show_item: bool, focus_item: bool, leave: bool) -> bool {
        let mut on_screen_or_none = true;
        let _ = ctx.run(screen(), |ctx| {
            restore_pending_focus(ctx);
            egui::CentralPanel::default().show(ctx, |ui| {
                if show_item {
                    let b = ui.button("item");
                    if focus_item {
                        b.request_focus();
                    }
                }
            });
            if leave {
                dialog_leave(ctx, "orphan");
            } else if !focus_item {
                dialog_enter(ctx, "orphan");
            }
            drop_orphan_focus(ctx);
            on_screen_or_none = ctx.memory(|m| m.focused()).is_none_or_on_screen(ctx);
        });
        on_screen_or_none
    }

    trait FocusCheck {
        fn is_none_or_on_screen(self, ctx: &egui::Context) -> bool;
    }
    impl FocusCheck for Option<egui::Id> {
        fn is_none_or_on_screen(self, ctx: &egui::Context) -> bool {
            self.map_or(true, |id| ctx.read_response(id).is_some())
        }
    }

    #[test]
    fn focus_never_stays_on_a_widget_that_left_the_screen() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        // The item has focus, a dialog opens from it, the item goes (its popup closed), the
        // dialog closes: focus must not be handed back to something that is not there.
        assert!(orphan_frame(&ctx, true, true, false));
        assert!(orphan_frame(&ctx, true, false, false));
        assert!(orphan_frame(&ctx, false, false, false));
        assert!(orphan_frame(&ctx, false, false, true));
        for _ in 0..3 {
            assert!(orphan_frame(&ctx, false, false, false));
        }
    }

    #[test]
    fn a_dialog_is_never_wider_than_a_narrow_window() {
        for w in [320.0_f32, 360.0, 480.0, 700.0, 1200.0] {
            let (win, inner) = crate::ui_kit::dialog_widths(w);
            assert!(win <= (w - 32.0).max(200.0), "{w}: window {win}");
            assert!(inner < win, "{w}: content {inner} fits in window {win}");
        }
        assert_eq!(crate::ui_kit::dialog_widths(1200.0), (460.0, 440.0));
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

    // ── The accessibility tree of dialogs, password fields and collapsing headers ──────────

    use accesskit_consumer::Tree;
    use std::collections::HashMap;

    type Update = accesskit::TreeUpdate;

    fn node<'a>(u: &'a Update, id: accesskit::NodeId) -> &'a accesskit::Node {
        &u.nodes.iter().find(|(i, _)| *i == id).expect("node").1
    }

    fn named<'a>(u: &'a Update, name: &str) -> Vec<(accesskit::NodeId, &'a accesskit::Node)> {
        u.nodes
            .iter()
            .filter(|(_, n)| n.name() == Some(name))
            .map(|(i, n)| (*i, n))
            .collect()
    }

    /// Whether the node or one of its ancestors is hidden from assistive technology.
    fn is_hidden_in_tree(u: &Update, id: accesskit::NodeId) -> bool {
        let mut parent: HashMap<accesskit::NodeId, accesskit::NodeId> = HashMap::new();
        for (pid, n) in &u.nodes {
            for c in n.children() {
                parent.insert(*c, *pid);
            }
        }
        let mut cur = Some(id);
        while let Some(c) = cur {
            if node(u, c).is_hidden() {
                return true;
            }
            cur = parent.get(&c).copied();
        }
        false
    }

    /// Whether `id` is `ancestor` or below it.
    fn is_inside(u: &Update, id: accesskit::NodeId, ancestor: accesskit::NodeId) -> bool {
        let mut parent: HashMap<accesskit::NodeId, accesskit::NodeId> = HashMap::new();
        for (pid, n) in &u.nodes {
            for c in n.children() {
                parent.insert(*c, *pid);
            }
        }
        let mut cur = Some(id);
        while let Some(c) = cur {
            if c == ancestor {
                return true;
            }
            cur = parent.get(&c).copied();
        }
        false
    }

    /// The platform side applies the update to its own copy of the tree; building it panics when
    /// the update is inconsistent (a node nobody lists, a missing child).
    fn apply_like_the_platform(u: &Update) {
        let tree = Tree::new(u.clone(), true);
        let state = tree.state();
        for (id, _) in &u.nodes {
            assert!(state.node_by_id(*id).is_some());
        }
    }

    fn run_tree(ctx: &egui::Context, ui_fn: impl FnMut(&egui::Context)) -> Update {
        ctx.run(screen(), ui_fn)
            .platform_output
            .accesskit_update
            .expect("accesskit tree")
    }

    /// A value that differs on every run, so that no literal secret sits in the tests.
    fn random_secret() -> String {
        use std::hash::{BuildHasher, Hasher};
        let part = || {
            std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish()
        };
        format!("{:016x}{:016x}", part(), part())
    }

    fn password_frame(ctx: &egui::Context, secret: &mut String, publish: bool) -> Update {
        run_tree(ctx, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let r = ui.add(crate::ui_kit::input(secret).password(true));
                if publish {
                    crate::form_check::name(&r, "Password");
                }
                r.request_focus();
            });
        })
    }

    #[test]
    fn a_password_field_publishes_its_role_and_name_but_no_text() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut secret = random_secret();
        let typed = secret.clone();
        // Several frames: the field has focus and a caret, as while typing.
        let mut u = password_frame(&ctx, &mut secret, true);
        for _ in 0..3 {
            u = password_frame(&ctx, &mut secret, true);
        }
        let all = format!("{:?}", u.nodes);
        assert!(!all.contains(&typed), "the typed text is in the tree");
        let fields = named(&u, "Password");
        assert_eq!(fields.len(), 1);
        let (id, field) = fields[0];
        assert_eq!(field.role(), accesskit::Role::PasswordInput);
        assert_eq!(field.value(), None, "no value");
        assert!(field.text_selection().is_none(), "no caret or selection");
        for (_, n) in &u.nodes {
            assert_ne!(n.role(), accesskit::Role::InlineTextBox, "no text runs");
        }
        // What the Windows side derives from it: no value and no text, so neither ValuePattern
        // nor TextPattern is offered.
        apply_like_the_platform(&u);
        let tree = Tree::new(u.clone(), true);
        let n = tree.state().node_by_id(id).unwrap();
        assert!(!n.supports_text_ranges());
        assert!(!n.has_value());
    }

    #[test]
    fn without_the_name_call_egui_still_masks_the_text_it_publishes() {
        // The baseline this module builds on: egui publishes role PasswordInput and a masked
        // value; the text runs are what `secret_field` takes away.
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut secret = random_secret();
        let typed = secret.clone();
        let _ = password_frame(&ctx, &mut secret, false);
        let u = password_frame(&ctx, &mut secret, false);
        assert!(!format!("{:?}", u.nodes).contains(&typed));
        assert!(
            u.nodes
                .iter()
                .any(|(_, n)| n.role() == accesskit::Role::PasswordInput),
            "egui publishes the password role"
        );
        assert!(
            u.nodes
                .iter()
                .any(|(_, n)| n.role() == accesskit::Role::InlineTextBox),
            "unprotected, the field still has text runs"
        );
    }

    #[test]
    fn a_dialog_is_a_named_modal_node_and_the_page_behind_it_is_hidden() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let open = std::cell::Cell::new(false);
        let mut frame = |ctx: &egui::Context| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = ui.button("Behind");
            });
            if open.get() {
                crate::ui_kit::dialog(ctx, "t_modal", "Delete everything?", |ui| {
                    let _ = ui.button("Keep");
                });
            }
            drop_orphan_focus(ctx);
        };
        // Closed: no dialog node, the page is visible.
        let closed = run_tree(&ctx, &mut frame);
        assert!(closed
            .nodes
            .iter()
            .all(|(_, n)| n.role() != accesskit::Role::Dialog));
        let behind = named(&closed, "Behind")[0].0;
        assert!(!is_hidden_in_tree(&closed, behind));
        apply_like_the_platform(&closed);

        // Open.
        open.set(true);
        let _ = run_tree(&ctx, &mut frame);
        let u = run_tree(&ctx, &mut frame);
        let dialogs: Vec<_> = u
            .nodes
            .iter()
            .filter(|(_, n)| n.role() == accesskit::Role::Dialog)
            .collect();
        assert_eq!(dialogs.len(), 1);
        let (did, dlg) = dialogs[0];
        assert_eq!(dlg.name(), Some("Delete everything?"));
        assert!(dlg.is_modal());
        assert!(!is_hidden_in_tree(&u, *did));
        let keep = named(&u, "Keep")[0].0;
        assert!(
            is_inside(&u, keep, *did),
            "the dialog's button is in the dialog"
        );
        assert!(!is_hidden_in_tree(&u, keep));
        let behind = named(&u, "Behind")[0].0;
        assert!(!is_inside(&u, behind, *did));
        assert!(is_hidden_in_tree(&u, behind), "the page behind is inert");
        apply_like_the_platform(&u);

        // Closed again: the page is back.
        open.set(false);
        let u = run_tree(&ctx, &mut frame);
        let behind = named(&u, "Behind")[0].0;
        assert!(!is_hidden_in_tree(&u, behind));
        assert!(u
            .nodes
            .iter()
            .all(|(_, n)| n.role() != accesskit::Role::Dialog));
    }

    #[test]
    fn only_the_newest_of_two_open_dialogs_is_visible() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut frame = |ctx: &egui::Context| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = ui.button("Page");
            });
            crate::ui_kit::dialog(ctx, "t_first", "First", |ui| {
                let _ = ui.button("First button");
            });
            crate::ui_kit::dialog(ctx, "t_second", "Second", |ui| {
                let _ = ui.button("Second button");
            });
            drop_orphan_focus(ctx);
        };
        let _ = run_tree(&ctx, &mut frame);
        let u = run_tree(&ctx, &mut frame);
        let first = named(&u, "First")[0].0;
        let second = named(&u, "Second")[0].0;
        assert_eq!(node(&u, first).role(), accesskit::Role::Dialog);
        assert!(is_hidden_in_tree(&u, first));
        assert!(!is_hidden_in_tree(&u, second));
        assert!(is_inside(&u, named(&u, "Second button")[0].0, second));
        assert!(is_inside(&u, named(&u, "First button")[0].0, first));
        apply_like_the_platform(&u);
    }

    #[test]
    fn a_dialog_that_draws_its_own_window_is_named_by_dialog_title() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut frame = |ctx: &egui::Context| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = ui.button("Page");
            });
            dialog_enter(ctx, "t_raw");
            dialog_title(ctx, "Raw window");
            egui::Window::new("Raw window").show(ctx, |ui| {
                let _ = ui.button("Inside");
            });
            drop_orphan_focus(ctx);
        };
        let _ = run_tree(&ctx, &mut frame);
        let u = run_tree(&ctx, &mut frame);
        let d = named(&u, "Raw window")
            .into_iter()
            .find(|(_, n)| n.role() == accesskit::Role::Dialog)
            .expect("dialog node");
        assert!(is_inside(&u, named(&u, "Inside")[0].0, d.0));
        assert!(is_hidden_in_tree(&u, named(&u, "Page")[0].0));
        apply_like_the_platform(&u);
    }

    #[test]
    fn every_window_in_the_app_is_named_for_assistive_technology() {
        // A window that does not call `a11y::dialog_title` just before it is drawn is a dialog
        // without a name in the tree.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        let mut seen = 0usize;
        let mut missing = Vec::new();
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
            let code_end = src
                .find("\n#[cfg(test)]\nmod ")
                .or_else(|| src.find("\r\n#[cfg(test)]\r\nmod "))
                .unwrap_or(src.len());
            let lines: Vec<&str> = src[..code_end].lines().collect();
            for (i, l) in lines.iter().enumerate() {
                if l.trim_start().starts_with("egui::Window::new(")
                    || l.contains("= egui::Window::new(")
                {
                    seen += 1;
                    let from = i.saturating_sub(3);
                    if !lines[from..i].iter().any(|p| p.contains("dialog_title(")) {
                        missing.push(format!("{rel}:{}", i + 1));
                    }
                }
            }
        }
        assert!(seen >= 9, "the scan found only {seen} windows");
        assert!(
            missing.is_empty(),
            "windows without a11y::dialog_title: {missing:?}"
        );
    }

    fn header_frame(ctx: &egui::Context, open: bool) -> Update {
        run_tree(ctx, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::CollapsingHeader::new("Details")
                    .id_source("t_details")
                    .default_open(open)
                    .show_a11y(ui, |ui| {
                        ui.label("Body text");
                    });
            });
        })
    }

    #[test]
    fn a_collapsing_header_publishes_whether_it_is_open() {
        for open in [false, true] {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            let _ = header_frame(&ctx, open);
            let u = header_frame(&ctx, open);
            let h = named(&u, "Details");
            assert_eq!(h.len(), 1);
            let n = h[0].1;
            assert_eq!(n.is_expanded(), Some(open));
            assert_eq!(
                n.checked(),
                Some(if open {
                    accesskit::Checked::True
                } else {
                    accesskit::Checked::False
                }),
                "the state the Windows adapter can express"
            );
            assert_eq!(n.role(), accesskit::Role::DisclosureTriangle);
            assert_eq!(
                u.nodes
                    .iter()
                    .any(|(_, n)| n.name() == Some("Body text") || n.value() == Some("Body text")),
                open,
                "the body is in the tree only while open"
            );
            apply_like_the_platform(&u);
        }
    }

    #[test]
    fn every_collapsing_header_uses_show_a11y() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        let mut seen = 0usize;
        let mut plain = Vec::new();
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
            let code_end = src
                .find("\n#[cfg(test)]\nmod ")
                .or_else(|| src.find("\r\n#[cfg(test)]\r\nmod "))
                .unwrap_or(src.len());
            let lines: Vec<&str> = src[..code_end].lines().collect();
            for (i, l) in lines.iter().enumerate() {
                if l.contains("CollapsingHeader::new(") {
                    seen += 1;
                    let to = (i + 5).min(lines.len());
                    if !lines[i..to].iter().any(|n| n.contains(".show_a11y(")) {
                        plain.push(format!("{rel}:{}", i + 1));
                    }
                }
            }
        }
        assert!(seen >= 5, "the scan found only {seen} headers");
        assert!(
            plain.is_empty(),
            "collapsing headers without show_a11y: {plain:?}"
        );
    }

    // ── Incremental updates, as the platform adapter receives them ─────────────────────────

    /// The shape of the tree must be sound after every update: every listed child exists, every
    /// node has exactly one parent, and nothing is left over (`serialize` walks from the root and
    /// panics on a missing child or a node nobody lists).
    pub(crate) fn assert_sound(tree: &Tree) {
        let ser = tree.state().serialize();
        let mut seen = std::collections::HashSet::new();
        for (id, data) in &ser.nodes {
            assert!(seen.insert(*id), "node {id:?} reached twice");
            for c in data.children() {
                assert!(
                    tree.state().node_by_id(*c).is_some(),
                    "child {c:?} of {id:?} is missing"
                );
            }
        }
        assert!(
            tree.state().node_by_id(ser.focus).is_some(),
            "focus points at a missing node"
        );
    }

    /// A copy of the platform's tree.
    fn copy_tree(tree: &Tree) -> Tree {
        Tree::new(tree.state().serialize(), true)
    }

    /// Feeds one frame's update to the platform tree the way the Windows adapter does. egui
    /// lists the nodes of a frame in a hash map's order, which differs from frame to frame, so
    /// the same update is also applied with its nodes in other orders (to copies); each result
    /// must be sound.
    pub(crate) fn apply_in_every_order(tree: &mut Tree, u: &Update) {
        let n = u.nodes.len();
        let mut orders: Vec<Vec<usize>> = vec![(0..n).collect(), (0..n).rev().collect()];
        // Rotations and a deterministic shuffle.
        for k in [1usize, n / 3, n / 2, n.saturating_sub(1)] {
            orders.push((0..n).map(|i| (i + k) % n.max(1)).collect());
        }
        let mut x: u64 = n as u64 | 1;
        for _ in 0..6 {
            let mut o: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                o.swap(i, (x >> 33) as usize % (i + 1));
            }
            orders.push(o);
        }
        for order in orders {
            let mut copy = copy_tree(tree);
            let mut v = u.clone();
            v.nodes = order.iter().map(|&i| u.nodes[i].clone()).collect();
            copy.update(v);
            assert_sound(&copy);
        }
        tree.update(u.clone());
        assert_sound(tree);
    }

    #[test]
    fn a_dialog_opening_and_closing_keeps_the_platform_tree_sound() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let open = std::cell::Cell::new(false);
        let mut frame = |ctx: &egui::Context| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = ui.button("Behind");
                let _ = ui.button("Also behind");
            });
            if open.get() {
                crate::ui_kit::dialog(ctx, "t_sound", "Question", |ui| {
                    let _ = ui.button("Keep");
                });
            }
            drop_orphan_focus(ctx);
        };
        let first = run_tree(&ctx, &mut frame);
        let mut tree = Tree::new(first, true);
        assert_sound(&tree);
        for step in 0..9 {
            open.set((2..6).contains(&step));
            let u = run_tree(&ctx, &mut frame);
            apply_in_every_order(&mut tree, &u);
        }
    }
}
