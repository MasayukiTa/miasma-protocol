//! Small pieces of window behaviour that do not draw anything, kept apart so they can be tested:
//! when a list is asked for again, when the window repaints, when a message goes away, and whether
//! closing the window needs a question first. The drawing of the question itself is [`confirm`].

use std::time::{Duration, Instant};

// ─── Throttled queries ──────────────────────────────────────────────────────

/// How often a list that is on screen is asked for again, besides on opening the tab and after
/// something changed it.
pub const LIST_REFRESH_EVERY: Duration = Duration::from_secs(10);

/// Decides when a query to the background service may be sent again.
///
/// A list that comes back empty used to be asked for again on every frame; this lets a query go
/// out once, then again only after `every`, or at once after [`Self::reset`].
#[derive(Debug, Clone)]
pub struct RefreshGate {
    every: Duration,
    last: Option<Instant>,
}

impl RefreshGate {
    pub const fn new(every: Duration) -> Self {
        Self { every, last: None }
    }

    /// True when a query should go out now. Nothing sent yet counts as due.
    pub fn due(&self, now: Instant) -> bool {
        match self.last {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.every,
        }
    }

    /// A query went out at `now`.
    pub fn mark(&mut self, now: Instant) {
        self.last = Some(now);
    }

    /// The next check is due at once (the tab was opened, or something changed the list).
    pub fn reset(&mut self) {
        self.last = None;
    }

    /// `due` and, if so, `mark` in one step.
    pub fn take(&mut self, now: Instant) -> bool {
        let due = self.due(now);
        if due {
            self.mark(now);
        }
        due
    }
}

// ─── Repainting ─────────────────────────────────────────────────────────────

/// While something moves: about five frames a second.
pub const REPAINT_ACTIVE: Duration = Duration::from_millis(200);
/// When nothing moves: one frame a second. This is what keeps the timers (list refresh, status
/// poll, message expiry) running; input and replies from the worker wake the window sooner.
pub const REPAINT_IDLE: Duration = Duration::from_secs(1);

/// The longest the window may sleep before drawing again. `moving` is true while a transfer
/// runs, a push is in flight, a request waits for its answer, the service is starting or an
/// import runs: something on screen is changing.
pub fn repaint_delay(moving: bool) -> Duration {
    if moving {
        REPAINT_ACTIVE
    } else {
        REPAINT_IDLE
    }
}

// ─── Messages ───────────────────────────────────────────────────────────────

/// Kinds of message in the bar at the bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgLevel {
    Info,
    Success,
    Error,
}

/// How long a message stays before it goes away on its own. Errors never do: they stay until
/// they are closed.
pub fn message_lifetime(level: MsgLevel) -> Option<Duration> {
    match level {
        MsgLevel::Success => Some(Duration::from_secs(6)),
        MsgLevel::Info => Some(Duration::from_secs(10)),
        MsgLevel::Error => None,
    }
}

/// Whether a message shown for `age` should be removed now. A progress message ("saving...")
/// stays while the work it describes is still running.
pub fn message_expired(level: MsgLevel, age: Duration, work_running: bool) -> bool {
    if level == MsgLevel::Info && work_running {
        return false;
    }
    message_lifetime(level).is_some_and(|life| age >= life)
}

// ─── Closing the window ─────────────────────────────────────────────────────

/// Closing the window stops the background service the app started and, with it, every transfer
/// and push in progress. Ask first only when one is.
pub fn close_needs_confirmation(transfers_running: usize, pushes_active: usize) -> bool {
    transfers_running + pushes_active > 0
}

/// What the person answered to a question in a dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Still open.
    Pending,
    Confirm,
    /// The cancel button, or Esc.
    Cancel,
}

pub mod confirm {
    //! One drawing routine for the small "are you sure" dialogs.

    use eframe::egui;

    use super::Answer;
    use crate::ui_kit as kit;

    /// Show a dialog in the middle of the window until it is answered. Esc counts as cancel.
    /// `body` draws the text; `confirm_label` is what the confirming button does, in a word or
    /// two. The confirming button is drawn as a danger button, the cancel button as a plain one.
    pub fn show(
        ctx: &egui::Context,
        id: &'static str,
        title: &str,
        confirm_label: &str,
        cancel_label: &str,
        body: impl FnOnce(&mut egui::Ui),
    ) -> Answer {
        let mut answer = Answer::Pending;
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            return Answer::Cancel;
        }
        egui::Window::new(title)
            .id(egui::Id::new(id))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .max_width(440.0)
            .show(ctx, |ui| {
                body(ui);
                ui.add_space(kit::SP_1);
                kit::button_row(ui, |ui| {
                    if ui.add(kit::danger_button(confirm_label)).clicked() {
                        answer = Answer::Confirm;
                    }
                    if ui.add(kit::secondary_button(cancel_label)).clicked() {
                        answer = Answer::Cancel;
                    }
                });
            });
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_is_due_once_then_waits() {
        let t0 = Instant::now();
        let mut g = RefreshGate::new(Duration::from_secs(10));
        assert!(g.due(t0), "nothing sent yet");
        assert!(g.take(t0));
        // The old behaviour: asked again on every frame. Now: not until the interval is over.
        for ms in [16u64, 200, 1_000, 9_999] {
            assert!(!g.take(t0 + Duration::from_millis(ms)), "{ms} ms");
        }
        assert!(g.take(t0 + Duration::from_secs(10)));
        assert!(!g.take(t0 + Duration::from_secs(11)));
    }

    #[test]
    fn gate_reset_makes_the_next_check_due() {
        let t0 = Instant::now();
        let mut g = RefreshGate::new(Duration::from_secs(10));
        g.mark(t0);
        assert!(!g.due(t0 + Duration::from_secs(1)));
        g.reset();
        assert!(g.due(t0 + Duration::from_secs(1)));
    }

    #[test]
    fn gate_survives_a_clock_that_goes_backwards() {
        let t0 = Instant::now() + Duration::from_secs(100);
        let mut g = RefreshGate::new(Duration::from_secs(10));
        g.mark(t0);
        assert!(!g.due(Instant::now()));
    }

    #[test]
    fn idle_window_repaints_far_less_often_than_a_moving_one() {
        let idle = repaint_delay(false);
        let moving = repaint_delay(true);
        assert_eq!(moving, Duration::from_millis(200));
        assert_eq!(idle, Duration::from_secs(1));
        // Five times fewer wake-ups at rest than while a transfer runs.
        assert!(idle >= moving * 5);
    }

    #[test]
    fn success_and_info_messages_go_away_errors_stay() {
        let s = Duration::from_secs;
        assert!(!message_expired(MsgLevel::Success, s(5), false));
        assert!(message_expired(MsgLevel::Success, s(6), false));
        assert!(!message_expired(MsgLevel::Info, s(9), false));
        assert!(message_expired(MsgLevel::Info, s(10), false));
        // An error is never removed by the clock, however old.
        assert!(!message_expired(MsgLevel::Error, s(86_400), false));
        assert!(!message_expired(MsgLevel::Error, s(86_400), true));
    }

    #[test]
    fn progress_message_stays_while_the_work_runs() {
        let s = Duration::from_secs;
        assert!(!message_expired(MsgLevel::Info, s(600), true));
        assert!(message_expired(MsgLevel::Info, s(600), false));
        // A finished-job message is not held back by unrelated work.
        assert!(message_expired(MsgLevel::Success, s(6), true));
    }

    #[test]
    fn closing_asks_only_when_something_is_active() {
        assert!(!close_needs_confirmation(0, 0));
        assert!(close_needs_confirmation(1, 0));
        assert!(close_needs_confirmation(0, 1));
        assert!(close_needs_confirmation(3, 2));
    }

    /// The dialog must fit a 700 px wide window and stay on screen, at both widths the app is used
    /// at. This lays the dialog out without a window (default fonts, so Japanese glyphs have
    /// placeholder widths): it checks the box, not the look.
    #[test]
    fn dialog_stays_inside_the_window_at_both_widths() {
        for (w, h) in [(700.0_f32, 480.0_f32), (1400.0, 900.0)] {
            let ctx = egui::Context::default();
            let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(w, h));
            let mut answer = Answer::Pending;
            let long = "転送中です。閉じると転送が止まります。".repeat(8);
            // Two frames: the first sizes the window, the second places it.
            for _ in 0..2 {
                let input = egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                };
                let _ = ctx.run(input, |ctx| {
                    answer = confirm::show(ctx, "t", "title", "OK", "Cancel", |ui| {
                        ui.label(&long);
                    });
                });
            }
            assert_eq!(answer, Answer::Pending);
            let used = ctx.used_rect();
            assert!(
                screen.contains_rect(used),
                "{w}x{h}: dialog {used:?} leaves the window"
            );
            assert!(used.width() <= 460.0, "{w}: dialog wider than its limit");
        }
    }

    #[test]
    fn escape_cancels_the_dialog() {
        let ctx = egui::Context::default();
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 480.0),
            )),
            ..Default::default()
        };
        input.events.push(egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        let mut answer = Answer::Pending;
        let _ = ctx.run(input, |ctx| {
            answer = confirm::show(ctx, "t", "title", "OK", "Cancel", |ui| {
                ui.label("body");
            });
        });
        assert_eq!(answer, Answer::Cancel);
    }
}
