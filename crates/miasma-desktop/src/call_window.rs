//! The call window: a separate native window for a call, like a messenger's call window.
//!
//! A call (dialing, ringing in, or connected) gets its own OS window instead of a panel drawn
//! inside the main window. The main window keeps only the header Call button with a small "in a
//! call" marker while a call exists. This window shows the remote video or the remote's shared
//! screen as its main content, the remote name and call duration at the top, the safety code, and
//! a control bar at the bottom (mute, camera, screen share, device picker, hang up). Closing the
//! window with its own close button hangs up the call, so a call never runs with no window.
//!
//! The pure decisions live in `call.rs` (`call_window_state`) and in the small rect helpers below,
//! which are unit-tested headless. The drawing uses an eframe/egui 0.27 immediate viewport, which
//! keeps the window's widgets on the same `&mut self` as the rest of the app.
//!
//! Only built with the `pqc` feature, like `call.rs` and `call_ui.rs`.

use eframe::egui;

use crate::call::{self, CallUi, CallWindow};
use crate::call_ui::{self, CallAction};
use crate::locale::CallStrings;
use crate::theme;
use crate::ui_kit as kit;

/// The window's default inner size, and the smallest it may become. The video reads best in a
/// landscape window; the minimum keeps the control bar and the video area usable.
pub const DEFAULT_SIZE: (f32, f32) = (960.0, 640.0);
pub const MIN_SIZE: (f32, f32) = (480.0, 360.0);

/// The rectangle a picture of pixel size `src` fills when fitted inside `area`, keeping its aspect
/// ratio, centered, never upscaled past its native size. A zero-sized picture or area yields an
/// empty rect at the area's center (nothing is drawn).
///
/// This is the pure core of the video area: the window draws the remote frame into this rect over
/// a dark background, and the tests check the aspect ratio and the centering without a viewport.
pub fn fit_video_rect(area: egui::Rect, src: (u16, u16)) -> egui::Rect {
    let (w, h) = (f32::from(src.0), f32::from(src.1));
    let center = area.center();
    if w < 1.0 || h < 1.0 || area.width() < 1.0 || area.height() < 1.0 {
        return egui::Rect::from_center_size(center, egui::Vec2::ZERO);
    }
    // Scale by the tighter of the two axes so the whole picture fits; never enlarge past native.
    let scale = (area.width() / w).min(area.height() / h).min(1.0);
    let shown = egui::vec2(w * scale, h * scale);
    egui::Rect::from_center_size(center, shown)
}

/// Whether a control bar of `controls_width` fits within a window of `window_width`, given the
/// window's side margins. The control bar is the row of call buttons at the bottom; it must stay
/// within the window so no button is clipped. The test uses this against the real control width.
pub fn controls_fit_width(window_width: f32, controls_width: f32, margin: f32) -> bool {
    controls_width <= window_width - 2.0 * margin
}

/// The window title for a call with the given remote name. The name is a neutral word (the call
/// IPC carries no display name and a peer id must never be shown); it is placed in the title the
/// way a messenger names a call window after the other person.
pub fn window_title(c: &CallStrings, remote_name: &str) -> String {
    format!("{} — {}", c.panel_title, remote_name)
}

/// What the window asked the app to do when it was drawn this frame: a pressed call action, and
/// whether the window's own close button was used (which hangs up the call).
#[derive(Default)]
pub struct CallWindowOutcome {
    pub action: Option<CallAction>,
    pub close_requested: bool,
}

/// Draw the call window for the current call, if any, in its own native viewport.
///
/// Returns the pressed action and whether the window's close button was used. When there is no
/// call (`CallWindow::Closed`) nothing is shown and the outcome is empty. The caller (the app)
/// turns the action into the matching request and, on a close request, sends `HangUp` once.
///
/// `video` is the remote video texture and its pixel size, or `None` for an audio-only call or
/// before the first frame. `now_ms` drives the duration text.
pub fn show(
    ctx: &egui::Context,
    c: &CallStrings,
    state: &CallUi,
    now_ms: u64,
    video: Option<(&egui::TextureHandle, (u16, u16))>,
) -> CallWindowOutcome {
    let mut outcome = CallWindowOutcome::default();
    let window = call::call_window_state(state);
    if window == CallWindow::Closed {
        return outcome;
    }

    let title = window_title(c, c.caller_unknown);
    let viewport_id = egui::ViewportId::from_hash_of("miasma_call_window");
    let builder = egui::ViewportBuilder::default()
        .with_title(title)
        .with_inner_size([DEFAULT_SIZE.0, DEFAULT_SIZE.1])
        .with_min_inner_size([MIN_SIZE.0, MIN_SIZE.1]);

    ctx.show_viewport_immediate(viewport_id, builder, |ctx, _class| {
        egui::CentralPanel::default().show(ctx, |ui| {
            draw_contents(ui, c, state, window, now_ms, video, &mut outcome.action);
        });
        // The OS close button (or the window menu) asks the viewport to close; closing the call
        // window ends the call, so the request is reported and the app sends HangUp once.
        if ctx.input(|i| i.viewport().close_requested()) {
            outcome.close_requested = true;
        }
    });

    outcome
}

/// Draw the inside of the call window: the top name and duration, the video area, the safety code,
/// the self-tile, and the control bar. Kept separate from the viewport call so the body reads in
/// one place; the video area and control bar follow the rect helpers above.
fn draw_contents(
    ui: &mut egui::Ui,
    c: &CallStrings,
    state: &CallUi,
    window: CallWindow,
    now_ms: u64,
    video: Option<(&egui::TextureHandle, (u16, u16))>,
    action: &mut Option<CallAction>,
) {
    let status = state.status();

    // Top: the remote name, the state line, and the duration once connected.
    ui.vertical_centered(|ui| {
        ui.add(egui::Label::new(
            kit::meta_text(c.caller_unknown, theme::palette().text).strong(),
        ));
        kit::paragraph_muted(ui, call::call_state_text(c, state.state()));
        if let Some(secs) = state.duration_secs(now_ms) {
            kit::paragraph_muted(
                ui,
                &format!("{}: {}", c.duration_label, call::duration_text(secs)),
            );
        }
    });
    ui.add_space(kit::SP_2);

    // An incoming ringing call shows Accept / Reject in place of the in-call controls.
    if window == CallWindow::Incoming {
        if let Some(token) = state.pending_token() {
            if let Some(a) = call_ui::incoming_banner(ui, c, c.caller_unknown, token) {
                *action = Some(a);
            }
        }
        // The reminder that closing the window ends the call applies here too.
        ui.add_space(kit::SP_2);
        kit::paragraph_muted(ui, c.window_hint);
        return;
    }

    // The video area: all the height left above the control bar, with a dark background. The
    // remote frame — camera video OR the remote's shared screen — is drawn into it, scaled to fit
    // with the right aspect ratio and centered. An audio-only call shows just the dark area.
    // Heights reserved below the video for the safety area and the control bar, so the video area
    // takes the rest. These are plain pixel sizes (the kit's spacing scale stops at SP_5).
    let controls_height = 48.0;
    let safety_height = 72.0;
    let avail = ui.available_size();
    let video_height = (avail.y - controls_height - safety_height).max(48.0);
    let (area, mut response) =
        ui.allocate_exact_size(egui::vec2(avail.x, video_height), egui::Sense::hover());
    // The remote video is painted by hand, so it is invisible to a screen reader without a name;
    // give the region a localized accessible label (listed in a11y::inventory::INVENTORY).
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, c.a11y_video));
    ui.painter().rect_filled(area, 0.0, egui::Color32::BLACK);
    if let Some((texture, size)) = video {
        let rect = fit_video_rect(area, size);
        if rect.width() >= 1.0 && rect.height() >= 1.0 {
            ui.painter().image(
                texture.id(),
                rect,
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                egui::Color32::WHITE,
            );
        }
    }

    // A small tile saying what you are sending (your camera, or your screen) while it is active.
    if let Some(s) = status {
        if s.camera_in_use || s.screen_sharing {
            let label = if s.screen_sharing {
                c.self_screen_tile
            } else {
                c.self_camera_tile
            };
            let tile = egui::Rect::from_min_size(
                area.left_top() + egui::vec2(kit::SP_2, kit::SP_2),
                egui::vec2(area.width().min(220.0), 28.0),
            );
            ui.painter()
                .rect_filled(tile, 4.0, egui::Color32::from_black_alpha(160));
            ui.painter().text(
                tile.left_center() + egui::vec2(kit::SP_2, 0.0),
                egui::Align2::LEFT_CENTER,
                label,
                egui::FontId::proportional(13.0),
                egui::Color32::WHITE,
            );
        }
    }
    ui.add_space(kit::SP_2);

    // The safety code area.
    ui.add(egui::Label::new(
        kit::meta_text(c.safety_heading, theme::palette().muted).strong(),
    ));
    if let Some(code) = status.and_then(|s| call::safety_code_text(s)) {
        kit::paragraph_muted(ui, c.safety_explain);
        ui.add(egui::Label::new(code).selectable(true));
    } else {
        kit::paragraph_muted(ui, c.safety_pending);
    }
    ui.add_space(kit::SP_2);

    // The reminder that closing the window ends the call.
    kit::paragraph_muted(ui, c.window_hint);
    ui.add_space(kit::SP_2);

    // The control bar at the bottom: mute, camera, screen share, device picker, hang up. The
    // controls keep their accessibility names and locale texts; the real toggle requests are
    // chosen by the app from the last status, as before.
    ui.horizontal(|ui| {
        let mute_label = if state.is_muted() { c.unmute } else { c.mute };
        if ui
            .add(kit::secondary_button(mute_label))
            .on_hover_text(c.a11y_mute)
            .clicked()
        {
            *action = Some(CallAction::ToggleMute);
        }
        ui.add_space(kit::SP_2);
        let camera_on = status.map_or(false, |s| s.camera_in_use);
        let camera_label = if camera_on { c.camera_on } else { c.camera_off };
        let camera_ready =
            state.state() == "connected" && status.map_or(false, |s| s.negotiated_video);
        if crate::form_check::add_enabled(ui, camera_ready, kit::secondary_button(camera_label))
            .on_hover_text(c.a11y_camera)
            .clicked()
        {
            *action = Some(CallAction::ToggleCamera);
        }
        ui.add_space(kit::SP_2);
        let screen_on = status.map_or(false, |s| s.screen_sharing);
        let screen_label = if screen_on { c.screen_off } else { c.screen_on };
        if ui
            .add(kit::secondary_button(screen_label))
            .on_hover_text(c.a11y_screen_share)
            .clicked()
        {
            *action = Some(CallAction::ToggleScreenShare);
        }
        ui.add_space(kit::SP_2);
        if ui
            .add(kit::secondary_button(c.hang_up))
            .on_hover_text(c.a11y_hang_up)
            .clicked()
        {
            *action = Some(CallAction::HangUp);
        }
    });
    // The device picker sits under the control bar; a change returns a SelectDevices action.
    if let Some(a) = call_ui::device_picker(ui, c, state) {
        *action = Some(a);
    }

    // The always-on microphone indicator while the microphone is in use.
    if state.mic_in_use() {
        ui.add_space(kit::SP_2);
        call_ui::mic_indicator(ui, c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_video_rect_keeps_the_aspect_ratio_and_centers_in_the_area() {
        // A 16:9 picture in a wide area is limited by height; the shown rect keeps 16:9.
        let area = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(800.0, 300.0));
        let rect = fit_video_rect(area, (1600, 900));
        let ratio = rect.width() / rect.height();
        assert!((ratio - 16.0 / 9.0).abs() < 0.01, "ratio was {ratio}");
        // It fits within the area and is centered on it.
        assert!(rect.width() <= area.width() + 0.5 && rect.height() <= area.height() + 0.5);
        assert!((rect.center() - area.center()).length() < 0.5);
    }

    #[test]
    fn the_video_rect_is_limited_by_width_when_the_area_is_tall() {
        // The same picture in a tall, narrow area is limited by width instead.
        let area = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(320.0, 900.0));
        let rect = fit_video_rect(area, (1600, 900));
        assert!(rect.width() <= area.width() + 0.5, "wider than the area");
        let ratio = rect.width() / rect.height();
        assert!((ratio - 16.0 / 9.0).abs() < 0.01, "ratio was {ratio}");
    }

    #[test]
    fn the_video_rect_never_upscales_past_the_native_size() {
        // A small picture in a big area stays its native size (no upscaling).
        let area = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(800.0, 600.0));
        let rect = fit_video_rect(area, (320, 240));
        assert!(
            (rect.width() - 320.0).abs() < 0.5,
            "width was {}",
            rect.width()
        );
        assert!(
            (rect.height() - 240.0).abs() < 0.5,
            "height was {}",
            rect.height()
        );
    }

    #[test]
    fn a_zero_sized_frame_or_area_draws_nothing() {
        let area = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(800.0, 600.0));
        assert_eq!(fit_video_rect(area, (0, 0)).area(), 0.0);
        let empty = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::Vec2::ZERO);
        assert_eq!(fit_video_rect(empty, (1600, 900)).area(), 0.0);
    }

    #[test]
    fn the_control_bar_must_fit_inside_the_window_width() {
        // A control bar narrower than the window minus its margins fits; a wider one does not.
        assert!(controls_fit_width(960.0, 600.0, 16.0));
        assert!(controls_fit_width(MIN_SIZE.0, MIN_SIZE.0 - 32.0, 16.0));
        assert!(!controls_fit_width(480.0, 460.0, 16.0));
    }

    #[test]
    fn the_window_title_names_the_remote_without_an_id() {
        let c = crate::locale::call_strings(crate::locale::Locale::En);
        let title = window_title(c, c.caller_unknown);
        assert!(title.contains(c.caller_unknown));
        assert!(title.contains(c.panel_title));
    }
}
