//! The call screen, drawing part.
//!
//! Small, self-contained widgets: the Call button for a conversation header, the incoming-call
//! banner shown over whatever screen is open, the in-call panel (state, duration, mute, hang up,
//! and the safety-code area), and the always-on microphone indicator. Each returns the intent of
//! a press as a [`CallAction`]; none of them touch the network or hold app state, so the caller
//! (the app) decides what a press does. The decisions behind the text come from `call.rs`.
//!
//! Only built with the `pqc` feature, like `call.rs`.

use eframe::egui;

use crate::call::{self, CallUi};
use crate::locale::CallStrings;
use crate::theme::{self, Palette};
use crate::transfers::fill;
use crate::ui_kit::{self as kit, Level};

fn pal() -> Palette {
    theme::palette()
}

/// What a press on a call widget asks the app to do. The app turns it into the matching
/// [`miasma_core::chat::ipc::CallRequest`] (see the builders in `call.rs`) and updates its
/// [`CallUi`]. Accept and Reject carry the ringing call's token.
#[derive(Clone, PartialEq, Eq)]
pub enum CallAction {
    Dial,
    Accept(u64),
    Reject(u64),
    HangUp,
    ToggleMute,
    /// Start or stop sharing the screen; the app sends the matching start/stop
    /// request based on the current screen-sharing state.
    ToggleScreenShare,
    /// Start or stop sending the local camera; the app sends the matching
    /// start/stop request based on the current `camera_in_use` state.
    ToggleCamera,
    /// Ask the host for its audio devices, to fill the picker.
    ListDevices,
    /// Choose the input and/or output device by name (`None` means the host default).
    SelectDevices {
        input: Option<String>,
        output: Option<String>,
    },
}

// The token is not shown and not logged, so the action may be formatted safely for diagnostics
// without revealing it: Accept/Reject print without their number.
impl std::fmt::Debug for CallAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            CallAction::Dial => "Dial",
            CallAction::Accept(_) => "Accept",
            CallAction::Reject(_) => "Reject",
            CallAction::HangUp => "HangUp",
            CallAction::ToggleMute => "ToggleMute",
            CallAction::ToggleScreenShare => "ToggleScreenShare",
            CallAction::ToggleCamera => "ToggleCamera",
            CallAction::ListDevices => "ListDevices",
            // The device names are not shown here, so they are never formatted into diagnostics.
            CallAction::SelectDevices { .. } => "SelectDevices",
        };
        f.write_str(name)
    }
}

/// The Call button for a conversation header. Returns true when pressed. The caller places it in
/// the header row beside the contact's name and, on a press, dials that contact.
pub fn call_button(ui: &mut egui::Ui, c: &CallStrings) -> bool {
    ui.add(kit::secondary_button(c.call))
        .on_hover_text(c.a11y_call)
        .clicked()
}

/// The incoming-call banner, shown over whatever screen is open while a call is ringing. It names
/// the caller and offers Answer and Decline; the token is carried in the returned action, never
/// drawn. Returns the pressed action, or `None` when nothing was pressed.
pub fn incoming_banner(
    ui: &mut egui::Ui,
    c: &CallStrings,
    caller_name: &str,
    token: u64,
) -> Option<CallAction> {
    let mut action = None;
    kit::surface(ui, |ui| {
        kit::notice(ui, Level::Info, c.incoming_title);
        kit::paragraph(ui, &fill(c.incoming_body, &[("name", caller_name)]));
        ui.add_space(kit::SP_2);
        ui.horizontal(|ui| {
            if kit::primary(ui, true, c.accept)
                .on_hover_text(c.a11y_accept)
                .clicked()
            {
                action = Some(CallAction::Accept(token));
            }
            ui.add_space(kit::SP_2);
            if ui
                .add(kit::secondary_button(c.reject))
                .on_hover_text(c.a11y_reject)
                .clicked()
            {
                action = Some(CallAction::Reject(token));
            }
        });
    });
    action
}

/// Draw the remote video frame, scaled to fit the available width while keeping its aspect
/// ratio. `texture` is the egui texture the caller uploaded from the newest RGBA frame, and
/// `size` its pixel dimensions. Nothing is drawn for a zero-sized frame. Audio-only calls pass
/// no texture and so look exactly as before.
pub fn remote_video(ui: &mut egui::Ui, texture: &egui::TextureHandle, size: (u16, u16)) {
    let (w, h) = (f32::from(size.0), f32::from(size.1));
    if w < 1.0 || h < 1.0 {
        return;
    }
    // Fit within the panel width, never upscaling past the native size, and keep the aspect
    // ratio by scaling both axes by the same factor.
    let avail = ui.available_width().max(1.0);
    let scale = (avail / w).min(1.0);
    let shown = egui::vec2(w * scale, h * scale);
    ui.image(egui::load::SizedTexture::new(texture.id(), shown));
    ui.add_space(kit::SP_2);
}

/// The in-call panel: the remote video (when present), the state line, the duration, a mute
/// toggle, a camera toggle, a screen-share button, hang up, and the safety-code area. `now_ms`
/// is the current time for the duration. `video` is the remote video texture and its pixel size,
/// or `None` for an audio-only call or before the first frame arrives. Returns the pressed
/// action, or `None`.
pub fn in_call_panel(
    ui: &mut egui::Ui,
    c: &CallStrings,
    state: &CallUi,
    status: Option<&miasma_core::chat::ipc::CallStatusDto>,
    now_ms: u64,
    video: Option<(&egui::TextureHandle, (u16, u16))>,
) -> Option<CallAction> {
    let mut action = None;
    kit::surface(ui, |ui| {
        kit::section(ui, c.panel_title, |_| {});
        // The remote video, when a frame has arrived and video was negotiated. Drawn above the
        // state line so it reads as the main content of the call.
        if let Some((texture, size)) = video {
            remote_video(ui, texture, size);
        }
        // The state line (calling / ringing / connecting / connected).
        kit::paragraph(ui, call::call_state_text(c, state.state()));
        // The duration, once the call is connected.
        if let Some(secs) = state.duration_secs(now_ms) {
            kit::paragraph_muted(
                ui,
                &format!("{}: {}", c.duration_label, call::duration_text(secs)),
            );
        }
        ui.add_space(kit::SP_2);
        ui.horizontal(|ui| {
            // Mute toggle: the label follows the current flag.
            let mute_label = if state.is_muted() { c.unmute } else { c.mute };
            if ui
                .add(kit::secondary_button(mute_label))
                .on_hover_text(c.a11y_mute)
                .clicked()
            {
                action = Some(CallAction::ToggleMute);
            }
            ui.add_space(kit::SP_2);
            // Camera toggle, next to mute. The label follows the status flag (`camera_in_use`):
            // a press sends StartCamera when it is off and StopCamera when it is on. Enabled only
            // while the call is connected with video negotiated, the state the daemon honours a
            // start in; the request builder lives in `call.rs` and the handling in `chat_ui.rs`.
            let camera_on = status.map_or(false, |s| s.camera_in_use);
            let camera_label = if camera_on { c.camera_on } else { c.camera_off };
            let camera_ready =
                state.state() == "connected" && status.map_or(false, |s| s.negotiated_video);
            if crate::form_check::add_enabled(ui, camera_ready, kit::secondary_button(camera_label))
                .on_hover_text(c.a11y_camera)
                .clicked()
            {
                action = Some(CallAction::ToggleCamera);
            }
            ui.add_space(kit::SP_2);
            // Screen share toggle, next to the camera. The label follows the status flag
            // (`screen_sharing`); a press asks the app to start or stop the real screen-share
            // request, which the daemon honours only while the call is connected with video
            // negotiated.
            let screen_on = status.map_or(false, |s| s.screen_sharing);
            let screen_label = if screen_on { c.screen_off } else { c.screen_on };
            if ui
                .add(kit::secondary_button(screen_label))
                .on_hover_text(c.a11y_screen_share)
                .clicked()
            {
                action = Some(CallAction::ToggleScreenShare);
            }
            ui.add_space(kit::SP_2);
            if ui
                .add(kit::secondary_button(c.hang_up))
                .on_hover_text(c.a11y_hang_up)
                .clicked()
            {
                action = Some(CallAction::HangUp);
            }
        });
        ui.add_space(kit::SP_2);
        ui.add_space(kit::SP_1);
        ui.add(egui::Label::new(
            kit::meta_text(c.safety_heading, pal().muted).strong(),
        ));
        if let Some(code) = status.and_then(call::safety_code_text) {
            kit::paragraph_muted(ui, c.safety_explain);
            ui.add(egui::Label::new(code).selectable(true));
        } else {
            kit::paragraph_muted(ui, c.safety_pending);
        }
        // While connected, the microphone is in use: show the always-on indicator here too, so a
        // person in the panel always sees it.
        if let Some(status) = status {
            if status.camera_in_use {
                kit::notice(ui, Level::Warn, c.camera_in_use);
            }
            if status.screen_sharing {
                kit::notice(ui, Level::Warn, c.screen_sharing);
            }
        }
        // The daemon answered a camera-start with `no_camera`: a neutral notice says the camera
        // could not be turned on. It clears when the camera comes into use or the call ends.
        if state.camera_unavailable() {
            kit::notice(ui, Level::Warn, c.camera_unavailable);
        }
        if state.mic_in_use() {
            ui.add_space(kit::SP_2);
            mic_indicator(ui, c);
        }
    });
    action
}

/// The audio-device picker: two drop-downs, input and output, each with a "default" entry that
/// stands for the host default (sent as `None`). The current selection comes from `state`; the
/// list of names comes from the host's last `ListAudioDevices` answer, also held in `state`. When
/// a drop-down changes, the chosen input and output are returned together as a
/// [`CallAction::SelectDevices`] (each `None` for the default entry); otherwise `None`.
///
/// The widget holds no state of its own: the caller applies the returned action and, once the
/// runtime confirms it, the new selection shows here.
pub fn device_picker(ui: &mut egui::Ui, c: &CallStrings, state: &CallUi) -> Option<CallAction> {
    // The default entry is a neutral word; a real name is shown as itself. The empty selection
    // (host default) maps to that entry.
    let mut input = state.selected_input().map(str::to_owned);
    let mut output = state.selected_output().map(str::to_owned);
    let mut changed = false;

    ui.add(egui::Label::new(
        kit::meta_text(c.device_heading, pal().muted).strong(),
    ));

    // Input drop-down.
    ui.horizontal(|ui| {
        kit::paragraph_muted(ui, c.device_input_label);
        let shown = input.as_deref().unwrap_or(c.device_default);
        egui::ComboBox::from_id_source("call_device_input")
            .selected_text(shown)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(input.is_none(), c.device_default)
                    .clicked()
                    && input.is_some()
                {
                    input = None;
                    changed = true;
                }
                for name in state.device_inputs() {
                    if ui
                        .selectable_label(input.as_deref() == Some(name.as_str()), name)
                        .clicked()
                        && input.as_deref() != Some(name.as_str())
                    {
                        input = Some(name.clone());
                        changed = true;
                    }
                }
            })
            .response
            .widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, c.device_input_label)
            });
    });

    // Output drop-down.
    ui.horizontal(|ui| {
        kit::paragraph_muted(ui, c.device_output_label);
        let shown = output.as_deref().unwrap_or(c.device_default);
        egui::ComboBox::from_id_source("call_device_output")
            .selected_text(shown)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(output.is_none(), c.device_default)
                    .clicked()
                    && output.is_some()
                {
                    output = None;
                    changed = true;
                }
                for name in state.device_outputs() {
                    if ui
                        .selectable_label(output.as_deref() == Some(name.as_str()), name)
                        .clicked()
                        && output.as_deref() != Some(name.as_str())
                    {
                        output = Some(name.clone());
                        changed = true;
                    }
                }
            })
            .response
            .widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, c.device_output_label)
            });
    });

    if changed {
        Some(CallAction::SelectDevices { input, output })
    } else {
        None
    }
}

/// The always-on indicator shown while the microphone is in use during a call. It is a design
/// requirement that it cannot be hidden, so it is drawn plainly wherever the caller places it and
/// has no dismiss control.
pub fn mic_indicator(ui: &mut egui::Ui, c: &CallStrings) {
    kit::notice(ui, Level::Warn, c.mic_in_use);
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::chat::ipc::{CallRequest, CallStatusDto};

    fn status_with_camera(in_use: bool, negotiated_video: bool) -> CallStatusDto {
        // Built through serde so a new defaulted status field never breaks this helper.
        serde_json::from_value(serde_json::json!({
            "state": "connected",
            "pending_token": null,
            "signalling_connected": true,
            "negotiated_video": negotiated_video,
            "camera_in_use": in_use,
        }))
        .expect("a status with only the required fields")
    }

    // The panel chooses the camera label from `camera_in_use` and enables the button only while
    // connected with video negotiated; these mirror that decision without a window.
    fn camera_label<'a>(c: &'a CallStrings, status: &CallStatusDto) -> &'a str {
        if status.camera_in_use {
            c.camera_on
        } else {
            c.camera_off
        }
    }
    fn camera_ready(state: &str, status: &CallStatusDto) -> bool {
        state == "connected" && status.negotiated_video
    }

    #[test]
    fn the_camera_toggle_action_is_named_without_a_value() {
        // Like the other actions, the camera toggle formats to a bare name for diagnostics.
        assert_eq!(format!("{:?}", CallAction::ToggleCamera), "ToggleCamera");
    }

    #[test]
    fn the_camera_toggle_builds_start_when_off_and_stop_when_on() {
        // Off: a press sends StartCamera. On: a press sends StopCamera. This mirrors the handler
        // in `chat_ui.rs`, which chooses the request from the last `camera_in_use` flag.
        let request_for = |in_use: bool| {
            if in_use {
                crate::call::stop_camera()
            } else {
                crate::call::start_camera()
            }
        };
        assert!(matches!(request_for(false), CallRequest::StartCamera));
        assert!(matches!(request_for(true), CallRequest::StopCamera));
    }

    #[test]
    fn the_camera_label_follows_the_flag_and_the_button_needs_connected_video() {
        let c = crate::locale::call_strings(crate::locale::Locale::En);
        let off = status_with_camera(false, true);
        let on = status_with_camera(true, true);
        assert_eq!(camera_label(c, &off), c.camera_off);
        assert_eq!(camera_label(c, &on), c.camera_on);
        // Enabled only while connected with video negotiated.
        assert!(camera_ready("connected", &status_with_camera(false, true)));
        assert!(!camera_ready(
            "connecting",
            &status_with_camera(false, true)
        ));
        assert!(!camera_ready(
            "connected",
            &status_with_camera(false, false)
        ));
    }

    #[test]
    fn a_no_camera_answer_drives_the_panel_notice_flag() {
        // The error handling the panel reads: `no_camera` sets the notice; it clears when the
        // camera comes into use or the call ends. (`not_ready` leaves it untouched, as the
        // chat_ui handler only sets it on `no_camera`.)
        let mut call = CallUi::default();
        assert!(!call.camera_unavailable());
        call.set_camera_unavailable();
        assert!(call.camera_unavailable());
        call.on_status(&status_with_camera(true, true), 1_000);
        assert!(!call.camera_unavailable());
    }
}
