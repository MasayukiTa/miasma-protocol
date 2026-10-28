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
            // Camera toggle, next to mute. The label follows the status flag (`camera_in_use`).
            // The core call IPC has no camera on/off request in this build, so the button is
            // shown but disabled, with a neutral tooltip saying so; its label still reports the
            // current state. When the toggle request lands, enable it and return an action here.
            let camera_on = status.map_or(false, |s| s.camera_in_use);
            let camera_label = if camera_on { c.camera_on } else { c.camera_off };
            crate::form_check::add_enabled(ui, false, kit::secondary_button(camera_label))
                .on_disabled_hover_text(c.camera_unavailable)
                .on_disabled_hover_text(c.a11y_camera);
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
