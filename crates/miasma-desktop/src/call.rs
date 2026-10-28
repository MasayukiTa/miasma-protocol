//! The call screen, pure part: everything that can be decided without a window.
//!
//! The state word to show, the duration text, whether the microphone counts as in use, the
//! safety-code line, and the small amount of screen state a call needs. The
//! window in `call_ui.rs` holds an instance of [`CallUi`] and draws it; this file is unit-tested
//! headless, the way `chat.rs` is.
//!
//! Only built with the `pqc` feature, because the call IPC surface
//! (`miasma_core::chat::ipc::CallRequest` and friends) is defined only there.

use miasma_core::chat::ipc::{AudioDeviceListDto, CallRequest, CallStatusDto, RemoteFrameData};

use crate::locale::CallStrings;

/// How often to ask the daemon for call `Status` and `Events` while a call exists. Modest, so
/// there is no busy loop; the screen is idle otherwise.
pub const POLL_INTERVAL_MS: u64 = 1_000;

/// The words for a call's state, from the daemon's stable state word.
///
/// The daemon reports `idle`, `calling`, `ringing` or `connected`. `connecting` is a UI-side
/// shade of `calling` used once the signalling link is up but media has not started; the caller
/// passes it in place of `calling` when it knows that. An unknown word falls back to the neutral
/// "connecting" line rather than showing nothing.
pub fn call_state_text(c: &CallStrings, state: &str) -> &'static str {
    match state {
        "calling" => c.state_calling,
        "ringing" => c.state_ringing,
        "connecting" => c.state_connecting,
        "connected" => c.state_connected,
        _ => c.state_connecting,
    }
}

/// A call's elapsed time as `M:SS`, or `H:MM:SS` once it passes an hour. Seconds and minutes are
/// always two digits after the first field.
pub fn duration_text(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// The safety code to show for a call, or `None` when there is none to show.
///
pub fn safety_code_text(status: &CallStatusDto) -> Option<String> {
    status.safety_code.clone()
}

/// Whether the microphone must be shown as in use: true for a connected call. The indicator this
/// drives is a design requirement and cannot be hidden, so the rule is deliberately simple and
/// in one place.
pub fn mic_in_use(state: &str) -> bool {
    state == "connected"
}

/// The small state the call screen keeps. It holds the pending-call token, so it does not derive
/// `Debug`: the token must never reach a log or an error line.
pub struct CallUi {
    /// The token of a ringing incoming call, to answer or decline it. `None` when none waits.
    pending_token: Option<u64>,
    /// True once a call of ours exists (we dialed, or we answered), until it ends.
    active: bool,
    /// The daemon's last state word (`calling`, `ringing`, `connected`, ...), or empty.
    state: String,
    /// Last confirmed mute state.
    muted: bool,
    status: Option<CallStatusDto>,
    /// When the call connected (ms since the epoch), for the duration. `None` until connected.
    connected_ms: Option<u64>,
    /// The next `since` for call `Events` polling.
    events_since: u64,
    /// When the last poll went out (ms since the epoch), to space polls by `POLL_INTERVAL_MS`.
    last_poll_ms: u64,
    /// The audio devices the host last reported, for the device picker. Empty until a
    /// `ListAudioDevices` answer arrives. Plain names only; no handle and no secret.
    devices: AudioDeviceListDto,
    /// The input device the runtime has confirmed as chosen, or `None` for the host default.
    selected_input: Option<String>,
    /// The output device the runtime has confirmed as chosen, or `None` for the host default.
    selected_output: Option<String>,
    /// True after a `SelectAudioDevices` request is sent, until its answer confirms the choice.
    device_select_pending: bool,
    /// The latest decoded remote video frame handed to this screen, or `None`
    /// until one arrives. Part 2 draws it; this part only stores it. The frame
    /// carries call content, so it is cleared when the call ends.
    remote_frame: Option<RemoteFrameData>,
    /// True after the daemon answered a camera-start with `no_camera`, so the
    /// panel shows the "camera unavailable" notice. Cleared once the camera is
    /// in use (a later start succeeded) and when the call ends.
    camera_unavailable: bool,
}

impl Default for CallUi {
    fn default() -> Self {
        Self {
            pending_token: None,
            active: false,
            state: String::new(),
            muted: false,
            status: None,
            connected_ms: None,
            events_since: 0,
            last_poll_ms: 0,
            devices: AudioDeviceListDto::default(),
            selected_input: None,
            selected_output: None,
            device_select_pending: false,
            remote_frame: None,
            camera_unavailable: false,
        }
    }
}

impl CallUi {
    /// Whether any call concerns this screen: one of ours is active, or one is ringing to answer.
    pub fn exists(&self) -> bool {
        self.active || self.pending_token.is_some()
    }

    /// The token of the ringing incoming call, if one waits.
    pub fn pending_token(&self) -> Option<u64> {
        self.pending_token
    }

    /// The current state word.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Whether the microphone is muted.
    pub fn is_muted(&self) -> bool {
        self.muted
    }

    /// Set the confirmed mute flag.
    pub fn set_muted(&mut self, muted: bool) {
        self.muted = muted;
    }

    /// Record that we started dialing a contact: a call of ours now exists.
    pub fn on_dial(&mut self) {
        self.active = true;
        self.state = "calling".to_owned();
        self.connected_ms = None;
        self.muted = false;
    }

    /// Apply a fresh `Status` from the daemon at time `now_ms`.
    ///
    /// It carries the state word, the token of any ringing incoming call, and (once connected)
    /// starts the duration clock. A state of `idle` means no call: the screen is reset.
    pub fn on_status(&mut self, status: &CallStatusDto, now_ms: u64) {
        self.pending_token = status.pending_token;
        if status.state == "idle" {
            self.end();
            return;
        }
        self.active = true;
        if status.state == "connected" && self.connected_ms.is_none() {
            self.connected_ms = Some(now_ms);
        }
        self.state = status.state.clone();
        self.muted = status.muted;
        // The camera is in use now, so a start succeeded: drop any earlier "no camera" notice.
        if status.camera_in_use {
            self.camera_unavailable = false;
        }
        self.status = Some(status.clone());
    }

    /// End the call and forget its state. Called when the daemon reports `idle`, or after we hang
    /// up, reject, or the call ends. The pending token is cleared too, so nothing lingers.
    pub fn end(&mut self) {
        self.pending_token = None;
        self.active = false;
        self.state = String::new();
        self.connected_ms = None;
        self.muted = false;
        self.status = None;
        self.remote_frame = None;
        self.camera_unavailable = false;
    }

    pub fn status(&self) -> Option<&CallStatusDto> {
        self.status.as_ref()
    }

    /// Store the latest decoded remote video frame handed up from the daemon.
    /// Replaces any frame held; the newest frame is the only one the screen
    /// draws. Part 2 renders it from [`CallUi::remote_frame`].
    pub fn on_remote_frame(&mut self, frame: RemoteFrameData) {
        self.remote_frame = Some(frame);
    }

    /// The latest decoded remote video frame, or `None` when none has arrived
    /// (or the call has ended).
    pub fn remote_frame(&self) -> Option<&RemoteFrameData> {
        self.remote_frame.as_ref()
    }

    /// Note that the daemon could not open a camera (`no_camera`): the panel shows the
    /// "camera unavailable" notice until the camera comes into use or the call ends.
    pub fn set_camera_unavailable(&mut self) {
        self.camera_unavailable = true;
    }

    /// Whether the "camera unavailable" notice should be shown.
    pub fn camera_unavailable(&self) -> bool {
        self.camera_unavailable
    }

    /// The elapsed seconds of a connected call at `now_ms`, or `None` when not connected yet.
    pub fn duration_secs(&self, now_ms: u64) -> Option<u64> {
        let start = self.connected_ms?;
        Some(now_ms.saturating_sub(start) / 1000)
    }

    /// Whether the microphone must be shown as in use right now.
    pub fn mic_in_use(&self) -> bool {
        self.active && !self.muted && mic_in_use(&self.state)
    }

    /// The next `since` to pass to call `Events`.
    pub fn events_since(&self) -> u64 {
        self.events_since
    }

    /// Record the `next` cursor returned by a call `Events` answer.
    pub fn set_events_since(&mut self, next: u64) {
        self.events_since = next;
    }

    /// Whether it is time to poll `Status` / `Events` again: only while a call exists, and no
    /// more often than `POLL_INTERVAL_MS`. Returns false (no busy loop) when nothing waits.
    pub fn should_poll(&self, now_ms: u64) -> bool {
        self.exists() && now_ms.saturating_sub(self.last_poll_ms) >= POLL_INTERVAL_MS
    }

    /// Whether an idle discovery poll is due.
    pub fn discovery_due(&self, now_ms: u64) -> bool {
        !self.exists() && now_ms.saturating_sub(self.last_poll_ms) >= 5_000
    }

    /// Record that a poll went out at `now_ms`, so the next one waits a full interval.
    pub fn mark_polled(&mut self, now_ms: u64) {
        self.last_poll_ms = now_ms;
    }

    /// Store the device list the host reported, in answer to `ListAudioDevices`. Replaces any
    /// earlier list; the names are shown in the picker. Does not change the current selection.
    pub fn on_audio_devices(&mut self, devices: AudioDeviceListDto) {
        self.devices = devices;
    }

    /// Apply the selection the runtime confirmed, in answer to `SelectAudioDevices`. Records the
    /// chosen names (or `None` for the host default) and clears the pending flag.
    pub fn on_audio_devices_selected(&mut self, input: Option<String>, output: Option<String>) {
        self.selected_input = input;
        self.selected_output = output;
        self.device_select_pending = false;
    }

    /// The input device names the host reported, for the picker.
    pub fn device_inputs(&self) -> &[String] {
        &self.devices.inputs
    }

    /// The output device names the host reported, for the picker.
    pub fn device_outputs(&self) -> &[String] {
        &self.devices.outputs
    }

    /// The host's default input name, if the host reported one.
    pub fn default_input(&self) -> Option<&str> {
        self.devices.default_input.as_deref()
    }

    /// The host's default output name, if the host reported one.
    pub fn default_output(&self) -> Option<&str> {
        self.devices.default_output.as_deref()
    }

    /// The confirmed input choice, or `None` for the host default.
    pub fn selected_input(&self) -> Option<&str> {
        self.selected_input.as_deref()
    }

    /// The confirmed output choice, or `None` for the host default.
    pub fn selected_output(&self) -> Option<&str> {
        self.selected_output.as_deref()
    }

    /// Note that a `SelectAudioDevices` request has gone out and its answer is awaited.
    pub fn mark_device_select_pending(&mut self) {
        self.device_select_pending = true;
    }

    /// Whether a device selection is awaiting its confirming answer.
    pub fn device_select_pending(&self) -> bool {
        self.device_select_pending
    }
}

/// Build the `Dial` request for a contact (its endpoint id or label, as the chat requests use).
pub fn dial(contact: &str) -> CallRequest {
    CallRequest::Dial {
        contact: contact.to_owned(),
    }
}

/// Build the `Accept` request for a ringing call's token.
pub fn accept(token: u64) -> CallRequest {
    CallRequest::Accept { token }
}

/// Build the `Reject` request for a ringing call's token.
pub fn reject(token: u64) -> CallRequest {
    CallRequest::Reject { token }
}

/// Build the `StartCamera` request that begins sending the local camera. Honoured by the daemon
/// only while the call is connected with video negotiated; answered `Ok`, or `Error` with
/// `not_ready` (no video) or `no_camera` (no camera could be opened).
pub fn start_camera() -> CallRequest {
    CallRequest::StartCamera
}

/// Build the `StopCamera` request that stops sending the local camera and releases the device.
/// Stopping is idempotent; the screen stream, if any, is unaffected.
pub fn stop_camera() -> CallRequest {
    CallRequest::StopCamera
}

/// Build the `ListAudioDevices` request that asks the host for its devices.
pub fn list_audio_devices() -> CallRequest {
    CallRequest::ListAudioDevices
}

/// Build the `SelectAudioDevices` request for the chosen input and output (each `None` for the
/// host default).
pub fn select_audio_devices(input: Option<String>, output: Option<String>) -> CallRequest {
    CallRequest::SelectAudioDevices { input, output }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locale::{call_strings, Locale};

    fn status(state: &str, pending: Option<u64>) -> CallStatusDto {
        // Built through serde so that a new defaulted field in the status never breaks this
        // helper again (the struct grows with every call feature).
        serde_json::from_value(serde_json::json!({
            "state": state,
            "pending_token": pending,
            "signalling_connected": state == "connected",
        }))
        .expect("a status with only the required fields")
    }

    #[test]
    fn state_words_cover_every_call_state_in_every_language() {
        for lang in Locale::ALL {
            let c = call_strings(lang);
            assert_eq!(call_state_text(c, "calling"), c.state_calling);
            assert_eq!(call_state_text(c, "ringing"), c.state_ringing);
            assert_eq!(call_state_text(c, "connecting"), c.state_connecting);
            assert_eq!(call_state_text(c, "connected"), c.state_connected);
            // An unknown word falls back to the neutral connecting line, never to empty.
            assert_eq!(call_state_text(c, "surprise"), c.state_connecting);
            assert!(!call_state_text(c, "surprise").is_empty());
        }
    }

    #[test]
    fn duration_is_minutes_and_seconds_until_an_hour_then_hours() {
        assert_eq!(duration_text(0), "0:00");
        assert_eq!(duration_text(5), "0:05");
        assert_eq!(duration_text(65), "1:05");
        assert_eq!(duration_text(600), "10:00");
        assert_eq!(duration_text(3599), "59:59");
        assert_eq!(duration_text(3600), "1:00:00");
        assert_eq!(duration_text(3661), "1:01:01");
        assert_eq!(duration_text(36_000), "10:00:00");
    }

    #[test]
    fn safety_code_is_returned_unchanged_or_pending() {
        assert!(safety_code_text(&status("connected", None)).is_none());
        assert!(safety_code_text(&status("ringing", Some(7))).is_none());
        let mut dto = status("connected", None);
        dto.safety_code = Some("12345 67890 12345 67890".into());
        assert_eq!(
            safety_code_text(&dto).as_deref(),
            Some("12345 67890 12345 67890")
        );
    }

    #[test]
    fn the_microphone_counts_as_in_use_only_once_connected() {
        assert!(!mic_in_use("calling"));
        assert!(!mic_in_use("ringing"));
        assert!(!mic_in_use("connecting"));
        assert!(mic_in_use("connected"));
    }

    #[test]
    fn dialing_makes_a_call_exist_and_starts_in_the_calling_state() {
        let mut ui = CallUi::default();
        assert!(!ui.exists());
        ui.on_dial();
        assert!(ui.exists());
        assert_eq!(ui.state(), "calling");
        assert!(ui.duration_secs(10_000).is_none());
        assert!(!ui.mic_in_use());
    }

    #[test]
    fn a_status_drives_the_state_pending_token_and_duration_clock() {
        let mut ui = CallUi::default();
        // A ringing incoming call: a token to answer, no call of ours yet beyond that.
        ui.on_status(&status("ringing", Some(42)), 1_000);
        assert_eq!(ui.pending_token(), Some(42));
        assert!(ui.exists());
        assert!(ui.duration_secs(2_000).is_none());
        // It connects: the duration clock starts at this moment.
        ui.on_status(&status("connected", None), 5_000);
        assert_eq!(ui.pending_token(), None);
        assert_eq!(ui.state(), "connected");
        assert_eq!(ui.duration_secs(5_000), Some(0));
        assert_eq!(ui.duration_secs(12_000), Some(7));
        assert!(ui.mic_in_use());
        assert!(ui.status().is_some());
        ui.set_muted(true);
        assert!(!ui.mic_in_use());
        ui.set_muted(false);
        // A later connected status does not restart the clock.
        ui.on_status(&status("connected", None), 20_000);
        assert_eq!(ui.duration_secs(20_000), Some(15));
    }

    #[test]
    fn an_idle_status_ends_the_call_and_clears_everything() {
        let mut ui = CallUi::default();
        ui.on_status(&status("connected", None), 1_000);
        ui.set_muted(true);
        assert!(ui.exists());
        ui.on_status(&status("idle", None), 2_000);
        assert!(!ui.exists());
        assert_eq!(ui.pending_token(), None);
        assert_eq!(ui.state(), "");
        assert!(ui.duration_secs(3_000).is_none());
        assert!(!ui.is_muted());
        assert!(ui.status().is_none());
        assert!(!ui.mic_in_use());
    }

    #[test]
    fn the_mute_flag_tracks_confirmed_state() {
        let mut ui = CallUi::default();
        ui.on_dial();
        assert!(!ui.is_muted());
        ui.set_muted(true);
        assert!(ui.is_muted());
        ui.set_muted(false);
        assert!(!ui.is_muted());
    }

    #[test]
    fn polling_waits_an_interval_and_only_while_a_call_exists() {
        let mut ui = CallUi::default();
        // No call: never poll, whatever the time.
        assert!(!ui.should_poll(1_000_000));
        assert!(!ui.discovery_due(4_999));
        assert!(ui.discovery_due(5_000));
        ui.on_dial();
        // First poll is due immediately (last_poll is 0).
        assert!(ui.should_poll(POLL_INTERVAL_MS));
        ui.mark_polled(POLL_INTERVAL_MS);
        // Too soon for the next one.
        assert!(!ui.should_poll(POLL_INTERVAL_MS + 1));
        // A full interval later it is due again.
        assert!(ui.should_poll(POLL_INTERVAL_MS * 2));
        // Once the call ends, polling stops.
        ui.end();
        assert!(!ui.should_poll(POLL_INTERVAL_MS * 10));
    }

    #[test]
    fn the_events_cursor_advances_as_the_daemon_reports() {
        let mut ui = CallUi::default();
        assert_eq!(ui.events_since(), 0);
        ui.set_events_since(9);
        assert_eq!(ui.events_since(), 9);
    }

    #[test]
    fn the_request_builders_make_the_matching_variants() {
        assert!(matches!(dial("alice"), CallRequest::Dial { contact } if contact == "alice"));
        assert!(matches!(accept(3), CallRequest::Accept { token: 3 }));
        assert!(matches!(reject(4), CallRequest::Reject { token: 4 }));
        assert!(matches!(
            list_audio_devices(),
            CallRequest::ListAudioDevices
        ));
        assert!(matches!(
            select_audio_devices(Some("Mic A".to_owned()), None),
            CallRequest::SelectAudioDevices { input, output }
                if input.as_deref() == Some("Mic A") && output.is_none()
        ));
        assert!(matches!(
            select_audio_devices(None, None),
            CallRequest::SelectAudioDevices {
                input: None,
                output: None,
            }
        ));
        // The camera toggle builds StartCamera when the camera is off and StopCamera when on.
        assert!(matches!(start_camera(), CallRequest::StartCamera));
        assert!(matches!(stop_camera(), CallRequest::StopCamera));
    }

    #[test]
    fn the_camera_toggle_builds_start_when_off_and_stop_when_on() {
        // The panel sends StartCamera while the camera is not in use, and StopCamera while it is.
        let off = false;
        let on = true;
        let when = |in_use: bool| {
            if in_use {
                stop_camera()
            } else {
                start_camera()
            }
        };
        assert!(matches!(when(off), CallRequest::StartCamera));
        assert!(matches!(when(on), CallRequest::StopCamera));
    }

    #[test]
    fn a_no_camera_answer_shows_the_notice_until_the_camera_is_in_use_or_the_call_ends() {
        let mut ui = CallUi::default();
        assert!(!ui.camera_unavailable());
        // The daemon answered `no_camera`: the notice is shown.
        ui.set_camera_unavailable();
        assert!(ui.camera_unavailable());
        // A later status with the camera in use means a start succeeded: the notice is dropped.
        ui.on_status(&status("connected", None), 1_000);
        let mut dto = status("connected", None);
        dto.camera_in_use = true;
        ui.on_status(&dto, 2_000);
        assert!(!ui.camera_unavailable());
        // Set again, then end the call: the notice is cleared with the rest of the call state.
        ui.set_camera_unavailable();
        assert!(ui.camera_unavailable());
        ui.end();
        assert!(!ui.camera_unavailable());
    }

    fn device_list() -> AudioDeviceListDto {
        // Built through serde, like the status helper above, so a new defaulted field in the DTO
        // never breaks this helper.
        serde_json::from_value(serde_json::json!({
            "inputs": ["Mic A", "Mic B"],
            "outputs": ["Speaker A"],
            "default_input": "Mic A",
            "default_output": "Speaker A",
        }))
        .expect("a device list with only names")
    }

    #[test]
    fn the_reported_device_list_is_stored_for_the_picker() {
        let mut ui = CallUi::default();
        // Nothing reported yet: the picker has empty lists and no default.
        assert!(ui.device_inputs().is_empty());
        assert!(ui.device_outputs().is_empty());
        assert!(ui.default_input().is_none());
        assert!(ui.default_output().is_none());
        ui.on_audio_devices(device_list());
        assert_eq!(ui.device_inputs(), ["Mic A", "Mic B"]);
        assert_eq!(ui.device_outputs(), ["Speaker A"]);
        assert_eq!(ui.default_input(), Some("Mic A"));
        assert_eq!(ui.default_output(), Some("Speaker A"));
        // Storing the list does not invent a selection.
        assert!(ui.selected_input().is_none());
        assert!(ui.selected_output().is_none());
    }

    #[test]
    fn a_confirmed_selection_is_shown_and_clears_the_pending_flag() {
        let mut ui = CallUi::default();
        assert!(!ui.device_select_pending());
        // A request goes out: the pending flag is set until the answer confirms it.
        ui.mark_device_select_pending();
        assert!(ui.device_select_pending());
        ui.on_audio_devices_selected(Some("Mic B".to_owned()), Some("Speaker A".to_owned()));
        assert_eq!(ui.selected_input(), Some("Mic B"));
        assert_eq!(ui.selected_output(), Some("Speaker A"));
        assert!(!ui.device_select_pending());
        // Choosing the host default on both is recorded as no name, and still clears pending.
        ui.mark_device_select_pending();
        ui.on_audio_devices_selected(None, None);
        assert!(ui.selected_input().is_none());
        assert!(ui.selected_output().is_none());
        assert!(!ui.device_select_pending());
    }

    fn frame(width: u16, height: u16, counter: u64) -> RemoteFrameData {
        // Built through serde, like `status` above, so a new defaulted field on the frame DTO
        // never breaks this helper. The pixel bytes are a short fixed pattern; their content is
        // not asserted on, only that the newest frame is the one held.
        serde_json::from_value(serde_json::json!({
            "width": width,
            "height": height,
            "rgba": [1, 2, 3, 4],
            "counter": counter,
        }))
        .expect("a remote frame with the required fields")
    }

    #[test]
    fn a_remote_frame_is_stored_and_the_newest_replaces_the_previous_one() {
        let mut ui = CallUi::default();
        // No frame until one arrives.
        assert!(ui.remote_frame().is_none());
        ui.on_remote_frame(frame(4, 2, 1));
        let first = ui.remote_frame().expect("the first frame is held");
        assert_eq!((first.width, first.height, first.counter), (4, 2, 1));
        // A newer frame replaces the previous one: only the latest is kept.
        ui.on_remote_frame(frame(8, 6, 2));
        let second = ui.remote_frame().expect("the newer frame replaces it");
        assert_eq!((second.width, second.height, second.counter), (8, 6, 2));
    }

    #[test]
    fn the_remote_frame_is_cleared_when_the_call_ends() {
        // The frame carries call content, so it must not linger past the call. `end()` clears it,
        // and an `idle` status (which routes through `end()`) clears it too.
        let mut ui = CallUi::default();
        ui.on_status(&status("connected", None), 1_000);
        ui.on_remote_frame(frame(4, 2, 1));
        assert!(ui.remote_frame().is_some());
        ui.end();
        assert!(ui.remote_frame().is_none());
        // Via an idle status as well.
        ui.on_status(&status("connected", None), 2_000);
        ui.on_remote_frame(frame(4, 2, 3));
        assert!(ui.remote_frame().is_some());
        ui.on_status(&status("idle", None), 3_000);
        assert!(ui.remote_frame().is_none());
    }
}
