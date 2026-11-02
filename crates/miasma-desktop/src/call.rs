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

/// The line to show for a dial the daemon did not accept, from its stable reason word.
///
/// The daemon answers a `Dial` it will not start with one of `busy` (the contact is already in a
/// call), `not_ready` (the secure connection with the contact is not set up yet, so the call is
/// retried on its own), `not_allowed` / `refused` (turned away for good), or `unavailable` (calls
/// cannot run right now). An unknown word falls back to the neutral "could not be placed" line so
/// the caller never sees a blank where a reason belongs.
pub fn dial_failed_text(c: &CallStrings, reason: &str) -> &'static str {
    match reason {
        "busy" => c.dial_busy,
        "not_ready" => c.dial_securing,
        "unavailable" => c.unavailable,
        "not_allowed" | "refused" => c.dial_refused,
        _ => c.dial_refused,
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
    /// The stable reason word of a dial the daemon did not accept (`refused`,
    /// `not_allowed`, `busy`, or `unavailable`), or `None` when the last dial
    /// was accepted or none has been made. Set from the daemon's answer to a
    /// `Dial`, so the caller never leaves an ordinary "calling" line up for a
    /// dial that was turned away. Cleared on a new dial, on any status, and when
    /// the call ends.
    dial_failed: Option<String>,
    /// The contact of a dial the daemon could not start yet because the hybrid
    /// key exchange with that contact had not finished (`not_ready`). The screen
    /// holds it, shows a "securing" line, and redials once through the idle
    /// discovery poll; `None` when nothing waits. The retry is an ordinary
    /// `Dial` that the daemon gates again; nothing is sent in the classical
    /// session.
    pending_redial: Option<String>,
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
            dial_failed: None,
            pending_redial: None,
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
    ///
    /// This only shows the "calling" line; whether the daemon actually accepted
    /// the dial is reported later through [`CallUi::on_dial_accepted`] (which
    /// clears any earlier failure) or [`CallUi::on_dial_refused`] /
    /// [`CallUi::on_dial_not_ready`]. Any earlier dial failure is cleared here so
    /// a fresh attempt starts clean.
    pub fn on_dial(&mut self) {
        self.active = true;
        self.state = "calling".to_owned();
        self.connected_ms = None;
        self.muted = false;
        self.dial_failed = None;
        self.pending_redial = None;
    }

    /// The daemon accepted the dial (`Ok`): nothing to show beyond the state the
    /// next `Status` will carry. Any earlier failure word is cleared.
    pub fn on_dial_accepted(&mut self) {
        self.dial_failed = None;
    }

    /// The daemon turned the dial away for a reason that will not fix itself
    /// (`refused`, `not_allowed`, `busy`, `unavailable`): end the call we
    /// optimistically showed and record the reason word so the caller shows a
    /// short, clear line instead of an ordinary "calling".
    pub fn on_dial_refused(&mut self, reason: &str) {
        self.end();
        self.dial_failed = Some(reason.to_owned());
    }

    /// The daemon could not start the dial yet because the hybrid key exchange
    /// with `contact` had not finished (`not_ready`). End the optimistic call,
    /// show the "securing" line, and hold the contact so the idle discovery poll
    /// redials once the gate may be ready.
    pub fn on_dial_not_ready(&mut self, contact: &str) {
        self.end();
        self.dial_failed = Some("not_ready".to_owned());
        self.pending_redial = Some(contact.to_owned());
    }

    /// The reason word of a dial the daemon did not accept, or `None`.
    pub fn dial_failed(&self) -> Option<&str> {
        self.dial_failed.as_deref()
    }

    /// Dismiss the dial-failure line the caller showed. Clears the reason word so
    /// the banner goes away, and drops any held redial so a dial the user has
    /// given up on is not retried behind their back.
    pub fn clear_dial_failed(&mut self) {
        self.dial_failed = None;
        self.pending_redial = None;
    }

    /// Take the contact of a held dial to redial, if one waits. Clears it so the
    /// retry goes out exactly once per hold.
    pub fn take_redial(&mut self) -> Option<String> {
        self.pending_redial.take()
    }

    /// Apply a fresh `Status` from the daemon at time `now_ms`.
    ///
    /// It carries the state word, the token of any ringing incoming call, and (once connected)
    /// starts the duration clock. A state of `idle` means no call: the screen is reset.
    pub fn on_status(&mut self, status: &CallStatusDto, now_ms: u64) {
        self.pending_token = status.pending_token;
        // A real status word supersedes any earlier dial-refusal line.
        self.dial_failed = None;
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

    /// Whether an idle discovery poll is due. Kept short so a dial on the other
    /// side, and a held redial of ours (see [`CallUi::take_redial`]), are noticed
    /// within a couple of seconds rather than up to five.
    pub fn discovery_due(&self, now_ms: u64) -> bool {
        !self.exists() && now_ms.saturating_sub(self.last_poll_ms) >= 2_000
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
        assert!(!ui.discovery_due(1_999));
        assert!(ui.discovery_due(2_000));
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

    #[test]
    fn a_refused_dial_ends_the_call_and_records_the_reason_word() {
        // The daemon turned the dial away for good: the optimistic "calling" is dropped and the
        // reason word is held so the caller shows a short line instead of an endless "calling".
        let mut ui = CallUi::default();
        ui.on_dial();
        assert_eq!(ui.state(), "calling");
        ui.on_dial_refused("busy");
        assert!(!ui.exists());
        assert_eq!(ui.state(), "");
        assert_eq!(ui.dial_failed(), Some("busy"));
        // No redial is held for a refusal that will not fix itself.
        assert!(ui.take_redial().is_none());
        // A fresh dial clears the earlier reason.
        ui.on_dial();
        assert!(ui.dial_failed().is_none());
    }

    #[test]
    fn a_not_ready_dial_holds_the_contact_for_one_redial_and_shows_securing() {
        // The secure connection with the contact is not set up yet: the dial is held, the
        // "securing" reason is shown, and the contact is handed back exactly once so the idle
        // discovery poll redials it when the gate may be ready.
        let mut ui = CallUi::default();
        ui.on_dial();
        ui.on_dial_not_ready("alice");
        assert!(!ui.exists());
        assert_eq!(ui.dial_failed(), Some("not_ready"));
        // Taken exactly once per hold.
        assert_eq!(ui.take_redial().as_deref(), Some("alice"));
        assert!(ui.take_redial().is_none());
    }

    #[test]
    fn an_accepted_dial_and_a_status_both_clear_the_failure_line() {
        let mut ui = CallUi::default();
        ui.on_dial();
        ui.on_dial_refused("refused");
        assert_eq!(ui.dial_failed(), Some("refused"));
        // An explicit accept clears it.
        ui.on_dial_accepted();
        assert!(ui.dial_failed().is_none());
        // And so does a real status word that arrives afterwards.
        ui.on_dial();
        ui.on_dial_refused("not_allowed");
        assert_eq!(ui.dial_failed(), Some("not_allowed"));
        ui.on_status(&status("calling", None), 1_000);
        assert!(ui.dial_failed().is_none());
    }

    #[test]
    fn the_dial_failure_line_covers_every_reason_word_in_every_language() {
        for lang in Locale::ALL {
            let c = call_strings(lang);
            assert_eq!(dial_failed_text(c, "busy"), c.dial_busy);
            assert_eq!(dial_failed_text(c, "not_ready"), c.dial_securing);
            assert_eq!(dial_failed_text(c, "unavailable"), c.unavailable);
            assert_eq!(dial_failed_text(c, "not_allowed"), c.dial_refused);
            assert_eq!(dial_failed_text(c, "refused"), c.dial_refused);
            // An unknown word falls back to the neutral refused line, never to empty.
            assert_eq!(dial_failed_text(c, "surprise"), c.dial_refused);
            assert!(!dial_failed_text(c, "surprise").is_empty());
        }
    }

    #[test]
    fn idle_discovery_is_due_within_two_seconds_so_a_new_offer_is_noticed_quickly() {
        // With no call of ours, the idle discovery poll must come due a couple of seconds after
        // the last poll in every tab, so a dial from the other side (and a held redial of ours)
        // is found within a few seconds rather than up to five.
        let mut ui = CallUi::default();
        assert!(!ui.discovery_due(1_999));
        assert!(ui.discovery_due(2_000));
        ui.mark_polled(10_000);
        assert!(!ui.discovery_due(11_999));
        assert!(ui.discovery_due(12_000));
        // While a call of ours exists, idle discovery does not run (the active poll does).
        ui.on_dial();
        assert!(!ui.discovery_due(1_000_000));
    }
}
