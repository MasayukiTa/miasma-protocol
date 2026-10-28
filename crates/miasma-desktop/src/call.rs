//! The call screen, pure part: everything that can be decided without a window.
//!
//! The state word to show, the duration text, whether the microphone counts as in use, the
//! safety-code line, the camera and video state, and the small amount of screen state a call
//! needs. The window in `call_ui.rs` holds an instance of [`CallUi`] and draws it; this file is
//! unit-tested headless, the way `chat.rs` is.
//!
//! Only built with the `pqc` feature, because the call IPC surface
//! (`miasma_core::chat::ipc::CallRequest` and friends) is defined only there.

use miasma_core::chat::ipc::{CallRequest, CallStatusDto};

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
/// The daemon reports the short authentication string once both ends have confirmed the call;
/// until then the field is empty and this returns `None`, so the panel shows a neutral "pending"
/// line in its place. An empty string is treated the same as absent.
pub fn safety_code_text(status: &CallStatusDto) -> Option<String> {
    match &status.safety_code {
        Some(code) if !code.is_empty() => Some(code.clone()),
        _ => None,
    }
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
    /// The microphone mute flag. Until the audio work lands this is only a UI state flag; it is
    /// read by [`CallUi::is_muted`] and changed by [`CallUi::set_muted`], the named hook the
    /// audio layer will drive later.
    muted: bool,
    /// Whether the local camera is on. A UI intent flag set by [`CallUi::set_camera`]; the
    /// daemon's own view of the camera is read from the status (see [`CallUi::camera_in_use`]).
    camera_on: bool,
    /// Whether both ends agreed to carry video for this call, from the last status.
    negotiated_video: bool,
    /// Whether the daemon reports a screen as being shared, from the last status.
    screen_sharing: bool,
    /// The last safety code the daemon reported, if any. Shown by the panel; never logged.
    safety_code: Option<String>,
    /// When the call connected (ms since the epoch), for the duration. `None` until connected.
    connected_ms: Option<u64>,
    /// The next `since` for call `Events` polling.
    events_since: u64,
    /// When the last poll went out (ms since the epoch), to space polls by `POLL_INTERVAL_MS`.
    last_poll_ms: u64,
}

impl Default for CallUi {
    fn default() -> Self {
        Self {
            pending_token: None,
            active: false,
            state: String::new(),
            muted: false,
            camera_on: false,
            negotiated_video: false,
            screen_sharing: false,
            safety_code: None,
            connected_ms: None,
            events_since: 0,
            last_poll_ms: 0,
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

    /// Whether the microphone is muted (UI flag only for now).
    pub fn is_muted(&self) -> bool {
        self.muted
    }

    /// Set the mute flag. This is the named hook the audio layer will drive once it lands; today
    /// it only records the UI state so the button and the indicator reflect it.
    pub fn set_muted(&mut self, muted: bool) {
        self.muted = muted;
    }

    /// Whether the camera button shows the local camera as on. This is the UI intent; the panel
    /// uses it to label the button. The daemon's own view is [`CallUi::camera_in_use`].
    pub fn camera_on(&self) -> bool {
        self.camera_on
    }

    /// Record the camera intent after the app sends [`set_camera`]. The matching request is built
    /// by the [`set_camera`] builder; this only keeps the UI label in step.
    pub fn set_camera(&mut self, on: bool) {
        self.camera_on = on;
    }

    /// Whether the daemon reports the local camera as in use, from the last status. False until a
    /// status says otherwise, so audio-only calls never show it.
    pub fn camera_in_use(&self) -> bool {
        self.camera_on && self.active
    }

    /// Whether both ends agreed to carry video for this call, from the last status.
    pub fn negotiated_video(&self) -> bool {
        self.negotiated_video
    }

    /// Whether a screen is being shared, from the last status. Always false until screen capture
    /// is available in the daemon.
    pub fn screen_sharing(&self) -> bool {
        self.screen_sharing
    }

    /// The safety code the daemon last reported, or `None` when none is ready yet.
    pub fn safety_code(&self) -> Option<&str> {
        self.safety_code.as_deref()
    }

    /// Record that we started dialing a contact: a call of ours now exists.
    pub fn on_dial(&mut self) {
        self.active = true;
        self.state = "calling".to_owned();
        self.connected_ms = None;
        self.muted = false;
        self.camera_on = false;
        self.negotiated_video = false;
        self.screen_sharing = false;
        self.safety_code = None;
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
        self.camera_on = status.camera_in_use;
        self.negotiated_video = status.negotiated_video;
        self.screen_sharing = status.screen_sharing;
        self.safety_code = safety_code_text(status);
    }

    /// End the call and forget its state. Called when the daemon reports `idle`, or after we hang
    /// up, reject, or the call ends. The pending token is cleared too, so nothing lingers.
    pub fn end(&mut self) {
        self.pending_token = None;
        self.active = false;
        self.state = String::new();
        self.connected_ms = None;
        self.muted = false;
        self.camera_on = false;
        self.negotiated_video = false;
        self.screen_sharing = false;
        self.safety_code = None;
    }

    /// The elapsed seconds of a connected call at `now_ms`, or `None` when not connected yet.
    pub fn duration_secs(&self, now_ms: u64) -> Option<u64> {
        let start = self.connected_ms?;
        Some(now_ms.saturating_sub(start) / 1000)
    }

    /// Whether the microphone must be shown as in use right now.
    pub fn mic_in_use(&self) -> bool {
        self.active && mic_in_use(&self.state)
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

    /// Record that a poll went out at `now_ms`, so the next one waits a full interval.
    pub fn mark_polled(&mut self, now_ms: u64) {
        self.last_poll_ms = now_ms;
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

/// Build the `HangUp` request that ends the current call.
pub fn hang_up() -> CallRequest {
    CallRequest::HangUp
}

/// Build the `SetCamera` request that turns the local camera on or off during a connected call.
pub fn set_camera(on: bool) -> CallRequest {
    CallRequest::SetCamera { on }
}

/// Build the `VideoFrame` request that asks for the most recent decoded picture from the peer.
/// The panel polls this while a call carries video; the answer is handled where the request is
/// sent, so no picture bytes are kept here.
pub fn video_frame() -> CallRequest {
    CallRequest::VideoFrame
}

/// Build the `Status` request used to poll the call state.
pub fn status_request() -> CallRequest {
    CallRequest::Status
}

/// Build the `Events` request for call notices after event number `since`.
pub fn events(since: u64) -> CallRequest {
    CallRequest::Events { since }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locale::{call_strings, Locale};

    fn status(state: &str, pending: Option<u64>) -> CallStatusDto {
        CallStatusDto {
            state: state.to_owned(),
            pending_token: pending,
            signalling_connected: state == "connected",
            safety_code: None,
            media_frames_sent: 0,
            media_frames_played: 0,
            media_video_frames_sent: 0,
            media_video_frames_played: 0,
            camera_in_use: false,
            negotiated_video: false,
            screen_sharing: false,
        }
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
    fn the_safety_code_shows_only_once_the_daemon_reports_one() {
        // No code yet: a status without one gives None, so the panel shows its pending line.
        assert!(safety_code_text(&status("connected", None)).is_none());
        // An empty string counts as none, never as a blank code.
        let mut empty = status("connected", None);
        empty.safety_code = Some(String::new());
        assert!(safety_code_text(&empty).is_none());
        // Once the daemon reports a code it is shown verbatim.
        let mut ready = status("connected", None);
        ready.safety_code = Some("12345 67890 13579 24680".to_owned());
        assert_eq!(
            safety_code_text(&ready).as_deref(),
            Some("12345 67890 13579 24680")
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
        assert!(!ui.mic_in_use());
    }

    #[test]
    fn the_mute_hook_only_records_the_flag_for_now() {
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
        assert!(matches!(hang_up(), CallRequest::HangUp));
        assert!(matches!(
            set_camera(true),
            CallRequest::SetCamera { on: true }
        ));
        assert!(matches!(
            set_camera(false),
            CallRequest::SetCamera { on: false }
        ));
        assert!(matches!(video_frame(), CallRequest::VideoFrame));
        assert!(matches!(status_request(), CallRequest::Status));
        assert!(matches!(events(5), CallRequest::Events { since: 5 }));
    }

    #[test]
    fn an_audio_only_status_leaves_every_video_flag_off() {
        // A plain connected call (no camera, no video negotiated, no screen share) must look
        // exactly as before: all the video-related state stays off.
        let mut ui = CallUi::default();
        ui.on_status(&status("connected", None), 1_000);
        assert!(!ui.camera_on());
        assert!(!ui.camera_in_use());
        assert!(!ui.negotiated_video());
        assert!(!ui.screen_sharing());
        assert!(ui.safety_code().is_none());
    }

    #[test]
    fn a_status_carries_the_camera_video_and_safety_code_through() {
        let mut ui = CallUi::default();
        let mut st = status("connected", None);
        st.camera_in_use = true;
        st.negotiated_video = true;
        st.screen_sharing = true;
        st.safety_code = Some("12345 67890 13579 24680".to_owned());
        ui.on_status(&st, 1_000);
        assert!(ui.camera_on());
        assert!(ui.camera_in_use());
        assert!(ui.negotiated_video());
        assert!(ui.screen_sharing());
        assert_eq!(ui.safety_code(), Some("12345 67890 13579 24680"));
        // An idle status clears all of it, like the rest of the call state.
        ui.on_status(&status("idle", None), 2_000);
        assert!(!ui.camera_on());
        assert!(!ui.camera_in_use());
        assert!(!ui.negotiated_video());
        assert!(!ui.screen_sharing());
        assert!(ui.safety_code().is_none());
    }

    #[test]
    fn the_camera_hook_only_records_the_intent() {
        let mut ui = CallUi::default();
        ui.on_dial();
        assert!(!ui.camera_on());
        ui.set_camera(true);
        assert!(ui.camera_on());
        assert!(ui.camera_in_use());
        ui.set_camera(false);
        assert!(!ui.camera_on());
        assert!(!ui.camera_in_use());
    }

    #[test]
    fn the_camera_is_not_in_use_without_an_active_call() {
        // The intent flag alone never shows the camera as in use: a call must exist.
        let mut ui = CallUi::default();
        ui.set_camera(true);
        assert!(ui.camera_on());
        assert!(!ui.camera_in_use());
    }
}
