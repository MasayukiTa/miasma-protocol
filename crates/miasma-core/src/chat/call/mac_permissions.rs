//! macOS capture-permission preflight for screen recording and the microphone,
//! and the reason words the call UI shows when a capture permission is missing.
//!
//! On macOS the system withholds screen frames until the user has granted the
//! Screen Recording permission, and withholds microphone samples until the user
//! has granted the Microphone permission. Each is preflighted before the
//! matching capture starts, and where the decision has not been made the
//! preflight raises the one-time system prompt:
//!
//! * Screen Recording has no prompt-on-first-use; an app must preflight the
//!   permission and request it. [`preflight_screen`] does this with Core
//!   Graphics on macOS.
//! * The microphone can be prompted on first capture by Core Audio when the app
//!   bundle carries `NSMicrophoneUsageDescription`, but preflighting it before
//!   opening the device lets the call code learn the result up front and run
//!   receive-only with a neutral reason rather than waiting on a silent device.
//!   [`preflight_microphone`] does this with AVFoundation on macOS; the plist
//!   key is added in scripts/build-macos.sh.
//!
//! The permission *state* types and the mapping from a state (or a capture
//! error) to a stable reason word are plain Rust with no platform calls, so
//! they build and are unit-tested on every target. Only the preflight functions'
//! Core Graphics and AVFoundation calls are macOS-only.
//!
//! Privacy: nothing here handles a sample, a key, a call id or a peer id. The
//! reason words are fixed lowercase tokens with no content.

/// The outcome of a screen-recording preflight, independent of the platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenPermission {
    /// The permission is granted; capture may start.
    Granted,
    /// The permission is not granted (never decided, or refused). The preflight
    /// has raised the one-time prompt where it could; nothing can be captured
    /// on this press, so the UI shows the reason and the user allows it and
    /// tries again.
    NotGranted,
}

/// The stable reason word the call UI shows when screen sharing cannot start
/// because the Screen Recording permission is not granted. Mirrors the existing
/// lowercase codes such as `no_camera` and `not_ready`.
pub const SCREEN_PERMISSION_REASON: &str = "screen_permission";

/// The stable reason word the call UI shows when the microphone cannot be used
/// because its permission was refused.
pub const MIC_PERMISSION_REASON: &str = "mic_permission";

/// Map a screen-recording preflight result to an optional reason word: `None`
/// when capture may proceed, or the stable `screen_permission` word when the
/// permission is not granted. Keeping this a pure function lets the call code
/// and the tests agree without a platform call.
pub fn screen_reason(permission: ScreenPermission) -> Option<&'static str> {
    match permission {
        ScreenPermission::Granted => None,
        ScreenPermission::NotGranted => Some(SCREEN_PERMISSION_REASON),
    }
}

/// Whether a microphone capture failure means the permission was refused, in
/// which case the call UI shows the `mic_permission` word. A missing or
/// unsupported device is not a permission problem and yields `None` (the call
/// still runs receive-only). Pure; no platform call.
pub fn mic_reason_for_denied(denied: bool) -> Option<&'static str> {
    if denied {
        Some(MIC_PERMISSION_REASON)
    } else {
        None
    }
}

/// The outcome of a microphone preflight, independent of the platform. Mirrors
/// [`ScreenPermission`]: either capture may start, or it may not yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MicPermission {
    /// The permission is granted; capture may start.
    Granted,
    /// The permission is not granted (never decided, or refused). Where the
    /// decision had not been made, the preflight has raised the one-time prompt;
    /// nothing can be captured on this press, so the caller runs receive-only
    /// and the UI can show the reason.
    NotGranted,
}

/// Map a microphone preflight result to an optional reason word: `None` when
/// capture may proceed, or the stable `mic_permission` word when the permission
/// is not granted. Pure, so the call code and the tests agree without a
/// platform call.
pub fn mic_reason(permission: MicPermission) -> Option<&'static str> {
    match permission {
        MicPermission::Granted => None,
        MicPermission::NotGranted => Some(MIC_PERMISSION_REASON),
    }
}

/// Preflight the Microphone permission and, when the decision has not yet been
/// made, raise the one-time system prompt. Returns whether the permission was
/// granted at the time of the call.
///
/// Unlike screen recording, Core Audio does prompt on first capture when the
/// app bundle carries `NSMicrophoneUsageDescription`. Doing the preflight here
/// as well means the call code learns the result before it opens a device, so
/// it can run receive-only and surface a neutral reason instead of waiting on a
/// silent device. The prompt is raised at most once by the system; a later
/// grant takes effect for a subsequent call, so the completion result is not
/// awaited here (matching [`preflight_screen`]).
///
/// macOS-only; on every other target this is a compile-time no-op that reports
/// `Granted`, so Windows and Linux behaviour is unchanged.
#[cfg(target_os = "macos")]
pub fn preflight_microphone() -> MicPermission {
    use objc2::runtime::Bool;
    use objc2_av_foundation::{AVAuthorizationStatus, AVCaptureDevice, AVMediaTypeAudio};

    // SAFETY: `AVMediaTypeAudio` is the framework's media-type string constant;
    // the two AVCaptureDevice class methods take a reference to it and neither
    // touches a sample. When the constant is unavailable (it never is on a
    // supported system) there is nothing to preflight, so report granted and
    // let the capture path proceed as before.
    let audio = match unsafe { AVMediaTypeAudio } {
        Some(audio) => audio,
        None => return MicPermission::Granted,
    };
    // AVAuthorizationStatus is a transparent NSInteger newtype with associated
    // constants rather than enum variants, so compare against the constants.
    let status = unsafe { AVCaptureDevice::authorizationStatusForMediaType(audio) };
    if status == AVAuthorizationStatus::Authorized {
        MicPermission::Granted
    } else if status == AVAuthorizationStatus::NotDetermined {
        // Raise the one-time system prompt. The grant is delivered later and
        // applies to a subsequent call, not this one, so the completion handler
        // does nothing and its result is not awaited (matching the screen
        // preflight).
        let handler = block2::RcBlock::new(|_granted: Bool| {});
        unsafe {
            AVCaptureDevice::requestAccessForMediaType_completionHandler(audio, &handler);
        }
        MicPermission::NotGranted
    } else {
        // Denied or Restricted: not granted, and no prompt will appear.
        MicPermission::NotGranted
    }
}

#[cfg(not(target_os = "macos"))]
pub fn preflight_microphone() -> MicPermission {
    MicPermission::Granted
}

/// Preflight the Screen Recording permission and, when it is not already
/// granted, raise the one-time system prompt. Returns whether the permission
/// was granted at the time of the call.
///
/// macOS-only; on every other target this is a compile-time no-op that reports
/// `Granted`, so Windows and Linux behaviour is unchanged.
#[cfg(target_os = "macos")]
pub fn preflight_screen() -> ScreenPermission {
    // CGPreflightScreenCaptureAccess reports whether the app already holds the
    // Screen Recording permission, without raising a prompt. When it does not,
    // CGRequestScreenCaptureAccess raises the system prompt once; its bool
    // result is not awaited here because the grant takes effect for a later
    // capture, not this call. Both are stable CoreGraphics C functions declared
    // below; they are the documented way to gate screen recording on macOS.
    let granted = unsafe { CGPreflightScreenCaptureAccess() };
    if granted {
        ScreenPermission::Granted
    } else {
        unsafe {
            let _ = CGRequestScreenCaptureAccess();
        }
        ScreenPermission::NotGranted
    }
}

// CoreGraphics exposes the screen-recording permission gate as two C functions.
// They are linked directly from the CoreGraphics framework rather than through
// a binding crate, so the call site depends only on the stable Apple symbols.
// macOS-only; never referenced on other targets.
#[cfg(target_os = "macos")]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    // Returns true when the app already has Screen Recording permission. Does
    // not prompt.
    fn CGPreflightScreenCaptureAccess() -> bool;
    // Raises the one-time system prompt when permission has not been decided.
    // Returns whether permission is granted; the result is not relied on here.
    fn CGRequestScreenCaptureAccess() -> bool;
}

#[cfg(not(target_os = "macos"))]
pub fn preflight_screen() -> ScreenPermission {
    ScreenPermission::Granted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_reason_only_when_not_granted() {
        assert_eq!(screen_reason(ScreenPermission::Granted), None);
        assert_eq!(
            screen_reason(ScreenPermission::NotGranted),
            Some(SCREEN_PERMISSION_REASON)
        );
    }

    #[test]
    fn mic_reason_only_when_denied() {
        assert_eq!(mic_reason_for_denied(false), None);
        assert_eq!(mic_reason_for_denied(true), Some(MIC_PERMISSION_REASON));
    }

    #[test]
    fn mic_reason_only_when_not_granted() {
        assert_eq!(mic_reason(MicPermission::Granted), None);
        assert_eq!(
            mic_reason(MicPermission::NotGranted),
            Some(MIC_PERMISSION_REASON)
        );
    }

    #[test]
    fn reason_words_are_stable_and_distinct() {
        assert_eq!(SCREEN_PERMISSION_REASON, "screen_permission");
        assert_eq!(MIC_PERMISSION_REASON, "mic_permission");
        assert_ne!(SCREEN_PERMISSION_REASON, MIC_PERMISSION_REASON);
    }

    #[test]
    fn non_macos_preflight_reports_granted() {
        // On a non-macOS host the preflight is a no-op reporting Granted, so
        // Windows and Linux behaviour is unchanged.
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(preflight_screen(), ScreenPermission::Granted);
            assert_eq!(preflight_microphone(), MicPermission::Granted);
        }
    }
}
