//! Which wrap a program installs by default.
//!
//! On Windows the key is wrapped by DPAPI for the signed-in user. If DPAPI does
//! not work for this user, the file wrap is used so the program still starts
//! with a sealed key (a sealed key is never opened by older programs, which stop
//! instead of starting a new key). A service in session 0 keeps the plain key:
//! sealing there would make the key unreadable to the user's own programs. Other
//! systems keep the plain key until they have a provider of their own.

#[cfg(windows)]
use std::sync::Arc;

use super::ProviderId;
#[cfg(windows)]
use super::{DeviceWrap, SealedProvider};

/// What the default choice comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) enum Pick {
    /// No provider: the plain `master.key` stays as it is.
    Plain,
    Dpapi,
    /// DPAPI failed its self-test; the file wrap stands in.
    FileWrap,
}

/// `user_session`: the process runs in a user's session. `dpapi_works`: the
/// DPAPI self-test passed (only asked when `user_session` is true).
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn pick(user_session: bool, dpapi_works: impl FnOnce() -> bool) -> Pick {
    if !user_session {
        Pick::Plain
    } else if dpapi_works() {
        Pick::Dpapi
    } else {
        Pick::FileWrap
    }
}

#[cfg(windows)]
fn windows_pick() -> Pick {
    use super::dpapi::{in_user_session, DpapiWrap};
    pick(in_user_session(), || match DpapiWrap::self_test() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("Windows data protection is not usable; using the file wrap: {e}");
            false
        }
    })
}

/// Install the default provider of this system. Called once by a program entry
/// point after logging is set up. Returns what is now in use for new and
/// moved keys: [`ProviderId::Dpapi`], [`ProviderId::File`] (file wrap), or
/// `None` when the plain key file is kept.
pub fn install_default_platform_provider() -> Option<ProviderId> {
    #[cfg(windows)]
    {
        let wrap: Arc<dyn DeviceWrap> = match windows_pick() {
            Pick::Plain => {
                tracing::info!("not in a user session; the key stays a plain file");
                return None;
            }
            Pick::Dpapi => Arc::new(super::dpapi::DpapiWrap),
            Pick::FileWrap => Arc::new(super::FileWrap),
        };
        let id = wrap.id();
        super::install_platform_provider(Arc::new(SealedProvider::new(wrap)));
        Some(id)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_is_the_default_when_it_works() {
        assert_eq!(pick(true, || true), Pick::Dpapi);
    }

    #[test]
    fn the_file_wrap_stands_in_when_dpapi_fails() {
        assert_eq!(pick(true, || false), Pick::FileWrap);
    }

    #[test]
    fn a_service_session_keeps_the_plain_key_without_asking_dpapi() {
        assert_eq!(
            pick(false, || panic!(
                "DPAPI must not be asked outside a user session"
            )),
            Pick::Plain
        );
    }
}
