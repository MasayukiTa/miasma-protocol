//! Whether the program runs inside an MSIX package (a Microsoft Store install).
//!
//! A packaged program is updated by the Store, and its install folder is
//! read-only, so the self-update must not run there. On Windows the answer
//! comes from `GetCurrentPackageFullName`: a process with package identity gets
//! `ERROR_INSUFFICIENT_BUFFER` when it asks with an empty buffer, a process
//! without one gets `APPMODEL_ERROR_NO_PACKAGE`. Everywhere else the answer is
//! "not packaged".
//!
//! The operating-system call sits behind a function pointer
//! ([`PackageQuery`]), so the decision is testable on every platform.

use std::sync::OnceLock;

/// `ERROR_INSUFFICIENT_BUFFER`: the process has a package name that did not fit
/// the (empty) buffer we passed.
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// `APPMODEL_ERROR_NO_PACKAGE`: the process has no package identity.
pub const APPMODEL_ERROR_NO_PACKAGE: u32 = 15700;

/// Asks the system for the package name length and returns the raw Win32 status.
pub type PackageQuery = fn() -> u32;

/// What a status from `GetCurrentPackageFullName` (called with a zero length and
/// no buffer) means. Only "a name exists" counts as packaged; the no-package
/// code and any other answer count as a normal install.
pub fn packaged_from_status(status: u32) -> bool {
    status == ERROR_INSUFFICIENT_BUFFER || status == 0
}

/// The decision with a given query (the real one or a test double).
pub fn is_packaged_with(query: PackageQuery) -> bool {
    packaged_from_status(query())
}

#[cfg(windows)]
fn os_query() -> u32 {
    use windows_sys::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
    let mut len: u32 = 0;
    // SAFETY: `len` is a valid, writable u32 for the whole call. A null buffer
    // together with a length of 0 is the documented way to ask for the needed
    // length; nothing is written through the null pointer.
    unsafe { GetCurrentPackageFullName(&mut len, std::ptr::null_mut()) }
}

#[cfg(not(windows))]
fn os_query() -> u32 {
    APPMODEL_ERROR_NO_PACKAGE
}

/// Whether this process runs inside an MSIX package. Asked once per process.
pub fn is_packaged() -> bool {
    static PACKAGED: OnceLock<bool> = OnceLock::new();
    *PACKAGED.get_or_init(|| is_packaged_with(os_query))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_package_name_that_did_not_fit_means_packaged() {
        assert!(is_packaged_with(|| ERROR_INSUFFICIENT_BUFFER));
        assert!(packaged_from_status(0));
    }

    #[test]
    fn the_no_package_status_means_a_normal_install() {
        assert!(!is_packaged_with(|| APPMODEL_ERROR_NO_PACKAGE));
    }

    #[test]
    fn any_other_status_counts_as_a_normal_install() {
        for s in [1, 5, 87, 1168, 15701, u32::MAX] {
            assert!(!packaged_from_status(s), "status {s}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn other_platforms_are_never_packaged() {
        assert!(!is_packaged());
        assert!(!is_packaged_with(os_query));
    }

    /// The call really reaches the system on Windows. The test runner is an
    /// ordinary program, so it has no package identity; this proves the call
    /// links and returns the no-package status. It cannot show the packaged
    /// answer, which needs a program started from an MSIX package.
    #[cfg(windows)]
    #[test]
    fn an_ordinary_windows_process_has_no_package_identity() {
        assert_eq!(os_query(), APPMODEL_ERROR_NO_PACKAGE);
        assert!(!is_packaged());
    }
}
