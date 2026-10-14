//! Free disk space for the volume holding a path (no extra crates).

use std::path::Path;

/// Bytes available to this user on the volume that holds `path`. The path need
/// not exist: the nearest existing ancestor is used. `None` if unknown (the
/// caller then does not block on it).
pub fn free_space(path: &Path) -> Option<u64> {
    let mut p = path;
    while !p.exists() {
        p = p.parent()?;
    }
    imp(p)
}

#[cfg(windows)]
fn imp(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            dir: *const u16,
            free_to_caller: *mut u64,
            total: *mut u64,
            total_free: *mut u64,
        ) -> i32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    // SAFETY: `wide` is NUL-terminated and outlives the call; the three
    // out-pointers are valid for writes.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) };
    (ok != 0).then_some(avail)
}

#[cfg(unix)]
fn imp(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a valid C string and `st` is a properly sized, writable
    // statvfs struct that is only read after the call succeeds.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return None;
        }
        Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
    }
}

#[cfg(not(any(windows, unix)))]
fn imp(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn reports_something_for_the_temp_dir() {
        let d = tempfile::tempdir().unwrap();
        let free = super::free_space(&d.path().join("not/yet/created")).unwrap();
        assert!(free > 0);
    }
}
