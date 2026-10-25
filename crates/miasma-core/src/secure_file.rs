/// Create and write files with restricted permissions from the start.
///
/// On Windows, uses `CreateFileW` with a `SECURITY_DESCRIPTOR` / DACL that
/// grants only the current user full control.  The file is born restricted —
/// there is no window where it exists with inherited (permissive) ACLs.
///
/// On Unix, uses `open()` with mode `0o600`.
///
/// All callers that write secrets (master key, config with proxy credentials)
/// MUST use this module rather than `std::fs::write` / `File::create`.
use std::path::Path;

use crate::MiasmaError;

/// Write `data` to `path` with permissions restricted to the current user.
///
/// - If the file already exists it is **replaced** (truncated and rewritten)
///   while preserving the existing ACL on Windows (the OS keeps the ACL on
///   overwrite when the file handle carries no new security descriptor).
///   For first-time creation, the restrictive DACL is applied.
/// - On failure, returns `Err` — the file is **not** written insecurely.
pub fn write_restricted(path: &Path, data: &[u8]) -> Result<(), MiasmaError> {
    platform::write_restricted_impl(path, data)
}

/// Atomic restricted write: write to a temp file (restricted), then rename.
///
/// This is the preferred pattern for secrets that must never be readable by
/// other users even momentarily at the final path.
pub fn atomic_write_restricted(path: &Path, data: &[u8]) -> Result<(), MiasmaError> {
    // The temp file carries the process id and a fresh random suffix in its
    // name, so two writers staging the same final path, or an unrelated `.tmp`
    // user in the same directory, never collide on the temp name.
    let tmp = crate::paths::atomic_secure_tmp_unique(path, std::process::id(), rand::random());
    write_restricted(&tmp, data).inspect_err(|_e| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        MiasmaError::Io(std::io::Error::other(format!(
            "failed to rename restricted file into place: {e}"
        )))
    })
}

/// Atomic plain write: write to a temp file in the same directory, then rename
/// it over the final path. The rename is atomic on the same volume, so a crash
/// or a concurrent writer never leaves a truncated file at the final path.
///
/// Use this instead of `std::fs::write` for persisted paths that do not need
/// restricted permissions, so the temp+rename guarantee lives in one audited
/// place. The temp name includes the process id and a fresh random suffix to
/// avoid colliding with another writer in the same directory.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), MiasmaError> {
    let tmp = crate::paths::atomic_tmp_unique(path, std::process::id(), rand::random());
    std::fs::write(&tmp, data).inspect_err(|_e| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        MiasmaError::Io(std::io::Error::other(format!(
            "failed to rename file into place: {e}"
        )))
    })
}

/// Atomic plain write that never replaces an existing file. The bytes go to a
/// uniquely named temp file in the same directory, and are then linked into
/// place only if nothing already holds the final name; the temp file is always
/// removed. Returns `Ok(true)` when this call created `path`,
/// `Ok(false)` when a file was already there (left untouched). A reader sees
/// either no file or the whole file, never a partial one.
///
/// Use this instead of a bare `File::create` + `hard_link` so the no-clobber
/// temp+link guarantee lives in one audited place. The temp name includes the
/// process id and a fresh random suffix to avoid colliding with another writer
/// in the same directory.
pub fn atomic_write_new(path: &Path, data: &[u8]) -> Result<bool, MiasmaError> {
    let tmp = crate::paths::atomic_tmp_unique(path, std::process::id(), rand::random());
    std::fs::write(&tmp, data).inspect_err(|_e| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    // A hard link fails with AlreadyExists rather than overwriting, so an
    // existing file at the final path is never lost.
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(MiasmaError::Io(std::io::Error::other(format!(
            "failed to place file: {e}"
        )))),
    }
}

/// Verify that `path` is restricted to the current user (best-effort).
///
/// Returns `Ok(true)` if the file is restricted, `Ok(false)` if it is not
/// or if verification is not supported on this platform.  Returns `Err`
/// only on unexpected system errors.
pub fn verify_restricted(path: &Path) -> Result<bool, MiasmaError> {
    platform::verify_restricted_impl(path)
}

/// Create a new, empty file that only the current user can access from its
/// first byte (Windows: security descriptor passed to `CreateFileW`, owner set
/// to the current user; Unix: mode `0600`).  Fails if `path` already exists.
/// On an unsupported platform this always fails.
pub fn create_new_restricted(path: &Path) -> Result<std::fs::File, MiasmaError> {
    platform::create_new_restricted_impl(path)
}

/// Strict check: `Ok(())` only if `path` is a file only the current user can
/// access (Windows: a single allow ACE for the user and the user as owner;
/// Unix: regular file, mode `0600`, owned by the effective user).  Any other
/// outcome, including an unsupported platform, is an `Err` that says why.
pub fn verify_owner_only(path: &Path) -> Result<(), MiasmaError> {
    platform::verify_owner_only_impl(path)
}

/// Check that nobody but the current user can add or replace entries in `dir`
/// (Unix: owned by the effective user, not writable by other users; Windows: not
/// checked here, the file's own access list is verified instead).
pub fn verify_private_dir(dir: &Path) -> Result<(), MiasmaError> {
    platform::verify_private_dir_impl(dir)
}

// ─── Platform implementation ─────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::OsStr;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::ptr;

    // Win32 constants — avoids pulling in the large windows-sys crate.
    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const CREATE_NEW: u32 = 1;
    const CREATE_ALWAYS: u32 = 2;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const INVALID_HANDLE_VALUE: isize = -1;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_INFO_CLASS: u32 = 1; // TokenUser

    // ACL / SECURITY_DESCRIPTOR constants
    const ACL_REVISION: u32 = 2;
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    // The ACE flags and access mask for "Full Control"
    const FILE_ALL_ACCESS: u32 = 0x1F01FF;

    #[repr(C)]
    struct SecurityDescriptor {
        revision: u8,
        sbz1: u8,
        control: u16,
        owner: *mut u8,
        group: *mut u8,
        sacl: *mut u8,
        dacl: *mut u8,
    }

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut SecurityDescriptor,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    struct Acl {
        acl_revision: u8,
        sbz1: u8,
        acl_size: u16,
        ace_count: u16,
        sbz2: u16,
    }

    #[repr(C)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut u8,
        attributes: u32,
    }

    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut SecurityAttributes,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: isize,
        ) -> isize;

        fn CloseHandle(hObject: isize) -> i32;

        fn GetCurrentProcess() -> isize;
        fn OpenProcessToken(
            ProcessHandle: isize,
            DesiredAccess: u32,
            TokenHandle: *mut isize,
        ) -> i32;
        fn GetTokenInformation(
            TokenHandle: isize,
            TokenInformationClass: u32,
            TokenInformation: *mut u8,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;

        fn InitializeSecurityDescriptor(
            pSecurityDescriptor: *mut SecurityDescriptor,
            dwRevision: u32,
        ) -> i32;
        fn SetSecurityDescriptorDacl(
            pSecurityDescriptor: *mut SecurityDescriptor,
            bDaclPresent: i32,
            pDacl: *mut Acl,
            bDaclDefaulted: i32,
        ) -> i32;
        fn SetSecurityDescriptorOwner(
            pSecurityDescriptor: *mut SecurityDescriptor,
            pOwner: *mut u8,
            bOwnerDefaulted: i32,
        ) -> i32;
        fn GetSecurityDescriptorOwner(
            pSecurityDescriptor: *const u8,
            pOwner: *mut *mut u8,
            lpbOwnerDefaulted: *mut i32,
        ) -> i32;
        fn InitializeAcl(pAcl: *mut Acl, nAclLength: u32, dwAclRevision: u32) -> i32;
        fn AddAccessAllowedAce(
            pAcl: *mut Acl,
            dwAceRevision: u32,
            AccessMask: u32,
            pSid: *mut u8,
        ) -> i32;
        fn GetLengthSid(pSid: *mut u8) -> u32;
        fn IsValidSid(pSid: *mut u8) -> i32;

        fn GetFileSecurityW(
            lpFileName: *const u16,
            RequestedInformation: u32,
            pSecurityDescriptor: *mut u8,
            nLength: u32,
            lpnLengthNeeded: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            pSecurityDescriptor: *const u8,
            lpbDaclPresent: *mut i32,
            pDacl: *mut *mut Acl,
            lpbDaclDefaulted: *mut i32,
        ) -> i32;
        fn GetAce(pAcl: *mut Acl, dwAceIndex: u32, pAce: *mut *mut AceHeader) -> i32;
        fn EqualSid(pSid1: *mut u8, pSid2: *mut u8) -> i32;
    }

    fn to_wide(s: &Path) -> Vec<u16> {
        let os: &OsStr = s.as_ref();
        os.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Get the current user's SID as a heap-allocated buffer.
    fn current_user_sid() -> Result<Vec<u8>, MiasmaError> {
        unsafe {
            let mut token: isize = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(MiasmaError::KeyDerivation("OpenProcessToken failed".into()));
            }

            // Query required buffer size.
            let mut needed: u32 = 0;
            GetTokenInformation(
                token,
                TOKEN_USER_INFO_CLASS,
                ptr::null_mut(),
                0,
                &mut needed,
            );
            if needed == 0 {
                CloseHandle(token);
                return Err(MiasmaError::KeyDerivation(
                    "GetTokenInformation size query returned 0".into(),
                ));
            }

            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TOKEN_USER_INFO_CLASS,
                buf.as_mut_ptr(),
                needed,
                &mut needed,
            ) == 0
            {
                CloseHandle(token);
                return Err(MiasmaError::KeyDerivation(
                    "GetTokenInformation failed".into(),
                ));
            }
            CloseHandle(token);

            let token_user = &*(buf.as_ptr() as *const TokenUser);
            let sid_ptr = token_user.user.sid;
            if IsValidSid(sid_ptr) == 0 {
                return Err(MiasmaError::KeyDerivation("invalid user SID".into()));
            }
            let sid_len = GetLengthSid(sid_ptr) as usize;
            let mut sid_copy = vec![0u8; sid_len];
            std::ptr::copy_nonoverlapping(sid_ptr, sid_copy.as_mut_ptr(), sid_len);
            Ok(sid_copy)
        }
    }

    pub(super) fn write_restricted_impl(path: &Path, data: &[u8]) -> Result<(), MiasmaError> {
        // If the file already exists, delete it first.  CREATE_ALWAYS only
        // applies the SECURITY_DESCRIPTOR on actual creation; truncating an
        // existing file preserves the old DACL.  By deleting first we ensure
        // the new DACL is always applied.
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        let mut file = open_restricted(path, CREATE_ALWAYS, false)?;
        if let Err(e) = file.write_all(data) {
            // File is closed by drop.
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(MiasmaError::Io(e));
        }
        if let Err(e) = file.flush() {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(MiasmaError::Io(e));
        }
        Ok(())
    }

    /// Create a file whose security descriptor (one ACE for the current
    /// user, no inheritance) is applied by `CreateFileW` itself.  With
    /// `CREATE_NEW` the call fails if the path already exists.  With
    /// `set_owner` the owner is set to the current user explicitly (the
    /// default owner of an elevated process is the Administrators group).
    fn open_restricted(
        path: &Path,
        disposition: u32,
        set_owner: bool,
    ) -> Result<std::fs::File, MiasmaError> {
        let sid = current_user_sid()?;
        let sid_len = sid.len();

        unsafe {
            // Build DACL: one ACE granting current user FILE_ALL_ACCESS.
            let ace_size = std::mem::size_of::<AceHeader>() + std::mem::size_of::<u32>() + sid_len;
            let acl_size = std::mem::size_of::<Acl>() + ace_size;
            let mut acl_buf = vec![0u8; acl_size];
            let acl_ptr = acl_buf.as_mut_ptr() as *mut Acl;

            if InitializeAcl(acl_ptr, acl_size as u32, ACL_REVISION) == 0 {
                return Err(MiasmaError::KeyDerivation("InitializeAcl failed".into()));
            }

            // AddAccessAllowedAce appends the ACE into the ACL buffer.
            let sid_ptr = sid.as_ptr() as *mut u8;
            if AddAccessAllowedAce(acl_ptr, ACL_REVISION, FILE_ALL_ACCESS, sid_ptr) == 0 {
                return Err(MiasmaError::KeyDerivation(
                    "AddAccessAllowedAce failed".into(),
                ));
            }

            // Build security descriptor with only this DACL (no inherited ACEs).
            let mut sd = std::mem::zeroed::<SecurityDescriptor>();
            if InitializeSecurityDescriptor(&mut sd, SECURITY_DESCRIPTOR_REVISION) == 0 {
                return Err(MiasmaError::KeyDerivation(
                    "InitializeSecurityDescriptor failed".into(),
                ));
            }
            // bDaclPresent=TRUE, pDacl=our ACL, bDaclDefaulted=FALSE
            if SetSecurityDescriptorDacl(&mut sd, 1, acl_ptr, 0) == 0 {
                return Err(MiasmaError::KeyDerivation(
                    "SetSecurityDescriptorDacl failed".into(),
                ));
            }

            if set_owner && SetSecurityDescriptorOwner(&mut sd, sid_ptr, 0) == 0 {
                return Err(MiasmaError::KeyDerivation(
                    "SetSecurityDescriptorOwner failed".into(),
                ));
            }

            let mut sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: &mut sd,
                b_inherit_handle: 0,
            };

            let wide = to_wide(path);
            let handle = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0, // no sharing
                &mut sa,
                disposition,
                FILE_ATTRIBUTE_NORMAL,
                0,
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(MiasmaError::KeyDerivation(format!(
                    "CreateFileW failed for {}: OS error {}",
                    path.display(),
                    std::io::Error::last_os_error()
                )));
            }

            // Wrap in a std::fs::File so we get RAII close + Write trait.
            Ok(std::fs::File::from_raw_handle(
                handle as *mut std::ffi::c_void,
            ))
        }
    }

    pub(super) fn create_new_restricted_impl(path: &Path) -> Result<std::fs::File, MiasmaError> {
        open_restricted(path, CREATE_NEW, true)
    }

    /// Fetch the self-relative security descriptor of `path` for `info`.
    fn file_security(path: &Path, info: u32) -> Result<Vec<u8>, MiasmaError> {
        let wide = to_wide(path);
        let mut needed: u32 = 0;
        unsafe {
            GetFileSecurityW(wide.as_ptr(), info, ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                return Err(MiasmaError::KeyDerivation(format!(
                    "GetFileSecurityW size query failed for {}",
                    path.display()
                )));
            }
            let mut buf = vec![0u8; needed as usize];
            if GetFileSecurityW(wide.as_ptr(), info, buf.as_mut_ptr(), needed, &mut needed) == 0 {
                return Err(MiasmaError::KeyDerivation(format!(
                    "GetFileSecurityW failed for {}",
                    path.display()
                )));
            }
            Ok(buf)
        }
    }

    /// Fail unless the DACL holds exactly one allow ACE for the current user
    /// and the owner is the current user.
    pub(super) fn verify_owner_only_impl(path: &Path) -> Result<(), MiasmaError> {
        if !verify_restricted_impl(path)? {
            return Err(MiasmaError::Io(std::io::Error::other(format!(
                "{} is not restricted to the current user (unexpected access list)",
                path.display()
            ))));
        }
        let sid = current_user_sid()?;
        let sd = file_security(path, OWNER_SECURITY_INFORMATION)?;
        unsafe {
            let mut owner: *mut u8 = ptr::null_mut();
            let mut defaulted: i32 = 0;
            if GetSecurityDescriptorOwner(sd.as_ptr(), &mut owner, &mut defaulted) == 0 {
                return Err(MiasmaError::KeyDerivation(
                    "GetSecurityDescriptorOwner failed".into(),
                ));
            }
            if owner.is_null() || EqualSid(owner, sid.as_ptr() as *mut u8) == 0 {
                return Err(MiasmaError::Io(std::io::Error::other(format!(
                    "{} is not owned by the current user",
                    path.display()
                ))));
            }
        }
        Ok(())
    }

    /// The directory is not checked on Windows: the default data directory
    /// lives under the per-user profile, and the file's own access list is
    /// verified instead.
    pub(super) fn verify_private_dir_impl(_dir: &Path) -> Result<(), MiasmaError> {
        Ok(())
    }

    pub(super) fn verify_restricted_impl(path: &Path) -> Result<bool, MiasmaError> {
        let sid = current_user_sid()?;

        unsafe {
            let wide = to_wide(path);

            // Query required buffer size for security descriptor.
            let mut needed: u32 = 0;
            GetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                0,
                &mut needed,
            );
            if needed == 0 {
                return Err(MiasmaError::KeyDerivation(format!(
                    "GetFileSecurityW size query failed for {}",
                    path.display()
                )));
            }

            let mut sd_buf = vec![0u8; needed as usize];
            if GetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION,
                sd_buf.as_mut_ptr(),
                needed,
                &mut needed,
            ) == 0
            {
                return Err(MiasmaError::KeyDerivation(format!(
                    "GetFileSecurityW failed for {}",
                    path.display()
                )));
            }

            let mut dacl_present: i32 = 0;
            let mut dacl_ptr: *mut Acl = ptr::null_mut();
            let mut dacl_defaulted: i32 = 0;
            if GetSecurityDescriptorDacl(
                sd_buf.as_ptr(),
                &mut dacl_present,
                &mut dacl_ptr,
                &mut dacl_defaulted,
            ) == 0
            {
                return Err(MiasmaError::KeyDerivation(
                    "GetSecurityDescriptorDacl failed".into(),
                ));
            }

            if dacl_present == 0 || dacl_ptr.is_null() {
                // No DACL = everyone has access.
                return Ok(false);
            }

            let acl = &*dacl_ptr;

            // Check: exactly 1 ACE, it's ACCESS_ALLOWED, and the SID matches ours.
            if acl.ace_count != 1 {
                return Ok(false);
            }

            let mut ace_ptr: *mut AceHeader = ptr::null_mut();
            if GetAce(dacl_ptr, 0, &mut ace_ptr) == 0 {
                return Ok(false);
            }
            let ace = &*ace_ptr;
            if ace.ace_type != ACCESS_ALLOWED_ACE_TYPE {
                return Ok(false);
            }

            // The SID follows the 4-byte access mask after the ACE header.
            let ace_sid = (ace_ptr as *mut u8)
                .add(std::mem::size_of::<AceHeader>() + std::mem::size_of::<u32>());
            if EqualSid(ace_sid, sid.as_ptr() as *mut u8) == 0 {
                return Ok(false);
            }

            Ok(true)
        }
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    pub(super) fn write_restricted_impl(path: &Path, data: &[u8]) -> Result<(), MiasmaError> {
        // `OpenOptions::mode()` is only honoured by open(2) when O_CREAT
        // actually creates the file -- if `path` already exists (e.g. it was
        // first written without restriction, then rewritten with it once
        // credentials were added), `.truncate(true).mode(0o600)` truncates
        // and reuses the file's EXISTING permission bits, silently leaving a
        // previously-unrestricted file unrestricted. Removing it first (same
        // fix already applied on the Windows side, a few lines up in this
        // file) forces every restricted write through real O_CREAT, so mode
        // is always applied. See docs/adr/005 VULN-004/005 -- this is the
        // same "must be born restricted, not restricted after the fact" bug,
        // just missing on this platform's implementation.
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        file.flush()?;
        Ok(())
    }

    pub(super) fn verify_restricted_impl(path: &Path) -> Result<bool, MiasmaError> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mode = meta.permissions().mode() & 0o777;
        Ok(mode == 0o600)
    }

    pub(super) fn create_new_restricted_impl(path: &Path) -> Result<std::fs::File, MiasmaError> {
        // O_EXCL: fails on an existing path and never follows a symlink.
        Ok(std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?)
    }

    /// A file is owner-only when no group/other bit is set and the owner can
    /// read and write it.
    pub(super) fn file_mode_is_owner_only(mode: u32) -> bool {
        mode & 0o777 == 0o600
    }

    /// A directory is private enough to hold a secret file when it is not
    /// writable by other users.  The group bit is tolerated: many Linux
    /// setups create directories as 0775 with a per-user group.
    pub(super) fn dir_mode_is_private(mode: u32) -> bool {
        mode & 0o002 == 0
    }

    fn other(msg: String) -> MiasmaError {
        MiasmaError::Io(std::io::Error::other(msg))
    }

    pub(super) fn verify_owner_only_impl(path: &Path) -> Result<(), MiasmaError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // symlink_metadata: a link in place of the file is a failure.
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_file() {
            return Err(other(format!("{} is not a regular file", path.display())));
        }
        let mode = meta.permissions().mode();
        if !file_mode_is_owner_only(mode) {
            return Err(other(format!(
                "{} has mode {:o}, expected 600",
                path.display(),
                mode & 0o777
            )));
        }
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(other(format!(
                "{} is not owned by the current user",
                path.display()
            )));
        }
        Ok(())
    }

    pub(super) fn verify_private_dir_impl(dir: &Path) -> Result<(), MiasmaError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::metadata(dir)?;
        if !meta.is_dir() {
            return Err(other(format!("{} is not a directory", dir.display())));
        }
        let mode = meta.permissions().mode();
        if !dir_mode_is_private(mode) {
            return Err(other(format!(
                "{} has mode {:o}; other users may modify it",
                dir.display(),
                mode & 0o777
            )));
        }
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(other(format!(
                "{} is not owned by the current user",
                dir.display()
            )));
        }
        Ok(())
    }
}

// Fallback for non-Windows, non-Unix (e.g. WASM).
#[cfg(not(any(windows, unix)))]
mod platform {
    use super::*;

    pub(super) fn write_restricted_impl(path: &Path, data: &[u8]) -> Result<(), MiasmaError> {
        std::fs::write(path, data)?;
        Ok(())
    }

    pub(super) fn verify_restricted_impl(_path: &Path) -> Result<bool, MiasmaError> {
        Ok(false)
    }

    fn unsupported() -> MiasmaError {
        MiasmaError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported platform: owner-only files cannot be created or verified here",
        ))
    }

    pub(super) fn create_new_restricted_impl(_path: &Path) -> Result<std::fs::File, MiasmaError> {
        Err(unsupported())
    }

    pub(super) fn verify_owner_only_impl(_path: &Path) -> Result<(), MiasmaError> {
        Err(unsupported())
    }

    pub(super) fn verify_private_dir_impl(_dir: &Path) -> Result<(), MiasmaError> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_verify_restricted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        let data = b"supersecret";

        write_restricted(&path, data).unwrap();

        // File must exist with correct contents.
        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, data);

        // Verify permissions.
        let restricted = verify_restricted(&path).unwrap();
        assert!(restricted, "file should be restricted to current user");
    }

    #[test]
    fn atomic_write_restricted_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret2.key");

        // First write.
        atomic_write_restricted(&path, b"version1").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"version1");

        // Second write replaces content.
        atomic_write_restricted(&path, b"version2").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"version2");

        // Temp file must not linger.
        assert!(!path.with_extension("sec.tmp").exists());
    }

    #[test]
    fn atomic_write_writes_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.dat");

        // First write creates the file.
        atomic_write(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        // Second write replaces the contents in place.
        atomic_write(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        // No temp file is left behind, under the old fixed name or any other:
        // after a successful rename the directory holds only the final file.
        assert!(!crate::paths::atomic_tmp(&path).exists());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "plain.dat")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file left behind: {leftovers:?}"
        );
    }

    #[test]
    fn atomic_write_fails_and_cleans_up_when_the_final_path_is_a_directory() {
        // Force the rename step itself to fail: a directory already sits at the
        // final path, so renaming the temp file over it cannot succeed on
        // either Windows or Unix. The temp file must be cleaned up and the
        // existing entry at the final path left exactly as it was.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("occupied");

        // A directory stands where the file would land, holding one marker file
        // whose contents must survive the failed save untouched.
        std::fs::create_dir(&target).unwrap();
        let sentinel = target.join("keep.txt");
        std::fs::write(&sentinel, b"original").unwrap();

        let result = atomic_write(&target, b"should not land");
        assert!(result.is_err(), "the rename over a directory must fail");

        // The directory and its contents are unchanged.
        assert!(target.is_dir(), "the existing directory is still there");
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"original",
            "the existing contents were left untouched"
        );

        // No temp file is left behind in the parent directory: after the failed
        // rename only the `occupied` directory remains.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "occupied")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file left behind after the failed rename: {leftovers:?}"
        );
    }

    #[test]
    fn atomic_write_fails_without_corrupting_when_parent_is_a_file() {
        let dir = tempfile::tempdir().unwrap();

        // A good file written first.
        let good = dir.path().join("good.dat");
        atomic_write(&good, b"keep").unwrap();

        // A regular file that cannot act as a parent directory.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();

        // Writing under it fails; the good file is untouched.
        let doomed = blocker.join("child.dat");
        assert!(atomic_write(&doomed, b"nope").is_err());
        assert_eq!(std::fs::read(&good).unwrap(), b"keep");
        assert!(!doomed.exists());
    }

    #[test]
    fn atomic_write_new_creates_the_file_and_reads_back_the_same_bytes() {
        // A fresh path is created and holds exactly the bytes given. The bytes
        // are drawn at run time, never a fixed literal.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.dat");
        let payload: [u8; 32] = rand::random();
        assert!(atomic_write_new(&path, &payload).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), payload);
    }

    #[test]
    fn atomic_write_new_refuses_to_replace_an_existing_file() {
        // An existing file at the path is never overwritten: the call reports
        // `false` and the earlier bytes are left exactly as they were.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exists.dat");
        let existing: [u8; 16] = rand::random();
        std::fs::write(&path, existing).unwrap();
        // `rand::random::<[u8; N]>()` only implements N <= 32; build the 48
        // bytes one at a time so no zero-filled array stands in for the bytes.
        let other: Vec<u8> = (0..48).map(|_| rand::random::<u8>()).collect();
        assert!(!atomic_write_new(&path, &other).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), existing);
    }

    #[test]
    fn atomic_write_new_leaves_no_temp_file_behind() {
        // After a successful create the directory holds only the final file:
        // the temporary staging file is always removed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("only.dat");
        let payload: [u8; 24] = rand::random();
        atomic_write_new(&path, &payload).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "only.dat")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file left behind: {leftovers:?}"
        );
    }

    #[test]
    fn write_restricted_is_actually_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("readable.key");
        write_restricted(&path, b"hello").unwrap();

        // The current user must be able to read their own restricted file.
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"hello");
    }

    #[test]
    fn create_new_restricted_is_owner_only_from_creation() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.tok");

        let mut f = create_new_restricted(&path).unwrap();
        // Verified while still empty: the secret is never written first.
        verify_owner_only(&path).unwrap();
        f.write_all(b"payload").unwrap();
        drop(f);
        verify_owner_only(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    }

    #[test]
    fn create_new_restricted_refuses_an_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exists.tok");
        std::fs::write(&path, b"old").unwrap();
        assert!(create_new_restricted(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
    }

    #[test]
    fn verify_owner_only_rejects_a_file_with_default_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loose.tok");
        std::fs::write(&path, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // Windows: the file inherits the directory's list (several ACEs).
        assert!(verify_owner_only(&path).is_err());
    }

    #[test]
    fn verify_owner_only_rejects_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(verify_owner_only(&dir.path().join("absent.tok")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_mode_checks() {
        use super::platform::{dir_mode_is_private, file_mode_is_owner_only};
        assert!(file_mode_is_owner_only(0o100600));
        assert!(!file_mode_is_owner_only(0o100640));
        assert!(!file_mode_is_owner_only(0o100604));
        assert!(!file_mode_is_owner_only(0o100400));
        assert!(!file_mode_is_owner_only(0o100700));
        assert!(dir_mode_is_private(0o40700));
        assert!(dir_mode_is_private(0o40775));
        assert!(!dir_mode_is_private(0o40777));
        assert!(!dir_mode_is_private(0o40757));
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_dir_check_rejects_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        verify_private_dir(dir.path()).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(verify_private_dir(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_verify_rejects_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.tok");
        let link = dir.path().join("link.tok");
        create_new_restricted(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(verify_owner_only(&link).is_err());
    }

    /// Windows: the owner of a freshly created file is the current user, and
    /// the list has exactly one entry; a copy that inherits the directory's
    /// list is refused.
    #[cfg(windows)]
    #[test]
    fn windows_dacl_and_owner_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("win.tok");
        drop(create_new_restricted(&path).unwrap());
        verify_owner_only(&path).unwrap();
        assert!(verify_restricted(&path).unwrap());

        let inherited = dir.path().join("inherited.tok");
        std::fs::write(&inherited, b"x").unwrap();
        let err = verify_owner_only(&inherited).unwrap_err();
        assert!(err.to_string().contains("restricted"), "{err}");
    }

    #[test]
    fn overwrite_preserves_restriction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overwrite.key");

        write_restricted(&path, b"v1").unwrap();
        assert!(verify_restricted(&path).unwrap());

        // Overwrite.
        write_restricted(&path, b"v2").unwrap();
        assert!(verify_restricted(&path).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"v2");
    }
}
