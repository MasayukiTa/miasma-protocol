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
    let tmp = path.with_extension("sec.tmp");
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

/// Verify that `path` is restricted to the current user (best-effort).
///
/// Returns `Ok(true)` if the file is restricted, `Ok(false)` if it is not
/// or if verification is not supported on this platform.  Returns `Err`
/// only on unexpected system errors.
pub fn verify_restricted(path: &Path) -> Result<bool, MiasmaError> {
    platform::verify_restricted_impl(path)
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
    const CREATE_ALWAYS: u32 = 2;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const INVALID_HANDLE_VALUE: isize = -1;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_INFO_CLASS: u32 = 1; // TokenUser

    // ACL / SECURITY_DESCRIPTOR constants
    const ACL_REVISION: u32 = 2;
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
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
                CREATE_ALWAYS,
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
            let mut file = std::fs::File::from_raw_handle(handle as *mut std::ffi::c_void);
            if let Err(e) = file.write_all(data) {
                // File is closed by drop.
                let _ = std::fs::remove_file(path);
                return Err(MiasmaError::Io(e));
            }
            if let Err(e) = file.flush() {
                let _ = std::fs::remove_file(path);
                return Err(MiasmaError::Io(e));
            }
            // file dropped here → handle closed
        }
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
    fn write_restricted_is_actually_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("readable.key");
        write_restricted(&path, b"hello").unwrap();

        // The current user must be able to read their own restricted file.
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"hello");
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
