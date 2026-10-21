//! The Windows data-protection wrap: the root key is wrapped by the operating
//! system for the signed-in user (DPAPI), so a copy of the data directory is of
//! no use on another account or another PC.
//!
//! The record's `aad` is bound in as the DPAPI "optional entropy"
//! (`SHA-256("miasma/root/v1" || aad)`), so a blob cannot be moved to another
//! file or install. The scope is the current user; the machine scope is never
//! used because any process on the PC could then open the blob. No prompt is
//! ever shown.
//!
//! What this protects: a stolen or copied data directory. What it does not
//! protect: other programs running as the same user. A blob that is still on
//! disk can be opened by the same user, so this is not an erasure on its own.

use std::path::Path;

use chacha20poly1305::aead::{AeadCore, KeyInit, OsRng};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INVALID_DATA, HANDLE,
};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalServiceSid, WinLocalSystemSid,
    WinNetworkServiceSid, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use zeroize::Zeroizing;

use super::provider::{Availability, DestroyOutcome, DeviceWrap, ProviderId, WrapError};
use crate::secure_memory::SecureBytes;

/// `NTE_BAD_DATA`: the other way DPAPI reports a blob that does not open.
const NTE_BAD_DATA: u32 = 0x8009_0005;

pub struct DpapiWrap;

impl std::fmt::Debug for DpapiWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DpapiWrap")
    }
}

/// `false` only when the process runs as LocalSystem, LocalService or
/// NetworkService. A key sealed by such a service would be unreadable to the
/// user's own programs. Any query that fails counts as a user.
pub fn in_user_session() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle of this process is always valid; `token` is
    // closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return true;
    }
    let mut len = 0u32;
    // SAFETY: a size query with no buffer.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    let mut service = false;
    if len > 0 {
        // Eight-byte units keep the buffer aligned for `TOKEN_USER`.
        let mut buf: Vec<u64> = vec![0; (len as usize).div_ceil(8)];
        // SAFETY: the buffer holds at least `len` bytes; on success it starts
        // with a `TOKEN_USER` whose SID lives inside the same buffer.
        unsafe {
            if GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) != 0 {
                let sid = (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid;
                service = [WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid]
                    .iter()
                    .any(|kind| IsWellKnownSid(sid, *kind) != 0);
            }
        }
    }
    // SAFETY: `token` was opened above.
    unsafe { CloseHandle(token) };
    !service
}

fn entropy_of(aad: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"miasma/root/v1")
        .chain_update(aad)
        .finalize()
        .into()
}

fn blob_of(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

fn map_error(code: u32) -> WrapError {
    if code == ERROR_INVALID_DATA || code == NTE_BAD_DATA {
        WrapError::Corrupt
    } else {
        // Only the number is reported; it carries no key material.
        WrapError::Unavailable(format!(
            "Windows data protection failed (error 0x{code:08x})"
        ))
    }
}

fn protect(plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, WrapError> {
    let entropy = entropy_of(aad);
    let input = blob_of(plain);
    let ent = blob_of(&entropy);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: both input blobs point at live slices for the whole call; `out`
    // is filled by the system and released below with `LocalFree`.
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &ent,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(map_error(unsafe { GetLastError() }));
    }
    // SAFETY: on success `pbData` points at `cbData` bytes owned by the system.
    let wrapped = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe { LocalFree(out.pbData as _) };
    Ok(wrapped)
}

fn unprotect(wrapped: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, WrapError> {
    let entropy = entropy_of(aad);
    let input = blob_of(wrapped);
    let ent = blob_of(&entropy);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: as in `protect`; the description out-pointer is not requested.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &ent,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(map_error(unsafe { GetLastError() }));
    }
    // SAFETY: on success `pbData` points at `cbData` bytes owned by the system.
    // They are copied into a buffer that is zeroed on drop, then the system's
    // copy is zeroed before it is freed.
    let plain = unsafe {
        let len = out.cbData as usize;
        let copy = Zeroizing::new(std::slice::from_raw_parts(out.pbData, len).to_vec());
        std::ptr::write_bytes(out.pbData, 0, len);
        LocalFree(out.pbData as _);
        copy
    };
    Ok(plain)
}

impl DpapiWrap {
    /// Wrap and unwrap a throw-away random value. `Ok` means DPAPI works for
    /// this user right now.
    pub fn self_test() -> Result<(), WrapError> {
        let probe: [u8; 32] = XChaCha20Poly1305::generate_key(&mut OsRng).into();
        let aad = XChaCha20Poly1305::generate_nonce(&mut OsRng).to_vec();
        let wrapped = protect(&probe, &aad)?;
        let back = unprotect(&wrapped, &aad)?;
        if back.as_slice() == probe.as_slice() {
            Ok(())
        } else {
            Err(WrapError::Corrupt)
        }
    }
}

impl DeviceWrap for DpapiWrap {
    fn id(&self) -> ProviderId {
        ProviderId::Dpapi
    }

    fn available(&self) -> Availability {
        if in_user_session() {
            Availability::Ready
        } else {
            Availability::Unavailable("service_account")
        }
    }

    fn wrap(&self, _data_dir: &Path, aad: &[u8], root: &[u8; 32]) -> Result<Vec<u8>, WrapError> {
        protect(root, aad)
    }

    fn unwrap(
        &self,
        _data_dir: &Path,
        aad: &[u8],
        wrapped: &[u8],
    ) -> Result<SecureBytes<32>, WrapError> {
        let plain = unprotect(wrapped, aad)?;
        let key: &[u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| WrapError::Corrupt)?;
        Ok(SecureBytes::from_slice(key))
    }

    /// DPAPI keeps nothing outside the blob in `root.sealed`, which the
    /// registry wipe removes. A wipe never needs DPAPI to work.
    fn destroy(&self, _data_dir: &Path) -> Result<DestroyOutcome, WrapError> {
        Ok(DestroyOutcome::NothingToDestroy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_key::{get_with, CreatePolicy, RootKeyError, SealedProvider};
    use std::sync::Arc;

    fn random_key() -> [u8; 32] {
        XChaCha20Poly1305::generate_key(&mut OsRng).into()
    }

    fn random_aad() -> Vec<u8> {
        XChaCha20Poly1305::generate_nonce(&mut OsRng).to_vec()
    }

    #[test]
    fn a_wrapped_key_opens_to_the_same_key() {
        let (key, aad) = (random_key(), random_aad());
        let blob = DpapiWrap.wrap(Path::new("."), &aad, &key).unwrap();
        let back = DpapiWrap.unwrap(Path::new("."), &aad, &blob).unwrap();
        assert_eq!(back.as_array(), &key);
    }

    #[test]
    fn the_blob_does_not_contain_the_key() {
        let (key, aad) = (random_key(), random_aad());
        let blob = DpapiWrap.wrap(Path::new("."), &aad, &key).unwrap();
        assert!(!blob.windows(32).any(|w| w == key.as_slice()));
    }

    #[test]
    fn another_aad_is_refused() {
        let (key, aad) = (random_key(), random_aad());
        let blob = DpapiWrap.wrap(Path::new("."), &aad, &key).unwrap();
        let mut other = aad.clone();
        other[0] ^= 1;
        assert!(matches!(
            DpapiWrap.unwrap(Path::new("."), &other, &blob),
            Err(WrapError::Corrupt)
        ));
    }

    #[test]
    fn a_changed_blob_is_refused() {
        let (key, aad) = (random_key(), random_aad());
        let blob = DpapiWrap.wrap(Path::new("."), &aad, &key).unwrap();
        for at in [0, blob.len() / 2, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[at] ^= 0x01;
            assert!(
                DpapiWrap.unwrap(Path::new("."), &aad, &bad).is_err(),
                "a change at byte {at} was accepted"
            );
        }
        assert!(DpapiWrap.unwrap(Path::new("."), &aad, &[]).is_err());
    }

    #[test]
    fn debug_output_names_no_key() {
        assert_eq!(format!("{DpapiWrap:?}"), "DpapiWrap");
    }

    #[test]
    fn an_ordinary_user_is_not_taken_for_a_service() {
        assert!(in_user_session());
        assert!(matches!(DpapiWrap.available(), Availability::Ready));
    }

    #[test]
    fn the_self_test_passes_for_this_user() {
        DpapiWrap::self_test().unwrap();
    }

    fn sealing() -> SealedProvider {
        SealedProvider::new(Arc::new(DpapiWrap))
    }

    #[test]
    fn a_plain_key_is_sealed_automatically_and_stays_the_same() {
        let d = tempfile::tempdir().unwrap();
        let key = random_key();
        std::fs::write(crate::paths::master_key(d.path()), key).unwrap();

        // The first open still answers with the old key and seals it.
        let first = get_with(d.path(), CreatePolicy::Never, &sealing()).unwrap();
        assert_eq!(first.with(|k| *k).unwrap(), key);

        let master = std::fs::read(crate::paths::master_key(d.path())).unwrap();
        assert_eq!(master.len(), super::super::stub::STUB_LEN);
        assert!(crate::paths::ROOT_SEALED.in_dir(d.path()).exists());
        let blob = std::fs::read(crate::paths::ROOT_SEALED.in_dir(d.path())).unwrap();
        assert!(!blob.windows(32).any(|w| w == key.as_slice()));

        let again = get_with(d.path(), CreatePolicy::Never, &sealing()).unwrap();
        assert_eq!(again.with(|k| *k).unwrap(), key);
    }

    #[test]
    fn a_new_key_is_created_sealed() {
        let d = tempfile::tempdir().unwrap();
        let a = get_with(d.path(), CreatePolicy::FirstUse, &sealing()).unwrap();
        assert_eq!(
            std::fs::metadata(crate::paths::master_key(d.path()))
                .unwrap()
                .len(),
            super::super::stub::STUB_LEN as u64
        );
        let b = get_with(d.path(), CreatePolicy::Never, &sealing()).unwrap();
        assert_eq!(a.with(|k| *k).unwrap(), b.with(|k| *k).unwrap());
    }

    #[test]
    fn a_program_without_the_wrap_stops_instead_of_starting_a_new_key() {
        let d = tempfile::tempdir().unwrap();
        get_with(d.path(), CreatePolicy::FirstUse, &sealing()).unwrap();
        let before = std::fs::read(crate::paths::master_key(d.path())).unwrap();
        for policy in [
            CreatePolicy::Never,
            CreatePolicy::IfFreshDataDir,
            CreatePolicy::FirstUse,
        ] {
            let r = get_with(d.path(), policy, &crate::root_key::FileProvider);
            assert!(matches!(r, Err(RootKeyError::SealedUnavailable)));
        }
        assert_eq!(
            std::fs::read(crate::paths::master_key(d.path())).unwrap(),
            before
        );
    }

    /// DPAPI answering "unavailable" must never turn into a fresh key or a
    /// changed file.
    struct Broken;
    impl DeviceWrap for Broken {
        fn id(&self) -> ProviderId {
            ProviderId::Dpapi
        }
        fn available(&self) -> Availability {
            Availability::Ready
        }
        fn wrap(&self, _: &Path, _: &[u8], _: &[u8; 32]) -> Result<Vec<u8>, WrapError> {
            Err(WrapError::Unavailable("down".into()))
        }
        fn unwrap(&self, _: &Path, _: &[u8], _: &[u8]) -> Result<SecureBytes<32>, WrapError> {
            Err(WrapError::Unavailable("down".into()))
        }
        fn destroy(&self, _: &Path) -> Result<DestroyOutcome, WrapError> {
            Ok(DestroyOutcome::NothingToDestroy)
        }
    }

    #[test]
    fn a_failing_dpapi_fails_closed_and_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        get_with(d.path(), CreatePolicy::FirstUse, &sealing()).unwrap();
        let master = std::fs::read(crate::paths::master_key(d.path())).unwrap();
        let sealed = std::fs::read(crate::paths::ROOT_SEALED.in_dir(d.path())).unwrap();
        let broken = SealedProvider::new(Arc::new(Broken));
        for policy in [CreatePolicy::Never, CreatePolicy::FirstUse] {
            let r = get_with(d.path(), policy, &broken);
            assert!(matches!(r, Err(RootKeyError::KeyStoreUnavailable(_))));
        }
        assert_eq!(
            std::fs::read(crate::paths::master_key(d.path())).unwrap(),
            master
        );
        assert_eq!(
            std::fs::read(crate::paths::ROOT_SEALED.in_dir(d.path())).unwrap(),
            sealed
        );
    }

    #[test]
    fn a_failing_dpapi_leaves_a_plain_key_in_use() {
        let d = tempfile::tempdir().unwrap();
        let key = random_key();
        std::fs::write(crate::paths::master_key(d.path()), key).unwrap();
        let broken = SealedProvider::new(Arc::new(Broken));
        let root = get_with(d.path(), CreatePolicy::Never, &broken).unwrap();
        assert_eq!(root.with(|k| *k).unwrap(), key);
        assert_eq!(
            std::fs::read(crate::paths::master_key(d.path())).unwrap(),
            key
        );
        assert!(!crate::paths::ROOT_SEALED.in_dir(d.path()).exists());
    }

    #[test]
    fn a_wipe_needs_no_provider() {
        let d = tempfile::tempdir().unwrap();
        get_with(d.path(), CreatePolicy::FirstUse, &sealing()).unwrap();
        let report = crate::root_key::wipe_data_dir(d.path());
        assert!(report.is_complete(), "{:?}", report.errors);
        assert!(!crate::paths::master_key(d.path()).exists());
        assert!(!crate::paths::ROOT_SEALED.in_dir(d.path()).exists());
    }
}
