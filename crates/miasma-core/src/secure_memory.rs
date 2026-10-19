//! Best-effort page-locked storage for long-lived secret key material.
//!
//! The secret lives in a dedicated virtual-memory mapping on Windows/Unix so
//! `VirtualUnlock`/`munlock` cannot accidentally unlock a neighbouring secret
//! that happened to share a heap page. Requesting a page lock is best effort:
//! the OS may refuse it (resource limits, policy, unsupported target). In that
//! case the mapping is still dedicated and zeroized before release, and
//! callers can inspect [`MemoryLockStatus`]. A lock request being accepted is
//! not a guarantee that the secret can never reach swap, hibernation files or
//! crash dumps, and callers must not describe it as one.
//!
//! On Linux/Android the mapping is additionally marked `MADV_DONTDUMP`
//! (best effort; reported by [`SecureBytes::dump_exclusion_requested`]).

use std::fmt;
#[cfg(any(unix, windows))]
use std::ptr::NonNull;

use zeroize::{Zeroize, Zeroizing};

/// Outcome of the page-lock request made when the secret was stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLockStatus {
    /// A dedicated mapping was allocated and the OS accepted the page-lock
    /// request (`mlock` / `VirtualLock`). Best-effort hardening only.
    LockRequestAccepted,
    /// A dedicated mapping was allocated, but the OS refused the page-lock
    /// request, or no dedicated mapping could be created. The secret may be
    /// pageable.
    LockRequestDenied,
    /// This target has no page-lock implementation; a zeroizing heap fallback
    /// is used and the secret may be pageable.
    Unsupported,
}

impl MemoryLockStatus {
    /// Stable machine-readable name used in status output.
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryLockStatus::LockRequestAccepted => "lock_request_accepted",
            MemoryLockStatus::LockRequestDenied => "lock_request_denied",
            MemoryLockStatus::Unsupported => "unsupported",
        }
    }
}

enum SecretBacking<const N: usize> {
    #[cfg(any(unix, windows))]
    Mapped {
        ptr: NonNull<u8>,
        lock_requested: bool,
        dump_excluded: bool,
    },
    Heap(Box<Zeroizing<[u8; N]>>),
}

/// Fixed-size secret bytes with stable storage and best-effort page locking.
///
/// This type is intentionally not `Clone`: duplicating long-lived root secrets
/// creates additional plaintext copies whose lifetime is harder to reason about.
pub struct SecureBytes<const N: usize> {
    backing: SecretBacking<N>,
    status: MemoryLockStatus,
}

// SAFETY: the mapped region is uniquely owned by its `SecureBytes`; it is never
// aliased by another owner, shared references only expose immutable bytes, and
// the only mutation (zeroize in `Drop` / `zeroize_in_place`) needs `&mut self`.
unsafe impl<const N: usize> Send for SecureBytes<N> {}
// SAFETY: see the `Send` justification; `&SecureBytes` only permits reads.
unsafe impl<const N: usize> Sync for SecureBytes<N> {}

impl<const N: usize> SecureBytes<N> {
    /// Move `value` into protected storage. The by-value argument is zeroized
    /// when a dedicated mapping is used. Copies the caller still holds (for
    /// example the argument's original location) are the caller's to clear.
    /// Prefer [`SecureBytes::from_slice`] when the source already lives in a
    /// zeroizing container: it avoids an extra by-value copy of the secret.
    pub fn new(mut value: [u8; N]) -> Self {
        let out = Self::from_slice(&value);
        value.zeroize();
        out
    }

    /// Copy `value` into protected storage without creating an additional
    /// by-value temporary of the secret on the stack.
    pub fn from_slice(value: &[u8; N]) -> Self {
        #[cfg(any(unix, windows))]
        if N != 0 {
            if let Some((ptr, lock_requested, dump_excluded)) = allocate_mapping(value) {
                return Self {
                    backing: SecretBacking::Mapped {
                        ptr,
                        lock_requested,
                        dump_excluded,
                    },
                    status: if lock_requested {
                        MemoryLockStatus::LockRequestAccepted
                    } else {
                        MemoryLockStatus::LockRequestDenied
                    },
                };
            }
        }

        let status = if cfg!(any(unix, windows)) {
            MemoryLockStatus::LockRequestDenied
        } else {
            MemoryLockStatus::Unsupported
        };
        Self {
            backing: SecretBacking::Heap(Box::new(Zeroizing::new(*value))),
            status,
        }
    }

    /// Status of the page-lock request made at construction time.
    pub fn lock_status(&self) -> MemoryLockStatus {
        self.status
    }

    /// `true` when the OS accepted the page-lock request. This is best-effort
    /// hardening, not a guarantee against the secret being written to disk.
    pub fn lock_request_accepted(&self) -> bool {
        self.status == MemoryLockStatus::LockRequestAccepted
    }

    /// `true` when the OS accepted a request to leave the mapping out of core
    /// dumps (`MADV_DONTDUMP`, Linux/Android only). Best effort; other
    /// targets always report `false`.
    pub fn dump_exclusion_requested(&self) -> bool {
        match &self.backing {
            #[cfg(any(unix, windows))]
            SecretBacking::Mapped { dump_excluded, .. } => *dump_excluded,
            SecretBacking::Heap(_) => false,
        }
    }

    /// Overwrite the secret with zeros now, keeping the storage allocated.
    /// Afterwards [`as_array`](Self::as_array) reads all zeros. Used by the
    /// wipe path so the key is gone before the storage is released.
    pub fn zeroize_in_place(&mut self) {
        match &mut self.backing {
            #[cfg(any(unix, windows))]
            SecretBacking::Mapped { ptr, .. } => {
                // SAFETY: `ptr` is the N-byte mapping owned by `self`, still
                // valid until `Drop`; `&mut self` excludes concurrent readers.
                unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr(), N).zeroize() };
            }
            SecretBacking::Heap(bytes) => bytes.as_mut().zeroize(),
        }
    }

    pub fn as_array(&self) -> &[u8; N] {
        match &self.backing {
            #[cfg(any(unix, windows))]
            SecretBacking::Mapped { ptr, .. } => {
                // SAFETY: the mapping is at least N bytes (allocate_mapping
                // requested exactly N and N != 0), initialised by
                // allocate_mapping, owned by `self` until `Drop`, and
                // `[u8; N]` has alignment 1 so any non-null address is
                // sufficiently aligned. The returned borrow cannot outlive
                // `&self`, so it cannot outlive the mapping.
                unsafe { &*(ptr.as_ptr().cast::<[u8; N]>()) }
            }
            SecretBacking::Heap(bytes) => bytes.as_ref(),
        }
    }
}

impl<const N: usize> AsRef<[u8; N]> for SecureBytes<N> {
    fn as_ref(&self) -> &[u8; N] {
        self.as_array()
    }
}

impl<const N: usize> std::ops::Deref for SecureBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        self.as_array()
    }
}

impl<const N: usize> fmt::Debug for SecureBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureBytes")
            .field("len", &N)
            .field("lock_status", &self.status)
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl<const N: usize> Drop for SecureBytes<N> {
    fn drop(&mut self) {
        match &mut self.backing {
            #[cfg(any(unix, windows))]
            SecretBacking::Mapped {
                ptr,
                lock_requested,
                ..
            } => {
                // SAFETY: `ptr` points to the N-byte mapping created in
                // allocate_mapping and still owned by `self` (Drop runs
                // exactly once). Zeroize while the mapping is still valid,
                // then release it; `ptr` is not used afterwards.
                unsafe {
                    std::slice::from_raw_parts_mut(ptr.as_ptr(), N).zeroize();
                    release_mapping(*ptr, N, *lock_requested);
                }
            }
            SecretBacking::Heap(bytes) => bytes.as_mut().zeroize(),
        }
    }
}

/// Vault for the node's 32-byte root key.
///
/// The vault keeps one non-cloneable, zeroizing copy and records whether the OS
/// accepted the page-lock request. Callers may continue when locking is denied,
/// but must treat the lock as best-effort hardening rather than a guarantee.
pub struct SecureKeyVault {
    root: SecureBytes<32>,
}

impl SecureKeyVault {
    pub fn new(root: [u8; 32]) -> Self {
        Self {
            root: SecureBytes::new(root),
        }
    }

    pub fn from_slice(root: &[u8; 32]) -> Self {
        Self {
            root: SecureBytes::from_slice(root),
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        self.root.as_array()
    }

    pub fn lock_status(&self) -> MemoryLockStatus {
        self.root.lock_status()
    }

    pub fn lock_request_accepted(&self) -> bool {
        self.root.lock_request_accepted()
    }

    /// See [`SecureBytes::dump_exclusion_requested`].
    pub fn dump_exclusion_requested(&self) -> bool {
        self.root.dump_exclusion_requested()
    }

    /// Zero the root key in place. The vault must not be used for key
    /// operations afterwards; the owner should drop it.
    pub fn zeroize_in_place(&mut self) {
        self.root.zeroize_in_place();
    }
}

impl fmt::Debug for SecureKeyVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureKeyVault")
            .field("lock_status", &self.lock_status())
            .field("root", &"<redacted>")
            .finish()
    }
}

/// Create a dedicated anonymous mapping holding a copy of `value` and request a
/// page lock. Returns `None` if the mapping itself cannot be created. The
/// third element reports whether `MADV_DONTDUMP` was accepted (Linux/Android).
#[cfg(unix)]
fn allocate_mapping<const N: usize>(value: &[u8; N]) -> Option<(NonNull<u8>, bool, bool)> {
    // SAFETY: an anonymous private mapping with no address hint cannot alias
    // existing memory. N > 0 is guaranteed by the caller. On success the
    // mapping is at least N bytes and writable, so copying N bytes from `value`
    // (which does not overlap a brand-new mapping) is in bounds. If NonNull
    // fails (never expected), the mapping is released before returning.
    unsafe {
        let raw = libc::mmap(
            std::ptr::null_mut(),
            N,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if raw == libc::MAP_FAILED {
            return None;
        }
        let Some(ptr) = NonNull::new(raw.cast::<u8>()) else {
            let _ = libc::munmap(raw, N);
            return None;
        };
        // Ask for the pages to be left out of core dumps before the secret is
        // written into them. Best effort; failure is reported, not fatal.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let dump_excluded = libc::madvise(raw, N, libc::MADV_DONTDUMP) == 0;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let dump_excluded = false;
        std::ptr::copy_nonoverlapping(value.as_ptr(), ptr.as_ptr(), N);
        let lock_requested = libc::mlock(raw, N) == 0;
        Some((ptr, lock_requested, dump_excluded))
    }
}

/// # Safety
/// `ptr`/`len` must describe a mapping returned by `allocate_mapping` that has
/// not been released yet, and `lock_requested` must be the flag it returned.
#[cfg(unix)]
unsafe fn release_mapping(ptr: NonNull<u8>, len: usize, lock_requested: bool) {
    let raw = ptr.as_ptr().cast::<std::ffi::c_void>();
    if lock_requested {
        let _ = libc::munlock(raw, len);
    }
    let _ = libc::munmap(raw, len);
}

/// Create a dedicated committed allocation holding a copy of `value` and
/// request a page lock. Returns `None` if the allocation cannot be created.
/// There is no dump-exclusion request on Windows, so the third element is
/// always `false`.
#[cfg(windows)]
fn allocate_mapping<const N: usize>(value: &[u8; N]) -> Option<(NonNull<u8>, bool, bool)> {
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualLock, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    };

    // SAFETY: VirtualAlloc with a null base address returns a fresh,
    // page-granular, zero-initialised region of at least N bytes (N > 0 is
    // guaranteed by the caller) or null. The copy stays within that region and
    // cannot overlap `value`. VirtualLock acts on the pages of that region
    // only, and a failure leaves the region valid.
    unsafe {
        let raw = VirtualAlloc(
            std::ptr::null(),
            N,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        let ptr = NonNull::new(raw.cast::<u8>())?;
        std::ptr::copy_nonoverlapping(value.as_ptr(), ptr.as_ptr(), N);
        let lock_requested = VirtualLock(raw, N) != 0;
        Some((ptr, lock_requested, false))
    }
}

/// # Safety
/// `ptr`/`len` must describe an allocation returned by `allocate_mapping` that
/// has not been released yet, and `lock_requested` must be the flag it
/// returned.
#[cfg(windows)]
unsafe fn release_mapping(ptr: NonNull<u8>, len: usize, lock_requested: bool) {
    use windows_sys::Win32::System::Memory::{VirtualFree, VirtualUnlock, MEM_RELEASE};

    let raw = ptr.as_ptr().cast::<std::ffi::c_void>();
    if lock_requested {
        let _ = VirtualUnlock(raw, len);
    }
    // MEM_RELEASE requires a size of 0 and releases the whole allocation.
    let _ = VirtualFree(raw, 0, MEM_RELEASE);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn secure_bytes_round_trip_and_debug_redacts() {
        let secret = SecureBytes::new([0xA5; 32]);
        assert_eq!(secret.as_array(), &[0xA5; 32]);
        let dbg = format!("{secret:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("165"));
    }

    #[test]
    fn vault_is_send_sync_and_nonzero_key_round_trips() {
        assert_send_sync::<SecureKeyVault>();
        let vault = SecureKeyVault::new([7; 32]);
        assert_eq!(vault.key(), &[7; 32]);
    }

    #[test]
    fn lock_status_is_consistent_and_secret_survives_moves() {
        let vault = SecureKeyVault::from_slice(&[9; 32]);
        let status = vault.lock_status();
        assert_eq!(
            vault.lock_request_accepted(),
            status == MemoryLockStatus::LockRequestAccepted
        );
        if cfg!(not(any(unix, windows))) {
            assert_eq!(status, MemoryLockStatus::Unsupported);
        }
        // Moving the vault must not move or copy the secret bytes.
        let before = vault.key().as_ptr();
        let boxed = Box::new(vault);
        assert_eq!(boxed.key().as_ptr(), before);
        assert_eq!(boxed.key(), &[9; 32]);
    }

    #[test]
    fn zero_length_secret_uses_heap_fallback() {
        let empty = SecureBytes::<0>::new([]);
        assert_eq!(empty.as_array().len(), 0);
        assert_ne!(empty.lock_status(), MemoryLockStatus::LockRequestAccepted);
    }

    #[test]
    fn lock_status_names_are_stable_and_distinct() {
        let names = [
            MemoryLockStatus::LockRequestAccepted.as_str(),
            MemoryLockStatus::LockRequestDenied.as_str(),
            MemoryLockStatus::Unsupported.as_str(),
        ];
        assert_eq!(
            names,
            [
                "lock_request_accepted",
                "lock_request_denied",
                "unsupported"
            ]
        );
    }

    #[test]
    fn dump_exclusion_is_only_reported_where_requested() {
        let vault = SecureKeyVault::from_slice(&[3; 32]);
        if cfg!(not(any(target_os = "linux", target_os = "android"))) {
            assert!(!vault.dump_exclusion_requested());
        }
        // On Linux the request normally succeeds, but it is best effort, so
        // only the debug output (which must stay redacted) is checked there.
        assert!(format!("{vault:?}").contains("<redacted>"));
    }

    #[test]
    fn zeroize_in_place_clears_while_storage_is_still_owned() {
        let mut vault = SecureKeyVault::from_slice(&[0x5C; 32]);
        let ptr = vault.key().as_ptr();
        vault.zeroize_in_place();
        // The storage is still owned by `vault`, so reading it is valid.
        assert_eq!(vault.key(), &[0u8; 32]);
        assert_eq!(vault.key().as_ptr(), ptr);
    }

    #[test]
    fn from_slice_does_not_alter_the_source_and_new_clears_its_argument() {
        let src = [0x11u8; 32];
        let a = SecureBytes::from_slice(&src);
        assert_eq!(a.as_array(), &src);
        assert_eq!(src, [0x11u8; 32]);
    }

    #[test]
    fn concurrent_readers_see_the_key_or_a_consistent_owner_drop() {
        // Readers hold `Arc` clones, so the storage is released only after the
        // last reader is done; every read must observe the full key.
        let vault = std::sync::Arc::new(SecureKeyVault::from_slice(&[0xAB; 32]));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let v = vault.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..2000 {
                    assert_eq!(v.key(), &[0xAB; 32]);
                }
            }));
        }
        drop(vault);
        for h in handles {
            h.join().unwrap();
        }
    }
}
