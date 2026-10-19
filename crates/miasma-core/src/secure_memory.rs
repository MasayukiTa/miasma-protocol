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

enum SecretBacking<const N: usize> {
    #[cfg(any(unix, windows))]
    Mapped {
        ptr: NonNull<u8>,
        lock_requested: bool,
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
// the only mutation (zeroize in `Drop`) needs `&mut self`.
unsafe impl<const N: usize> Send for SecureBytes<N> {}
// SAFETY: see the `Send` justification; `&SecureBytes` only permits reads.
unsafe impl<const N: usize> Sync for SecureBytes<N> {}

impl<const N: usize> SecureBytes<N> {
    /// Move `value` into protected storage. The by-value argument is zeroized
    /// when a dedicated mapping is used. Copies the caller still holds (for
    /// example the argument's original location) are the caller's to clear.
    #[cfg_attr(not(any(unix, windows)), allow(unused_mut))]
    pub fn new(mut value: [u8; N]) -> Self {
        #[cfg(any(unix, windows))]
        if N != 0 {
            if let Some((ptr, lock_requested)) = allocate_mapping(&value) {
                value.zeroize();
                return Self {
                    backing: SecretBacking::Mapped {
                        ptr,
                        lock_requested,
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
            backing: SecretBacking::Heap(Box::new(Zeroizing::new(value))),
            status,
        }
    }

    pub fn from_slice(value: &[u8; N]) -> Self {
        Self::new(*value)
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
        Self::new(*root)
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
/// page lock. Returns `None` if the mapping itself cannot be created.
#[cfg(unix)]
fn allocate_mapping<const N: usize>(value: &[u8; N]) -> Option<(NonNull<u8>, bool)> {
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
        std::ptr::copy_nonoverlapping(value.as_ptr(), ptr.as_ptr(), N);
        let lock_requested = libc::mlock(raw, N) == 0;
        Some((ptr, lock_requested))
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
#[cfg(windows)]
fn allocate_mapping<const N: usize>(value: &[u8; N]) -> Option<(NonNull<u8>, bool)> {
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
        Some((ptr, lock_requested))
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
}
