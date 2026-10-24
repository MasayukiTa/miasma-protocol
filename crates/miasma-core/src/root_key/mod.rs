//! The one place that reads, creates and erases the node's 32-byte root key.
//!
//! Identity, the shared-storage key, the protected-state key and the directed
//! sharing key are all derived from it. Every caller gets it through [`get`];
//! no other code opens `master.key`. Which files hold the key, how a `master.key`
//! that is not a plain key is recognised, and which files a wipe removes are
//! decided here and in [`paths`](crate::paths).
//!
//! By default the key is a plain 32-byte `master.key` ([`FileProvider`]). A
//! program that installs a [`SealedProvider`] keeps it instead in `root.sealed`
//! ([`format`]), wrapped by a [`DeviceWrap`], with a 64-byte marker in
//! `master.key` ([`stub`]) so that older programs stop instead of starting a new
//! key; an existing plain key is moved over automatically at start-up
//! ([`sealed`]). A key this build cannot open is reported
//! ([`RootKeyError::SealedUnavailable`] and its neighbours) and nothing is
//! created or changed.

mod durable;
mod filewrap;
pub mod format;
mod provider;
pub mod recovery;
pub mod sealed;
pub mod stub;
pub mod wipe;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};

pub use filewrap::FileWrap;
pub use provider::{
    Availability, DestroyOutcome, DeviceWrap, FileProvider, ProtectionLevel, ProviderId,
    RootKeyProvider, WrapError,
};
pub use sealed::SealedProvider;
pub use wipe::{wipe_data_dir, WipeReport};

use crate::secure_memory::SecureBytes;

/// Why the root key could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum RootKeyError {
    /// No key exists and the caller did not allow creating one.
    #[error("the master key is missing")]
    Missing,
    #[error("master.key has wrong length")]
    WrongLength,
    #[error("master.key is erased/all-zero; refusing known key material")]
    Erased,
    /// `master.key` has the marker length but is not a valid marker.
    #[error("master.key is damaged")]
    DamagedMarker,
    /// The key is sealed elsewhere and this build has no way to open it.
    /// Nothing was created or changed.
    #[error("sealed key unavailable: the master key is stored in a form this program cannot open")]
    SealedUnavailable,
    /// The marker is there but `root.sealed` is not.
    #[error("sealed key unavailable: root.sealed is missing")]
    SealedFileMissing,
    /// `root.sealed` does not authenticate or does not parse.
    #[error("sealed key unavailable: root.sealed is damaged ({0})")]
    SealedCorrupt(String),
    /// The marker and `root.sealed` belong to different keys.
    #[error("sealed key unavailable: master.key and root.sealed do not belong together")]
    SealedMismatch,
    /// What wrapped the key is gone (the wrapping secret was deleted).
    #[error("sealed key unavailable: the secret that wraps the key is gone")]
    SealedKeyGone,
    /// The key store that wraps the key cannot be reached right now.
    #[error("sealed key unavailable: the key store cannot be used ({0})")]
    KeyStoreUnavailable(String),
    /// A file was written by a newer program.
    #[error(
        "sealed key unavailable: {file} has format version {found}, newer than this program \
         understands; update the program"
    )]
    FutureVersion { file: &'static str, found: u8 },
    /// A wipe is running or could not be finished.
    #[error("a wipe is pending; the master key cannot be used")]
    WipePending,
    /// A wipe finished just now (it had been interrupted earlier).
    #[error("a pending wipe was completed; the master key is gone")]
    Wiped,
    /// The key held by this handle was erased by a wipe.
    #[error("the master key was erased by a wipe")]
    KeyErased,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Whether [`get`] may create a key when none exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatePolicy {
    /// Never create one: the node must already be initialised.
    Never,
    /// Create one only if the data directory holds no protected state yet. A
    /// node must not silently start over next to data it can no longer read.
    IfFreshDataDir,
    /// Create one whenever none exists (the first start of the share store).
    FirstUse,
}

// ── The key handle ──────────────────────────────────────────────────────────

struct RootKeyCell {
    key: Mutex<Option<SecureBytes<32>>>,
}

impl RootKeyCell {
    fn erase(&self) -> bool {
        let mut g = self.key.lock().unwrap_or_else(|e| e.into_inner());
        // Dropping a `SecureBytes` zeroizes its mapping.
        g.take().is_some()
    }
}

/// A handle to the root key. Cloning shares the same protected storage; the
/// bytes are zeroed when the last holder drops it or when a wipe erases it.
#[derive(Clone)]
pub struct RootKey {
    cell: Arc<RootKeyCell>,
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootKey(<redacted>)")
    }
}

impl RootKey {
    fn new(key: SecureBytes<32>) -> Self {
        Self {
            cell: Arc::new(RootKeyCell {
                key: Mutex::new(Some(key)),
            }),
        }
    }

    /// Run `f` on the key bytes. The key is lent for the call only. After a
    /// wipe erased it this returns [`RootKeyError::KeyErased`].
    pub fn with<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, RootKeyError> {
        let g = self.cell.key.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_ref() {
            Some(k) => Ok(f(k.as_array())),
            None => Err(RootKeyError::KeyErased),
        }
    }

    /// `true` once a wipe erased this handle's key.
    pub fn is_erased(&self) -> bool {
        self.cell
            .key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none()
    }
}

// ── Providers ───────────────────────────────────────────────────────────────

static PROVIDER: RwLock<Option<Arc<dyn RootKeyProvider>>> = RwLock::new(None);

/// Use `p` instead of the file provider for the rest of the process. Called by
/// the program entry points only; library code and tests keep the file
/// provider.
pub fn install_platform_provider(p: Arc<dyn RootKeyProvider>) {
    *PROVIDER.write().unwrap_or_else(|e| e.into_inner()) = Some(p);
}

/// Back to the file provider (for tests).
pub fn reset_provider() {
    *PROVIDER.write().unwrap_or_else(|e| e.into_inner()) = None;
}

pub(crate) fn current_provider() -> Arc<dyn RootKeyProvider> {
    match PROVIDER.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some(p) => p.clone(),
        None => Arc::new(FileProvider),
    }
}

// ── Live handles, so a wipe can erase the ones other components still hold ──

type LiveCells = Mutex<Vec<(Option<PathBuf>, PathBuf, Weak<RootKeyCell>)>>;
static LIVE: std::sync::OnceLock<LiveCells> = std::sync::OnceLock::new();

fn comparable_dir(dir: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(dir).ok()
}

fn register(data_dir: &Path, key: &RootKey) {
    let reg = LIVE.get_or_init(|| Mutex::new(Vec::new()));
    let mut g = reg.lock().unwrap_or_else(|e| e.into_inner());
    g.retain(|(_, _, w)| w.strong_count() > 0);
    g.push((
        comparable_dir(data_dir),
        data_dir.to_path_buf(),
        Arc::downgrade(&key.cell),
    ));
}

/// Erase, in place, every root key handle that was obtained for `data_dir` and
/// is still held in this process. Holders keep their [`RootKey`] but can no
/// longer use it. Returns how many were erased.
pub fn erase_cached(data_dir: &Path) -> usize {
    let Some(reg) = LIVE.get() else {
        return 0;
    };
    let canon = comparable_dir(data_dir);
    let mut erased = 0;
    let mut g = reg.lock().unwrap_or_else(|e| e.into_inner());
    g.retain(|(c, raw, weak)| {
        let Some(cell) = weak.upgrade() else {
            return false;
        };
        let same = raw == data_dir || (c.is_some() && *c == canon);
        if same && cell.erase() {
            erased += 1;
        }
        true
    });
    erased
}

// ── Entry points ────────────────────────────────────────────────────────────

/// The root key of `data_dir`.
///
/// A key is created only when none exists and `create` allows it; a key that
/// exists but cannot be used is an error and nothing is created next to it.
/// A `wipe.pending` marker left by an interrupted wipe is finished first (the
/// wipe never opens the key).
pub fn get(data_dir: &Path, create: CreatePolicy) -> Result<RootKey, RootKeyError> {
    get_with(data_dir, create, &*current_provider())
}

/// [`get`] with an explicit provider instead of the installed one.
pub fn get_with(
    data_dir: &Path,
    create: CreatePolicy,
    provider: &dyn RootKeyProvider,
) -> Result<RootKey, RootKeyError> {
    wipe::finish_pending(data_dir)?;
    let key = match provider.open(data_dir)? {
        Some(k) => k,
        None => {
            match create {
                CreatePolicy::Never => return Err(RootKeyError::Missing),
                CreatePolicy::IfFreshDataDir => {
                    if crate::state_crypto::has_protected_state(data_dir) {
                        return Err(RootKeyError::Missing);
                    }
                }
                CreatePolicy::FirstUse => {}
            }
            provider.create(data_dir)?;
            // Adopt the key that is on disk now: when two processes race, the
            // loser uses the winner's.
            provider.open(data_dir)?.ok_or(RootKeyError::Missing)?
        }
    };
    let root = RootKey::new(key);
    register(data_dir, &root);
    Ok(root)
}

/// Seal the plain key of `data_dir` with `wrap` now. `Ok(true)` when this call
/// sealed it; `Ok(false)` when there is nothing to do (no plain key, already
/// sealed, or another process holds the migration lock). The same move runs
/// automatically from [`get`] when a [`SealedProvider`] is installed.
pub fn seal_with(data_dir: &Path, wrap: &dyn DeviceWrap) -> Result<bool, RootKeyError> {
    wipe::finish_pending(data_dir)?;
    let plain = match std::fs::read(crate::paths::master_key(data_dir)) {
        Ok(b) => zeroize::Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(RootKeyError::Io(e)),
    };
    if plain.len() != 32 {
        return Ok(false);
    }
    let key = provider::classify(&plain)?;
    Ok(sealed::migrate(data_dir, wrap, &key)? == sealed::Moved::Sealed)
}

/// `true` when the data directory has a key in any form (plain, or the marker
/// of a key kept elsewhere). Does not read or open the key.
pub fn is_initialized(data_dir: &Path) -> bool {
    crate::paths::master_key(data_dir).exists()
        || crate::paths::ROOT_SEALED.in_dir(data_dir).exists()
}

/// What is on disk, without opening the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKeyState {
    /// No `master.key`.
    Absent,
    /// A plain 32-byte key file.
    File,
    /// A valid marker: the key is kept elsewhere.
    Sealed,
    /// `master.key` is neither a plain key nor a valid marker.
    Damaged,
    /// An interrupted wipe left its marker.
    WipePending,
}

/// The state of the key, read from the file length and (for the marker) the
/// marker itself. Works after a wipe and when the key cannot be opened.
pub fn status(data_dir: &Path) -> RootKeyState {
    if crate::paths::WIPE_PENDING.in_dir(data_dir).exists() {
        return RootKeyState::WipePending;
    }
    let path = crate::paths::master_key(data_dir);
    let len = match std::fs::metadata(&path) {
        Ok(m) => m.len(),
        Err(_) => {
            // The marker is lost but the sealed file is there.
            return if crate::paths::ROOT_SEALED.in_dir(data_dir).exists() {
                RootKeyState::Sealed
            } else {
                RootKeyState::Absent
            };
        }
    };
    if len == 32 {
        return RootKeyState::File;
    }
    if len == stub::STUB_LEN as u64 {
        return match std::fs::read(&path) {
            Ok(bytes) if stub::Stub::parse(&bytes).is_ok() => RootKeyState::Sealed,
            _ => RootKeyState::Damaged,
        };
    }
    RootKeyState::Damaged
}

impl From<RootKeyError> for crate::MiasmaError {
    fn from(e: RootKeyError) -> Self {
        match e {
            RootKeyError::Io(io) => crate::MiasmaError::Io(io),
            other => crate::MiasmaError::KeyDerivation(other.to_string()),
        }
    }
}

impl From<RootKeyError> for crate::state_crypto::StateError {
    fn from(e: RootKeyError) -> Self {
        use crate::state_crypto::StateError;
        match e {
            RootKeyError::Missing => StateError::KeyMissing,
            RootKeyError::WrongLength => StateError::KeyInvalid("wrong length".into()),
            RootKeyError::Io(io) => StateError::Io(io),
            other => StateError::KeyInvalid(other.to_string()),
        }
    }
}

#[cfg(test)]
mod sealed_tests;
#[cfg(test)]
mod tests;
