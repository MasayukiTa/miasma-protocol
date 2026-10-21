//! Where the root key comes from.
//!
//! A provider reads, creates and destroys the key of one data directory. The
//! file provider is the only one: it keeps the key as the plain 32-byte
//! `master.key`, exactly as every released version does. Later providers
//! (a sealed form, operating-system key stores) implement the same trait and
//! are installed by the program entry points with
//! [`install_platform_provider`](super::install_platform_provider).

use std::path::Path;

use zeroize::Zeroizing;

use super::stub::Stub;
use super::RootKeyError;
use crate::secure_memory::SecureBytes;

/// Which provider holds a key. The numbers are stable: they are written into
/// the 64-byte marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderId {
    File = 0,
    Dpapi = 1,
    CngTpm = 2,
    CngSoftware = 3,
    Keystore = 4,
    Keychain = 5,
    SecretService = 6,
    Passphrase = 7,
}

impl ProviderId {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::File,
            1 => Self::Dpapi,
            2 => Self::CngTpm,
            3 => Self::CngSoftware,
            4 => Self::Keystore,
            5 => Self::Keychain,
            6 => Self::SecretService,
            7 => Self::Passphrase,
            _ => return None,
        })
    }
}

/// How strongly the key is protected, for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLevel {
    /// A plain file in the data directory.
    File,
    Software,
    Tee,
    Hardware,
}

/// Whether the provider can be used right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Ready,
    Unavailable(&'static str),
    NeedsUserPresence,
}

/// What destroying a provider's own key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyOutcome {
    Destroyed,
    /// The provider keeps nothing outside the data directory.
    NothingToDestroy,
}

pub trait RootKeyProvider: Send + Sync {
    fn id(&self) -> ProviderId;
    fn level(&self) -> ProtectionLevel;
    fn available(&self) -> Availability;
    /// Read the key of `data_dir`. `Ok(None)` means no key exists at all.
    /// A key that exists but cannot be opened is an error, never `None`.
    fn open(&self, data_dir: &Path) -> Result<Option<SecureBytes<32>>, RootKeyError>;
    /// Create a new random key. Never replaces a key that already exists.
    fn create(&self, data_dir: &Path) -> Result<(), RootKeyError>;
    /// Destroy whatever the provider keeps outside the data directory.
    fn destroy(&self, data_dir: &Path) -> Result<DestroyOutcome, RootKeyError>;
}

/// Why a wrap could not be made or opened.
#[derive(Debug, thiserror::Error)]
pub enum WrapError {
    /// The place that holds the wrapping secret cannot be reached right now.
    #[error("{0}")]
    Unavailable(String),
    /// The wrapping secret is gone for good.
    #[error("the wrapping secret is gone")]
    KeyGone,
    /// The wrapped bytes do not authenticate (damaged, or made for another
    /// header).
    #[error("the wrapped key does not authenticate")]
    Corrupt,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// What protects the root key on this device. It turns the 32 key bytes into an
/// opaque blob and back; `aad` (the header and the record head of
/// `root.sealed`) must be authenticated by the wrap, so a blob cannot be moved
/// to another file or install.
pub trait DeviceWrap: Send + Sync {
    /// Written into the record, so the right wrap is used to open it.
    fn id(&self) -> ProviderId;
    fn available(&self) -> Availability;
    fn wrap(&self, data_dir: &Path, aad: &[u8], root: &[u8; 32]) -> Result<Vec<u8>, WrapError>;
    fn unwrap(
        &self,
        data_dir: &Path,
        aad: &[u8],
        wrapped: &[u8],
    ) -> Result<SecureBytes<32>, WrapError>;
    /// Destroy whatever the wrap keeps outside the data directory.
    fn destroy(&self, data_dir: &Path) -> Result<DestroyOutcome, WrapError>;
}

/// The plain-file provider.
pub struct FileProvider;

/// Turn the bytes of a `master.key` into a key or the reason it is unusable.
pub(super) fn classify(bytes: &[u8]) -> Result<SecureBytes<32>, RootKeyError> {
    match bytes.len() {
        32 => {
            let mut arr = Zeroizing::new([0u8; 32]);
            arr.copy_from_slice(bytes);
            if arr.iter().all(|byte| *byte == 0) {
                return Err(RootKeyError::Erased);
            }
            Ok(SecureBytes::from_slice(&arr))
        }
        super::stub::STUB_LEN => match Stub::parse(bytes) {
            Ok(_) => Err(RootKeyError::SealedUnavailable),
            Err(super::stub::StubError::UnsupportedVersion(v)) => {
                Err(RootKeyError::FutureVersion {
                    file: "master.key marker",
                    found: v,
                })
            }
            Err(_) => Err(RootKeyError::DamagedMarker),
        },
        _ => Err(RootKeyError::WrongLength),
    }
}

impl RootKeyProvider for FileProvider {
    fn id(&self) -> ProviderId {
        ProviderId::File
    }

    fn level(&self) -> ProtectionLevel {
        ProtectionLevel::File
    }

    fn available(&self) -> Availability {
        Availability::Ready
    }

    /// Plain key as before. A key sealed with the file wrap is opened too; one
    /// sealed any other way fails closed ([`RootKeyError::SealedUnavailable`]).
    /// No sealing or migration happens without an installed wrap.
    fn open(&self, data_dir: &Path) -> Result<Option<SecureBytes<32>>, RootKeyError> {
        super::sealed::open(data_dir, None)
    }

    /// Write a fresh 32-byte key if none exists yet. Safe against a second
    /// process doing the same: the loser keeps the winner's key.
    fn create(&self, data_dir: &Path) -> Result<(), RootKeyError> {
        std::fs::create_dir_all(data_dir)?;
        let key_path = crate::paths::master_key(data_dir);
        let mut key = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key.as_mut());
        let tmp = crate::paths::atomic_secure_tmp(&key_path);
        // The file is born with a restricted DACL / mode 0o600 and never
        // exists with wider permissions.
        crate::secure_file::write_restricted(&tmp, key.as_ref()).map_err(|e| match e {
            crate::MiasmaError::Io(io) => RootKeyError::Io(io),
            other => RootKeyError::Io(std::io::Error::other(other.to_string())),
        })?;
        // `hard_link` fails when the target exists, so an existing key is
        // never replaced.
        let linked = std::fs::hard_link(&tmp, &key_path);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(RootKeyError::Io(e)),
        }
    }

    fn destroy(&self, _data_dir: &Path) -> Result<DestroyOutcome, RootKeyError> {
        Ok(DestroyOutcome::NothingToDestroy)
    }
}
