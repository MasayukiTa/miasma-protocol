//! Encryption of persisted application state at rest.
//!
//! Everything that describes what the user did or who they know (contacts,
//! transfer history, replication queue, transfer journals, directed-share
//! envelopes, the share index, desktop preferences) is stored encrypted under
//! a key derived from `master.key`. Deleting `master.key` therefore makes the
//! state unreadable even when the files themselves cannot be removed.
//!
//! ## Keys
//!
//! ```text
//! master key (32 bytes, master.key)
//!   state key  = HKDF-SHA256(master, info = "miasma/state/v1")
//!     doc key  = HKDF-SHA256(state key, info = "miasma/state/v1/doc/" + label)
//!       log key = HKDF-SHA256(doc key, salt = file salt, info = ".../log-file")
//! ```
//!
//! Every class of data has its own label, so a file of one class never opens
//! under the key of another. The derivation functions live in
//! [`crate::crypto::keyderive`].
//!
//! ## Two storage shapes
//!
//! * **Document** (`MSD1`, see [`doc`]): one small file, rewritten whole and
//!   atomically (temp file, fsync, rename).
//! * **Record log** (`MSL1`, see [`log`]): an append-only file of
//!   independently sealed records for data that grows. Reads stream one
//!   record at a time; the last record may be torn and is then dropped.
//!
//! Both use XChaCha20-Poly1305 with random nonces and bind the format
//! version, the label and (documents) the file name or (logs) the file salt
//! and record position as associated data.
//!
//! [`migrate`] converts the plaintext files written by earlier versions.
//!
//! ## What stays readable
//!
//! `master.key` itself, the daemon discovery files (port, http port, token),
//! lock files, the version stamp, the share blobs (already ciphertext) and
//! files meant for the user. `config.toml` also stays readable: the daemon and
//! the command line read it before they hold a key, and the key-erasing wipe
//! rewrites it after the key is gone. Its secret values keep their owner-only
//! file permissions.

use std::{
    fmt,
    io::Write,
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::{crypto::keyderive, MiasmaError};

pub mod doc;
pub mod log;
pub mod migrate;

pub use doc::{read_document, write_document};
pub use log::{LogReader, LogRewrite, LogWriter};

/// XChaCha20-Poly1305 nonce length.
pub(crate) const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub(crate) const TAG_LEN: usize = 16;

/// Class of persisted data. Each class has its own derived key; the numeric id
/// is part of every file header and of the associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Label {
    Contacts,
    PushHistory,
    ReplicationWal,
    TransferJournal,
    DirectedMeta,
    StoreIndex,
    DesktopPrefs,
    /// Chat messages (one record log per contact).
    ChatHistory,
    /// Chat ratchet sessions and delivery counters (one document per contact).
    ChatSessions,
    /// Chat messages waiting to be delivered.
    ChatOutbox,
    /// Group chat state: membership chain, counters, deliveries (one document per group).
    ChatGroups,
    /// Group chat messages (one record log per group).
    ChatGroupHistory,
    /// Files waiting to be pushed to a trusted contact (path, size, hash, progress).
    PushOutbox,
}

impl Label {
    pub const ALL: [Label; 13] = [
        Label::Contacts,
        Label::PushHistory,
        Label::ReplicationWal,
        Label::TransferJournal,
        Label::DirectedMeta,
        Label::StoreIndex,
        Label::DesktopPrefs,
        Label::ChatHistory,
        Label::ChatSessions,
        Label::ChatOutbox,
        Label::ChatGroups,
        Label::ChatGroupHistory,
        Label::PushOutbox,
    ];

    /// The id stored in file headers.
    pub const fn id(self) -> u8 {
        match self {
            Label::Contacts => 1,
            Label::PushHistory => 2,
            Label::ReplicationWal => 3,
            Label::TransferJournal => 4,
            Label::DirectedMeta => 5,
            Label::StoreIndex => 6,
            Label::DesktopPrefs => 7,
            Label::ChatHistory => 8,
            Label::ChatSessions => 9,
            Label::ChatOutbox => 10,
            Label::ChatGroups => 11,
            Label::ChatGroupHistory => 12,
            Label::PushOutbox => 13,
        }
    }

    pub fn from_id(id: u8) -> Option<Label> {
        Label::ALL.into_iter().find(|l| l.id() == id)
    }

    /// The name that separates this class's key from every other one.
    pub const fn name(self) -> &'static str {
        match self {
            Label::Contacts => "contacts",
            Label::PushHistory => "push-history",
            Label::ReplicationWal => "replication-wal",
            Label::TransferJournal => "transfer-journal",
            Label::DirectedMeta => "directed-meta",
            Label::StoreIndex => "store-index",
            Label::DesktopPrefs => "desktop-prefs",
            Label::ChatHistory => "chat-history",
            Label::ChatSessions => "chat-sessions",
            Label::ChatOutbox => "chat-outbox",
            Label::ChatGroups => "chat-groups",
            Label::ChatGroupHistory => "chat-group-history",
            Label::PushOutbox => "push-outbox",
        }
    }

    /// Largest plaintext record of a log of this class. Most records are a few
    /// hundred bytes; the replication queue stores the shard locations of a
    /// whole file in one record, which grows with the file.
    pub const fn max_record_bytes(self) -> usize {
        match self {
            Label::ReplicationWal => 16 * 1024 * 1024,
            Label::TransferJournal => 1024 * 1024,
            _ => 64 * 1024,
        }
    }

    /// Largest document of this class that is read or written.
    pub const fn max_document_bytes(self) -> usize {
        match self {
            // A map of every stored share; grows with the store.
            Label::StoreIndex => 256 * 1024 * 1024,
            _ => 16 * 1024 * 1024,
        }
    }
}

/// Why reading or writing protected state failed.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// `master.key` is missing and protected state exists, so nothing can be
    /// opened. Nothing is created or overwritten.
    #[error("the master key is missing; protected state cannot be opened")]
    KeyMissing,
    #[error("the master key is unusable: {0}")]
    KeyInvalid(String),
    /// The file does not start with the protected-state magic.
    #[error("not a protected state file")]
    NotProtected,
    #[error("unsupported protected state version {0}")]
    UnsupportedVersion(u8),
    #[error("file belongs to another class of state (found id {found}, expected {expected})")]
    WrongLabel { expected: u8, found: u8 },
    /// The authentication tag did not verify: wrong key, damaged or altered.
    #[error("protected state failed authentication (wrong key, damaged or altered)")]
    Authentication,
    /// The file ends inside its header or a document body.
    #[error("protected state is truncated")]
    Truncated,
    /// A record log is damaged before its end.
    #[error("protected record log is damaged at byte {0}")]
    Corrupt(u64),
    #[error("protected state too large: {size} bytes (limit {limit})")]
    TooLarge { size: u64, limit: u64 },
    #[error("state migration: {0}")]
    Migration(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<MiasmaError> for StateError {
    fn from(e: MiasmaError) -> Self {
        match e {
            MiasmaError::Io(io) => StateError::Io(io),
            other => StateError::Io(std::io::Error::other(other.to_string())),
        }
    }
}

impl From<StateError> for MiasmaError {
    fn from(e: StateError) -> Self {
        match e {
            StateError::Io(io) => MiasmaError::Io(io),
            other => MiasmaError::Storage(other.to_string()),
        }
    }
}

/// Shared storage of one derived state key. It can be erased in place while
/// other components still hold the [`StateKeys`] that owns it.
struct KeyCell {
    key: std::sync::Mutex<Option<Zeroizing<[u8; 32]>>>,
    /// Test probe: incremented when this cell is dropped.
    #[cfg(test)]
    drop_probe: std::sync::Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>>,
}

impl KeyCell {
    fn erase(&self) -> bool {
        let mut g = self.key.lock().unwrap_or_else(|e| e.into_inner());
        match g.take() {
            // Dropping a `Zeroizing` wipes the bytes.
            Some(k) => {
                drop(k);
                true
            }
            None => false,
        }
    }
}

impl Drop for KeyCell {
    fn drop(&mut self) {
        // Wipe the bytes even if the mutex was poisoned.
        let slot = self.key.get_mut().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = slot.take() {
            drop(k);
        }
        #[cfg(test)]
        if let Some(p) = self
            .drop_probe
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            p.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Every key cell that was loaded from a data directory, so a wipe can erase
/// the ones other components still hold.
type CellRegistry = std::sync::Mutex<Vec<(Option<PathBuf>, PathBuf, std::sync::Weak<KeyCell>)>>;
static LIVE_CELLS: std::sync::OnceLock<CellRegistry> = std::sync::OnceLock::new();

fn comparable_dir(dir: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(dir).ok()
}

/// Erase, in place, every state key that was loaded from `data_dir` and is
/// still held somewhere in this process. Holders keep their `StateKeys`
/// object, but every later seal/open on it fails with a key error. Returns how
/// many live keys were erased.
pub fn erase_state_keys(data_dir: &Path) -> usize {
    let Some(reg) = LIVE_CELLS.get() else {
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

/// The key hierarchy below the master key. Cheap to create; holds one
/// zeroizing 32-byte key that is wiped when the last holder drops it or when
/// [`erase_state_keys`] runs for its data directory.
pub struct StateKeys {
    cell: std::sync::Arc<KeyCell>,
}

impl fmt::Debug for StateKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateKeys(<redacted>)")
    }
}

impl StateKeys {
    /// Derive from an in-memory master key.
    pub fn from_master_key(master: &[u8; 32]) -> Result<Self, StateError> {
        if master.iter().all(|b| *b == 0) {
            return Err(StateError::KeyInvalid(
                "erased (all-zero) key material".into(),
            ));
        }
        let state_key = keyderive::derive_state_key(master)
            .map_err(|e| StateError::KeyInvalid(e.to_string()))?;
        Ok(Self {
            cell: std::sync::Arc::new(KeyCell {
                key: std::sync::Mutex::new(Some(state_key)),
                #[cfg(test)]
                drop_probe: std::sync::Mutex::new(None),
            }),
        })
    }

    /// Erase this key in place (see [`erase_state_keys`]).
    pub fn erase(&self) {
        self.cell.erase();
    }

    /// `true` once the key has been erased.
    pub fn is_erased(&self) -> bool {
        self.cell
            .key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none()
    }

    fn register(&self, data_dir: &Path) {
        let reg = LIVE_CELLS.get_or_init(|| std::sync::Mutex::new(Vec::new()));
        let mut g = reg.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|(_, _, w)| w.strong_count() > 0);
        g.push((
            comparable_dir(data_dir),
            data_dir.to_path_buf(),
            std::sync::Arc::downgrade(&self.cell),
        ));
    }

    /// Read `master.key` from `data_dir`. Never creates it.
    pub fn load(data_dir: &Path) -> Result<Self, StateError> {
        let path = crate::paths::master_key(data_dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => Zeroizing::new(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StateError::KeyMissing)
            }
            Err(e) => return Err(StateError::Io(e)),
        };
        if bytes.len() != 32 {
            return Err(StateError::KeyInvalid("wrong length".into()));
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&bytes);
        let keys = Self::from_master_key(&arr)?;
        keys.register(data_dir);
        Ok(keys)
    }

    /// Like [`load`](Self::load), but a data directory that has never held
    /// any protected state may get its master key created here (the same
    /// first-start rule as the share store). When protected state already
    /// exists the missing key is an error and nothing is created: a node must
    /// not silently start over next to data it can no longer read.
    pub fn open_or_init(data_dir: &Path) -> Result<Self, StateError> {
        match Self::load(data_dir) {
            Err(StateError::KeyMissing) => {
                if has_protected_state(data_dir) {
                    return Err(StateError::KeyMissing);
                }
                create_master_key(data_dir)?;
                Self::load(data_dir)
            }
            other => other,
        }
    }

    /// Find the keys for a state file by looking for `master.key` in the
    /// directories above it (a journal lives in `<data>/transfers/`). Never
    /// creates a key.
    pub fn for_state_file(path: &Path) -> Result<Self, StateError> {
        let mut dir = path.parent();
        for _ in 0..3 {
            let Some(d) = dir else { break };
            if crate::paths::master_key(d).exists() {
                return Self::load(d);
            }
            dir = d.parent();
        }
        Err(StateError::KeyMissing)
    }

    pub(crate) fn doc_key(&self, label: Label) -> Result<Zeroizing<[u8; 32]>, StateError> {
        let g = self.cell.key.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state_key) = g.as_ref() else {
            return Err(StateError::KeyInvalid(
                "the state key was erased by a wipe".into(),
            ));
        };
        Ok(
            keyderive::derive_state_doc_key(state_key.as_ref(), label.name())
                .expect("HKDF expand of 32 bytes cannot fail"),
        )
    }
}

#[cfg(test)]
mod erase_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn dir_with_key() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        std::fs::write(crate::paths::master_key(d.path()), key).unwrap();
        d
    }

    #[test]
    fn erase_state_keys_fails_closed_for_holders_and_drop_wipes_the_cell() {
        let dir = dir_with_key();
        let other = dir_with_key();
        let held = std::sync::Arc::new(StateKeys::load(dir.path()).unwrap());
        let held_by_component = held.clone();
        let unrelated = StateKeys::load(other.path()).unwrap();
        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *held.cell.drop_probe.lock().unwrap() = Some(drops.clone());
        let unrelated_drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *unrelated.cell.drop_probe.lock().unwrap() = Some(unrelated_drops.clone());

        assert!(held.doc_key(Label::Contacts).is_ok());
        let sealed = doc::seal(&held, Label::Contacts, b"ctx", b"hello").unwrap();

        assert!(erase_state_keys(dir.path()) >= 1);

        // The holder still exists, but cannot seal or open anything.
        assert!(held_by_component.is_erased());
        assert!(doc::seal(&held_by_component, Label::Contacts, b"ctx", b"x").is_err());
        assert!(doc::open(&held_by_component, Label::Contacts, b"ctx", sealed).is_err());
        // Another data directory is untouched.
        assert!(!unrelated.is_erased());
        assert!(unrelated.doc_key(Label::Contacts).is_ok());

        // The cell lives while a component holds it; dropping the last holder
        // drops it exactly once.
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(held);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(held_by_component);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(unrelated_drops.load(Ordering::SeqCst), 0);
        drop(unrelated);
        assert_eq!(unrelated_drops.load(Ordering::SeqCst), 1);
    }
}

/// True when any file of a known protected class already exists in `data_dir`.
fn has_protected_state(data_dir: &Path) -> bool {
    use crate::paths::*;
    let singles = [
        CONTACTS.in_dir(data_dir),
        PUSH_HISTORY.in_dir(data_dir),
        REPLICATION_WAL.in_dir(data_dir),
        STORE_INDEX.in_dir(data_dir),
        DESKTOP_PREFS.in_dir(data_dir),
    ];
    if singles.iter().any(|p| sniff(p).is_protected()) {
        return true;
    }
    [
        TRANSFERS_DIR.in_dir(data_dir),
        DIRECTED_INCOMING.in_dir(data_dir),
        DIRECTED_OUTGOING.in_dir(data_dir),
        CHAT_DIR.in_dir(data_dir),
    ]
    .iter()
    .any(|dir| {
        std::fs::read_dir(dir)
            .map(|rd| rd.flatten().any(|e| sniff(&e.path()).is_protected()))
            .unwrap_or(false)
    })
}

/// Write a fresh 32-byte master key if none exists yet. Safe against a second
/// process doing the same: the loser keeps the winner's key.
fn create_master_key(data_dir: &Path) -> Result<(), StateError> {
    std::fs::create_dir_all(data_dir)?;
    let key_path = crate::paths::master_key(data_dir);
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key.as_mut());
    let tmp = crate::paths::atomic_secure_tmp(&key_path);
    crate::secure_file::write_restricted(&tmp, key.as_ref())?;
    // `hard_link` fails when the target exists, so an existing key is never replaced.
    let linked = std::fs::hard_link(&tmp, &key_path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(StateError::Io(e)),
    }
}

/// What a file looks like on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniffed {
    Missing,
    Empty,
    /// A document; carries its label id.
    Document(u8),
    /// A record log; carries its label id.
    Log(u8),
    /// Anything else (a file from an earlier version).
    Plain,
}

impl Sniffed {
    pub fn is_protected(self) -> bool {
        matches!(self, Sniffed::Document(_) | Sniffed::Log(_))
    }
}

pub(crate) const DOC_MAGIC: &[u8; 4] = b"MSD1";
pub(crate) const LOG_MAGIC: &[u8; 4] = b"MSL1";

/// Look at the first bytes of `path`.
pub fn sniff(path: &Path) -> Sniffed {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return Sniffed::Missing;
    };
    let mut head = [0u8; 6];
    let mut n = 0;
    while n < head.len() {
        match f.read(&mut head[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => break,
        }
    }
    if n == 0 {
        return Sniffed::Empty;
    }
    if n == 6 && &head[..4] == DOC_MAGIC {
        return Sniffed::Document(head[5]);
    }
    if n == 6 && &head[..4] == LOG_MAGIC {
        return Sniffed::Log(head[5]);
    }
    Sniffed::Plain
}

// ─── AEAD helpers (shared by documents and logs) ────────────────────────────

/// Encrypt `buf` in place and return the tag.
pub(crate) fn seal_detached(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<Tag, StateError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, buf)
        .map_err(|_| StateError::Authentication)
}

/// Decrypt `buf` in place; the tag check is constant time.
pub(crate) fn open_detached(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), StateError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(XNonce::from_slice(nonce), aad, buf, Tag::from_slice(tag))
        .map_err(|_| StateError::Authentication)
}

// ─── File helpers ───────────────────────────────────────────────────────────

/// Flush the directory entry of a just-renamed file (a no-op where the
/// platform has no such call).
pub(crate) fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Make the data of an existing file durable.
pub(crate) fn fsync_path(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .sync_all()
}

/// Overwrite `path` with random bytes, flush, and remove it. Missing is fine.
pub fn overwrite_and_remove(path: &Path) -> std::io::Result<()> {
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut left = len;
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf[..n]);
            f.write_all(&buf[..n])?;
            left -= n as u64;
        }
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::remove_file(path)
}

/// Move an unreadable state file aside (never delete it) so a fresh one can be
/// started. Returns the new name: `<file>.corrupt-<unix seconds>`.
pub fn set_aside(path: &Path) -> std::io::Result<PathBuf> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let aside = crate::paths::corrupt_aside(path, secs);
    std::fs::rename(path, &aside)?;
    Ok(aside)
}

/// Provision a master key in `data_dir` when none exists (the same raw 32-byte
/// format the share store uses). For callers that set up a data directory
/// before any store has run; it never replaces an existing key.
pub fn provision_master_key(data_dir: &Path) -> Result<(), StateError> {
    if crate::paths::master_key(data_dir).exists() {
        return Ok(());
    }
    create_master_key(data_dir)
}
