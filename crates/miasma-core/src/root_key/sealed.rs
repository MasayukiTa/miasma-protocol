//! The sealed form of the root key: `root.sealed` plus a 64-byte `master.key`
//! marker, the start-up rules for every combination of files, and the automatic
//! move from a plain `master.key` to that form.
//!
//! # Start-up rules
//!
//! `L` = plain 32-byte `master.key`, `S` = 64-byte marker, `B` = `root.sealed`.
//!
//! | on disk | meaning | action |
//! |---|---|---|
//! | nothing | new | `Ok(None)`; the caller may create a key |
//! | `L` | not sealed yet | use `L`; seal it when a wrap is installed |
//! | `L` + `B` | sealing was interrupted | `B` opens to `L`: finish. `B` damaged or another key: set it aside, seal again. `B` cannot be opened right now: keep using `L` |
//! | `S` + `B` | sealed | open `B`; the marker and `B` must name the same key |
//! | `S` | the sealed file is gone | error; nothing is created |
//! | `B` | marker lost | open `B`, write the marker again |
//! | marker unreadable | damaged | error; `B` is not touched |
//!
//! A key is created only in the first row, and only by the caller's policy.
//!
//! # Moving `L` to `S` + `B`
//!
//! Under the migration lock: wrap the key into `B`, make `B` durable, read it
//! back and open it, stage the marker, give `L` a second name
//! (`master.key.premigrate`), move the marker over `master.key`, open `B` again
//! through the marker, and only then overwrite and remove the second name.
//! `master.key` exists at every instant, as `L` or as `S`, so a program that
//! knows only the plain file never finds it missing and never starts a new key;
//! and at every instant either `L` or a verified `B` holds the key.
//!
//! Nothing here asks the user anything.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::format::{self, Blob, FormatError, Header, Record};
use super::provider::{
    Availability, DestroyOutcome, DeviceWrap, ProtectionLevel, ProviderId, RootKeyProvider,
    WrapError,
};
use super::stub::{Stub, StubError, STUB_LEN};
use super::{FileWrap, RootKeyError};
use crate::secure_memory::SecureBytes;

// ── Provider that seals ─────────────────────────────────────────────────────

/// A provider that keeps the key in `root.sealed`, wrapped by `wrap`, and moves
/// a plain `master.key` into that form when it opens one.
pub struct SealedProvider {
    wrap: Arc<dyn DeviceWrap>,
}

impl SealedProvider {
    pub fn new(wrap: Arc<dyn DeviceWrap>) -> Self {
        Self { wrap }
    }
}

impl std::fmt::Debug for SealedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedProvider")
            .field("wrap", &self.wrap.id())
            .finish()
    }
}

impl RootKeyProvider for SealedProvider {
    fn id(&self) -> ProviderId {
        self.wrap.id()
    }

    fn level(&self) -> ProtectionLevel {
        match self.wrap.id() {
            ProviderId::File => ProtectionLevel::File,
            ProviderId::CngTpm => ProtectionLevel::Hardware,
            ProviderId::Keystore => ProtectionLevel::Tee,
            _ => ProtectionLevel::Software,
        }
    }

    fn available(&self) -> Availability {
        self.wrap.available()
    }

    fn open(&self, data_dir: &Path) -> Result<Option<SecureBytes<32>>, RootKeyError> {
        open(data_dir, Some(&*self.wrap))
    }

    fn create(&self, data_dir: &Path) -> Result<(), RootKeyError> {
        create(data_dir, &*self.wrap)
    }

    fn destroy(&self, data_dir: &Path) -> Result<DestroyOutcome, RootKeyError> {
        self.wrap.destroy(data_dir).map_err(|e| match e {
            WrapError::Io(io) => RootKeyError::Io(io),
            other => RootKeyError::KeyStoreUnavailable(other.to_string()),
        })
    }
}

// ── Test-only fault injection ───────────────────────────────────────────────

/// A point in the move to the sealed form, right after a step finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    SealedStaged,
    SealedInPlace,
    SealedVerified,
    StubStaged,
    PlainLinkedAside,
    StubInPlace,
    SealedReverified,
    AsideErased,
}

#[cfg(test)]
pub(super) const ALL_STEPS: [Step; 8] = [
    Step::SealedStaged,
    Step::SealedInPlace,
    Step::SealedVerified,
    Step::StubStaged,
    Step::PlainLinkedAside,
    Step::StubInPlace,
    Step::SealedReverified,
    Step::AsideErased,
];

#[cfg(test)]
thread_local! {
    pub(super) static STOP_AFTER: std::cell::Cell<Option<Step>> =
        const { std::cell::Cell::new(None) };
}

/// Where a test can stop the move, as if the program had been killed. Nothing
/// after the point runs and nothing is cleaned up.
fn after(step: Step) -> Result<(), RootKeyError> {
    #[cfg(test)]
    if STOP_AFTER.with(|c| c.get()) == Some(step) {
        return Err(RootKeyError::Io(std::io::Error::other(format!(
            "stopped after {step:?}"
        ))));
    }
    let _ = step;
    Ok(())
}

// ── Reading ─────────────────────────────────────────────────────────────────

enum Master {
    Absent,
    Plain(SecureBytes<32>),
    Stub(Stub),
}

fn read_master(data_dir: &Path) -> Result<Master, RootKeyError> {
    let bytes = match std::fs::read(crate::paths::master_key(data_dir)) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Master::Absent),
        Err(e) => return Err(RootKeyError::Io(e)),
    };
    if bytes.len() == STUB_LEN {
        return match Stub::parse(&bytes) {
            Ok(s) => Ok(Master::Stub(s)),
            Err(StubError::UnsupportedVersion(v)) => Err(RootKeyError::FutureVersion {
                file: "master.key marker",
                found: v,
            }),
            Err(_) => Err(RootKeyError::DamagedMarker),
        };
    }
    super::provider::classify(&bytes).map(Master::Plain)
}

fn read_sealed(data_dir: &Path) -> Result<Option<Vec<u8>>, RootKeyError> {
    match std::fs::read(crate::paths::ROOT_SEALED.in_dir(data_dir)) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(RootKeyError::Io(e)),
    }
}

fn map_format(e: FormatError) -> RootKeyError {
    match e {
        FormatError::FutureVersion(found) => RootKeyError::FutureVersion {
            file: "root.sealed",
            found,
        },
        other => RootKeyError::SealedCorrupt(other.to_string()),
    }
}

fn map_wrap(e: WrapError) -> RootKeyError {
    match e {
        WrapError::Unavailable(why) => RootKeyError::KeyStoreUnavailable(why),
        WrapError::KeyGone => RootKeyError::SealedKeyGone,
        WrapError::Corrupt => RootKeyError::SealedCorrupt("authentication failed".into()),
        WrapError::Io(io) => RootKeyError::Io(io),
    }
}

fn same_key(a: &SecureBytes<32>, b: &SecureBytes<32>) -> bool {
    a.as_array().ct_eq(b.as_array()).into()
}

/// Parse `bytes` and open the key in it. `stub`, when given, must name the same
/// install and key. Only the file wrap is built in; any other wrap must be the
/// installed `wrap`.
fn open_blob(
    data_dir: &Path,
    bytes: &[u8],
    stub: Option<&Stub>,
    wrap: Option<&dyn DeviceWrap>,
) -> Result<(Blob, SecureBytes<32>), RootKeyError> {
    let blob = Blob::parse(bytes).map_err(map_format)?;
    let record = blob.device_record();
    if let Some(s) = stub {
        if s.install_id != blob.header.install_id
            || s.key_id != blob.header.key_id
            || s.provider != record.provider
        {
            return Err(RootKeyError::SealedMismatch);
        }
    }
    let provider = ProviderId::from_u8(record.provider).ok_or(RootKeyError::SealedUnavailable)?;
    let builtin = FileWrap;
    let w: &dyn DeviceWrap = match wrap {
        Some(w) if w.id() == provider => w,
        _ if provider == ProviderId::File => &builtin,
        _ => return Err(RootKeyError::SealedUnavailable),
    };
    match w.available() {
        Availability::Ready => {}
        Availability::Unavailable(why) => {
            return Err(RootKeyError::KeyStoreUnavailable(why.to_string()))
        }
        Availability::NeedsUserPresence => {
            return Err(RootKeyError::KeyStoreUnavailable(
                "the user must be present".into(),
            ))
        }
    }
    let key = w
        .unwrap(data_dir, &record.aad(&blob.header), &record.wrapped)
        .map_err(map_wrap)?;
    let check = format::root_check(key.as_array());
    if !bool::from(check.ct_eq(&blob.header.root_check)) {
        return Err(RootKeyError::SealedCorrupt("key check failed".into()));
    }
    Ok((blob, key))
}

fn stub_of(blob: &Blob) -> Stub {
    Stub {
        provider: blob.device_record().provider,
        flags: 0,
        install_id: blob.header.install_id,
        key_id: blob.header.key_id,
        created_epoch: blob.header.created_epoch,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}

// ── The start-up rules ──────────────────────────────────────────────────────

/// Read the key of `data_dir`. `wrap` is the installed wrap: with it a plain
/// key is sealed; without it nothing is ever written.
pub(super) fn open(
    data_dir: &Path,
    wrap: Option<&dyn DeviceWrap>,
) -> Result<Option<SecureBytes<32>>, RootKeyError> {
    let master = read_master(data_dir)?;
    let sealed = read_sealed(data_dir)?;
    match (master, sealed) {
        (Master::Absent, None) => Ok(None),
        (Master::Plain(plain), sealed) => {
            // The plain key stays authoritative until the marker replaces it,
            // so an unfinished or failed move never changes which key is used.
            if let Some(w) = wrap {
                let have_sealed = sealed.is_some();
                if let Err(e) = migrate(data_dir, w, &plain) {
                    tracing::warn!(
                        sealed_file_present = have_sealed,
                        "the key stays in its old form for now: {e}"
                    );
                }
            }
            Ok(Some(plain))
        }
        (Master::Stub(_), None) => Err(RootKeyError::SealedFileMissing),
        (Master::Stub(stub), Some(bytes)) => {
            open_sealed_state(data_dir, &stub, &bytes, wrap).map(Some)
        }
        (Master::Absent, Some(bytes)) => {
            let (blob, key) = open_blob(data_dir, &bytes, None, wrap)?;
            // Put the marker back (best effort; the key is already open).
            let _ = super::durable::write_new(
                &crate::paths::master_key(data_dir),
                &stub_of(&blob).encode(),
            );
            Ok(Some(key))
        }
    }
}

fn aside_path(data_dir: &Path) -> PathBuf {
    crate::paths::premigrate_copy(&crate::paths::master_key(data_dir))
}

/// The marker and `root.sealed` are both there.
fn open_sealed_state(
    data_dir: &Path,
    stub: &Stub,
    bytes: &[u8],
    wrap: Option<&dyn DeviceWrap>,
) -> Result<SecureBytes<32>, RootKeyError> {
    let aside = aside_path(data_dir);
    let aside_present = std::fs::symlink_metadata(&aside).is_ok();
    match open_blob(data_dir, bytes, Some(stub), wrap) {
        Ok((_, key)) => {
            if aside_present {
                finish_aside(&aside, &key);
            }
            Ok(key)
        }
        // A move was interrupted and what it sealed cannot be opened. The
        // second name of the old plain key is the way back.
        Err(e @ (RootKeyError::SealedCorrupt(_) | RootKeyError::SealedKeyGone))
            if aside_present =>
        {
            match restore_from_aside(data_dir, &aside, bytes) {
                Ok(Some(key)) => Ok(key),
                _ => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// The old plain copy is no longer needed once `B` opens to the same key.
fn finish_aside(aside: &Path, key: &SecureBytes<32>) {
    let Ok(bytes) = std::fs::read(aside).map(Zeroizing::new) else {
        return;
    };
    if bytes.len() == 32 && bool::from(bytes.as_slice().ct_eq(key.as_array().as_slice())) {
        let _ = crate::state_crypto::overwrite_and_remove(aside);
    }
}

/// Put the old plain key back over the marker and set the unusable `root.sealed`
/// aside. Returns the key, or `None` when this is not a state it may repair.
fn restore_from_aside(
    data_dir: &Path,
    aside: &Path,
    sealed_bytes: &[u8],
) -> Result<Option<SecureBytes<32>>, RootKeyError> {
    let Some(_lock) = try_lock(data_dir)? else {
        return Ok(None);
    };
    let plain = Zeroizing::new(std::fs::read(aside)?);
    let Ok(key) = super::provider::classify(&plain) else {
        return Ok(None);
    };
    // When the header can still be read it must belong to this key.
    if let Ok(blob) = Blob::parse(sealed_bytes) {
        let check = format::root_check(key.as_array());
        if !bool::from(check.ct_eq(&blob.header.root_check)) {
            return Ok(None);
        }
    }
    super::durable::replace_with(aside, &crate::paths::master_key(data_dir))?;
    set_aside_corrupt(&crate::paths::ROOT_SEALED.in_dir(data_dir))?;
    Ok(Some(key))
}

fn set_aside_corrupt(path: &Path) -> std::io::Result<()> {
    let target = crate::paths::corrupt_aside(path, now_secs());
    std::fs::rename(path, target)
}

// ── Lock ────────────────────────────────────────────────────────────────────

struct Lock(std::fs::File);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// The lock that serialises changes to the key files (the same file as the
/// state-file conversion). `None` when another holder has it; the caller then
/// leaves the work for a later start.
fn try_lock(data_dir: &Path) -> Result<Option<Lock>, RootKeyError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(crate::paths::state_migration_lock(data_dir))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(Lock(file))),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(RootKeyError::Io(e)),
    }
}

// ── Creating and moving ─────────────────────────────────────────────────────

fn new_blob(data_dir: &Path, w: &dyn DeviceWrap, root: &[u8; 32]) -> Result<Blob, RootKeyError> {
    let header = Header {
        flags: 0,
        install_id: random(),
        key_id: random(),
        created_epoch: now_secs(),
        root_check: format::root_check(root),
    };
    let mut record = Record {
        rtype: format::RECORD_DEVICE,
        provider: w.id() as u8,
        kdf_id: format::KDF_HKDF_SHA256,
        kdf_params: Vec::new(),
        wrapped: Vec::new(),
    };
    record.wrapped = w
        .wrap(data_dir, &record.aad(&header), root)
        .map_err(map_wrap)?;
    Ok(Blob {
        header,
        records: vec![record],
    })
}

/// Make a new random key, sealed. Never replaces anything: when another process
/// won the race, its key is the one in use.
pub(super) fn create(data_dir: &Path, w: &dyn DeviceWrap) -> Result<(), RootKeyError> {
    std::fs::create_dir_all(data_dir)?;
    let root = Zeroizing::new(random::<32>());
    let blob = new_blob(data_dir, w, &root)?;
    let sealed_path = crate::paths::ROOT_SEALED.in_dir(data_dir);
    if !super::durable::write_new(&sealed_path, &blob.encode())? {
        return Ok(());
    }
    // Read it back before anything points at it.
    let bytes = read_sealed(data_dir)?.ok_or(RootKeyError::SealedFileMissing)?;
    let verified = open_blob(data_dir, &bytes, None, Some(w))
        .map(|(_, k)| bool::from(k.as_array().ct_eq(&*root)));
    if !matches!(verified, Ok(true)) {
        let _ = std::fs::remove_file(&sealed_path);
        return Err(RootKeyError::SealedCorrupt(
            "the sealed key did not read back".into(),
        ));
    }
    super::durable::write_new(
        &crate::paths::master_key(data_dir),
        &stub_of(&blob).encode(),
    )?;
    Ok(())
}

/// What a move did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Moved {
    /// Another process holds the lock or already finished.
    Skipped,
    Sealed,
}

/// Seal the plain key `plain` of `data_dir` with `w`. See the module comment
/// for the order. On any error the files are left as they are (nothing is
/// cleaned up on the way out); the next start converges.
pub(super) fn migrate(
    data_dir: &Path,
    w: &dyn DeviceWrap,
    plain: &SecureBytes<32>,
) -> Result<Moved, RootKeyError> {
    match w.available() {
        Availability::Ready => {}
        Availability::Unavailable(why) => {
            return Err(RootKeyError::KeyStoreUnavailable(why.to_string()))
        }
        Availability::NeedsUserPresence => {
            return Err(RootKeyError::KeyStoreUnavailable(
                "the user must be present".into(),
            ))
        }
    }
    let Some(_lock) = try_lock(data_dir)? else {
        return Ok(Moved::Skipped);
    };
    let master_path = crate::paths::master_key(data_dir);
    let sealed_path = crate::paths::ROOT_SEALED.in_dir(data_dir);
    let aside = aside_path(data_dir);

    // Anything the lock holder left behind earlier. The second name of the
    // plain key is only unlinked here: `master.key` is still the plain key and
    // may be the same file.
    for stale in sidecar_files(data_dir) {
        if stale != aside && is_staging_name(&stale) {
            let _ = std::fs::remove_file(&stale);
        }
    }
    let _ = std::fs::remove_file(&aside);

    // The state may have moved on while this process waited for the lock.
    match read_master(data_dir)? {
        Master::Plain(now) if same_key(&now, plain) => {}
        _ => return Ok(Moved::Skipped),
    }

    // A `root.sealed` from an interrupted earlier attempt is reused when it
    // opens to this key, set aside when it is damaged or another key's, and
    // left alone (error) when it cannot be judged now.
    let mut blob = None;
    if let Some(bytes) = read_sealed(data_dir)? {
        match open_blob(data_dir, &bytes, None, Some(w)) {
            Ok((b, key)) if same_key(&key, plain) => blob = Some(b),
            Ok(_) | Err(RootKeyError::SealedCorrupt(_) | RootKeyError::SealedKeyGone) => {
                set_aside_corrupt(&sealed_path)?;
            }
            Err(e) => return Err(e),
        }
    }
    let blob = match blob {
        Some(b) => b,
        None => {
            let b = new_blob(data_dir, w, plain.as_array())?;
            let staged = super::durable::stage(&sealed_path, &b.encode())?;
            after(Step::SealedStaged)?;
            if !super::durable::link_into_place(&staged, &sealed_path)? {
                return Err(RootKeyError::SealedCorrupt(
                    "a sealed file appeared during the move".into(),
                ));
            }
            after(Step::SealedInPlace)?;
            b
        }
    };

    // Read it back from disk and open it.
    let verify = |stub: Option<&Stub>| -> Result<(), RootKeyError> {
        let bytes = read_sealed(data_dir)?.ok_or(RootKeyError::SealedFileMissing)?;
        let (_, key) = open_blob(data_dir, &bytes, stub, Some(w))?;
        if same_key(&key, plain) {
            Ok(())
        } else {
            Err(RootKeyError::SealedCorrupt("verification failed".into()))
        }
    };
    verify(None)?;
    after(Step::SealedVerified)?;

    let stub = stub_of(&blob);
    let staged_stub = super::durable::stage(&master_path, &stub.encode())?;
    after(Step::StubStaged)?;

    super::durable::link_or_copy(&master_path, &aside)?;
    after(Step::PlainLinkedAside)?;

    super::durable::replace_with(&staged_stub, &master_path)?;
    after(Step::StubInPlace)?;

    // Through the marker this time. If this fails the plain key goes back.
    let reopened = read_master(data_dir)
        .and_then(|m| match m {
            Master::Stub(s) if s == stub => Ok(()),
            _ => Err(RootKeyError::DamagedMarker),
        })
        .and_then(|()| verify(Some(&stub)));
    if let Err(e) = reopened {
        if let Err(restore) = super::durable::replace_with(&aside, &master_path) {
            tracing::warn!("could not put the old key file back: {restore}");
        }
        return Err(e);
    }
    after(Step::SealedReverified)?;

    crate::state_crypto::overwrite_and_remove(&aside)?;
    after(Step::AsideErased)?;
    Ok(Moved::Sealed)
}

// ── Leftovers ───────────────────────────────────────────────────────────────

fn is_staging_name(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().ends_with(".sec.tmp"))
}

/// Files the sealed form can leave next to the registered key files: the second
/// name of a plain key during the move, staging files, and a `root.sealed` set
/// aside as damaged. A wipe removes them all.
pub(super) fn sidecar_files(data_dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![aside_path(data_dir)];
    let prefixes = [
        crate::paths::MASTER_KEY.name,
        crate::paths::ROOT_SEALED.name,
        crate::paths::WRAP_SECRET.name,
    ];
    let corrupt = format!("{}.corrupt-", crate::paths::ROOT_SEALED.name);
    if let Ok(rd) = std::fs::read_dir(data_dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let staging = name.ends_with(".sec.tmp")
                && prefixes.iter().any(|p| name.starts_with(&format!("{p}.")));
            if staging || name.starts_with(&corrupt) {
                out.push(e.path());
            }
        }
    }
    out
}
