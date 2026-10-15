//! One-time conversion of the plaintext state files written by earlier
//! versions into the protected shapes.
//!
//! For every file the steps are:
//!
//! 1. read the plaintext original;
//! 2. write the protected copy to a temp file next to it and flush it;
//! 3. read the temp file back and compare it with the original;
//! 4. rename the original to `<name>.premigrate`, rename the protected copy to
//!    the real name, flush the directory;
//! 5. overwrite the `.premigrate` file with random bytes, flush it, delete it.
//!
//! At every instant either the plaintext original or a verified protected
//! copy exists, so an interruption never loses data, and the next start
//! finishes the job from whatever is on disk:
//!
//! | found on disk | meaning | action |
//! |---|---|---|
//! | plaintext file | not started, or stopped before step 4 | redo from step 1 |
//! | `.premigrate` and no usable protected file | stopped inside step 4 | continue from the `.premigrate` file |
//! | `.premigrate` and a protected file that opens | stopped before step 5 | finish step 5 |
//! | protected file only | done | nothing |
//!
//! A second run therefore changes nothing. Files are converted byte for byte
//! (documents) or line for line (logs); damaged content moves into the
//! protected file unchanged and is dealt with by the code that reads it, as
//! before.
//!
//! The conversion needs `master.key`. Without it nothing is read, written or
//! created and an error is returned.
//!
//! Concurrent starters (daemon and desktop) are serialised by an advisory
//! lock on `state-migration.lock` in the data directory, which is only
//! touched when there is something to convert.

use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    doc::{self, context_of},
    log::{LogReader, LogRewrite},
    overwrite_and_remove, sniff, sync_parent_dir, Label, Sniffed, StateError, StateKeys,
};

/// Result for one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Absent,
    AlreadyProtected,
    /// A zero-length plaintext file was removed (it holds nothing).
    RemovedEmpty,
    Migrated,
    /// An interrupted earlier run was completed.
    Recovered,
}

/// What a run did.
#[derive(Debug, Default)]
pub struct MigrationReport {
    pub migrated: usize,
    pub recovered: usize,
    pub already_protected: usize,
    /// Plaintext leftovers of interrupted writes that were wiped and removed.
    pub discarded_leftovers: usize,
    /// Plaintext log lines too long to keep (none are expected).
    pub skipped_lines: usize,
    /// Files that could not be converted, with the reason; their plaintext is untouched.
    pub failures: Vec<(PathBuf, String)>,
}

impl MigrationReport {
    pub fn changed_anything(&self) -> bool {
        self.migrated + self.recovered + self.discarded_leftovers > 0
    }

    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Document,
    Log,
}

#[derive(Debug, Clone)]
struct Target {
    path: PathBuf,
    label: Label,
    shape: Shape,
}

// ─── Lock ───────────────────────────────────────────────────────────────────

struct MigrationLock {
    file: File,
}

impl Drop for MigrationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// The directory that holds `master.key` for a state file.
fn state_dir_of(path: &Path) -> PathBuf {
    let mut dir = path.parent();
    for _ in 0..3 {
        let Some(d) = dir else { break };
        if crate::paths::master_key(d).exists() {
            return d.to_path_buf();
        }
        dir = d.parent();
    }
    path.parent().map(Path::to_path_buf).unwrap_or_default()
}

fn lock_in(state_dir: &Path) -> Result<MigrationLock, StateError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(crate::paths::state_migration_lock(state_dir))?;
    file.lock()?;
    Ok(MigrationLock { file })
}

// ─── Single files ───────────────────────────────────────────────────────────

fn premigrate(path: &Path) -> PathBuf {
    crate::paths::premigrate_copy(path)
}

/// True when `path` still needs attention: a plaintext file, or the remains of
/// an interrupted run.
fn pending(path: &Path) -> bool {
    premigrate(path).exists() || matches!(sniff(path), Sniffed::Plain | Sniffed::Empty)
}

/// Convert one document file if it is still plaintext (or finish an
/// interrupted conversion). Cheap when there is nothing to do.
pub fn migrate_document(
    keys: &StateKeys,
    label: Label,
    path: &Path,
) -> Result<Outcome, StateError> {
    if !pending(path) {
        return already_or_absent(path, label);
    }
    let _lock = lock_in(&state_dir_of(path))?;
    document_locked(keys, label, path)
}

/// Convert one log file; see [`migrate_document`].
pub fn migrate_log(keys: &StateKeys, label: Label, path: &Path) -> Result<Outcome, StateError> {
    if !pending(path) {
        return already_or_absent(path, label);
    }
    let _lock = lock_in(&state_dir_of(path))?;
    log_locked(keys, label, path, &mut 0)
}

fn already_or_absent(path: &Path, label: Label) -> Result<Outcome, StateError> {
    match sniff(path) {
        Sniffed::Missing => Ok(Outcome::Absent),
        Sniffed::Document(id) | Sniffed::Log(id) if id != label.id() => {
            Err(StateError::WrongLabel {
                expected: label.id(),
                found: id,
            })
        }
        _ => Ok(Outcome::AlreadyProtected),
    }
}

/// Decide what the source of a conversion is. `Ok(None)` means the file is
/// settled (the outcome is returned through `done`).
fn pick_source(
    path: &Path,
    old: &Path,
    protected_ok: impl Fn() -> bool,
    label: Label,
) -> Result<Result<(PathBuf, bool), Outcome>, StateError> {
    if old.exists() {
        if sniff(path).is_protected() && protected_ok() {
            overwrite_and_remove(old)?;
            return Ok(Err(Outcome::Recovered));
        }
        return Ok(Ok((old.to_path_buf(), true)));
    }
    match sniff(path) {
        Sniffed::Missing => Ok(Err(Outcome::Absent)),
        Sniffed::Empty => {
            std::fs::remove_file(path)?;
            Ok(Err(Outcome::RemovedEmpty))
        }
        Sniffed::Document(id) | Sniffed::Log(id) => {
            if id != label.id() {
                return Err(StateError::WrongLabel {
                    expected: label.id(),
                    found: id,
                });
            }
            Ok(Err(Outcome::AlreadyProtected))
        }
        Sniffed::Plain => Ok(Ok((path.to_path_buf(), false))),
    }
}

/// Steps 4 and 5: swap the staged protected file in and wipe the plaintext.
fn swap_in(path: &Path, old: &Path, staged: &Path, source_is_old: bool) -> Result<(), StateError> {
    if !source_is_old {
        std::fs::rename(path, old)?;
    }
    if let Err(e) = std::fs::rename(staged, path) {
        if !source_is_old {
            // Put the original back; nothing is lost.
            let _ = std::fs::rename(old, path);
        }
        let _ = std::fs::remove_file(staged);
        return Err(e.into());
    }
    sync_parent_dir(path);
    overwrite_and_remove(old)?;
    Ok(())
}

fn document_locked(keys: &StateKeys, label: Label, path: &Path) -> Result<Outcome, StateError> {
    let old = premigrate(path);
    let (source, source_is_old) = match pick_source(
        path,
        &old,
        || doc::read_document(keys, label, path).is_ok(),
        label,
    )? {
        Ok(s) => s,
        Err(done) => return Ok(done),
    };
    let size = std::fs::metadata(&source)?.len();
    let limit = label.max_document_bytes() as u64;
    if size > limit {
        return Err(StateError::TooLarge { size, limit });
    }
    let plain = Zeroizing::new(std::fs::read(&source)?);
    let staged = doc::stage_document(keys, label, path, &plain)?;
    // Verified round trip before anything is destroyed.
    let back = match doc::read_document_as(keys, label, &staged, &context_of(path)) {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
    };
    if back.len() != plain.len() || !bool::from(back.as_slice().ct_eq(plain.as_slice())) {
        let _ = std::fs::remove_file(&staged);
        return Err(StateError::Migration(
            "protected copy does not match the original".into(),
        ));
    }
    drop(back);
    drop(plain);
    swap_in(path, &old, &staged, source_is_old)?;
    Ok(if source_is_old {
        Outcome::Recovered
    } else {
        Outcome::Migrated
    })
}

/// Feed every non-blank line of a plaintext JSONL file to `f`. Lines longer
/// than a record are skipped and counted.
fn for_each_line(
    max_record: usize,
    path: &Path,
    skipped: &mut usize,
    mut f: impl FnMut(&[u8]) -> Result<(), StateError>,
) -> Result<(), StateError> {
    let limit = max_record as u64 + 2;
    let mut r = BufReader::with_capacity(64 * 1024, File::open(path)?);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let n = (&mut r).take(limit).read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if buf.last() != Some(&b'\n') && n as u64 == limit {
            // Too long: drop the rest of the line without keeping it.
            let mut scrap: Vec<u8> = Vec::new();
            loop {
                scrap.clear();
                let m = (&mut r).take(64 * 1024).read_until(b'\n', &mut scrap)?;
                if m == 0 || scrap.last() == Some(&b'\n') {
                    break;
                }
            }
            *skipped += 1;
            continue;
        }
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        if buf.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        if buf.len() > max_record {
            *skipped += 1;
            continue;
        }
        f(&buf)?;
    }
}

fn digest_step(h: &mut blake3::Hasher, rec: &[u8]) {
    h.update(&(rec.len() as u64).to_le_bytes());
    h.update(rec);
}

fn log_locked(
    keys: &StateKeys,
    label: Label,
    path: &Path,
    skipped: &mut usize,
) -> Result<Outcome, StateError> {
    let old = premigrate(path);
    let (source, source_is_old) = match pick_source(
        path,
        &old,
        || {
            LogReader::open(keys, label, path)
                .map(|r| r.is_some())
                .unwrap_or(false)
        },
        label,
    )? {
        Ok(s) => s,
        Err(done) => return Ok(done),
    };
    let tmp = crate::paths::staged_tmp(path);
    let mut rewrite = LogRewrite::begin(keys, label, path, &tmp)?;
    let mut want = blake3::Hasher::new();
    let mut count = 0u64;
    for_each_line(label.max_record_bytes(), &source, skipped, |line| {
        digest_step(&mut want, line);
        count += 1;
        rewrite.append(line)
    })?;
    let staged = rewrite.finish()?;

    // Verified round trip before anything is destroyed.
    let verify = (|| -> Result<(), StateError> {
        let mut got = blake3::Hasher::new();
        let mut n = 0u64;
        let mut r = LogReader::open(keys, label, &staged)?
            .ok_or_else(|| StateError::Migration("staged log vanished".into()))?;
        while let Some(rec) = r.next_record()? {
            digest_step(&mut got, &rec);
            n += 1;
        }
        if n != count || r.torn_at().is_some() || got.finalize() != want.finalize() {
            return Err(StateError::Migration(
                "protected copy does not match the original".into(),
            ));
        }
        Ok(())
    })();
    if let Err(e) = verify {
        let _ = std::fs::remove_file(&staged);
        return Err(e);
    }
    swap_in(path, &old, &staged, source_is_old)?;
    Ok(if source_is_old {
        Outcome::Recovered
    } else {
        Outcome::Migrated
    })
}

// ─── Whole data directory ───────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum DirKind {
    Data,
    Transfers,
    Directed,
}

fn classify(kind: DirKind, name: &str) -> Option<(Label, Shape)> {
    use crate::paths as p;
    match kind {
        DirKind::Data => {
            if name == p::CONTACTS.name || p::is_contacts_corrupt_name(name) {
                Some((Label::Contacts, Shape::Document))
            } else if name == p::PUSH_HISTORY.name {
                Some((Label::PushHistory, Shape::Log))
            } else if name == p::REPLICATION_WAL.name {
                Some((Label::ReplicationWal, Shape::Log))
            } else if name == p::STORE_INDEX.name {
                Some((Label::StoreIndex, Shape::Document))
            } else if name == p::DESKTOP_PREFS.name {
                Some((Label::DesktopPrefs, Shape::Document))
            } else {
                None
            }
        }
        DirKind::Transfers => {
            if p::is_recv_journal_name(name) {
                Some((Label::TransferJournal, Shape::Document))
            } else if p::is_send_journal_name(name) {
                Some((Label::TransferJournal, Shape::Log))
            } else {
                None
            }
        }
        DirKind::Directed => {
            if p::is_directed_meta_name(name) {
                Some((Label::DirectedMeta, Shape::Document))
            } else {
                None
            }
        }
    }
}

fn collect(data_dir: &Path) -> (Vec<Target>, Vec<PathBuf>) {
    use crate::paths as p;
    let mut targets: Vec<Target> = Vec::new();
    let mut tmps: Vec<PathBuf> = Vec::new();
    let dirs = [
        (data_dir.to_path_buf(), DirKind::Data),
        (p::TRANSFERS_DIR.in_dir(data_dir), DirKind::Transfers),
        (p::DIRECTED_INCOMING.in_dir(data_dir), DirKind::Directed),
        (p::DIRECTED_OUTGOING.in_dir(data_dir), DirKind::Directed),
    ];
    for (dir, kind) in dirs {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let base = name.strip_suffix(p::PREMIGRATE_SUFFIX).unwrap_or(&name);
            if let Some((label, shape)) = classify(kind, base) {
                let path = dir.join(base);
                if !targets.iter().any(|t| t.path == path) {
                    targets.push(Target { path, label, shape });
                }
            } else if (kind == DirKind::Data
                && (name == p::REPLICATION_WAL_TMP.name || name == p::PUSH_HISTORY_TMP.name))
                || (kind == DirKind::Transfers && name.ends_with(".tmp"))
            {
                tmps.push(entry.path());
            }
        }
    }
    (targets, tmps)
}

/// True when [`migrate_data_dir`] would change something.
pub fn needs_migration(data_dir: &Path) -> bool {
    let (targets, tmps) = collect(data_dir);
    targets.iter().any(|t| pending(&t.path))
        || tmps
            .iter()
            .any(|t| matches!(sniff(t), Sniffed::Plain | Sniffed::Empty))
}

/// Convert every plaintext state file in `data_dir`. Safe to run on every
/// start: when everything is converted it only lists a few directories.
///
/// Fails with [`StateError::KeyMissing`] when `master.key` is absent, without
/// reading, writing or creating anything. A file that cannot be converted is
/// listed in the report and left exactly as it was.
pub fn migrate_data_dir(data_dir: &Path) -> Result<MigrationReport, StateError> {
    let keys = StateKeys::load(data_dir)?;
    let mut report = MigrationReport::default();
    if !needs_migration(data_dir) {
        return Ok(report);
    }
    let _lock = lock_in(data_dir)?;
    // Re-scan under the lock: another process may have just finished.
    let (targets, tmps) = collect(data_dir);
    for t in targets {
        let result = match t.shape {
            Shape::Document => document_locked(&keys, t.label, &t.path),
            Shape::Log => log_locked(&keys, t.label, &t.path, &mut report.skipped_lines),
        };
        match result {
            Ok(Outcome::Migrated) => report.migrated += 1,
            Ok(Outcome::Recovered) => report.recovered += 1,
            Ok(Outcome::AlreadyProtected) => report.already_protected += 1,
            Ok(Outcome::Absent | Outcome::RemovedEmpty) => {}
            Err(e) => report.failures.push((t.path, e.to_string())),
        }
    }
    // Plaintext copies left by an interrupted compaction or journal write were
    // never read by any version; wipe them.
    for t in tmps {
        if matches!(sniff(&t), Sniffed::Plain | Sniffed::Empty) {
            match overwrite_and_remove(&t) {
                Ok(()) => report.discarded_leftovers += 1,
                Err(e) => report.failures.push((t, e.to_string())),
            }
        }
    }
    Ok(report)
}
