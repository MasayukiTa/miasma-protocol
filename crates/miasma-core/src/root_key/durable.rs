//! Crash-safe writes for the key files.
//!
//! Every file is written in full to a uniquely named restricted temporary file
//! beside it, flushed to disk, and only then moved into place; the directory is
//! flushed afterwards. A reader sees the old file or the new one, never half of
//! either.
//!
//! The temporary name is the whole target name plus a random part plus
//! `.sec.tmp`. It is not made with `Path::with_extension`: that replaces the
//! extension, so `master.key` and `master.key.enc` would share one temporary
//! name and two writers could overwrite each other's staging file.

use std::io;
use std::path::{Path, PathBuf};

use crate::state_crypto::{fsync_path, sync_parent_dir};

fn to_io(e: crate::MiasmaError) -> io::Error {
    match e {
        crate::MiasmaError::Io(io) => io,
        other => io::Error::other(other.to_string()),
    }
}

/// A fresh temporary name for `target`, in the same directory.
pub(super) fn unique_tmp(target: &Path) -> PathBuf {
    let mut r = [0u8; 6];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut r);
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let mut name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{hex}"));
    let tmp = target.with_file_name(name);
    crate::paths::staged_tmp(&tmp)
}

/// Write `bytes` to a new restricted temporary file beside `target` and make
/// them durable. Returns the temporary path.
pub(super) fn stage(target: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    let tmp = unique_tmp(target);
    let result = crate::secure_file::write_restricted(&tmp, bytes)
        .map_err(to_io)
        .and_then(|()| fsync_path(&tmp));
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(tmp)
}

/// Move a staged file over `target` (replacing it atomically) and flush the
/// directory.
pub(super) fn replace_with(tmp: &Path, target: &Path) -> io::Result<()> {
    std::fs::rename(tmp, target).inspect_err(|_| {
        let _ = std::fs::remove_file(tmp);
    })?;
    sync_parent_dir(target);
    Ok(())
}

/// Give a staged file the name `target` only if nothing has that name. Returns
/// `true` when this call created `target`, `false` when it already existed (the
/// existing file is left alone). The staged file is always removed.
pub(super) fn link_into_place(tmp: &Path, target: &Path) -> io::Result<bool> {
    let linked = std::fs::hard_link(tmp, target);
    let _ = std::fs::remove_file(tmp);
    match linked {
        Ok(()) => {
            sync_parent_dir(target);
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Create `target` with `bytes` only if it does not exist (see
/// [`link_into_place`]).
pub(super) fn write_new(target: &Path, bytes: &[u8]) -> io::Result<bool> {
    let tmp = stage(target, bytes)?;
    link_into_place(&tmp, target)
}

/// Give `existing` a second name. If the file system cannot link, copy it.
pub(super) fn link_or_copy(existing: &Path, second: &Path) -> io::Result<()> {
    match std::fs::hard_link(existing, second) {
        Ok(()) => Ok(()),
        Err(_) => {
            let bytes = zeroize::Zeroizing::new(std::fs::read(existing)?);
            crate::secure_file::write_restricted(second, &bytes).map_err(to_io)?;
            fsync_path(second)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_names_do_not_collide_across_similar_targets() {
        let d = Path::new("D");
        let a = unique_tmp(&d.join("master.key"));
        let b = unique_tmp(&d.join("master.key.enc"));
        let c = unique_tmp(&d.join("master.key"));
        assert_ne!(a, b);
        assert_ne!(a, c);
        for p in [&a, &b] {
            assert!(p.to_string_lossy().ends_with(".sec.tmp"));
        }
        assert!(a
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("master.key."));
    }

    #[test]
    fn replace_and_create_never_leave_a_staging_file() {
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("x.bin");
        assert!(write_new(&t, b"one").unwrap());
        assert!(!write_new(&t, b"two").unwrap());
        assert_eq!(std::fs::read(&t).unwrap(), b"one");
        replace_with(&stage(&t, b"three").unwrap(), &t).unwrap();
        assert_eq!(std::fs::read(&t).unwrap(), b"three");
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }
}
