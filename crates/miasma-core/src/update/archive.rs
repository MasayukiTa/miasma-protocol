//! Reading a release zip safely.
//!
//! The archive was already checked against `SHA256SUMS.txt`, but it is still
//! treated as hostile: every entry name is checked (no `..`, no absolute path,
//! no drive letter or alternate data stream, no symbolic link), the number and
//! size of entries are capped, and only the files the updater asks for are
//! written. Entries are streamed to disk in 64 KiB pieces.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Most entries an archive may have.
pub const MAX_ENTRIES: usize = 20_000;
/// Largest single entry, in bytes.
pub const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
/// Largest sum of all entries, in bytes.
pub const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    /// An entry name that would leave the target folder (or is not a plain
    /// relative path).
    Unsafe(String),
    /// A symbolic link inside the archive.
    Symlink(String),
    TooMany,
    TooBig,
    /// A wanted file is not in the archive.
    Missing(String),
    /// The same wanted file appears twice at the same depth.
    Ambiguous(String),
    Corrupt(String),
    Io(String),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsafe(n) => write!(f, "the archive contains an unsafe path: {n}"),
            Self::Symlink(n) => write!(f, "the archive contains a symbolic link: {n}"),
            Self::TooMany => f.write_str("the archive has too many entries"),
            Self::TooBig => f.write_str("the archive unpacks to more than allowed"),
            Self::Missing(n) => write!(f, "the archive does not contain {n}"),
            Self::Ambiguous(n) => write!(f, "the archive contains {n} more than once"),
            Self::Corrupt(m) => write!(f, "the archive is damaged: {m}"),
            Self::Io(m) => write!(f, "cannot write the update files: {m}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// An entry name as a relative path with plain components, or an error.
///
/// Both `/` and `\` separate components (an archive made on Windows may use
/// either). Empty and `.` components are dropped; `..` anywhere, a leading
/// separator, a `:` (drive letter, `file:stream`) or a NUL byte is refused.
pub fn safe_relative(name: &str) -> Result<PathBuf, ArchiveError> {
    let bad = || ArchiveError::Unsafe(name.chars().take(80).collect());
    if name.is_empty() || name.contains('\0') || name.contains(':') {
        return Err(bad());
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(bad());
    }
    let mut out = PathBuf::new();
    for part in name.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => return Err(bad()),
            p => out.push(p),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(bad());
    }
    Ok(out)
}

fn is_symlink(mode: Option<u32>) -> bool {
    mode.is_some_and(|m| m & 0o170000 == 0o120000)
}

/// Entries that archivers add on their own and that are never extracted.
fn is_junk(name: &str) -> bool {
    name.starts_with("__MACOSX/") || name.ends_with(".DS_Store")
}

pub struct Archive {
    zip: zip::ZipArchive<File>,
    /// (index, safe relative path, size, is dir, unix mode)
    entries: Vec<Entry>,
}

#[derive(Debug, Clone)]
struct Entry {
    index: usize,
    path: PathBuf,
    size: u64,
    dir: bool,
    mode: Option<u32>,
}

impl Archive {
    /// Open `path` and check every entry. Nothing is written.
    pub fn open(path: &Path) -> Result<Self, ArchiveError> {
        let file = File::open(path).map_err(|e| ArchiveError::Io(e.to_string()))?;
        let mut zip =
            zip::ZipArchive::new(file).map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        if zip.len() > MAX_ENTRIES {
            return Err(ArchiveError::TooMany);
        }
        let mut entries = Vec::with_capacity(zip.len());
        let mut total: u64 = 0;
        for i in 0..zip.len() {
            let f = zip
                .by_index(i)
                .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
            let name = f
                .name()
                .map_err(|e| ArchiveError::Corrupt(e.to_string()))?
                .into_owned();
            let rel = safe_relative(&name)?;
            if is_symlink(f.unix_mode()) {
                return Err(ArchiveError::Symlink(name));
            }
            if f.size() > MAX_ENTRY_BYTES {
                return Err(ArchiveError::TooBig);
            }
            total = total.saturating_add(f.size());
            if total > MAX_TOTAL_BYTES {
                return Err(ArchiveError::TooBig);
            }
            entries.push(Entry {
                index: i,
                path: rel,
                size: f.size(),
                dir: f.is_dir(),
                mode: f.unix_mode(),
            });
        }
        Ok(Self { zip, entries })
    }

    /// Relative paths of all entries (for tests and diagnostics).
    pub fn names(&self) -> Vec<PathBuf> {
        self.entries.iter().map(|e| e.path.clone()).collect()
    }

    fn write_entry(&mut self, e: &Entry, dest: &Path) -> Result<String, ArchiveError> {
        let mut f = self
            .zip
            .by_index(e.index)
            .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        let mut out = File::create(dest).map_err(|e| ArchiveError::Io(e.to_string()))?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut written: u64 = 0;
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > MAX_ENTRY_BYTES.min(e.size.saturating_add(1)) {
                return Err(ArchiveError::TooBig);
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])
                .map_err(|e| ArchiveError::Io(e.to_string()))?;
        }
        out.flush().map_err(|e| ArchiveError::Io(e.to_string()))?;
        drop(out);
        set_mode(dest, e.mode, false)?;
        Ok(hex::encode(h.finalize()))
    }

    /// Extract the programs called `wanted` (matched on the last path
    /// component, found at the shallowest depth) into `dest_dir` as
    /// `<name><suffix>`. Every name must be found.
    pub fn extract_named(
        &mut self,
        wanted: &[&str],
        dest_dir: &Path,
        suffix: &str,
    ) -> Result<Vec<Extracted>, ArchiveError> {
        let mut out = Vec::new();
        for name in wanted {
            let mut hits: Vec<Entry> = self
                .entries
                .iter()
                .filter(|e| !e.dir)
                .filter(|e| !is_junk(&e.path.to_string_lossy().replace('\\', "/")))
                .filter(|e| e.path.file_name().is_some_and(|n| n == *name))
                .cloned()
                .collect();
            hits.sort_by_key(|e| e.path.components().count());
            let Some(best) = hits.first().cloned() else {
                return Err(ArchiveError::Missing((*name).to_owned()));
            };
            if hits
                .get(1)
                .is_some_and(|h| h.path.components().count() == best.path.components().count())
            {
                return Err(ArchiveError::Ambiguous((*name).to_owned()));
            }
            let dest = dest_dir.join(format!("{name}{suffix}"));
            let sha256 = self.write_entry(&best, &dest)?;
            set_mode(&dest, best.mode, true)?;
            out.push(Extracted {
                name: (*name).to_owned(),
                path: dest,
                sha256,
            });
        }
        Ok(out)
    }

    /// Extract the folder `top` (for example `Miasma.app`) with everything below
    /// it into `dest_dir` (which is created). Entries outside `top` are an error
    /// unless they are archiver junk.
    pub fn extract_tree(&mut self, top: &str, dest_dir: &Path) -> Result<u64, ArchiveError> {
        std::fs::create_dir_all(dest_dir).map_err(|e| ArchiveError::Io(e.to_string()))?;
        let entries = self.entries.clone();
        let mut count = 0u64;
        let mut saw_top = false;
        for e in &entries {
            let slashed = e.path.to_string_lossy().replace('\\', "/");
            if is_junk(&slashed) {
                continue;
            }
            let Ok(rest) = e.path.strip_prefix(top) else {
                return Err(ArchiveError::Unsafe(slashed));
            };
            saw_top = true;
            if rest.as_os_str().is_empty() {
                continue;
            }
            let target = dest_dir.join(rest);
            if e.dir {
                std::fs::create_dir_all(&target).map_err(|e| ArchiveError::Io(e.to_string()))?;
                continue;
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| ArchiveError::Io(e.to_string()))?;
            }
            self.write_entry(e, &target)?;
            count += 1;
        }
        if !saw_top || count == 0 {
            return Err(ArchiveError::Missing(top.to_owned()));
        }
        Ok(count)
    }
}

/// One file written by [`Archive::extract_named`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub name: String,
    pub path: PathBuf,
    pub sha256: String,
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: Option<u32>, program: bool) -> Result<(), ArchiveError> {
    use std::os::unix::fs::PermissionsExt;
    // Keep the executable bits the archive recorded; a program the updater was
    // asked for is executable even if the archive lost the bit (zip artifacts
    // from CI do). Never setuid/setgid/sticky.
    let mut m = mode.unwrap_or(0o644) & 0o755;
    if program {
        m |= 0o755;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(m))
        .map_err(|e| ArchiveError::Io(e.to_string()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: Option<u32>, _program: bool) -> Result<(), ArchiveError> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::io::Write;
    use std::path::Path;
    use zip::write::SimpleFileOptions;

    /// Write a zip with the given (name, content) entries. A name ending in `/`
    /// is a directory.
    pub fn make_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let f = std::fs::File::create(path).unwrap();
        let mut z = zip::ZipWriter::new(f);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o755);
        for (name, data) in entries {
            if name.ends_with('/') {
                z.add_directory(*name, opts).unwrap();
            } else {
                z.start_file(*name, opts).unwrap();
                z.write_all(data).unwrap();
            }
        }
        z.finish().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::make_zip;
    use super::*;

    #[test]
    fn plain_relative_names_pass() {
        assert_eq!(
            safe_relative("miasma.exe").unwrap(),
            PathBuf::from("miasma.exe")
        );
        assert_eq!(
            safe_relative("miasma-0.4.0/miasma.exe").unwrap(),
            PathBuf::from("miasma-0.4.0").join("miasma.exe")
        );
        assert_eq!(
            safe_relative("a\\b/./c").unwrap(),
            PathBuf::from("a").join("b").join("c")
        );
    }

    #[test]
    fn traversal_and_absolute_names_are_rejected() {
        for bad in [
            "",
            "../evil.exe",
            "a/../../evil.exe",
            "a\\..\\evil",
            "/etc/passwd",
            "\\windows\\system32\\x.dll",
            "C:\\x.exe",
            "c:/x.exe",
            "miasma.exe:stream",
            "a\0b",
            "..",
            "./",
        ] {
            assert!(
                matches!(safe_relative(bad), Err(ArchiveError::Unsafe(_))),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn an_archive_with_one_bad_entry_is_refused_whole() {
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("a.zip");
        make_zip(&z, &[("miasma.exe", b"ok"), ("../escape.txt", b"x")]);
        assert!(matches!(Archive::open(&z), Err(ArchiveError::Unsafe(_))));
        // Nothing was written next to the archive.
        assert!(!dir.path().join("escape.txt").exists());
        assert!(!dir.path().parent().unwrap().join("escape.txt").exists());
    }

    #[test]
    fn wanted_programs_are_found_at_any_shallow_depth_and_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("a.zip");
        make_zip(
            &z,
            &[
                ("miasma-0.4.0/", b""),
                ("miasma-0.4.0/miasma.exe", b"cli"),
                ("miasma-0.4.0/miasma-desktop.exe", b"gui"),
                ("miasma-0.4.0/README.txt", b"not wanted"),
            ],
        );
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let mut a = Archive::open(&z).unwrap();
        let got = a
            .extract_named(&["miasma.exe", "miasma-desktop.exe"], &out, ".new")
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(std::fs::read(out.join("miasma.exe.new")).unwrap(), b"cli");
        assert_eq!(got[0].sha256, super::super::verify::sha256_bytes(b"cli"));
        // Unwanted files are not written.
        assert!(!out.join("README.txt").exists());
    }

    #[test]
    fn a_missing_program_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("a.zip");
        make_zip(&z, &[("miasma.exe", b"cli")]);
        let mut a = Archive::open(&z).unwrap();
        assert_eq!(
            a.extract_named(&["miasma.exe", "miasma-desktop.exe"], dir.path(), ".new"),
            Err(ArchiveError::Missing("miasma-desktop.exe".into()))
        );
    }

    #[test]
    fn the_same_program_twice_at_the_same_depth_is_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("a.zip");
        make_zip(&z, &[("a/miasma.exe", b"1"), ("b/miasma.exe", b"2")]);
        let mut a = Archive::open(&z).unwrap();
        assert_eq!(
            a.extract_named(&["miasma.exe"], dir.path(), ".new"),
            Err(ArchiveError::Ambiguous("miasma.exe".into()))
        );
    }

    #[test]
    fn a_bundle_tree_is_extracted_and_stray_entries_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("app.zip");
        make_zip(
            &z,
            &[
                ("Miasma.app/", b""),
                ("Miasma.app/Contents/", b""),
                ("Miasma.app/Contents/Info.plist", b"plist"),
                ("Miasma.app/Contents/MacOS/miasma", b"cli"),
                ("__MACOSX/._Miasma.app", b"junk"),
            ],
        );
        let out = dir.path().join("Miasma.app.new");
        let mut a = Archive::open(&z).unwrap();
        assert_eq!(a.extract_tree("Miasma.app", &out).unwrap(), 2);
        assert_eq!(
            std::fs::read(out.join("Contents").join("MacOS").join("miasma")).unwrap(),
            b"cli"
        );

        let z2 = dir.path().join("stray.zip");
        make_zip(
            &z2,
            &[("Miasma.app/Contents/Info.plist", b"p"), ("evil.sh", b"x")],
        );
        let mut a2 = Archive::open(&z2).unwrap();
        assert!(matches!(
            a2.extract_tree("Miasma.app", &dir.path().join("o2")),
            Err(ArchiveError::Unsafe(_))
        ));
    }

    #[test]
    fn a_symbolic_link_entry_refuses_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("link.zip");
        {
            let f = std::fs::File::create(&z).unwrap();
            let mut w = zip::ZipWriter::new(f);
            let o = zip::write::SimpleFileOptions::default();
            w.start_file("miasma.exe", o).unwrap();
            w.write_all(b"cli").unwrap();
            w.add_symlink("evil", "/etc/passwd", o).unwrap();
            w.finish().unwrap();
        }
        assert!(matches!(Archive::open(&z), Err(ArchiveError::Symlink(_))));
    }

    #[test]
    fn a_damaged_archive_is_reported_not_panicked_on() {
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("bad.zip");
        std::fs::write(&z, b"PK this is not a zip").unwrap();
        assert!(matches!(Archive::open(&z), Err(ArchiveError::Corrupt(_))));
        assert!(matches!(
            Archive::open(&dir.path().join("none.zip")),
            Err(ArchiveError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn programs_come_out_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("a.zip");
        make_zip(&z, &[("miasma", b"cli")]);
        let mut a = Archive::open(&z).unwrap();
        let got = a.extract_named(&["miasma"], dir.path(), ".new").unwrap();
        let mode = std::fs::metadata(&got[0].path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }
}
