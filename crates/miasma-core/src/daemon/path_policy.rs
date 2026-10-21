//! Path policy for the daemon-side file endpoints.
//!
//! The HTTP bridge and the control socket accept file paths that the daemon
//! then reads or writes with its own rights.  This module keeps those paths
//! away from the daemon's own data directory (master key, control token,
//! state), resolves them before use, refuses links as the final component, and
//! never replaces an existing file unless the caller asks for it.

use std::{
    io,
    path::{Component, Path, PathBuf},
};

/// Why a path was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathRefusal {
    #[error("the path is inside the daemon's data directory")]
    DataDir,
    #[error("the path is a link; give the real file location")]
    Link,
    #[error("the output file already exists (pass \"overwrite\": true to replace it)")]
    Exists,
    #[error("the parent folder does not exist or cannot be used")]
    Parent,
    #[error("the input file does not exist or is not a regular file")]
    Input,
    #[error("the path has no file name")]
    NoName,
    #[error("the output path is a folder")]
    IsDirectory,
    #[error("cannot prepare the output file: {0}")]
    Io(String),
}

/// An output file the daemon may write.
#[derive(Debug)]
pub struct OutputTarget {
    /// Resolved path to hand to the writer.
    pub path: String,
    /// `true` when this call created (reserved) an empty file at `path`.
    created: bool,
}

impl OutputTarget {
    /// Remove the empty placeholder this call created, if the writer never
    /// got as far as writing to it.  A file that has content is never touched.
    pub fn release_if_unused(&self) {
        if !self.created {
            return;
        }
        if let Ok(m) = std::fs::symlink_metadata(&self.path) {
            if m.is_file() && m.len() == 0 {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

/// Drop the `\\?\` prefix `canonicalize` adds on Windows when the path is a
/// plain drive path, so the daemon reports the path the caller would expect.
fn simplify(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
            return PathBuf::from(rest);
        }
    }
    p
}

/// Canonicalize `path` as far as it exists: the longest existing ancestor is
/// resolved (links and junctions followed) and the remaining names are appended.
fn resolve_lenient(path: &Path) -> PathBuf {
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        match std::fs::canonicalize(&cur) {
            Ok(real) => {
                let mut out = real;
                for name in missing.iter().rev() {
                    out.push(name);
                }
                return out;
            }
            Err(_) => match (cur.parent(), cur.file_name()) {
                (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
                    missing.push(name.to_owned());
                    cur = parent.to_path_buf();
                }
                _ => return path.to_path_buf(),
            },
        }
    }
}

fn normalize(p: &Path) -> PathBuf {
    // `..` cannot occur after resolve_lenient on an existing prefix; drop `.`.
    p.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect()
}

#[cfg(windows)]
fn same_or_inside(path: &Path, dir: &Path) -> bool {
    let a = normalize(path).to_string_lossy().to_lowercase();
    let b = normalize(dir).to_string_lossy().to_lowercase();
    Path::new(&a).starts_with(Path::new(&b))
}

#[cfg(not(windows))]
fn same_or_inside(path: &Path, dir: &Path) -> bool {
    normalize(path).starts_with(normalize(dir))
}

/// Refuse `path` when it is, or resolves to a place inside, `data_dir`.
/// Works for paths that do not exist yet (the existing ancestor is resolved).
pub fn refuse_data_dir(path: &Path, data_dir: &Path) -> Result<(), PathRefusal> {
    let dir = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let real = resolve_lenient(path);
    if same_or_inside(&real, &dir) || same_or_inside(&simplify(real), &simplify(dir)) {
        Err(PathRefusal::DataDir)
    } else {
        Ok(())
    }
}

/// Whether the entry at `path` is a symlink, junction or other reparse point.
fn is_link(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// A file the daemon is asked to read: it must exist, be a regular file, and
/// resolve to somewhere outside the data directory.  Returns the resolved path.
pub fn resolve_input(path: &str, data_dir: &Path) -> Result<String, PathRefusal> {
    let real = std::fs::canonicalize(path).map_err(|_| PathRefusal::Input)?;
    let real = simplify(real);
    refuse_data_dir(&real, data_dir)?;
    match std::fs::metadata(&real) {
        Ok(m) if m.is_file() => Ok(real.to_string_lossy().into_owned()),
        _ => Err(PathRefusal::Input),
    }
}

/// A file the daemon is asked to write.  The parent folder must exist; it is
/// resolved (links and junctions followed) and checked against the data
/// directory.  A link as the last component is refused.  Unless `overwrite`,
/// an existing file is refused and the file is created empty here with
/// create-new semantics, so nothing can appear at the path between this check
/// and the writer's open.
pub fn reserve_output(
    path: &str,
    data_dir: &Path,
    overwrite: bool,
) -> Result<OutputTarget, PathRefusal> {
    let requested = Path::new(path);
    let name = requested.file_name().ok_or(PathRefusal::NoName)?;
    let parent = requested.parent().ok_or(PathRefusal::Parent)?;
    let real_parent = std::fs::canonicalize(parent).map_err(|_| PathRefusal::Parent)?;
    if !std::fs::metadata(&real_parent)
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return Err(PathRefusal::Parent);
    }
    let real = simplify(real_parent).join(name);
    refuse_data_dir(&real, data_dir)?;

    match std::fs::symlink_metadata(&real) {
        Ok(m) => {
            if is_link(&m) {
                return Err(PathRefusal::Link);
            }
            if m.is_dir() {
                return Err(PathRefusal::IsDirectory);
            }
            if !overwrite {
                return Err(PathRefusal::Exists);
            }
            Ok(OutputTarget {
                path: real.to_string_lossy().into_owned(),
                created: false,
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let created = if overwrite {
                false
            } else {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&real)
                {
                    Ok(_) => true,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(PathRefusal::Exists)
                    }
                    Err(e) => return Err(PathRefusal::Io(e.kind().to_string())),
                }
            };
            Ok(OutputTarget {
                path: real.to_string_lossy().into_owned(),
                created,
            })
        }
        Err(e) => Err(PathRefusal::Io(e.kind().to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let other = root.path().join("other");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        (root, data, other)
    }

    #[test]
    fn data_dir_is_refused_for_existing_and_new_names() {
        let (_r, data, other) = dirs();
        std::fs::write(data.join("state.bin"), b"x").unwrap();
        assert_eq!(
            refuse_data_dir(&data.join("state.bin"), &data),
            Err(PathRefusal::DataDir)
        );
        assert_eq!(
            refuse_data_dir(&data.join("sub").join("new.bin"), &data),
            Err(PathRefusal::DataDir)
        );
        assert!(refuse_data_dir(&other.join("a.bin"), &data).is_ok());
    }

    #[test]
    fn input_inside_the_data_dir_is_refused_and_outside_is_resolved() {
        let (_r, data, other) = dirs();
        std::fs::write(data.join("state.bin"), b"x").unwrap();
        std::fs::write(other.join("in.bin"), b"x").unwrap();
        assert_eq!(
            resolve_input(data.join("state.bin").to_str().unwrap(), &data),
            Err(PathRefusal::DataDir)
        );
        assert!(resolve_input(other.join("in.bin").to_str().unwrap(), &data).is_ok());
        assert_eq!(
            resolve_input(other.join("missing.bin").to_str().unwrap(), &data),
            Err(PathRefusal::Input)
        );
        assert_eq!(
            resolve_input(other.to_str().unwrap(), &data),
            Err(PathRefusal::Input)
        );
    }

    #[test]
    fn output_is_created_new_and_an_existing_file_is_refused() {
        let (_r, data, other) = dirs();
        let p = other.join("out.bin");
        let t = reserve_output(p.to_str().unwrap(), &data, false).unwrap();
        assert!(p.exists());
        assert_eq!(
            reserve_output(p.to_str().unwrap(), &data, false).unwrap_err(),
            PathRefusal::Exists
        );
        // The placeholder is removed when the writer never used it.
        t.release_if_unused();
        assert!(!p.exists());
        // With the flag an existing file is accepted and left alone.
        std::fs::write(&p, b"keep").unwrap();
        let t = reserve_output(p.to_str().unwrap(), &data, true).unwrap();
        t.release_if_unused();
        assert_eq!(std::fs::read(&p).unwrap(), b"keep");
    }

    #[test]
    fn release_never_removes_a_file_with_content() {
        let (_r, data, other) = dirs();
        let p = other.join("out.bin");
        let t = reserve_output(p.to_str().unwrap(), &data, false).unwrap();
        std::fs::write(&p, b"data").unwrap();
        t.release_if_unused();
        assert!(p.exists());
    }

    #[test]
    fn output_in_the_data_dir_or_a_missing_parent_is_refused() {
        let (_r, data, other) = dirs();
        assert_eq!(
            reserve_output(data.join("x.bin").to_str().unwrap(), &data, true).unwrap_err(),
            PathRefusal::DataDir
        );
        assert_eq!(
            reserve_output(
                other.join("no").join("x.bin").to_str().unwrap(),
                &data,
                true
            )
            .unwrap_err(),
            PathRefusal::Parent
        );
        assert!(!data.join("x.bin").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_cannot_reach_the_data_dir_or_be_replaced() {
        use std::os::unix::fs::symlink;
        let (_r, data, other) = dirs();
        std::fs::write(data.join("secret.bin"), b"s").unwrap();
        // Directory link into the data dir.
        symlink(&data, other.join("dirlink")).unwrap();
        let via = other.join("dirlink").join("new.bin");
        assert_eq!(
            reserve_output(via.to_str().unwrap(), &data, true).unwrap_err(),
            PathRefusal::DataDir
        );
        let via_in = other.join("dirlink").join("secret.bin");
        assert_eq!(
            resolve_input(via_in.to_str().unwrap(), &data),
            Err(PathRefusal::DataDir)
        );
        // File link as the last component.
        symlink(data.join("secret.bin"), other.join("filelink")).unwrap();
        assert_eq!(
            reserve_output(other.join("filelink").to_str().unwrap(), &data, true).unwrap_err(),
            PathRefusal::Link
        );
        assert_eq!(
            resolve_input(other.join("filelink").to_str().unwrap(), &data),
            Err(PathRefusal::DataDir)
        );
        assert_eq!(std::fs::read(data.join("secret.bin")).unwrap(), b"s");
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_cannot_reach_the_data_dir() {
        let (_r, data, other) = dirs();
        std::fs::write(data.join("secret.bin"), b"s").unwrap();
        let link = other.join("junc");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&data)
            .output();
        if !matches!(status, Ok(ref o) if o.status.success()) {
            return; // junction creation unavailable here
        }
        assert_eq!(
            reserve_output(link.join("new.bin").to_str().unwrap(), &data, true).unwrap_err(),
            PathRefusal::DataDir
        );
        assert_eq!(
            resolve_input(link.join("secret.bin").to_str().unwrap(), &data),
            Err(PathRefusal::DataDir)
        );
        // Remove only the junction itself.
        let _ = std::fs::remove_dir(&link);
        assert!(data.join("secret.bin").exists());
    }
}
