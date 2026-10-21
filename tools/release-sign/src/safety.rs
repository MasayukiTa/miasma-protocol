//! Where a new secret key may be written.
//!
//! A signing key must not land in a git work tree (it would be one `git add`
//! from a public repository) or in a folder that a sync client uploads.

use std::path::{Path, PathBuf};

/// Folder-name fragments that identify a sync client's folder.
const SYNC_SUBSTRINGS: &[&str] = &[
    "onedrive",
    "dropbox",
    "icloud",
    "google drive",
    "googledrive",
    "nextcloud",
    "owncloud",
    "pcloud",
    "syncthing",
    "resilio",
    "mobile documents",
];

/// Folder names that identify a sync client only when they are the whole name.
const SYNC_EXACT: &[&str] = &["mega", "box", "box sync", "sync"];

/// Files that a sync client leaves in the root of its folder.
const SYNC_MARKER_FILES: &[&str] = &[".stfolder", ".dropbox", ".dropbox.cache", ".nextcloudsync.log"];

/// Environment variables that name a OneDrive root.
const ONEDRIVE_ENV: &[&str] = &["OneDrive", "OneDriveConsumer", "OneDriveCommercial"];

fn nearest_existing(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    while !p.exists() {
        if !p.pop() {
            break;
        }
    }
    p
}

/// `Ok(())` if a key may be written under `dir`; otherwise the reason.
///
/// `dir` does not need to exist yet: the nearest existing parent is checked.
pub fn check_output_dir(dir: &Path) -> Result<(), String> {
    let abs = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(dir)
    };
    let existing = nearest_existing(&abs);
    let resolved = existing.canonicalize().map_err(|e| e.to_string())?;

    for anc in resolved.ancestors() {
        if anc.join(".git").exists() {
            return Err(format!(
                "{} is inside a git repository (found .git in {})",
                dir.display(),
                anc.display()
            ));
        }
        for m in SYNC_MARKER_FILES {
            if anc.join(m).exists() {
                return Err(format!(
                    "{} looks like a synchronised folder (found {m} in {})",
                    dir.display(),
                    anc.display()
                ));
            }
        }
    }

    for c in resolved.components() {
        let name = c.as_os_str().to_string_lossy().to_lowercase();
        if SYNC_EXACT.contains(&name.as_str()) || SYNC_SUBSTRINGS.iter().any(|s| name.contains(s)) {
            return Err(format!(
                "{} is under a folder that looks synchronised ({})",
                dir.display(),
                c.as_os_str().to_string_lossy()
            ));
        }
    }

    for var in ONEDRIVE_ENV {
        if let Ok(root) = std::env::var(var) {
            if root.is_empty() {
                continue;
            }
            if let Ok(root) = Path::new(&root).canonicalize() {
                if resolved.starts_with(&root) {
                    return Err(format!(
                        "{} is under the OneDrive folder {}",
                        dir.display(),
                        root.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_temp_dir_is_accepted() {
        let t = tempfile::tempdir().unwrap();
        // The temporary root itself must not be inside a repository or a
        // synchronised folder for this test to mean anything.
        if check_output_dir(t.path()).is_err() {
            return;
        }
        assert!(check_output_dir(&t.path().join("new").join("sub")).is_ok());
    }

    #[test]
    fn git_work_tree_is_refused_even_for_a_dir_not_yet_created() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join(".git")).unwrap();
        assert!(check_output_dir(t.path()).unwrap_err().contains("git"));
        assert!(check_output_dir(&t.path().join("keys").join("a"))
            .unwrap_err()
            .contains("git"));
    }

    #[test]
    fn sync_folder_names_and_markers_are_refused() {
        let t = tempfile::tempdir().unwrap();
        for name in ["OneDrive - Company", "Dropbox", "iCloudDrive", "Google Drive", "MEGA", "Box"] {
            let d = t.path().join(name).join("keys");
            std::fs::create_dir_all(&d).unwrap();
            assert!(check_output_dir(&d).is_err(), "{name}");
        }
        let marked = t.path().join("plain");
        std::fs::create_dir_all(&marked).unwrap();
        std::fs::create_dir(marked.join(".stfolder")).unwrap();
        assert!(check_output_dir(&marked).is_err());
    }

    #[test]
    fn a_name_that_merely_contains_a_short_marker_is_fine() {
        let t = tempfile::tempdir().unwrap();
        if check_output_dir(t.path()).is_err() {
            return;
        }
        let ok = t.path().join("omega");
        std::fs::create_dir_all(&ok).unwrap();
        assert!(check_output_dir(&ok).is_ok());
    }
}
