//! Wiping the key files without opening the key.
//!
//! The wipe never reads the key. It lists what to remove from the persisted-paths
//! registry ([`crate::paths::wipe_key_files`]), writes a `wipe.pending` marker
//! first and removes it last. If the program stops in between, the next call to
//! [`get`](super::get) finishes the wipe instead of opening anything.
//!
//! Every step is attempted even when an earlier one failed; the report says
//! which did. This is a logical erase: it overwrites and removes the files and
//! does not promise that old storage blocks (for example on an SSD) are
//! physically overwritten.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::RootKeyError;
use crate::MiasmaError;

/// Directories with a wipe running in this process.
static RUNNING: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn keys_of(dir: &Path) -> Vec<PathBuf> {
    let mut v = vec![dir.to_path_buf()];
    if let Ok(c) = std::fs::canonicalize(dir) {
        if c != v[0] {
            v.push(c);
        }
    }
    v
}

pub(super) struct Running(Vec<PathBuf>);

impl Running {
    pub(super) fn enter(dir: &Path) -> Self {
        let keys = keys_of(dir);
        RUNNING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(keys.iter().cloned());
        Running(keys)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let mut g = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
        for k in &self.0 {
            if let Some(i) = g.iter().position(|p| p == k) {
                g.remove(i);
            }
        }
    }
}

fn is_running(dir: &Path) -> bool {
    let keys = keys_of(dir);
    let g = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    g.iter().any(|p| keys.contains(p))
}

/// What a wipe did.
#[derive(Debug, Default)]
pub struct WipeReport {
    /// Root key and state key handles erased in memory.
    pub erased_live_keys: usize,
    /// Key files that were present and are gone now.
    pub key_files_removed: usize,
    /// One line per step that failed.
    pub errors: Vec<String>,
}

impl WipeReport {
    pub fn is_complete(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn into_result(self) -> Result<(), MiasmaError> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(MiasmaError::Storage(format!(
                "distress wipe incomplete: {}",
                self.errors.join("; ")
            )))
        }
    }
}

fn present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Erase the key material of `data_dir` and scrub the secrets in its
/// configuration. Never opens the key, so it works when the key is damaged or
/// cannot be opened.
pub fn wipe_data_dir(data_dir: &Path) -> WipeReport {
    let mut report = WipeReport::default();
    if !data_dir.exists() {
        return report;
    }
    let _running = Running::enter(data_dir);
    let marker = crate::paths::WIPE_PENDING.in_dir(data_dir);

    // 1. Mark the wipe as started, so an interruption is finished later.
    if let Err(e) = crate::secure_file::write_restricted(&marker, b"wipe\n") {
        report
            .errors
            .push(format!("write {}: {e}", crate::paths::WIPE_PENDING.name));
    } else if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&marker) {
        let _ = f.sync_all();
    }

    // 2. Keys held in memory.
    report.erased_live_keys = super::erase_cached(data_dir);
    report.erased_live_keys += crate::state_crypto::erase_state_keys(data_dir);

    // 3. Whatever the provider keeps outside the data directory.
    if let Err(e) = super::current_provider().destroy(data_dir) {
        report.errors.push(format!("destroy provider key: {e}"));
    }

    // 4. The key files named by the registry. Both the overwrite and the
    //    removal are always attempted: a failed overwrite (a locked or
    //    read-only file) must not leave the key on disk when it can still be
    //    removed.
    for path in crate::paths::wipe_key_files(data_dir) {
        if !present(&path) {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::metadata(&path) {
            Ok(m) => {
                let zeros = vec![0u8; m.len() as usize];
                if let Err(e) = crate::store::atomic_write(&path, &zeros) {
                    report.errors.push(format!("erase {name}: {e}"));
                }
            }
            Err(e) => report.errors.push(format!("inspect {name}: {e}")),
        }
        match std::fs::remove_file(&path) {
            Ok(()) => report.key_files_removed += 1,
            Err(e) => report.errors.push(format!("remove erased {name}: {e}")),
        }
    }

    // 4b. The chat records kept outside the data directory go with the key.
    crate::chat::anchor::wipe_for(data_dir);

    // 5. Persisted transport secrets in config.toml. A parse or save failure
    //    is a wipe failure, never advisory.
    let config_path = crate::paths::config_file(data_dir);
    if config_path.exists() {
        match crate::config::NodeConfig::load(data_dir) {
            Ok(mut config) => {
                if config.has_persisted_secrets() {
                    if let Err(e) = config.scrub_credentials(data_dir) {
                        report.errors.push(format!("scrub transport secrets: {e}"));
                    }
                }
            }
            Err(e) => report
                .errors
                .push(format!("load config for proxy credential scrub: {e}")),
        }
    }

    // 6. The marker goes last, and only when no key file is left.
    let left = crate::paths::wipe_key_files(data_dir)
        .iter()
        .filter(|p| present(p))
        .count();
    if left == 0 {
        if let Err(e) = std::fs::remove_file(&marker) {
            if e.kind() != std::io::ErrorKind::NotFound {
                report
                    .errors
                    .push(format!("remove {}: {e}", crate::paths::WIPE_PENDING.name));
            }
        }
    } else {
        report
            .errors
            .push(format!("{left} key file(s) could not be removed"));
    }
    report
}

/// Finish a wipe that was interrupted (its marker is still there). Returns
/// `Ok` when there is nothing pending. Never opens the key.
pub(super) fn finish_pending(data_dir: &Path) -> Result<(), RootKeyError> {
    let marker = crate::paths::WIPE_PENDING.in_dir(data_dir);
    if !present(&marker) {
        return Ok(());
    }
    // A wipe that is running right now owns the marker.
    if is_running(data_dir) {
        return Err(RootKeyError::WipePending);
    }
    let _ = wipe_data_dir(data_dir);
    if present(&marker) {
        Err(RootKeyError::WipePending)
    } else {
        Err(RootKeyError::Wiped)
    }
}
