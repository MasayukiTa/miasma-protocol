//! Log files written by earlier versions, and their one-time removal.
//!
//! Earlier versions wrote `daemon.log.<date>`, `desktop.log.<date>` and
//! `bridge.log.<date>` next to the node's data. They show when the programs
//! were used, so after an upgrade the user is told once and the files are
//! removed (overwritten with zeros, then deleted) unless the user keeps them.
//!
//! The decision lives in `[privacy]` of the node configuration:
//! `old_logs_notice_shown` (the notice has been presented) and
//! `old_logs_keep` (the user chose to keep the files). Nothing is removed
//! before the notice has been shown once.

use std::path::{Path, PathBuf};

use crate::config::NodeConfig;
use crate::paths;

use super::diag::secure_remove;

/// Set to `1` to keep old log files on a machine without a window to show the
/// notice in.
pub const KEEP_ENV: &str = "MIASMA_KEEP_OLD_LOGS";

/// Set by the desktop app when it starts the daemon: the app shows the notice
/// itself, so the daemon leaves old logs alone.
pub const GUI_NOTICE_ENV: &str = "MIASMA_LEGACY_LOGS_NOTICE";

/// What was found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyLogs {
    pub files: Vec<PathBuf>,
    pub bytes: u64,
}

impl LegacyLogs {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Result of a removal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoveReport {
    pub removed: usize,
    pub failed: usize,
}

fn scan_dir(dir: &Path, out: &mut LegacyLogs) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        if !paths::is_legacy_log_name(&name.to_string_lossy()) {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        if meta.is_file() {
            out.bytes += meta.len();
            out.files.push(e.path());
        }
    }
}

/// Redirected console output of the old smoke scripts: only counted when it
/// is clearly from this product.
#[cfg(windows)]
fn scan_roaming(out: &mut LegacyLogs) {
    use std::io::Read;
    let Some(base) = directories::BaseDirs::new() else {
        return;
    };
    let dir = base.config_dir().join("miasma");
    for name in ["stdout.log", "stderr.log"] {
        let p = dir.join(name);
        let Ok(mut f) = std::fs::File::open(&p) else {
            continue;
        };
        let mut head = [0u8; 8192];
        let n = f.read(&mut head).unwrap_or(0);
        let text = String::from_utf8_lossy(&head[..n]).to_ascii_lowercase();
        if text.contains("miasma") {
            if let Ok(m) = f.metadata() {
                out.bytes += m.len();
                out.files.push(p);
            }
        }
    }
}

#[cfg(not(windows))]
fn scan_roaming(_out: &mut LegacyLogs) {}

/// Find old log files in the given directories (the daemon's data directory
/// and, if different, the bridge's) and the console-output files of the old
/// test scripts.
pub fn scan(dirs: &[&Path]) -> LegacyLogs {
    let mut out = LegacyLogs::default();
    for d in dirs {
        scan_dir(d, &mut out);
    }
    out.files.sort();
    out.files.dedup();
    out
}

/// Directories that may hold old logs for `data_dir`: itself and the bridge's
/// default data directory.
pub fn candidate_dirs(data_dir: &Path) -> Vec<PathBuf> {
    let mut v = vec![data_dir.to_path_buf()];
    if let Some(b) = directories::ProjectDirs::from("dev", "miasma", "miasma") {
        let b = b.data_dir().to_path_buf();
        if b != data_dir {
            v.push(b);
        }
    }
    v
}

/// Scan `data_dir`. With `machine_wide`, also the bridge's default directory
/// and the console-output files of the old test scripts in the per-user
/// application folder; without it only `data_dir` (tests use this so they
/// never look at, or remove, files of the machine they run on).
pub fn scan_for(data_dir: &Path, machine_wide: bool) -> LegacyLogs {
    if !machine_wide {
        return scan(&[data_dir]);
    }
    let dirs = candidate_dirs(data_dir);
    let refs: Vec<&Path> = dirs.iter().map(|p| p.as_path()).collect();
    let mut out = scan(&refs);
    scan_roaming(&mut out);
    out.files.sort();
    out.files.dedup();
    out
}

/// Overwrite each file with zeros (bounded 64 KiB buffer), then delete it.
pub fn remove(logs: &LegacyLogs) -> RemoveReport {
    let mut r = RemoveReport::default();
    for f in &logs.files {
        match secure_remove(f) {
            Ok(()) => r.removed += 1,
            Err(_) => r.failed += 1,
        }
    }
    r
}

fn update_config(data_dir: &Path, f: impl FnOnce(&mut crate::config::PrivacyConfig)) {
    // Never create a config file just to remember this: its existence tells
    // the programs that the node has been initialised.
    if !paths::config_file(data_dir).exists() {
        return;
    }
    if let Ok(mut c) = NodeConfig::load(data_dir) {
        let before = c.privacy.clone();
        f(&mut c.privacy);
        if c.privacy != before {
            let _ = c.save(data_dir);
        }
        c.transport.zeroize_secret_copies();
    }
}

/// Remember that the notice has been shown.
pub fn record_notice_shown(data_dir: &Path) {
    update_config(data_dir, |p| p.old_logs_notice_shown = true);
}

/// Remember that the user chose to keep the old logs.
pub fn record_keep(data_dir: &Path) {
    update_config(data_dir, |p| {
        p.old_logs_notice_shown = true;
        p.old_logs_keep = true;
    });
}

/// Old logs that still need a decision from the user (the desktop app shows
/// its notice when this is `Some`).
pub fn pending(data_dir: &Path) -> Option<LegacyLogs> {
    pending_in(data_dir, true)
}

pub fn pending_in(data_dir: &Path, machine_wide: bool) -> Option<LegacyLogs> {
    let c = NodeConfig::load(data_dir).unwrap_or_default();
    if c.privacy.old_logs_keep {
        return None;
    }
    let found = scan_for(data_dir, machine_wide);
    (!found.is_empty()).then_some(found)
}

/// What a headless daemon did at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// No old logs, or they are being kept, or a window handles them.
    Nothing,
    /// First sight of old logs: the notice is to be printed; nothing deleted.
    Notice { files: usize, bytes: u64 },
    /// The notice was shown before: old logs were removed.
    Removed(RemoveReport),
}

/// The headless path: first start prints the notice, a later start removes
/// the files. `MIASMA_KEEP_OLD_LOGS=1` and the desktop app's own notice
/// (`MIASMA_LEGACY_LOGS_NOTICE=gui`) both leave them alone.
pub fn headless_startup(data_dir: &Path) -> Startup {
    let keep_env = std::env::var(KEEP_ENV).is_ok_and(|v| v == "1");
    let gui = std::env::var(GUI_NOTICE_ENV).is_ok_and(|v| v == "gui");
    headless_startup_with(data_dir, keep_env, gui, true)
}

pub fn headless_startup_with(
    data_dir: &Path,
    keep_env: bool,
    gui: bool,
    machine_wide: bool,
) -> Startup {
    if keep_env || gui {
        return Startup::Nothing;
    }
    let c = NodeConfig::load(data_dir).unwrap_or_default();
    if c.privacy.old_logs_keep {
        return Startup::Nothing;
    }
    let found = scan_for(data_dir, machine_wide);
    if found.is_empty() {
        return Startup::Nothing;
    }
    if !c.privacy.old_logs_notice_shown {
        record_notice_shown(data_dir);
        return Startup::Notice {
            files: found.files.len(),
            bytes: found.bytes,
        };
    }
    Startup::Removed(remove(&found))
}

/// One line for `miasma status`, if old logs are present and not kept.
pub fn status_line(data_dir: &Path) -> Option<String> {
    let found = pending(data_dir)?;
    Some(format!(
        "{} old log file(s) ({} KiB) from an earlier version: no longer written; \
         `miasma logs --delete-old` removes them now, `miasma logs --keep-old` keeps them",
        found.files.len(),
        found.bytes.div_ceil(1024)
    ))
}
