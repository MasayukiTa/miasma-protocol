//! Putting a verified update in place, and getting back out of a failed one.
//!
//! A running program cannot be overwritten on Windows, but it can be renamed.
//! So the swap is a sequence of renames in the install folder:
//!
//! ```text
//!   miasma.exe       -> miasma.exe.old.<id>     (the running image keeps working)
//!   miasma.exe.new   -> miasma.exe              (staged earlier, hash checked)
//!   ... health check: `miasma.exe --version` must answer within 10 s ...
//!   miasma.exe.old.<id> -> miasma.exe.prev      (the one backup that is kept)
//! ```
//!
//! With several programs the renames run in two passes (all current files
//! aside first, then all new files in), so the folder holds a mix of versions
//! for as short a time as possible. The journal must name the install folder
//! the running program itself would update, or it is refused.
//!
//! If the health check fails, or the swap breaks half way, the old files are
//! renamed back. A small JSON journal records the phase at every step, so a
//! process that dies in the middle (power cut, kill) is repaired at the next
//! start by [`resume`]: either the swap is completed, or it is undone. Only the
//! command line program is ever started for the check, never the desktop
//! program (which would open the window on real data).
//!
//! On macOS an `.app` bundle is replaced as a directory by the same sequence.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::archive::Archive;
use super::error::UpdateError;
use super::release::Os;
use super::verify::sha256_file;
use super::version::parse_version_output;

/// The new program must answer `--version` within this time.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);

/// The name of the command line program on `os`.
pub fn cli_name(os: Os) -> String {
    exe(os, "miasma")
}

/// The programs the updater replaces, command line first.
pub fn program_names(os: Os) -> Vec<String> {
    ["miasma", "miasma-desktop", "miasma-bridge"]
        .iter()
        .map(|n| exe(os, n))
        .collect()
}

fn exe(os: Os, base: &str) -> String {
    if os == Os::Windows {
        format!("{base}.exe")
    } else {
        base.to_owned()
    }
}

/// Runs a program with `--version` and reports what it printed.
pub trait Prober: Send + Sync {
    fn version(&self, exe: &Path, timeout: Duration) -> Result<String, String>;
}

/// Whether anything is going on that an update must not interrupt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Busy {
    Idle,
    /// A transfer, push or chat send is running.
    Active(String),
    /// The daemon is there but would not say.
    Unknown(String),
}

pub trait Activity: Send + Sync {
    fn busy(&self) -> Busy;
}

/// Starts the real program. Windows: no console window flashes up.
pub struct ProcessProber;

impl Prober for ProcessProber {
    fn version(&self, exe: &Path, timeout: Duration) -> Result<String, String> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        let mut cmd = Command::new(exe);
        cmd.arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = cmd.spawn().map_err(|e| format!("cannot start: {e}"))?;
        let started = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut out = String::new();
                    if let Some(mut so) = child.stdout.take() {
                        let _ = so.by_ref().take(4096).read_to_string(&mut out);
                    }
                    return if status.success() {
                        Ok(out)
                    } else {
                        Err(format!("exit status {status}"))
                    };
                }
                Ok(None) => {
                    if started.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err("no answer in time".into());
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(format!("cannot wait: {e}")),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Verified and waiting; nothing in the install folder has changed.
    Downloaded,
    /// New files are being written next to the old ones (`*.new`).
    Staging,
    /// Old files are being renamed away and new ones renamed in.
    Swapping,
    /// Swapped; the new program is being started once to see that it runs.
    Verifying,
    Done,
    RolledBack,
    /// An undo was needed but a program could not be put back. The journal and
    /// the `*.old.<id>` files stay; [`resume`] tries again at the next start.
    RestoreFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    /// Programs next to each other in a folder.
    Files,
    /// A macOS `.app` bundle replaced as a whole.
    Bundle,
}

/// The progress journal (`update/journal.json` in the data directory).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Journal {
    /// Short random id; part of the names of the temporary and backup files.
    pub id: String,
    /// `release` or `local`.
    pub source: String,
    pub version: String,
    /// Local builds: the build id the new program must report.
    pub build_id: Option<String>,
    pub phase: Phase,
    pub kind: TargetKind,
    /// `Files`: the install folder. `Bundle`: the folder that holds the bundle.
    pub dir: PathBuf,
    /// `Bundle`: the bundle's folder name, e.g. `Miasma.app`.
    pub bundle: Option<String>,
    /// `Files`: the programs to replace.
    pub names: Vec<String>,
    /// `Files`: the SHA-256 each program must have once staged (same order).
    pub hashes: Vec<String>,
    /// Folder below `update/` that holds the download.
    pub work_dir: PathBuf,
    pub archive: Option<PathBuf>,
    pub archive_name: Option<String>,
    pub archive_sha256: Option<String>,
    /// Local builds: where the new programs are copied from.
    pub local_dir: Option<PathBuf>,
    pub started_unix: u64,
}

impl Journal {
    fn path_of(&self, name: &str, suffix: &str) -> PathBuf {
        self.dir.join(format!("{name}{suffix}"))
    }
    fn old_of(&self, name: &str) -> PathBuf {
        self.path_of(name, &format!(".old.{}", self.id))
    }
    fn new_of(&self, name: &str) -> PathBuf {
        self.path_of(name, ".new")
    }
    fn failed_of(&self, name: &str) -> PathBuf {
        self.path_of(name, &format!(".failed.{}", self.id))
    }
    fn prev_of(&self, name: &str) -> PathBuf {
        self.path_of(name, ".prev")
    }
    /// The names that are swapped: programs, or the one bundle folder.
    fn units(&self) -> Vec<String> {
        match self.kind {
            TargetKind::Files => self.names.clone(),
            TargetKind::Bundle => self.bundle.iter().cloned().collect(),
        }
    }
}

/// A short random id.
pub fn new_id() -> String {
    let n: u32 = rand::random();
    format!("{n:08x}")
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── journal files ───────────────────────────────────────────────────────────

/// Read the journal. `install_dir` is the folder this program itself would
/// update (see `engine::install_dir_of`); a journal that names any other folder
/// is refused.
pub fn load_journal(data_dir: &Path, install_dir: &Path) -> Result<Option<Journal>, UpdateError> {
    let p = crate::paths::update_journal(data_dir);
    match fs::read(&p) {
        Ok(b) => {
            let j: Journal =
                serde_json::from_slice(&b).map_err(|e| UpdateError::Journal(e.to_string()))?;
            validate_journal(&j, data_dir, install_dir)?;
            Ok(Some(j))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(UpdateError::Journal(e.to_string())),
    }
}

/// The journal is a file in the user's data folder, and `resume` renames and
/// deletes whatever it names. So it is not trusted: ids and program names must
/// be plain words, the download folder must lie inside `update/`, and the
/// install folder must be exactly the one the running program would update.
fn validate_journal(j: &Journal, data_dir: &Path, install_dir: &Path) -> Result<(), UpdateError> {
    let bad = |what: &str| Err(UpdateError::Journal(format!("{what} is not valid")));
    let plain = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s != "."
            && s != ".."
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    let no_parent = |p: &Path| {
        !p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    };
    if !plain(&j.id) {
        return bad("the update id");
    }
    let known = ["miasma", "miasma-desktop", "miasma-bridge"];
    for n in &j.names {
        let stem = n.strip_suffix(".exe").unwrap_or(n);
        if !known.contains(&stem) {
            return bad("a program name");
        }
    }
    if let Some(b) = &j.bundle {
        if !plain(b) || !b.ends_with(".app") {
            return bad("the bundle name");
        }
    }
    let update_dir = crate::paths::update_dir(data_dir);
    if !j.work_dir.starts_with(&update_dir) || !no_parent(&j.work_dir) {
        return bad("the download folder");
    }
    if let Some(a) = &j.archive {
        if !a.starts_with(&j.work_dir) || !no_parent(a) {
            return bad("the downloaded file");
        }
    }
    if !j.dir.is_absolute()
        || !install_dir.is_absolute()
        || !no_parent(&j.dir)
        || j.dir != install_dir
    {
        return bad("the install folder");
    }
    Ok(())
}

pub fn save_journal(data_dir: &Path, j: &Journal) -> Result<(), UpdateError> {
    let p = crate::paths::update_journal(data_dir);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = p.with_extension(crate::paths::ATOMIC_TMP_EXT);
    let bytes = serde_json::to_vec(j).map_err(|e| UpdateError::Journal(e.to_string()))?;
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, &p)?;
    Ok(())
}

pub fn clear_journal(data_dir: &Path) {
    let _ = fs::remove_file(crate::paths::update_journal(data_dir));
}

/// Remove the download folder of `j` (it lives below `update/`).
pub fn clear_work(j: &Journal) {
    let _ = fs::remove_dir_all(&j.work_dir);
}

// ── environment ─────────────────────────────────────────────────────────────

pub struct Env<'a> {
    pub data_dir: &'a Path,
    pub os: Os,
    pub prober: &'a dyn Prober,
    pub activity: &'a dyn Activity,
    pub health_timeout: Duration,
}

/// What an applied update did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub version: String,
    pub replaced: Vec<String>,
}

/// Whether `dir` can be written to: create and remove a probe file.
pub fn probe_writable(dir: &Path) -> Result<(), UpdateError> {
    let probe = dir.join(format!(".write-probe-{}", new_id()));
    fs::File::create(&probe).map_err(|e| UpdateError::NotWritable(e.to_string()))?;
    let _ = fs::remove_file(&probe);
    Ok(())
}

fn remove_any(p: &Path) {
    if p.is_dir() {
        let _ = fs::remove_dir_all(p);
    } else {
        let _ = fs::remove_file(p);
    }
}

/// Delete `*.new`, `*.failed.*` and old `*.old.*` files of the units, left by an
/// attempt that never finished.
fn sweep_leftovers(j: &Journal, keep_old_of_this_id: bool) {
    for name in j.units() {
        remove_any(&j.new_of(&name));
        let Ok(rd) = fs::read_dir(&j.dir) else {
            continue;
        };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let is_ours_failed = n.starts_with(&format!("{name}.failed."));
            let is_old = n.starts_with(&format!("{name}.old."));
            let this_id = n == format!("{name}.old.{}", j.id);
            if is_ours_failed || (is_old && !(keep_old_of_this_id && this_id)) {
                remove_any(&e.path());
            }
        }
    }
}

// ── the update itself ───────────────────────────────────────────────────────

/// Apply the update described by `j`. See the module comment for the steps.
///
/// On success the journal and the download are gone and the previous version
/// is kept as `*.prev`. On failure the install folder holds the old version
/// again (or, if even that failed, the journal stays so [`resume`] can try).
pub fn apply(env: &Env, j: &mut Journal) -> Result<Applied, UpdateError> {
    match env.activity.busy() {
        Busy::Idle => {}
        Busy::Active(why) | Busy::Unknown(why) => return Err(UpdateError::Busy(why)),
    }
    probe_writable(&j.dir)?;
    sweep_leftovers(j, false);

    j.phase = Phase::Staging;
    save_journal(env.data_dir, j)?;
    if let Err(e) = stage(env, j) {
        sweep_leftovers(j, false);
        j.phase = Phase::Downloaded;
        let _ = save_journal(env.data_dir, j);
        return Err(e);
    }

    j.phase = Phase::Swapping;
    save_journal(env.data_dir, j)?;
    if let Err(e) = swap(j) {
        undo(env, j)?;
        return Err(e);
    }

    j.phase = Phase::Verifying;
    save_journal(env.data_dir, j)?;
    finish(env, j)
}

/// Undo the swap and record the outcome: `RolledBack` when every program is
/// back, `RestoreFailed` (and an error) when one could not be put back.
fn undo(env: &Env, j: &mut Journal) -> Result<(), UpdateError> {
    match rollback(j) {
        Ok(()) => {
            j.phase = Phase::RolledBack;
            let _ = save_journal(env.data_dir, j);
            Ok(())
        }
        Err(why) => {
            tracing::error!("update: the previous version could not be restored");
            j.phase = Phase::RestoreFailed;
            let _ = save_journal(env.data_dir, j);
            Err(UpdateError::RestoreFailed(why))
        }
    }
}

/// Health check, then keep or undo. Shared by [`apply`] and [`resume`].
fn finish(env: &Env, j: &mut Journal) -> Result<Applied, UpdateError> {
    if let Err(why) = health(env, j) {
        tracing::warn!("update: the new version did not pass the start check, restoring");
        undo(env, j)?;
        return Err(UpdateError::HealthCheck(why));
    }
    finalize(j);
    j.phase = Phase::Done;
    clear_journal(env.data_dir);
    clear_work(j);
    tracing::info!("update: installed version {}", j.version);
    Ok(Applied {
        version: j.version.clone(),
        replaced: j.units(),
    })
}

fn stage(env: &Env, j: &mut Journal) -> Result<(), UpdateError> {
    match (j.kind, j.source.as_str()) {
        (TargetKind::Files, "release") => {
            let archive = j
                .archive
                .clone()
                .ok_or_else(|| UpdateError::Journal("no archive recorded".into()))?;
            check_archive_unchanged(j, &archive)?;
            let mut a = Archive::open(&archive)?;
            let names: Vec<&str> = j.names.iter().map(String::as_str).collect();
            let got = a.extract_named(&names, &j.dir, ".new")?;
            j.hashes = got.into_iter().map(|g| g.sha256).collect();
            Ok(())
        }
        (TargetKind::Files, _) => {
            let src = j
                .local_dir
                .clone()
                .ok_or_else(|| UpdateError::Journal("no local folder recorded".into()))?;
            let mut hashes = Vec::new();
            for name in &j.names {
                let dest = j.new_of(name);
                fs::copy(src.join(name), &dest)?;
                make_executable(&dest);
                hashes.push(sha256_file(&dest)?);
            }
            j.hashes = hashes;
            Ok(())
        }
        (TargetKind::Bundle, "release") => {
            let archive = j
                .archive
                .clone()
                .ok_or_else(|| UpdateError::Journal("no archive recorded".into()))?;
            check_archive_unchanged(j, &archive)?;
            let bundle = j
                .bundle
                .clone()
                .ok_or_else(|| UpdateError::Journal("no bundle name".into()))?;
            let mut a = Archive::open(&archive)?;
            a.extract_tree(&bundle, &j.new_of(&bundle))?;
            let _ = env;
            Ok(())
        }
        (TargetKind::Bundle, _) => Err(UpdateError::NoTarget(
            "a local build cannot replace an application bundle".into(),
        )),
    }
}

fn check_archive_unchanged(j: &Journal, archive: &Path) -> Result<(), UpdateError> {
    let want = j
        .archive_sha256
        .as_deref()
        .ok_or_else(|| UpdateError::Journal("no archive hash recorded".into()))?;
    let have = sha256_file(archive)?;
    if want != have {
        return Err(UpdateError::Journal(
            "the downloaded file changed after it was checked".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn make_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
}
#[cfg(not(unix))]
fn make_executable(_p: &Path) {}

/// Two passes, so the time in which the folder mixes two versions is only the
/// short run of renames in the second pass: first every current program is
/// moved aside, then every staged one is moved in. A stop between any two
/// renames is repaired by `complete_forward` or `rollback`.
fn swap(j: &Journal) -> Result<(), UpdateError> {
    let units = j.units();
    for name in &units {
        let cur = j.dir.join(name);
        if cur.exists() {
            fs::rename(&cur, j.old_of(name))?;
        }
    }
    for name in &units {
        fs::rename(j.new_of(name), j.dir.join(name))?;
    }
    Ok(())
}

/// The program the start check runs: always the command line program.
fn health_exe(env: &Env, j: &Journal) -> PathBuf {
    match j.kind {
        TargetKind::Files => j.dir.join(cli_name(env.os)),
        TargetKind::Bundle => j
            .dir
            .join(j.bundle.clone().unwrap_or_default())
            .join("Contents")
            .join("MacOS")
            .join("miasma"),
    }
}

fn health(env: &Env, j: &Journal) -> Result<(), String> {
    let exe = health_exe(env, j);
    let out = env.prober.version(&exe, env.health_timeout)?;
    let info =
        parse_version_output(&out).ok_or_else(|| "unexpected --version output".to_owned())?;
    if let Some(want) = &j.build_id {
        if &info.build_id != want {
            return Err("the build id is not the one that was installed".into());
        }
    }
    Ok(())
}

/// Undo the swap: put the old files back, remove the new ones. Fails (after
/// trying every unit) when an old program could not be put back; the files of
/// that unit are then left where they are so a later try can finish the job.
fn rollback(j: &Journal) -> Result<(), String> {
    let mut failed: Vec<String> = Vec::new();
    for (i, name) in j.units().iter().enumerate() {
        let cur = j.dir.join(name);
        let old = j.old_of(name);
        if old.exists() {
            if cur.exists() {
                // Rename rather than delete: on Windows the new program may be running.
                let _ = fs::rename(&cur, j.failed_of(name));
            }
            if let Err(e) = fs::rename(&old, &cur) {
                tracing::error!("update: cannot restore a program: {e}");
                failed.push(format!("{name}: {e}"));
                // Leave something runnable where the program belongs.
                if !cur.exists() {
                    let _ = fs::rename(j.failed_of(name), &cur);
                }
                remove_any(&j.new_of(name));
                continue;
            }
        } else if cur.exists() {
            // A program that did not exist before: remove only what we put there.
            let ours = match (j.kind, j.hashes.get(i)) {
                (TargetKind::Files, Some(h)) => sha256_file(&cur).is_ok_and(|x| &x == h),
                _ => false,
            };
            if ours {
                let _ = fs::rename(&cur, j.failed_of(name));
            }
        }
        remove_any(&j.failed_of(name));
        remove_any(&j.new_of(name));
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// Every unit must have its program in place. One that is missing (a stop or
/// a failure between two renames) is brought back from `*.old.<id>`, else from
/// the kept `.prev`. A unit with nothing to restore from is left alone: it did
/// not exist before the update.
fn ensure_present(j: &Journal) -> Result<(), String> {
    let mut failed: Vec<String> = Vec::new();
    for name in j.units() {
        let cur = j.dir.join(&name);
        if cur.exists() {
            continue;
        }
        let Some(src) = [j.old_of(&name), j.prev_of(&name)]
            .into_iter()
            .find(|p| p.exists())
        else {
            continue;
        };
        if let Err(e) = fs::rename(&src, &cur) {
            failed.push(format!("{name}: {e}"));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// Keep the old files as the one `.prev` backup; drop anything older.
fn finalize(j: &Journal) {
    for name in j.units() {
        let old = j.old_of(&name);
        let prev = j.prev_of(&name);
        if old.exists() {
            remove_any(&prev);
            if let Err(e) = fs::rename(&old, &prev) {
                tracing::warn!("update: cannot keep the previous version as a backup: {e}");
            }
        }
    }
    sweep_leftovers(j, false);
}

// ── resuming after an interruption ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Resumed {
    /// No update was in progress.
    Nothing,
    /// A verified update is waiting to be applied (nothing was changed).
    Pending(Box<Journal>),
    /// An interrupted swap was completed.
    Completed(Applied),
    /// An interrupted swap was undone; the old version is in place.
    RolledBack(String),
}

/// Look at the journal left by an earlier run and bring the install folder to a
/// consistent state: finish the swap, undo it, or discard stale scraps.
///
/// `install_dir` is the folder this program would update; a journal naming any
/// other folder is refused before anything is touched.
pub fn resume(env: &Env, install_dir: &Path) -> Result<Resumed, UpdateError> {
    let Some(mut j) = load_journal(env.data_dir, install_dir)? else {
        return Ok(Resumed::Nothing);
    };
    match j.phase {
        Phase::RestoreFailed => {
            // An earlier undo did not finish: try it again.
            undo(env, &mut j)?;
            Ok(Resumed::RolledBack("restored".into()))
        }
        Phase::Done | Phase::RolledBack => {
            // Before the leftovers (which hold the old files) are swept, make
            // sure the programs themselves are there.
            if let Err(why) = ensure_present(&j) {
                j.phase = Phase::RestoreFailed;
                let _ = save_journal(env.data_dir, &j);
                return Err(UpdateError::RestoreFailed(why));
            }
            sweep_leftovers(&j, false);
            clear_journal(env.data_dir);
            clear_work(&j);
            Ok(Resumed::Nothing)
        }
        Phase::Downloaded | Phase::Staging => {
            sweep_leftovers(&j, false);
            let usable = match (&j.archive, &j.archive_sha256) {
                (Some(a), Some(h)) => sha256_file(a).is_ok_and(|x| &x == h),
                _ => j.source == "local",
            };
            if usable {
                j.phase = Phase::Downloaded;
                save_journal(env.data_dir, &j)?;
                Ok(Resumed::Pending(Box::new(j)))
            } else {
                clear_journal(env.data_dir);
                clear_work(&j);
                Ok(Resumed::Nothing)
            }
        }
        Phase::Swapping | Phase::Verifying => {
            if !complete_forward(&j) {
                tracing::warn!("update: an interrupted update cannot be completed, undoing it");
                undo(env, &mut j)?;
                return Ok(Resumed::RolledBack("interrupted".into()));
            }
            j.phase = Phase::Verifying;
            let _ = save_journal(env.data_dir, &j);
            match finish(env, &mut j) {
                Ok(a) => Ok(Resumed::Completed(a)),
                Err(UpdateError::HealthCheck(why)) => Ok(Resumed::RolledBack(why)),
                Err(e) => Err(e),
            }
        }
    }
}

/// Bring every unit to "new version in place". False when some unit can be
/// neither found in place nor completed from its staged file.
fn complete_forward(j: &Journal) -> bool {
    for (i, name) in j.units().iter().enumerate() {
        let cur = j.dir.join(name);
        let new = j.new_of(name);
        let old = j.old_of(name);
        let want = j.hashes.get(i);
        let in_place = match (j.kind, want) {
            (TargetKind::Files, Some(h)) => {
                cur.is_file() && sha256_file(&cur).is_ok_and(|x| &x == h)
            }
            // A bundle has no single hash: it is in place when the staged copy is gone.
            (TargetKind::Bundle, _) => cur.exists() && !new.exists(),
            _ => false,
        };
        if in_place {
            continue;
        }
        let staged_ok = match (j.kind, want) {
            (TargetKind::Files, Some(h)) => {
                new.is_file() && sha256_file(&new).is_ok_and(|x| &x == h)
            }
            (TargetKind::Bundle, _) => new.is_dir(),
            _ => false,
        };
        if !staged_ok {
            return false;
        }
        if cur.exists() && !old.exists() && fs::rename(&cur, &old).is_err() {
            return false;
        }
        if fs::rename(&new, &cur).is_err() {
            return false;
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use std::sync::Mutex;

    /// A "program" in the tests is a text file; its content is what `--version`
    /// would print, except `BROKEN` (fails) and `HANG` (times out).
    pub struct FileProber {
        pub calls: Mutex<Vec<PathBuf>>,
    }

    impl FileProber {
        pub fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Prober for FileProber {
        fn version(&self, exe: &Path, _t: Duration) -> Result<String, String> {
            self.calls.lock().unwrap().push(exe.to_path_buf());
            let text = fs::read_to_string(exe).map_err(|e| e.to_string())?;
            match text.trim() {
                "BROKEN" => Err("exit status 1".into()),
                "HANG" => Err("no answer in time".into()),
                _ => Ok(text),
            }
        }
    }

    impl Prober for std::sync::Arc<FileProber> {
        fn version(&self, exe: &Path, t: Duration) -> Result<String, String> {
            (**self).version(exe, t)
        }
    }

    pub struct FixedActivity(pub Busy);
    impl Activity for FixedActivity {
        fn busy(&self) -> Busy {
            self.0.clone()
        }
    }

    pub fn version_text(v: &str, id: &str) -> String {
        format!("miasma {v} ({id})\n")
    }

    /// A release journal for programs `names` (Windows-style names) whose zip is
    /// built from `(name, content)` pairs.
    pub fn release_journal(
        data: &Path,
        install: &Path,
        names: &[&str],
        archive_entries: &[(&str, &[u8])],
        version: &str,
    ) -> Journal {
        let work = crate::paths::update_dir(data).join("work-test");
        fs::create_dir_all(&work).unwrap();
        let zip = work.join("a.zip");
        crate::update::archive::testutil::make_zip(&zip, archive_entries);
        Journal {
            id: "t1".into(),
            source: "release".into(),
            version: version.into(),
            build_id: None,
            phase: Phase::Downloaded,
            kind: TargetKind::Files,
            dir: install.to_path_buf(),
            bundle: None,
            names: names.iter().map(|s| (*s).to_owned()).collect(),
            hashes: Vec::new(),
            work_dir: work,
            archive_sha256: Some(sha256_file(&zip).unwrap()),
            archive: Some(zip),
            archive_name: Some("a.zip".into()),
            local_dir: None,
            started_unix: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::update::verify::sha256_bytes;

    struct Fixture {
        _t: tempfile::TempDir,
        data: PathBuf,
        install: PathBuf,
    }

    fn fixture() -> Fixture {
        let t = tempfile::tempdir().unwrap();
        let data = t.path().join("data");
        let install = t.path().join("install");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&install).unwrap();
        Fixture {
            _t: t,
            data,
            install,
        }
    }

    const OLD: &str = "miasma 0.3.2 (old000000)\n";
    const NEW: &str = "miasma 0.4.0 (new000000)\n";

    fn env<'a>(f: &'a Fixture, p: &'a FileProber, a: &'a FixedActivity) -> Env<'a> {
        Env {
            data_dir: &f.data,
            os: Os::Windows,
            prober: p,
            activity: a,
            health_timeout: Duration::from_secs(1),
        }
    }

    fn install_old(f: &Fixture) {
        fs::write(f.install.join("miasma.exe"), OLD).unwrap();
        fs::write(f.install.join("miasma-desktop.exe"), "old desktop").unwrap();
        fs::write(f.install.join("Miasma.cmd"), "@echo off").unwrap();
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn journal(f: &Fixture, new_cli: &str) -> Journal {
        release_journal(
            &f.data,
            &f.install,
            &["miasma.exe", "miasma-desktop.exe"],
            &[
                ("pkg/miasma.exe", new_cli.as_bytes()),
                ("pkg/miasma-desktop.exe", b"new desktop"),
                ("pkg/Miasma.cmd", b"must not be copied"),
            ],
            "0.4.0",
        )
    }

    #[test]
    fn a_good_update_swaps_keeps_one_prev_and_leaves_other_files_alone() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        let applied = apply(&env(&f, &p, &a), &mut j).unwrap();
        assert_eq!(applied.version, "0.4.0");
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            NEW
        );
        assert_eq!(
            fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
            b"new desktop"
        );
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe.prev")).unwrap(),
            OLD
        );
        assert_eq!(
            fs::read(f.install.join("miasma-desktop.exe.prev")).unwrap(),
            b"old desktop"
        );
        // The launcher script is not a managed file and is untouched.
        assert_eq!(
            fs::read(f.install.join("Miasma.cmd")).unwrap(),
            b"@echo off"
        );
        // No scraps: no .new, no .old.*, no journal, no download.
        assert_eq!(
            files(&f.install),
            vec![
                "Miasma.cmd",
                "miasma-desktop.exe",
                "miasma-desktop.exe.prev",
                "miasma.exe",
                "miasma.exe.prev"
            ]
        );
        assert!(load_journal(&f.data, &f.install).unwrap().is_none());
        assert!(!j.work_dir.exists());
        // The check ran the command line program only, never the desktop one.
        let calls = p.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].file_name().unwrap(), "miasma.exe");
    }

    #[test]
    fn a_second_update_replaces_prev_so_only_one_backup_is_kept() {
        let f = fixture();
        install_old(&f);
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        let mut j1 = journal(&f, NEW);
        apply(&env(&f, &p, &a), &mut j1).unwrap();

        let newer = "miasma 0.5.0 (newer0000)\n";
        let mut j2 = journal(&f, newer);
        j2.id = "t2".into();
        apply(&env(&f, &p, &a), &mut j2).unwrap();
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            newer
        );
        // .prev is the version just replaced (0.4.0), not the first one.
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe.prev")).unwrap(),
            NEW
        );
        assert_eq!(
            files(&f.install)
                .iter()
                .filter(|n| n.contains(".prev"))
                .count(),
            2
        );
        assert!(!files(&f.install).iter().any(|n| n.contains(".old.")));
    }

    #[test]
    fn a_failed_health_check_rolls_back_to_the_old_files() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, "BROKEN");
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        let err = apply(&env(&f, &p, &a), &mut j).unwrap_err();
        assert!(matches!(err, UpdateError::HealthCheck(_)), "{err:?}");
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
        assert_eq!(
            fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
            b"old desktop"
        );
        assert_eq!(
            files(&f.install),
            vec!["Miasma.cmd", "miasma-desktop.exe", "miasma.exe"],
            "no .new, .old, .failed or .prev scraps"
        );
    }

    #[test]
    fn a_program_that_hangs_counts_as_failed_too() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, "HANG");
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            apply(&env(&f, &p, &a), &mut j),
            Err(UpdateError::HealthCheck(_))
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
    }

    #[test]
    fn output_that_is_not_a_version_line_fails_the_check() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, "hello world");
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            apply(&env(&f, &p, &a), &mut j),
            Err(UpdateError::HealthCheck(_))
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
    }

    #[test]
    fn nothing_is_touched_while_something_is_running_or_unknown() {
        for busy in [
            Busy::Active("a transfer is running".into()),
            Busy::Unknown("no answer".into()),
        ] {
            let f = fixture();
            install_old(&f);
            let mut j = journal(&f, NEW);
            let (p, a) = (FileProber::new(), FixedActivity(busy));
            assert!(matches!(
                apply(&env(&f, &p, &a), &mut j),
                Err(UpdateError::Busy(_))
            ));
            assert_eq!(
                files(&f.install),
                vec!["Miasma.cmd", "miasma-desktop.exe", "miasma.exe"]
            );
            assert_eq!(
                fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
                OLD
            );
            assert!(p.calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn an_archive_that_changed_after_the_check_is_refused_before_any_swap() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        // Someone modifies the downloaded file between verification and apply.
        let zip = j.archive.clone().unwrap();
        let mut bytes = fs::read(&zip).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        fs::write(&zip, bytes).unwrap();
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            apply(&env(&f, &p, &a), &mut j),
            Err(UpdateError::Journal(_))
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
        assert_eq!(
            files(&f.install),
            vec!["Miasma.cmd", "miasma-desktop.exe", "miasma.exe"]
        );
    }

    #[test]
    fn a_traversal_entry_in_the_archive_stops_the_update_before_anything_changes() {
        let f = fixture();
        install_old(&f);
        let mut j = release_journal(
            &f.data,
            &f.install,
            &["miasma.exe"],
            &[("miasma.exe", NEW.as_bytes()), ("../../evil.dll", b"x")],
            "0.4.0",
        );
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            apply(&env(&f, &p, &a), &mut j),
            Err(UpdateError::Archive(_))
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
        assert!(!f.install.parent().unwrap().join("evil.dll").exists());
    }

    #[test]
    fn a_read_only_install_folder_is_reported_not_attempted() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        j.dir = f.install.join("does-not-exist");
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            apply(&env(&f, &p, &a), &mut j),
            Err(UpdateError::NotWritable(_))
        ));
    }

    // ── resume ──

    /// Put the install folder in the state of a process that died right after
    /// `done` of the two programs were swapped.
    fn crash_after(f: &Fixture, j: &mut Journal, done: usize, phase: Phase) {
        let mut a = Archive::open(j.archive.as_ref().unwrap()).unwrap();
        let names: Vec<&str> = j.names.iter().map(String::as_str).collect();
        let got = a.extract_named(&names, &j.dir, ".new").unwrap();
        j.hashes = got.iter().map(|g| g.sha256.clone()).collect();
        for name in j.names.clone().iter().take(done) {
            fs::rename(f.install.join(name), j.old_of(name)).unwrap();
            fs::rename(j.new_of(name), f.install.join(name)).unwrap();
        }
        j.phase = phase;
        save_journal(&f.data, j).unwrap();
    }

    #[test]
    fn an_interrupted_swap_is_completed_at_the_next_start() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        crash_after(&f, &mut j, 1, Phase::Swapping);
        // State now: miasma.exe new, miasma-desktop.exe old, its .new waiting.
        assert!(f.install.join("miasma-desktop.exe.new").exists());

        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        match resume(&env(&f, &p, &a), &f.install).unwrap() {
            Resumed::Completed(done) => assert_eq!(done.version, "0.4.0"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            NEW
        );
        assert_eq!(
            fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
            b"new desktop"
        );
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe.prev")).unwrap(),
            OLD
        );
        assert!(!files(&f.install)
            .iter()
            .any(|n| n.ends_with(".new") || n.contains(".old.")));
        assert!(load_journal(&f.data, &f.install).unwrap().is_none());
    }

    #[test]
    fn a_crash_between_the_two_renames_of_one_file_is_completed_too() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        crash_after(&f, &mut j, 0, Phase::Swapping);
        // The first program was renamed away but its new file not yet moved in.
        fs::rename(f.install.join("miasma.exe"), j.old_of("miasma.exe")).unwrap();
        assert!(!f.install.join("miasma.exe").exists());

        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            resume(&env(&f, &p, &a), &f.install).unwrap(),
            Resumed::Completed(_)
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            NEW
        );
    }

    #[test]
    fn an_interrupted_swap_whose_new_file_is_gone_is_undone() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        crash_after(&f, &mut j, 1, Phase::Swapping);
        // The staged file of the second program was lost.
        fs::remove_file(f.install.join("miasma-desktop.exe.new")).unwrap();

        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            resume(&env(&f, &p, &a), &f.install).unwrap(),
            Resumed::RolledBack(_)
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
        assert_eq!(
            fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
            b"old desktop"
        );
        assert_eq!(
            files(&f.install),
            vec!["Miasma.cmd", "miasma-desktop.exe", "miasma.exe"]
        );
    }

    #[test]
    fn a_crash_after_the_swap_but_before_the_check_still_checks_and_can_roll_back() {
        let f = fixture();
        install_old(&f);
        let mut j = release_journal(
            &f.data,
            &f.install,
            &["miasma.exe", "miasma-desktop.exe"],
            &[
                ("miasma.exe", b"BROKEN"),
                ("miasma-desktop.exe", b"new desktop"),
            ],
            "0.4.0",
        );
        crash_after(&f, &mut j, 2, Phase::Verifying);
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            resume(&env(&f, &p, &a), &f.install).unwrap(),
            Resumed::RolledBack(_)
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
    }

    /// The folder as the two-pass swap leaves it when the process stops after
    /// `away` programs were moved aside and `inn` new ones were moved in
    /// (`inn <= away`; the first pass finishes before the second begins, so
    /// `inn > 0` implies `away == all`).
    fn crash_two_pass(f: &Fixture, j: &mut Journal, away: usize, inn: usize, phase: Phase) {
        let mut a = Archive::open(j.archive.as_ref().unwrap()).unwrap();
        let names: Vec<&str> = j.names.iter().map(String::as_str).collect();
        let got = a.extract_named(&names, &j.dir, ".new").unwrap();
        j.hashes = got.iter().map(|g| g.sha256.clone()).collect();
        for name in j.names.clone().iter().take(away) {
            fs::rename(f.install.join(name), j.old_of(name)).unwrap();
        }
        for name in j.names.clone().iter().take(inn) {
            fs::rename(j.new_of(name), f.install.join(name)).unwrap();
        }
        j.phase = phase;
        save_journal(&f.data, j).unwrap();
    }

    /// Every place a stop can fall in the two passes: 0..=2 moved aside, then
    /// 0..=2 moved in.
    fn stop_points() -> Vec<(usize, usize)> {
        vec![(0, 0), (1, 0), (2, 0), (2, 1), (2, 2)]
    }

    #[test]
    fn a_stop_between_any_two_renames_of_the_two_passes_is_completed() {
        for (away, inn) in stop_points() {
            let f = fixture();
            install_old(&f);
            let mut j = journal(&f, NEW);
            crash_two_pass(&f, &mut j, away, inn, Phase::Swapping);
            let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
            match resume(&env(&f, &p, &a), &f.install).unwrap() {
                Resumed::Completed(done) => assert_eq!(done.version, "0.4.0"),
                other => panic!("stop {away}/{inn}: {other:?}"),
            }
            assert_eq!(
                fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
                NEW,
                "stop {away}/{inn}"
            );
            assert_eq!(
                fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
                b"new desktop",
                "stop {away}/{inn}"
            );
            assert_eq!(
                fs::read_to_string(f.install.join("miasma.exe.prev")).unwrap(),
                OLD,
                "stop {away}/{inn}"
            );
            assert_eq!(
                fs::read(f.install.join("miasma-desktop.exe.prev")).unwrap(),
                b"old desktop",
                "stop {away}/{inn}"
            );
            assert!(!files(&f.install)
                .iter()
                .any(|n| n.ends_with(".new") || n.contains(".old.")));
        }
    }

    #[test]
    fn a_stop_between_any_two_renames_is_undone_when_the_new_program_fails() {
        for (away, inn) in stop_points() {
            let f = fixture();
            install_old(&f);
            let mut j = release_journal(
                &f.data,
                &f.install,
                &["miasma.exe", "miasma-desktop.exe"],
                &[
                    ("miasma.exe", b"BROKEN"),
                    ("miasma-desktop.exe", b"new desktop"),
                ],
                "0.4.0",
            );
            crash_two_pass(&f, &mut j, away, inn, Phase::Swapping);
            let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
            assert!(
                matches!(
                    resume(&env(&f, &p, &a), &f.install).unwrap(),
                    Resumed::RolledBack(_)
                ),
                "stop {away}/{inn}"
            );
            assert_eq!(
                fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
                OLD,
                "stop {away}/{inn}"
            );
            assert_eq!(
                fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
                b"old desktop",
                "stop {away}/{inn}"
            );
            assert_eq!(
                files(&f.install),
                vec!["Miasma.cmd", "miasma-desktop.exe", "miasma.exe"],
                "stop {away}/{inn}"
            );
        }
    }

    #[test]
    fn a_stop_between_the_passes_with_a_lost_staged_file_is_undone() {
        for (away, inn) in [(2, 0), (2, 1)] {
            let f = fixture();
            install_old(&f);
            let mut j = journal(&f, NEW);
            crash_two_pass(&f, &mut j, away, inn, Phase::Swapping);
            // The staged copy of the last program is gone.
            let lost = f.install.join("miasma-desktop.exe.new");
            if lost.exists() {
                fs::remove_file(lost).unwrap();
            } else {
                fs::remove_file(f.install.join("miasma-desktop.exe")).unwrap();
            }
            let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
            assert!(matches!(
                resume(&env(&f, &p, &a), &f.install).unwrap(),
                Resumed::RolledBack(_)
            ));
            assert_eq!(
                fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
                OLD
            );
            assert_eq!(
                fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
                b"old desktop"
            );
        }
    }

    #[test]
    fn a_swap_that_fails_in_the_second_pass_moves_all_programs_aside_first() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        // The second program's staged file is missing, so the second pass fails
        // after the first program was moved in.
        let mut a = Archive::open(j.archive.as_ref().unwrap()).unwrap();
        let names: Vec<&str> = j.names.iter().map(String::as_str).collect();
        let got = a.extract_named(&names, &j.dir, ".new").unwrap();
        j.hashes = got.iter().map(|g| g.sha256.clone()).collect();
        fs::remove_file(f.install.join("miasma-desktop.exe.new")).unwrap();
        assert!(swap(&j).is_err());
        // Both programs were moved aside before the failing move-in.
        assert!(j.old_of("miasma.exe").exists());
        assert!(j.old_of("miasma-desktop.exe").exists());
        rollback(&j).unwrap();
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
        assert_eq!(
            fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
            b"old desktop"
        );
    }

    /// A state in which `rollback` cannot put the first program back: the
    /// program's place holds a non-empty folder and so does the `.failed` name.
    fn block_restore(f: &Fixture, j: &mut Journal) {
        crash_two_pass(f, j, 1, 0, Phase::Swapping);
        // The staged file of the second program is gone, so the swap cannot be
        // completed and must be undone.
        fs::remove_file(f.install.join("miasma-desktop.exe.new")).unwrap();
        let cur = f.install.join("miasma.exe");
        fs::create_dir_all(&cur).unwrap();
        fs::write(cur.join("x"), "x").unwrap();
        let failed = j.failed_of("miasma.exe");
        fs::create_dir_all(&failed).unwrap();
        fs::write(failed.join("x"), "x").unwrap();
    }

    #[test]
    fn a_restore_that_fails_is_reported_and_retried_at_the_next_start() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        block_restore(&f, &mut j);
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        match resume(&env(&f, &p, &a), &f.install) {
            Err(UpdateError::RestoreFailed(_)) => {}
            other => panic!("{other:?}"),
        }
        // The journal says so and the old file is still there to restore from.
        let saved = load_journal(&f.data, &f.install).unwrap().unwrap();
        assert_eq!(saved.phase, Phase::RestoreFailed);
        assert!(j.old_of("miasma.exe").exists());
        // Still blocked: still reported, still kept.
        assert!(matches!(
            resume(&env(&f, &p, &a), &f.install),
            Err(UpdateError::RestoreFailed(_))
        ));
        // The obstacle goes away: the next start restores the old program.
        fs::remove_dir_all(f.install.join("miasma.exe")).unwrap();
        fs::remove_dir_all(j.failed_of("miasma.exe")).unwrap();
        assert!(matches!(
            resume(&env(&f, &p, &a), &f.install).unwrap(),
            Resumed::RolledBack(_)
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
        assert_eq!(
            fs::read(f.install.join("miasma-desktop.exe")).unwrap(),
            b"old desktop"
        );
        // And the next one finds nothing left to do.
        assert_eq!(
            resume(&env(&f, &p, &a), &f.install).unwrap(),
            Resumed::Nothing
        );
        assert!(load_journal(&f.data, &f.install).unwrap().is_none());
    }

    #[test]
    fn a_rolled_back_or_done_journal_restores_a_missing_program_before_clearing() {
        for phase in [Phase::RolledBack, Phase::Done] {
            let f = fixture();
            install_old(&f);
            let mut j = journal(&f, NEW);
            j.phase = phase;
            save_journal(&f.data, &j).unwrap();
            // The program is gone; its backup is there.
            fs::remove_file(f.install.join("miasma.exe")).unwrap();
            let backup = if phase == Phase::RolledBack {
                j.old_of("miasma.exe")
            } else {
                j.prev_of("miasma.exe")
            };
            fs::write(&backup, OLD).unwrap();
            let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
            assert_eq!(
                resume(&env(&f, &p, &a), &f.install).unwrap(),
                Resumed::Nothing
            );
            assert_eq!(
                fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
                OLD,
                "{phase:?}"
            );
            assert!(load_journal(&f.data, &f.install).unwrap().is_none());
        }
    }

    #[test]
    fn a_crash_while_staging_leaves_a_pending_update_and_no_scraps() {
        let f = fixture();
        install_old(&f);
        let mut j = journal(&f, NEW);
        j.phase = Phase::Staging;
        save_journal(&f.data, &j).unwrap();
        fs::write(f.install.join("miasma.exe.new"), "half").unwrap();

        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        match resume(&env(&f, &p, &a), &f.install).unwrap() {
            Resumed::Pending(pj) => assert_eq!(pj.phase, Phase::Downloaded),
            other => panic!("{other:?}"),
        }
        assert!(!f.install.join("miasma.exe.new").exists());
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
    }

    #[test]
    fn a_pending_update_whose_download_vanished_is_forgotten() {
        let f = fixture();
        install_old(&f);
        let j = journal(&f, NEW);
        save_journal(&f.data, &j).unwrap();
        fs::remove_file(j.archive.as_ref().unwrap()).unwrap();
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert_eq!(
            resume(&env(&f, &p, &a), &f.install).unwrap(),
            Resumed::Nothing
        );
        assert!(load_journal(&f.data, &f.install).unwrap().is_none());
    }

    #[test]
    fn with_no_journal_resume_does_nothing() {
        let f = fixture();
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert_eq!(
            resume(&env(&f, &p, &a), &f.install).unwrap(),
            Resumed::Nothing
        );
    }

    // ── macOS bundle ──

    fn bundle_journal(f: &Fixture, new_cli: &str) -> Journal {
        let mut j = release_journal(
            &f.data,
            &f.install,
            &[],
            &[
                ("Miasma.app/Contents/Info.plist", b"plist"),
                ("Miasma.app/Contents/MacOS/miasma", new_cli.as_bytes()),
                ("Miasma.app/Contents/MacOS/miasma-desktop", b"gui"),
            ],
            "0.4.0",
        );
        j.kind = TargetKind::Bundle;
        j.bundle = Some("Miasma.app".into());
        j
    }

    fn install_old_bundle(f: &Fixture) {
        let mac = f.install.join("Miasma.app").join("Contents").join("MacOS");
        fs::create_dir_all(&mac).unwrap();
        fs::write(mac.join("miasma"), OLD).unwrap();
        fs::write(mac.join("miasma-desktop"), "old gui").unwrap();
    }

    fn mac_env<'a>(f: &'a Fixture, p: &'a FileProber, a: &'a FixedActivity) -> Env<'a> {
        Env {
            os: Os::MacOs,
            ..env(f, p, a)
        }
    }

    #[test]
    fn a_macos_bundle_is_replaced_as_a_directory_and_the_old_one_kept() {
        let f = fixture();
        install_old_bundle(&f);
        let mut j = bundle_journal(&f, NEW);
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        apply(&mac_env(&f, &p, &a), &mut j).unwrap();
        let cli = |name: &str| {
            f.install
                .join(name)
                .join("Contents")
                .join("MacOS")
                .join("miasma")
        };
        assert_eq!(fs::read_to_string(cli("Miasma.app")).unwrap(), NEW);
        assert_eq!(fs::read_to_string(cli("Miasma.app.prev")).unwrap(), OLD);
        assert_eq!(files(&f.install), vec!["Miasma.app", "Miasma.app.prev"]);
        // The check ran the command line program inside the bundle.
        let calls = p.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].ends_with(Path::new("Contents/MacOS/miasma")),
            "{calls:?}"
        );
    }

    #[test]
    fn a_macos_bundle_that_does_not_start_is_put_back() {
        let f = fixture();
        install_old_bundle(&f);
        let mut j = bundle_journal(&f, "BROKEN");
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            apply(&mac_env(&f, &p, &a), &mut j),
            Err(UpdateError::HealthCheck(_))
        ));
        let mac = f.install.join("Miasma.app").join("Contents").join("MacOS");
        assert_eq!(fs::read_to_string(mac.join("miasma")).unwrap(), OLD);
        assert_eq!(
            fs::read_to_string(mac.join("miasma-desktop")).unwrap(),
            "old gui"
        );
        assert_eq!(files(&f.install), vec!["Miasma.app"]);
    }

    #[test]
    fn an_interrupted_bundle_swap_is_completed_at_the_next_start() {
        let f = fixture();
        install_old_bundle(&f);
        let mut j = bundle_journal(&f, NEW);
        // Staged, and the old bundle already renamed away: the new one is not in place yet.
        let mut a = Archive::open(j.archive.as_ref().unwrap()).unwrap();
        a.extract_tree("Miasma.app", &j.new_of("Miasma.app"))
            .unwrap();
        fs::rename(f.install.join("Miasma.app"), j.old_of("Miasma.app")).unwrap();
        j.phase = Phase::Swapping;
        save_journal(&f.data, &j).unwrap();
        let (p, act) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            resume(&mac_env(&f, &p, &act), &f.install).unwrap(),
            Resumed::Completed(_)
        ));
        let cli = f
            .install
            .join("Miasma.app")
            .join("Contents")
            .join("MacOS")
            .join("miasma");
        assert_eq!(fs::read_to_string(cli).unwrap(), NEW);
        assert!(f.install.join("Miasma.app.prev").exists());
    }

    // ── local builds ──

    #[test]
    fn a_local_build_is_copied_checked_and_swapped_the_same_way() {
        let f = fixture();
        install_old(&f);
        let src = f._t.path().join("target-release");
        fs::create_dir_all(&src).unwrap();
        let new_cli = version_text("0.4.0", "devbuild01");
        fs::write(src.join("miasma.exe"), &new_cli).unwrap();
        fs::write(src.join("miasma-desktop.exe"), "dev desktop").unwrap();
        let mut j = journal(&f, NEW);
        j.source = "local".into();
        j.build_id = Some("devbuild01".into());
        j.local_dir = Some(src);
        j.archive = None;
        j.archive_sha256 = None;
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        apply(&env(&f, &p, &a), &mut j).unwrap();
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            new_cli
        );
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe.prev")).unwrap(),
            OLD
        );
    }

    #[test]
    fn a_local_build_that_reports_another_id_than_offered_is_rolled_back() {
        let f = fixture();
        install_old(&f);
        let src = f._t.path().join("target-release");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("miasma.exe"),
            version_text("0.4.0", "somethingelse"),
        )
        .unwrap();
        fs::write(src.join("miasma-desktop.exe"), "dev desktop").unwrap();
        let mut j = journal(&f, NEW);
        j.source = "local".into();
        j.build_id = Some("devbuild01".into());
        j.local_dir = Some(src);
        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        assert!(matches!(
            apply(&env(&f, &p, &a), &mut j),
            Err(UpdateError::HealthCheck(_))
        ));
        assert_eq!(
            fs::read_to_string(f.install.join("miasma.exe")).unwrap(),
            OLD
        );
    }

    #[test]
    fn journal_round_trips_through_its_file() {
        let f = fixture();
        let j = journal(&f, NEW);
        save_journal(&f.data, &j).unwrap();
        assert_eq!(load_journal(&f.data, &f.install).unwrap().unwrap(), j);
        fs::write(crate::paths::update_journal(&f.data), b"{ not json").unwrap();
        assert!(matches!(
            load_journal(&f.data, &f.install),
            Err(UpdateError::Journal(_))
        ));
        clear_journal(&f.data);
        assert!(load_journal(&f.data, &f.install).unwrap().is_none());
        assert_eq!(sha256_bytes(b""), sha256_bytes(b""));
    }

    #[test]
    fn a_journal_that_names_paths_outside_its_folders_is_refused_and_deletes_nothing() {
        let f = fixture();
        let victim = f._t.path().join("precious");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep.txt"), "mine").unwrap();

        let good = journal(&f, NEW);
        let mut cases: Vec<Journal> = Vec::new();
        // A finished update whose "download folder" is somewhere else: resume
        // would delete it.
        let mut j = good.clone();
        j.phase = Phase::Done;
        j.work_dir = victim.clone();
        cases.push(j);
        let mut j = good.clone();
        j.work_dir = crate::paths::update_dir(&f.data)
            .join("..")
            .join("precious");
        cases.push(j);
        let mut j = good.clone();
        j.names = vec!["..\\..\\evil.exe".into()];
        cases.push(j);
        let mut j = good.clone();
        j.names = vec!["notepad.exe".into()];
        cases.push(j);
        let mut j = good.clone();
        j.id = "../x".into();
        cases.push(j);
        let mut j = good.clone();
        j.archive = Some(victim.join("keep.txt"));
        cases.push(j);
        let mut j = good.clone();
        j.dir = f.install.join("..").join("..");
        cases.push(j);
        // An absolute folder that is not the install folder of this program.
        let mut j = good.clone();
        j.dir = f._t.path().join("somewhere-else");
        cases.push(j);
        let mut j = good.clone();
        j.dir = victim.clone();
        cases.push(j);
        // A relative folder.
        let mut j = good.clone();
        j.dir = PathBuf::from("install");
        cases.push(j);

        let (p, a) = (FileProber::new(), FixedActivity(Busy::Idle));
        for j in cases {
            save_journal(&f.data, &j).unwrap();
            assert!(
                matches!(
                    load_journal(&f.data, &f.install),
                    Err(UpdateError::Journal(_))
                ),
                "{j:?}"
            );
            assert!(matches!(
                resume(&env(&f, &p, &a), &f.install),
                Err(UpdateError::Journal(_))
            ));
            assert_eq!(fs::read_to_string(victim.join("keep.txt")).unwrap(), "mine");
        }
        // The real thing still loads.
        save_journal(&f.data, &good).unwrap();
        assert!(load_journal(&f.data, &f.install).unwrap().is_some());
    }

    #[test]
    fn program_names_follow_the_platform() {
        assert_eq!(
            program_names(Os::Windows),
            ["miasma.exe", "miasma-desktop.exe", "miasma-bridge.exe"]
        );
        assert_eq!(
            program_names(Os::MacOs),
            ["miasma", "miasma-desktop", "miasma-bridge"]
        );
        assert_eq!(cli_name(Os::Windows), "miasma.exe");
    }

    #[cfg(unix)]
    mod real_process {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
            let p = dir.join(name);
            fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            p
        }

        #[test]
        fn the_real_prober_reads_the_version_line() {
            let d = tempfile::tempdir().unwrap();
            let s = script(d.path(), "ok", "echo 'miasma 0.4.0 (abc123)'");
            let out = ProcessProber.version(&s, Duration::from_secs(5)).unwrap();
            assert!(parse_version_output(&out).is_some());
        }

        #[test]
        fn the_real_prober_reports_failure_and_timeout() {
            let d = tempfile::tempdir().unwrap();
            let bad = script(d.path(), "bad", "exit 3");
            assert!(ProcessProber.version(&bad, Duration::from_secs(5)).is_err());
            let slow = script(d.path(), "slow", "sleep 5");
            let t = std::time::Instant::now();
            let e = ProcessProber
                .version(&slow, Duration::from_millis(300))
                .unwrap_err();
            assert!(e.contains("in time"), "{e}");
            assert!(t.elapsed() < Duration::from_secs(3));
            assert!(ProcessProber
                .version(&d.path().join("missing"), Duration::from_secs(1))
                .is_err());
        }
    }
}
