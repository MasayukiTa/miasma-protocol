//! `miasma-share:` links: the launch argument, the per-user URL scheme registration, and the
//! hand-off to an already running window.
//!
//! The link IS the share ID (`miasma-share:<base58>`), so clicking one in a mail client, a browser
//! or the Run box opens Miasma on New transfer > Receive with the ID filled in and the cursor on the
//! password field. A link never starts a download by itself and carries no password.
//!
//! # Single instance
//!
//! The desktop app had no single-instance mechanism, and a normal launch must keep behaving as
//! before (a second copy is allowed). Only a *link* launch hands over:
//!
//! * Every instance tries to take an exclusive lock on `desktop.lock` in the data dir
//!   (`File::try_lock`; the OS drops it when the process dies, so a crash leaves nothing stale).
//! * The holder runs a small thread that looks for `pending-link.txt` twice a second.
//! * A link launch that finds the lock held writes the share ID to that file (temp file + rename)
//!   and waits a few seconds for the holder to take it. If it is taken, this process exits; if not
//!   (the holder is hung or just closing) the file is removed and this process opens the form
//!   itself, so a link is never lost.
//!
//! Why a file and not a socket: no port to guard, no token to manage, and the data dir is already
//! the per-user, per-`--data-dir` trust boundary. What crosses it is only a checksum-validated
//! share ID that pre-fills a form.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, SystemTime};

use miasma_core::transfer::share_id_from_link;

const LOCK_FILE: &str = "desktop.lock";
const PENDING_FILE: &str = "pending-link.txt";
/// A pending link older than this is ignored (a leftover, not something just clicked).
const PENDING_MAX_AGE: Duration = Duration::from_secs(60);
/// How long a link launch waits for the running window to take the hand-off.
const HANDOFF_WAIT: Duration = Duration::from_secs(4);

/// The share ID in the launch arguments (argv without the program name), if any. The OS or
/// browser may add a trailing slash or percent-encoding; both are tolerated.
pub fn share_id_from_args(args: impl IntoIterator<Item = String>) -> Option<String> {
    args.into_iter().find_map(|a| share_id_from_link(&a))
}

/// Who owns the instance lock.
pub enum Instance {
    /// This process holds it (keep the value alive for the life of the process).
    Primary(#[allow(dead_code)] File),
    /// Another Miasma window of this data dir holds it.
    Other,
    /// The lock could not be taken for another reason; behave like a single process.
    Unknown,
}

pub fn acquire(data_dir: &Path) -> Instance {
    let file = match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(data_dir.join(LOCK_FILE))
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("instance lock: cannot open {LOCK_FILE}: {e}");
            return Instance::Unknown;
        }
    };
    match file.try_lock() {
        Ok(()) => Instance::Primary(file),
        Err(std::fs::TryLockError::WouldBlock) => Instance::Other,
        Err(std::fs::TryLockError::Error(e)) => {
            tracing::warn!("instance lock: {e}");
            Instance::Unknown
        }
    }
}

fn pending_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PENDING_FILE)
}

/// Give `share_id` to the running window. True once it has taken it.
pub fn hand_off(data_dir: &Path, share_id: &str) -> bool {
    let target = pending_path(data_dir);
    let tmp = data_dir.join(format!("{PENDING_FILE}.{}.tmp", std::process::id()));
    if std::fs::write(&tmp, share_id).is_err() || std::fs::rename(&tmp, &target).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    let deadline = std::time::Instant::now() + HANDOFF_WAIT;
    while std::time::Instant::now() < deadline {
        if !target.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_file(&target);
    false
}

/// Take a pending link, if a fresh one is there.
fn take_pending(data_dir: &Path) -> Option<String> {
    let path = pending_path(data_dir);
    let age = std::fs::metadata(&path)
        .ok()?
        .modified()
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok());
    let text = std::fs::read_to_string(&path).ok();
    let _ = std::fs::remove_file(&path);
    if age.is_some_and(|a| a > PENDING_MAX_AGE) {
        return None;
    }
    share_id_from_link(&text?)
}

/// Watch for links handed over by later launches. Each one is sent down the channel and the window
/// is raised. Runs on its own thread so a minimised window still receives it.
pub fn spawn_listener(data_dir: PathBuf, ctx: egui::Context) -> Receiver<String> {
    let (tx, rx) = channel();
    let spawned = std::thread::Builder::new()
        .name("link-listener".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            if let Some(id) = take_pending(&data_dir) {
                tracing::info!("opened a miasma-share link from another launch");
                if tx.send(id).is_err() {
                    return;
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                ctx.request_repaint();
            }
        });
    if let Err(e) = spawned {
        tracing::warn!("cannot start the link listener: {e}");
    }
    rx
}

/// The command a `miasma-share:` link runs: this exe with the link as its one argument.
#[cfg(any(windows, test))]
fn open_command(exe: &Path) -> String {
    let p = exe.display().to_string();
    let p = p.strip_prefix(r"\\?\").unwrap_or(&p);
    format!("\"{p}\" \"%1\"")
}

/// Whether the registry has to be written, given what `reg query` printed for the command key
/// (None when the key is missing). Pure so it can be tested away from Windows.
#[cfg(any(windows, test))]
fn needs_registration(query_output: Option<&str>, expected: &str) -> bool {
    match query_output {
        None => true,
        Some(out) => !out.to_lowercase().contains(&expected.to_lowercase()),
    }
}

/// Register the `miasma-share` URL scheme for the current user (HKCU only: no admin rights),
/// pointing at this exe. Idempotent; never fails the caller.
#[cfg(windows)]
pub fn register_url_scheme(data_dir: &Path) {
    match windows_register::register(data_dir) {
        Ok(true) => tracing::info!("registered the miasma-share URL scheme for this user"),
        Ok(false) => {}
        Err(e) => tracing::warn!("could not register the miasma-share URL scheme: {e}"),
    }
}

/// Other platforms: nothing to register (macOS needs `CFBundleURLTypes` in Info.plist and an
/// Apple Event handler; Linux needs a `.desktop` file with `x-scheme-handler/miasma-share`).
#[cfg(not(windows))]
pub fn register_url_scheme(_data_dir: &Path) {}

#[cfg(windows)]
mod windows_register {
    use super::{needs_registration, open_command};
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const SCHEME_KEY: &str = r"HKCU\Software\Classes\miasma-share";
    const COMMAND_KEY: &str = r"HKCU\Software\Classes\miasma-share\shell\open\command";
    /// Remembers which exe the keys were last written for: `reg query` prints in the OEM code
    /// page, so a non-ASCII install path cannot be compared reliably from its output.
    const MARKER_FILE: &str = "url-scheme-registered.txt";

    /// `reg.exe` with a hidden console, arguments passed raw (the value needs its own quotes).
    fn reg(args: &str) -> std::io::Result<std::process::Output> {
        Command::new("reg")
            .raw_arg(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
    }

    fn query(key: &str, value_arg: &str) -> Option<String> {
        let out = reg(&format!("query \"{key}\" {value_arg}")).ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn add(key: &str, value_arg: &str, kind: &str, data: &str) -> Result<(), String> {
        // `data` is already quoted by the caller where it needs to be.
        let out = reg(&format!("add \"{key}\" {value_arg} /t {kind} /d {data} /f"))
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "reg add {key} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// Ok(true) when something was written.
    pub fn register(data_dir: &Path) -> Result<bool, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let expected = open_command(&exe);
        let marker = data_dir.join(MARKER_FILE);
        let exe_text = expected.clone();

        let command_out = query(COMMAND_KEY, "/ve");
        let protocol_present = query(SCHEME_KEY, "/v \"URL Protocol\"").is_some();
        let stale = if expected.is_ascii() {
            needs_registration(command_out.as_deref(), &expected)
        } else {
            // Non-ASCII path: trust the marker, but still require the key to exist.
            command_out.is_none()
                || std::fs::read_to_string(&marker)
                    .map(|m| m != exe_text)
                    .unwrap_or(true)
        };
        if !stale && protocol_present {
            return Ok(false);
        }

        add(SCHEME_KEY, "/ve", "REG_SZ", "\"URL:Miasma Share\"")?;
        add(SCHEME_KEY, "/v \"URL Protocol\"", "REG_SZ", "\"\"")?;
        // The value is `"<exe>" "%1"`: quotes inside it are escaped for reg.exe.
        let escaped = expected.replace('"', "\\\"");
        add(COMMAND_KEY, "/ve", "REG_SZ", &format!("\"{escaped}\""))?;
        let _ = std::fs::write(&marker, exe_text);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "miasma-share:";

    fn sample_id() -> String {
        let sk = ed25519_sample();
        let mid = miasma_core::crypto::hash::ContentId::from_digest([9u8; 32]);
        miasma_core::transfer::ShareId::new(&mid, sk, true).to_string()
    }

    fn ed25519_sample() -> [u8; 32] {
        // A valid compressed Edwards point: the Ed25519 basepoint.
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        b
    }

    #[test]
    fn launch_argument_forms() {
        let id = sample_id();
        assert!(id.starts_with(ID));
        for arg in [
            id.clone(),
            format!("{id}/"),
            id.replace(':', "%3A"),
            format!("\"{id}\""),
        ] {
            assert_eq!(
                share_id_from_args(vec!["--mode".into(), "easy".into(), arg.clone()]),
                Some(id.clone()),
                "{arg}"
            );
        }
        assert_eq!(
            share_id_from_args(vec!["--mode".into(), "easy".into()]),
            None
        );
        assert_eq!(share_id_from_args(vec![format!("{ID}garbage")]), None);
    }

    #[test]
    fn open_command_quotes_the_exe_and_the_argument() {
        let c = open_command(Path::new(r"C:\Program Files\Miasma\miasma-desktop.exe"));
        assert_eq!(c, r#""C:\Program Files\Miasma\miasma-desktop.exe" "%1""#);
        let c = open_command(Path::new(r"\\?\C:\m\miasma-desktop.exe"));
        assert_eq!(c, r#""C:\m\miasma-desktop.exe" "%1""#);
    }

    #[test]
    fn registration_is_only_needed_when_missing_or_pointing_elsewhere() {
        let expected = r#""C:\m\miasma-desktop.exe" "%1""#;
        assert!(needs_registration(None, expected));
        let same = format!(
            "\r\nHKEY_CURRENT_USER\\...\\command\r\n    (Default)    REG_SZ    {expected}\r\n"
        );
        assert!(!needs_registration(Some(&same), expected));
        let upper = same.to_uppercase();
        assert!(!needs_registration(Some(&upper), expected));
        let other = r#"    (Default)    REG_SZ    "D:\old\miasma-desktop.exe" "%1""#;
        assert!(needs_registration(Some(other), expected));
    }

    #[test]
    fn hand_off_is_taken_by_the_listener_side_and_stale_files_are_ignored() {
        let dir = std::env::temp_dir().join(format!("miasma-link-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = sample_id();

        // The holder side: take what a launch wrote.
        std::fs::write(pending_path(&dir), format!("{id}\n")).unwrap();
        assert_eq!(take_pending(&dir), Some(id.clone()));
        assert!(!pending_path(&dir).exists(), "taken means removed");
        assert_eq!(take_pending(&dir), None);

        // Garbage is removed and ignored.
        std::fs::write(pending_path(&dir), "not a link").unwrap();
        assert_eq!(take_pending(&dir), None);
        assert!(!pending_path(&dir).exists());

        // A holder that takes the file while the launch waits: hand_off reports success.
        let d2 = dir.clone();
        let taker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            take_pending(&d2)
        });
        assert!(hand_off(&dir, &id));
        assert_eq!(taker.join().unwrap(), Some(id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_second_process_sees_the_lock_held() {
        let dir = std::env::temp_dir().join(format!("miasma-lock-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = acquire(&dir);
        assert!(matches!(first, Instance::Primary(_)));
        assert!(matches!(acquire(&dir), Instance::Other));
        drop(first);
        assert!(matches!(acquire(&dir), Instance::Primary(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
