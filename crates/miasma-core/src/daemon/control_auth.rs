//! Control-channel authentication for the local daemon.
//!
//! The daemon's control surfaces (the loopback IPC listener and the HTTP
//! bridge) accept requests that read and write arbitrary paths, publish
//! content and destroy the master key.  Anything that can open a loopback TCP
//! connection could previously do all of that.  Loopback reachability is not a
//! credential, so every connection must now present a secret that only the
//! account owning the data directory can read.
//!
//! * At every start the daemon draws a fresh 256-bit token from the OS CSPRNG
//!   and writes it to `<data_dir>/daemon.token` **before** it publishes
//!   `daemon.port` (clients wait for the port file, so the token is always
//!   there first).  A token left behind by a crashed daemon is replaced.
//! * The token file is deleted at clean shutdown.
//! * The first frame of every IPC connection is a small [`ControlAuth`] frame;
//!   nothing else is parsed until the token has been checked in constant time.
//! * Failed attempts are delayed, with the delay growing with consecutive
//!   failures.
//! * `Wipe` is a two-step exchange: the first request only returns a
//!   single-use, short-lived challenge issued by the daemon; the key is
//!   destroyed only by a second request that echoes it.
//!
//! # File permissions
//!
//! * Unix: the file is created with mode `0600` at creation time (never
//!   widened and narrowed afterwards); an existing file is unlinked first so a
//!   stale file with looser permissions is never reused.
//! * Windows: `std` has no ACL API and the crate has no direct dependency that
//!   does.  The file is created empty, then the system `icacls` tool is asked
//!   to drop inheritance and grant access to the current user only, and only
//!   then is the secret written.  If `icacls` cannot be run or fails, the
//!   daemon logs a warning and keeps running with the ACL the per-user data
//!   directory already provides; that fallback is not verified by the daemon.

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, Rng};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Filename inside the data directory holding the control token.
pub const TOKEN_FILE: &str = "daemon.token";

/// Largest frame accepted before the peer has authenticated.
pub const PRE_AUTH_FRAME_MAX: usize = 4 * 1024;

/// How long an unauthenticated peer may take to send its first frame.
pub const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a `Wipe` challenge stays valid.
pub const WIPE_CHALLENGE_TTL: Duration = Duration::from_secs(30);

/// Delay applied to the first failed attempt; doubles per consecutive failure.
const FAIL_DELAY_BASE: Duration = Duration::from_millis(100);
/// Upper bound of the failure delay.
const FAIL_DELAY_MAX: Duration = Duration::from_secs(3);

/// The 256-bit control token, hex encoded (64 characters).
pub struct ControlToken(Zeroizing<String>);

impl ControlToken {
    /// Draw a fresh token from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes: Zeroizing<[u8; 32]> = Zeroizing::new(OsRng.gen());
        let token = ControlToken(Zeroizing::new(hex::encode(bytes.as_slice())));
        zeroize::Zeroize::zeroize(&mut *bytes);
        token
    }

    /// Wrap an existing token string (as read from the token file).
    pub fn from_string(s: String) -> Self {
        ControlToken(Zeroizing::new(s))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Constant-time comparison against a presented token.
    pub fn matches(&self, presented: &str) -> bool {
        self.0.as_bytes().ct_eq(presented.as_bytes()).unwrap_u8() == 1
    }
}

#[derive(Default)]
struct FailState {
    consecutive: u32,
}

struct WipeChallenge {
    nonce: Zeroizing<String>,
    issued: Instant,
}

/// Shared authentication state of one daemon process.
pub struct ControlAuth {
    token: ControlToken,
    failures: Mutex<FailState>,
    wipe: Mutex<Option<WipeChallenge>>,
}

impl ControlAuth {
    pub fn new(token: ControlToken) -> Self {
        Self {
            token,
            failures: Mutex::new(FailState::default()),
            wipe: Mutex::new(None),
        }
    }

    /// The token, for the daemon to write to its token file.
    pub fn token(&self) -> &ControlToken {
        &self.token
    }

    /// Check a presented token.  On failure returns the delay the caller must
    /// wait before answering; on success resets the failure counter.
    pub fn check(&self, presented: &str) -> std::result::Result<(), Duration> {
        let ok = self.token.matches(presented);
        let mut st = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if ok {
            st.consecutive = 0;
            Ok(())
        } else {
            st.consecutive = st.consecutive.saturating_add(1);
            let shift = st.consecutive.saturating_sub(1).min(6);
            let delay = FAIL_DELAY_BASE
                .checked_mul(1u32 << shift)
                .unwrap_or(FAIL_DELAY_MAX)
                .min(FAIL_DELAY_MAX);
            Err(delay)
        }
    }

    /// Issue a fresh single-use `Wipe` challenge, replacing any earlier one.
    pub fn issue_wipe_challenge(&self) -> String {
        let raw: Zeroizing<[u8; 16]> = Zeroizing::new(OsRng.gen());
        let nonce = hex::encode(raw.as_slice());
        let mut slot = self.wipe.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(WipeChallenge {
            nonce: Zeroizing::new(nonce.clone()),
            issued: Instant::now(),
        });
        nonce
    }

    /// Consume the outstanding challenge if `presented` matches it and it has
    /// not expired.  A match (or an expired challenge) always clears it.
    pub fn consume_wipe_challenge(&self, presented: &str) -> bool {
        let mut slot = self.wipe.lock().unwrap_or_else(|e| e.into_inner());
        let Some(ch) = slot.as_ref() else {
            return false;
        };
        if ch.issued.elapsed() > WIPE_CHALLENGE_TTL {
            *slot = None;
            return false;
        }
        let ok = ch.nonce.as_bytes().ct_eq(presented.as_bytes()).unwrap_u8() == 1;
        if ok {
            *slot = None;
        }
        ok
    }
}

// ─── Token file ──────────────────────────────────────────────────────────────

/// Write the token to `<data_dir>/daemon.token`, replacing any stale file.
pub fn write_token_file(data_dir: &Path, token: &ControlToken) -> Result<()> {
    let path = data_dir.join(TOKEN_FILE);
    // Never reuse a stale file: it may carry looser permissions.
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("remove stale daemon.token"),
    }
    let mut file = create_private_file(&path).context("create daemon.token")?;
    file.write_all(token.as_str().as_bytes())
        .context("write daemon.token")?;
    file.flush().ok();
    Ok(())
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(windows)]
fn create_private_file(path: &Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    // The file is still empty here, so nothing secret is exposed while the
    // ACL is being tightened.
    if let Err(e) = restrict_to_current_user(path) {
        tracing::warn!(
            "could not restrict daemon.token to the current user ({e}); \
             relying on the ACL of the per-user data directory"
        );
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn create_private_file(path: &Path) -> Result<std::fs::File> {
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?)
}

/// Drop inherited ACEs on `path` and grant full control to the current user
/// only, through the system `icacls` tool.
#[cfg(windows)]
pub fn restrict_to_current_user(path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let user = std::env::var("USERNAME").context("USERNAME is not set")?;
    let principal = match std::env::var("USERDOMAIN") {
        Ok(d) if !d.is_empty() => format!("{d}\\{user}"),
        _ => user,
    };
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let icacls = PathBuf::from(system_root)
        .join("System32")
        .join("icacls.exe");
    let out = std::process::Command::new(icacls)
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{principal}:(F)"))
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("run icacls")?;
    if !out.status.success() {
        bail!("icacls exited with {}", out.status);
    }
    Ok(())
}

/// Read the token written by the running daemon of `data_dir`.
pub fn read_token_file(data_dir: &Path) -> Result<ControlToken> {
    let path = data_dir.join(TOKEN_FILE);
    let s = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "daemon.token not found - is the miasma daemon running?\n  (looked in {})",
            path.display()
        )
    })?;
    let s = Zeroizing::new(s);
    let t = s.trim();
    if t.is_empty() {
        bail!("daemon.token is empty");
    }
    Ok(ControlToken::from_string(t.to_owned()))
}

/// Remove `<data_dir>/daemon.token` (called on clean daemon exit).
pub fn remove_token_file(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join(TOKEN_FILE));
}

// ─── Path policy ─────────────────────────────────────────────────────────────

/// Why a client-supplied output path was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathPolicyError {
    #[error("output path is empty")]
    Empty,
    #[error("output path must be absolute")]
    NotAbsolute,
    #[error("output path must not contain '..'")]
    ParentTraversal,
}

/// Defence in depth for daemon-side writes to a caller-chosen location: the
/// path must be absolute and free of `..` components.  This is not a sandbox.
pub fn validate_output_path(path: &str) -> std::result::Result<PathBuf, PathPolicyError> {
    if path.is_empty() {
        return Err(PathPolicyError::Empty);
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(PathPolicyError::NotAbsolute);
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(PathPolicyError::ParentTraversal);
    }
    Ok(p.to_path_buf())
}

/// Make `path` absolute and free of `..` components without touching the disk
/// (the output file need not exist yet). Clients use this so the paths they
/// send satisfy [`validate_output_path`].
pub fn absolutize_lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let joined = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_64_hex() {
        let a = ControlToken::generate();
        let b = ControlToken::generate();
        assert_eq!(a.as_str().len(), 64);
        assert!(a.as_str().bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn failure_delay_grows_and_resets() {
        let auth = ControlAuth::new(ControlToken::generate());
        let d1 = auth.check("wrong").unwrap_err();
        let d2 = auth.check("wrong").unwrap_err();
        assert!(d2 > d1);
        let tok = auth.token.as_str().to_owned();
        assert!(auth.check(&tok).is_ok());
        assert_eq!(auth.check("wrong").unwrap_err(), d1);
    }

    #[test]
    fn wipe_challenge_is_single_use() {
        let auth = ControlAuth::new(ControlToken::generate());
        assert!(!auth.consume_wipe_challenge("nothing-issued"));
        let n = auth.issue_wipe_challenge();
        assert!(!auth.consume_wipe_challenge("wrong"));
        assert!(auth.consume_wipe_challenge(&n));
        assert!(!auth.consume_wipe_challenge(&n));
    }

    #[test]
    fn output_path_policy() {
        assert_eq!(validate_output_path(""), Err(PathPolicyError::Empty));
        assert_eq!(
            validate_output_path("relative/out.bin"),
            Err(PathPolicyError::NotAbsolute)
        );
        let base = std::env::temp_dir();
        let ok = base.join("out.bin");
        assert!(validate_output_path(ok.to_str().unwrap()).is_ok());
        let bad = base.join("..").join("out.bin");
        assert_eq!(
            validate_output_path(bad.to_str().unwrap()),
            Err(PathPolicyError::ParentTraversal)
        );
    }
}
