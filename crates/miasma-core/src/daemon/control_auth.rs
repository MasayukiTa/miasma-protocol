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
//! The file is created through [`crate::secure_file`] and checked before the
//! secret is written; any failure aborts the daemon start (fail closed).
//!
//! * Unix: the file is created with mode `0600` at creation time (never
//!   widened and narrowed afterwards); an existing file is unlinked first so a
//!   stale file with looser permissions is never reused.  Afterwards the file
//!   (regular file, mode `0600`, owned by the daemon's user) and its directory
//!   (owned by the daemon's user, not writable by others) are verified.
//! * Windows: the file is created with a security descriptor passed to
//!   `CreateFileW` (one entry for the current user, no inheritance, owner set
//!   to the current user), so it is restricted from the first byte.  Its access
//!   list and owner are then verified.
//! * Other platforms: not supported; creating the file fails.

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
pub const TOKEN_FILE: &str = crate::paths::DAEMON_TOKEN.name;

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
///
/// Fails closed: if the data directory is not private, the file cannot be
/// created owner-only, or the created file does not verify as owner-only,
/// nothing secret is written, the file is removed and an error is returned.
/// The daemon treats that error as a failed start, so neither the HTTP bridge
/// nor the control IPC is brought up.
pub fn write_token_file(data_dir: &Path, token: &ControlToken) -> Result<()> {
    write_token_file_with(data_dir, token, crate::secure_file::verify_owner_only)
}

/// [`write_token_file`] with the post-creation check injected (tests make it
/// fail to prove the start is refused).
fn write_token_file_with(
    data_dir: &Path,
    token: &ControlToken,
    verify: impl Fn(&Path) -> std::result::Result<(), crate::MiasmaError>,
) -> Result<()> {
    crate::secure_file::verify_private_dir(data_dir).with_context(|| {
        format!(
            "the data directory {} is not private to the current user; \
             refusing to start the control interface",
            data_dir.display()
        )
    })?;
    let path = data_dir.join(TOKEN_FILE);
    // Never reuse a stale file: it may carry looser permissions.
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("remove stale daemon.token"),
    }
    let mut file = crate::secure_file::create_new_restricted(&path)
        .context("could not create daemon.token as an owner-only file; refusing to start the control interface")?;
    // Verify while the file is still empty, so the secret is never written to
    // a file whose protection is unconfirmed.
    if let Err(e) = verify(&path) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(anyhow::Error::new(e)).context(
            "daemon.token is not restricted to the current user; \
             refusing to start the control interface",
        );
    }
    let written = file
        .write_all(token.as_str().as_bytes())
        .and_then(|()| file.flush());
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&path);
        return Err(e).context("write daemon.token");
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
    fn token_file_round_trips_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let token = ControlToken::generate();
        write_token_file(dir.path(), &token).unwrap();
        crate::secure_file::verify_owner_only(&dir.path().join(TOKEN_FILE)).unwrap();
        let read = read_token_file(dir.path()).unwrap();
        assert!(read.matches(token.as_str()));
    }

    #[test]
    fn stale_token_file_is_replaced_by_an_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(TOKEN_FILE), "stale").unwrap();
        let token = ControlToken::generate();
        write_token_file(dir.path(), &token).unwrap();
        crate::secure_file::verify_owner_only(&dir.path().join(TOKEN_FILE)).unwrap();
        assert!(read_token_file(dir.path()).unwrap().matches(token.as_str()));
    }

    /// A failed check must refuse the start and leave no secret on disk.
    #[test]
    fn failed_verification_refuses_and_leaves_no_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let token = ControlToken::generate();
        let err = write_token_file_with(dir.path(), &token, |_| {
            Err(crate::MiasmaError::Io(std::io::Error::other(
                "injected verification failure",
            )))
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to start"),
            "unexpected error: {err:#}"
        );
        assert!(!dir.path().join(TOKEN_FILE).exists());
    }

    /// The real check refuses a file with default (non owner-only) access.
    #[test]
    fn real_verification_rejects_a_loosely_protected_file() {
        let dir = tempfile::tempdir().unwrap();
        let loose = dir.path().join("loose.tmp");
        std::fs::write(&loose, "x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(crate::secure_file::verify_owner_only(&loose).is_err());
    }

    /// A token path that cannot be replaced fails the write.
    #[test]
    fn unreplaceable_token_path_fails() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join(TOKEN_FILE);
        std::fs::create_dir(&blocker).unwrap();
        std::fs::write(blocker.join("inner"), "x").unwrap();
        assert!(write_token_file(dir.path(), &ControlToken::generate()).is_err());
    }

    /// Unix: a data directory other users can write to is refused.
    #[cfg(unix)]
    #[test]
    fn world_writable_data_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = write_token_file(dir.path(), &ControlToken::generate()).unwrap_err();
        assert!(format!("{err:#}").contains("not private"), "{err:#}");
        assert!(!dir.path().join(TOKEN_FILE).exists());
    }

    /// Unix: the created file is 0600 and owned by the current user.
    #[cfg(unix)]
    #[test]
    fn unix_token_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        write_token_file(dir.path(), &ControlToken::generate()).unwrap();
        let mode = std::fs::metadata(dir.path().join(TOKEN_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
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
