//! What can go wrong while checking for, fetching or applying an update.

use super::archive::ArchiveError;
use super::http::HttpError;
use super::verify::VerifyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// `update.mode = off`.
    Disabled,
    /// A transfer, push or chat send is running (or the daemon could not say).
    Busy(String),
    /// The install folder cannot be written to.
    NotWritable(String),
    /// This installation is not one the updater can replace in place.
    NoTarget(String),
    /// The release has no file for this machine.
    NoAsset,
    /// The release has no `SHA256SUMS.txt`.
    Unverifiable,
    Network(HttpError),
    Verify(VerifyError),
    Archive(ArchiveError),
    /// The new program did not start within the limit; the old one is back.
    HealthCheck(String),
    Io(String),
    /// The progress file is missing, unreadable or does not fit this install.
    Journal(String),
}

impl UpdateError {
    /// A stable word for logs, exit codes and the window's error table.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Busy(_) => "busy",
            Self::NotWritable(_) => "not_writable",
            Self::NoTarget(_) => "no_target",
            Self::NoAsset => "no_asset",
            Self::Unverifiable => "unverifiable",
            Self::Network(_) => "network",
            Self::Verify(_) => "verify",
            Self::Archive(_) => "archive",
            Self::HealthCheck(_) => "health_check",
            Self::Io(_) => "io",
            Self::Journal(_) => "journal",
        }
    }
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("updates are switched off (update.mode = off)"),
            Self::Busy(why) => write!(f, "not now: {why}"),
            Self::NotWritable(m) => write!(f, "the install folder cannot be written to: {m}"),
            Self::NoTarget(m) => write!(f, "this installation cannot be updated in place: {m}"),
            Self::NoAsset => f.write_str("the release has no file for this platform"),
            Self::Unverifiable => f.write_str("the release has no SHA256SUMS.txt and is refused"),
            Self::Network(e) => e.fmt(f),
            Self::Verify(e) => e.fmt(f),
            Self::Archive(e) => e.fmt(f),
            Self::HealthCheck(m) => write!(
                f,
                "the new version did not start ({m}); the old one was restored"
            ),
            Self::Io(m) => write!(f, "file error: {m}"),
            Self::Journal(m) => write!(f, "progress file: {m}"),
        }
    }
}

impl std::error::Error for UpdateError {}

impl From<HttpError> for UpdateError {
    fn from(e: HttpError) -> Self {
        Self::Network(e)
    }
}
impl From<VerifyError> for UpdateError {
    fn from(e: VerifyError) -> Self {
        Self::Verify(e)
    }
}
impl From<ArchiveError> for UpdateError {
    fn from(e: ArchiveError) -> Self {
        Self::Archive(e)
    }
}
impl From<std::io::Error> for UpdateError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
