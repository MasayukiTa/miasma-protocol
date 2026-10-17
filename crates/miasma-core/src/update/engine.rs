//! The updater: check, fetch and verify, apply, resume.
//!
//! One [`Engine`] is built per operation by whoever needs it (the desktop
//! worker, the command line); it holds no connection and no buffer, so nothing
//! stays resident between checks.

use std::path::{Path, PathBuf};
use std::time::Duration;

use semver::Version;

use super::activity::DaemonActivity;
use super::apply::{
    self, cli_name, new_id, now_unix, program_names, save_journal, Activity, Applied, Env, Journal,
    Phase, Prober, ProcessProber, Resumed, TargetKind, HEALTH_TIMEOUT,
};
use super::archive::Archive;
use super::config::{UpdateChannel, UpdateConfig};
use super::error::UpdateError;
use super::http::{Http, HttpError, HttpsClient};
use super::release::{
    parse_releases, releases_url, select_release, sig_asset, sums_asset, Os, Selection, REPO,
};
use super::state::UpdateState;
use super::verify::{
    expected_hash, sha256_file, verify_file_against_sums, verify_sums_signature, UPDATE_PUBKEYS,
};
use super::version::{parse_version_output, BuildInfo};

/// Largest release list read into memory.
pub const MAX_LIST_BYTES: usize = 1024 * 1024;
/// Largest `SHA256SUMS.txt` accepted.
pub const MAX_SUMS_BYTES: usize = 64 * 1024;
/// Largest signature file accepted.
pub const MAX_SIG_BYTES: usize = 4 * 1024;
/// Largest archive downloaded.
pub const MAX_ARCHIVE_BYTES: u64 = 400 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Release,
    Local,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Local => "local",
        }
    }
}

/// Where the files of a release are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFiles {
    pub tag: String,
    pub archive_name: String,
    pub archive_url: String,
    pub archive_size: u64,
    pub sums_url: String,
    pub sig_url: Option<String>,
}

/// A newer build that can be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateOffer {
    pub source: Source,
    /// Version as text (`0.4.0`, `0.4.0-beta.1`).
    pub version: String,
    /// Local builds: the build id of the new program.
    pub build_id: Option<String>,
    pub release: Option<ReleaseFiles>,
    pub local_dir: Option<PathBuf>,
    /// The person chose "skip this version" for it.
    pub skipped: bool,
}

/// Why a check produced no answer. Never reported as "up to date".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckFailure {
    /// No network, DNS failure, connection refused.
    Offline,
    Timeout,
    RateLimited,
    /// The repository or its release list does not exist (404).
    NotFound,
    Server(u16),
    /// The answer was not a release list.
    BadAnswer(String),
    /// The local build folder could not be read.
    Local(String),
}

impl CheckFailure {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::NotFound => "not_found",
            Self::Server(_) => "server",
            Self::BadAnswer(_) => "bad_answer",
            Self::Local(_) => "local",
        }
    }
}

impl std::fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offline => f.write_str("cannot reach the update server"),
            Self::Timeout => f.write_str("the update server did not answer in time"),
            Self::RateLimited => f.write_str("the update server's request limit is reached"),
            Self::NotFound => f.write_str("the release list was not found"),
            Self::Server(s) => write!(f, "the update server answered {s}"),
            Self::BadAnswer(m) => write!(f, "unusable answer: {m}"),
            Self::Local(m) => write!(f, "local build folder: {m}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// `update.mode = off`: nothing was done, nothing was contacted.
    Disabled,
    /// Looked and found nothing newer. `latest` is the newest version seen.
    UpToDate {
        latest: Option<String>,
    },
    Available(UpdateOffer),
    /// Newer, but the release has no file for this platform.
    NoAsset {
        version: String,
    },
    /// Newer, but the release has no `SHA256SUMS.txt`: refused.
    Unverifiable {
        version: String,
    },
    /// Could not find out.
    Failed(CheckFailure),
}

impl CheckOutcome {
    /// `disabled`, `up_to_date`, `available`, `no_asset`, `unverifiable` or `failed`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::UpToDate { .. } => "up_to_date",
            Self::Available(_) => "available",
            Self::NoAsset { .. } => "no_asset",
            Self::Unverifiable { .. } => "unverifiable",
            Self::Failed(_) => "failed",
        }
    }
}

/// Where this installation lives and what an update replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kind: TargetKind,
    /// `Files`: the install folder. `Bundle`: the folder that holds the bundle.
    pub dir: PathBuf,
    pub bundle: Option<String>,
    pub names: Vec<String>,
}

/// The `.app` folder that contains `exe`, if any.
pub fn bundle_root(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .skip(1)
        .find(|a| a.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf)
}

/// Decide what an update would replace for the program at `exe`.
pub fn detect_target(exe: &Path, os: Os) -> Result<Target, UpdateError> {
    if os == Os::MacOs {
        if let Some(app) = bundle_root(exe) {
            let name = app
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .ok_or_else(|| UpdateError::NoTarget("bundle without a name".into()))?;
            let dir = app
                .parent()
                .ok_or_else(|| UpdateError::NoTarget("bundle without a folder".into()))?
                .to_path_buf();
            return Ok(Target {
                kind: TargetKind::Bundle,
                dir,
                bundle: Some(name),
                names: Vec::new(),
            });
        }
    }
    let dir = exe
        .parent()
        .ok_or_else(|| UpdateError::NoTarget("program without a folder".into()))?
        .to_path_buf();
    let names: Vec<String> = program_names(os)
        .into_iter()
        .filter(|n| dir.join(n).is_file())
        .collect();
    if !names.iter().any(|n| *n == cli_name(os)) {
        return Err(UpdateError::NoTarget(format!(
            "{} is not next to this program",
            cli_name(os)
        )));
    }
    Ok(Target {
        kind: TargetKind::Files,
        dir,
        bundle: None,
        names,
    })
}

pub struct Engine {
    pub http: Box<dyn Http>,
    pub prober: Box<dyn Prober>,
    pub activity: Box<dyn Activity>,
    pub os: Os,
    pub cfg: UpdateConfig,
    pub current: Version,
    pub build_id: String,
    /// The running program (`std::env::current_exe()`).
    pub exe: PathBuf,
    pub data_dir: PathBuf,
    pub keys: Vec<[u8; 32]>,
    pub repo: String,
    pub health_timeout: Duration,
}

impl Engine {
    /// The real engine for the running program: real network, real processes,
    /// the pinned keys, this repository.
    pub fn new(
        data_dir: &Path,
        cfg: UpdateConfig,
        version: &str,
        build_id: &str,
    ) -> Result<Self, UpdateError> {
        let current = Version::parse(version)
            .map_err(|e| UpdateError::NoTarget(format!("own version: {e}")))?;
        let exe = std::env::current_exe()?;
        Ok(Self {
            http: Box::new(HttpsClient::new()),
            prober: Box::new(ProcessProber),
            activity: Box::new(DaemonActivity {
                data_dir: data_dir.to_path_buf(),
            }),
            os: Os::current(),
            cfg,
            current,
            build_id: build_id.to_owned(),
            exe,
            data_dir: data_dir.to_path_buf(),
            keys: UPDATE_PUBKEYS.to_vec(),
            repo: REPO.to_owned(),
            health_timeout: HEALTH_TIMEOUT,
        })
    }

    /// Trust the extra CA file `transport.iroh_extra_ca_pem` names (in addition
    /// to the operating system's store) for the GitHub requests, as the relay
    /// connections do. The file is only opened when a request is made.
    pub fn with_extra_ca_file(mut self, path: Option<String>) -> Self {
        self.http = Box::new(HttpsClient::new().with_extra_ca_file(path));
        self
    }

    fn env(&self) -> Env<'_> {
        Env {
            data_dir: &self.data_dir,
            os: self.os,
            prober: self.prober.as_ref(),
            activity: self.activity.as_ref(),
            health_timeout: self.health_timeout,
        }
    }

    fn require_enabled(&self) -> Result<(), UpdateError> {
        if self.cfg.is_enabled() {
            Ok(())
        } else {
            Err(UpdateError::Disabled)
        }
    }

    // ── checking ────────────────────────────────────────────────────────────

    /// Look for a newer build. With `update.mode = off` this returns
    /// [`CheckOutcome::Disabled`] before doing anything at all.
    pub fn check(&self) -> CheckOutcome {
        if !self.cfg.is_enabled() {
            return CheckOutcome::Disabled;
        }
        if let Some(dir) = self.cfg.local_dir() {
            match self.check_local(&dir) {
                Ok(Some(offer)) => return CheckOutcome::Available(offer),
                Ok(None) => {}
                Err(f) => return CheckOutcome::Failed(f),
            }
        }
        self.check_release()
    }

    fn check_local(&self, dir: &Path) -> Result<Option<UpdateOffer>, CheckFailure> {
        let cli = dir.join(cli_name(self.os));
        let Ok(cand_meta) = std::fs::metadata(&cli) else {
            return Ok(None);
        };
        let running = std::fs::metadata(&self.exe)
            .and_then(|m| m.modified())
            .map_err(|e| CheckFailure::Local(e.to_string()))?;
        let cand = cand_meta
            .modified()
            .map_err(|e| CheckFailure::Local(e.to_string()))?;
        if cand <= running {
            return Ok(None);
        }
        // Only the command line program is started for its version; the
        // desktop program would open its window on the real data.
        let out = self
            .prober
            .version(&cli, self.health_timeout)
            .map_err(CheckFailure::Local)?;
        let BuildInfo { version, build_id } = parse_version_output(&out)
            .ok_or_else(|| CheckFailure::Local("unexpected --version output".into()))?;
        if build_id == self.build_id {
            return Ok(None);
        }
        let state = UpdateState::load(&self.data_dir);
        let label = format!("{version}+{build_id}");
        Ok(Some(UpdateOffer {
            source: Source::Local,
            skipped: state.is_skipped(&label),
            version: label,
            build_id: Some(build_id),
            release: None,
            local_dir: Some(dir.to_path_buf()),
        }))
    }

    fn check_release(&self) -> CheckOutcome {
        use CheckFailure as F;
        let url = releases_url(&self.repo);
        let resp = match self
            .http
            .get(&url, "application/vnd.github+json", MAX_LIST_BYTES)
        {
            Ok(r) => r,
            Err(e) => return CheckOutcome::Failed(failure_of(&e)),
        };
        if resp.rate_limited {
            return CheckOutcome::Failed(F::RateLimited);
        }
        match resp.status {
            200 => {}
            404 => return CheckOutcome::Failed(F::NotFound),
            403 | 429 => return CheckOutcome::Failed(F::RateLimited),
            s => return CheckOutcome::Failed(F::Server(s)),
        }
        let releases = match parse_releases(&resp.body) {
            Ok(r) => r,
            Err(m) => return CheckOutcome::Failed(F::BadAnswer(m)),
        };
        match select_release(&releases, self.cfg.channel, &self.current, self.os) {
            Selection::UpToDate { latest } => CheckOutcome::UpToDate {
                latest: latest.map(|v| v.to_string()),
            },
            Selection::NoAsset { version } => CheckOutcome::NoAsset {
                version: version.to_string(),
            },
            Selection::Unverifiable { version } => CheckOutcome::Unverifiable {
                version: version.to_string(),
            },
            Selection::Newer { index, version } => {
                let r = &releases[index];
                let (Some(archive), Some(sums)) =
                    (super::release::pick_asset(r, self.os), sums_asset(r))
                else {
                    return CheckOutcome::Failed(F::BadAnswer("release changed".into()));
                };
                let state = UpdateState::load(&self.data_dir);
                CheckOutcome::Available(UpdateOffer {
                    source: Source::Release,
                    skipped: state.is_skipped(&version.to_string()),
                    version: version.to_string(),
                    build_id: None,
                    release: Some(ReleaseFiles {
                        tag: r.tag_name.clone(),
                        archive_name: archive.name.clone(),
                        archive_url: archive.browser_download_url.clone(),
                        archive_size: archive.size,
                        sums_url: sums.browser_download_url.clone(),
                        sig_url: sig_asset(r).map(|a| a.browser_download_url.clone()),
                    }),
                    local_dir: None,
                })
            }
        }
    }

    // ── fetching ────────────────────────────────────────────────────────────

    /// Download and verify (release) or validate (local build) an offer, without
    /// changing the installation. The result is a journal in phase
    /// `Downloaded`, saved so a restart can pick it up.
    pub fn prepare(
        &self,
        offer: &UpdateOffer,
        progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> Result<Journal, UpdateError> {
        self.require_enabled()?;
        let target = detect_target(&self.exe, self.os)?;
        let id = new_id();
        let work_dir = crate::paths::update_work_dir(&self.data_dir, &id);
        let mut j = Journal {
            id,
            source: offer.source.as_str().to_owned(),
            version: offer.version.clone(),
            build_id: offer.build_id.clone(),
            phase: Phase::Downloaded,
            kind: target.kind,
            dir: target.dir.clone(),
            bundle: target.bundle.clone(),
            names: target.names.clone(),
            hashes: Vec::new(),
            work_dir: work_dir.clone(),
            archive: None,
            archive_name: None,
            archive_sha256: None,
            local_dir: None,
            started_unix: now_unix(),
        };
        match offer.source {
            Source::Release => {
                std::fs::create_dir_all(&work_dir)?;
                let r = self.fetch_release(offer, &work_dir, &mut j, progress);
                if let Err(e) = r {
                    let _ = std::fs::remove_dir_all(&work_dir);
                    return Err(e);
                }
            }
            Source::Local => {
                let dir = offer
                    .local_dir
                    .clone()
                    .ok_or_else(|| UpdateError::Journal("no local folder".into()))?;
                if target.kind == TargetKind::Bundle {
                    return Err(UpdateError::NoTarget(
                        "a local build cannot replace an application bundle".into(),
                    ));
                }
                // Every program installed must exist in the build folder, or the
                // result would mix two versions (the optional bridge excepted).
                let bridge = program_names(self.os).pop().unwrap_or_default();
                let mut names = Vec::new();
                for n in &target.names {
                    if dir.join(n).is_file() {
                        names.push(n.clone());
                    } else if *n != bridge {
                        return Err(UpdateError::NoTarget(format!(
                            "the build folder has no {n}"
                        )));
                    }
                }
                j.names = names;
                j.local_dir = Some(dir);
            }
        }
        save_journal(&self.data_dir, &j)?;
        Ok(j)
    }

    fn fetch_release(
        &self,
        offer: &UpdateOffer,
        work_dir: &Path,
        j: &mut Journal,
        progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> Result<(), UpdateError> {
        let files = offer.release.as_ref().ok_or(UpdateError::NoAsset)?;

        // 1. The checksum file is mandatory.
        let sums = match self
            .http
            .get(&files.sums_url, "application/octet-stream", MAX_SUMS_BYTES)
        {
            Ok(r) if r.status == 200 => r.body,
            Ok(_) => return Err(UpdateError::Unverifiable),
            Err(e) => return Err(UpdateError::Network(e)),
        };
        // It must list the archive (also checks that it parses).
        expected_hash(&sums, &files.archive_name)?;

        // 2. The signature, when this build pins keys.
        let sig = if self.keys.is_empty() {
            None
        } else {
            let url = files.sig_url.as_deref().ok_or(UpdateError::Verify(
                super::verify::VerifyError::SignatureMissing,
            ))?;
            match self
                .http
                .get(url, "application/octet-stream", MAX_SIG_BYTES)
            {
                Ok(r) if r.status == 200 => Some(r.body),
                Ok(_) => {
                    return Err(UpdateError::Verify(
                        super::verify::VerifyError::SignatureMissing,
                    ))
                }
                Err(e) => return Err(UpdateError::Network(e)),
            }
        };
        verify_sums_signature(&sums, sig.as_deref(), &self.keys)?;

        // 3. The archive, straight to disk.
        let path = work_dir.join("update.zip");
        self.http
            .download(&files.archive_url, &path, MAX_ARCHIVE_BYTES, progress)?;
        let hash = verify_file_against_sums(&path, &files.archive_name, &sums)?;

        // 4. It must be a readable archive with only safe entries.
        Archive::open(&path)?;

        j.archive = Some(path);
        j.archive_name = Some(files.archive_name.clone());
        j.archive_sha256 = Some(hash);
        Ok(())
    }

    // ── applying ────────────────────────────────────────────────────────────

    /// Put a prepared update in place. See [`apply::apply`].
    pub fn apply(&self, j: &mut Journal) -> Result<Applied, UpdateError> {
        self.require_enabled()?;
        let r = apply::apply(&self.env(), j);
        if let Err(UpdateError::HealthCheck(_)) = &r {
            let mut st = UpdateState::load(&self.data_dir);
            st.failed_update = Some(format!("{}/{}", j.version, self.build_id));
            let _ = st.save(&self.data_dir);
        }
        r
    }

    /// Whether this update already failed its start check from this build.
    pub fn failed_before(&self, offer: &UpdateOffer) -> bool {
        UpdateState::load(&self.data_dir).failed_update.as_deref()
            == Some(format!("{}/{}", offer.version, self.build_id).as_str())
    }

    /// Repair or finish what an earlier run left half done. Safe to call at
    /// every start; it does nothing when no update was in progress, and it does
    /// not touch the network.
    pub fn resume(&self) -> Result<Resumed, UpdateError> {
        apply::resume(&self.env())
    }

    /// Remember that the person does not want this version.
    pub fn skip(&self, version: &str) {
        let mut st = UpdateState::load(&self.data_dir);
        st.skipped_version = Some(version.to_owned());
        let _ = st.save(&self.data_dir);
    }

    /// The SHA-256 of the running program (for display and tests).
    pub fn own_hash(&self) -> Option<String> {
        sha256_file(&self.exe).ok()
    }
}

fn failure_of(e: &HttpError) -> CheckFailure {
    match e {
        HttpError::Offline(_) => CheckFailure::Offline,
        HttpError::Timeout => CheckFailure::Timeout,
        HttpError::RateLimited => CheckFailure::RateLimited,
        HttpError::Status(s) => CheckFailure::Server(*s),
        other => CheckFailure::BadAnswer(other.to_string()),
    }
}

/// Which channel names the release list; kept next to the engine so callers can
/// print it.
pub fn channel_label(c: UpdateChannel) -> &'static str {
    c.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::apply::testutil::{version_text, FileProber, FixedActivity};
    use crate::update::apply::Busy;
    use crate::update::archive::testutil::make_zip;
    use crate::update::config::UpdateMode;
    use crate::update::http::fake::{FakeHttp, Reply};
    use crate::update::verify::sha256_bytes;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::sync::Arc;

    const LIST_URL: &str =
        "https://api.github.com/repos/MasayukiTa/miasma-protocol/releases?per_page=10";
    const ZIP_URL: &str = "https://dl.invalid/miasma-0.4.0-windows-x64.zip";
    const SUMS_URL: &str = "https://dl.invalid/SHA256SUMS.txt";
    const SIG_URL: &str = "https://dl.invalid/SHA256SUMS.txt.sig";
    const ZIP_NAME: &str = "miasma-0.4.0-windows-x64.zip";
    const OLD: &str = "miasma 0.3.2 (old000000)\n";

    /// Lets a test keep a handle on the fake while the engine owns a box of it.
    struct Shared(Arc<FakeHttp>);
    impl Http for Shared {
        fn get(
            &self,
            u: &str,
            a: &str,
            m: usize,
        ) -> Result<super::super::http::HttpResponse, HttpError> {
            self.0.get(u, a, m)
        }
        fn download(
            &self,
            u: &str,
            d: &Path,
            m: u64,
            p: &mut (dyn FnMut(u64, Option<u64>) + Send),
        ) -> Result<u64, HttpError> {
            self.0.download(u, d, m, p)
        }
    }

    struct Rig {
        _t: tempfile::TempDir,
        http: Arc<FakeHttp>,
        engine: Engine,
        prober: Arc<FileProber>,
        install: PathBuf,
        data: PathBuf,
    }

    fn release_list(tag: &str, with_sums: bool, with_sig: bool) -> Vec<u8> {
        let mut assets = vec![format!(
            r#"{{"name":"{ZIP_NAME}","browser_download_url":"{ZIP_URL}","size":100}}"#
        )];
        if with_sums {
            assets.push(format!(
                r#"{{"name":"SHA256SUMS.txt","browser_download_url":"{SUMS_URL}","size":10}}"#
            ));
        }
        if with_sig {
            assets.push(format!(
                r#"{{"name":"SHA256SUMS.txt.sig","browser_download_url":"{SIG_URL}","size":10}}"#
            ));
        }
        format!(
            r#"[{{"tag_name":"{tag}","draft":false,"prerelease":false,"assets":[{}]}}]"#,
            assets.join(",")
        )
        .into_bytes()
    }

    fn rig(mode: UpdateMode) -> Rig {
        let t = tempfile::tempdir().unwrap();
        let install = t.path().join("install");
        let data = t.path().join("data");
        fs::create_dir_all(&install).unwrap();
        fs::create_dir_all(&data).unwrap();
        fs::write(install.join("miasma.exe"), OLD).unwrap();
        fs::write(install.join("miasma-desktop.exe"), "old desktop").unwrap();
        let http = Arc::new(FakeHttp::default());
        let prober = Arc::new(FileProber::new());
        let engine = Engine {
            http: Box::new(Shared(http.clone())),
            prober: Box::new(prober.clone()),
            activity: Box::new(FixedActivity(Busy::Idle)),
            os: Os::Windows,
            cfg: UpdateConfig {
                mode,
                ..UpdateConfig::default()
            },
            current: Version::parse("0.3.2").unwrap(),
            build_id: "old000000".into(),
            exe: install.join("miasma-desktop.exe"),
            data_dir: data.clone(),
            keys: Vec::new(),
            repo: REPO.to_owned(),
            health_timeout: Duration::from_secs(1),
        };
        Rig {
            _t: t,
            http,
            engine,
            prober,
            install,
            data,
        }
    }

    fn serve_release(r: &Rig, new_cli: &str) -> Vec<u8> {
        let zip_path = r._t.path().join("served.zip");
        make_zip(
            &zip_path,
            &[
                ("miasma.exe", new_cli.as_bytes()),
                ("miasma-desktop.exe", b"new desktop"),
            ],
        );
        let zip = fs::read(&zip_path).unwrap();
        let sums = format!("{}  {ZIP_NAME}\n", sha256_bytes(&zip)).into_bytes();
        r.http.route(
            LIST_URL,
            Reply::Body(200, release_list("v0.4.0", true, true)),
        );
        r.http.route(ZIP_URL, Reply::Body(200, zip));
        r.http.route(SUMS_URL, Reply::Body(200, sums.clone()));
        sums
    }

    fn offer_of(o: CheckOutcome) -> UpdateOffer {
        match o {
            CheckOutcome::Available(o) => o,
            other => panic!("{other:?}"),
        }
    }

    // ── check ──

    #[test]
    fn mode_off_checks_nothing_and_contacts_nothing() {
        let r = rig(UpdateMode::Off);
        r.http.route(
            LIST_URL,
            Reply::Body(200, release_list("v9.9.9", true, false)),
        );
        assert_eq!(r.engine.check(), CheckOutcome::Disabled);
        assert_eq!(r.http.count(), 0, "no request may be made when off");
        // The other entry points refuse too.
        let offer = UpdateOffer {
            source: Source::Release,
            version: "9.9.9".into(),
            build_id: None,
            release: None,
            local_dir: None,
            skipped: false,
        };
        assert_eq!(
            r.engine.prepare(&offer, &mut |_, _| {}).unwrap_err(),
            UpdateError::Disabled
        );
        assert_eq!(r.http.count(), 0);
    }

    #[test]
    fn mode_off_does_not_even_look_at_the_local_build_folder() {
        let mut r = rig(UpdateMode::Off);
        r.engine.cfg.local_build_dir =
            Some(r._t.path().join("nowhere").to_string_lossy().into_owned());
        assert_eq!(r.engine.check(), CheckOutcome::Disabled);
        assert!(
            r.prober.calls.lock().unwrap().is_empty(),
            "no program may be started when off"
        );
    }

    #[test]
    fn a_newer_release_is_offered_with_its_files() {
        let r = rig(UpdateMode::Notify);
        serve_release(&r, "miasma 0.4.0 (new000000)\n");
        let o = offer_of(r.engine.check());
        assert_eq!(o.version, "0.4.0");
        assert_eq!(o.source, Source::Release);
        let f = o.release.unwrap();
        assert_eq!(f.archive_name, ZIP_NAME);
        assert_eq!(f.sig_url.as_deref(), Some(SIG_URL));
        assert_eq!(r.http.count(), 1, "one request for the check");
    }

    #[test]
    fn the_same_or_an_older_version_is_up_to_date() {
        let r = rig(UpdateMode::Notify);
        r.http.route(
            LIST_URL,
            Reply::Body(200, release_list("v0.3.2", true, false)),
        );
        assert_eq!(
            r.engine.check(),
            CheckOutcome::UpToDate {
                latest: Some("0.3.2".into())
            }
        );
    }

    #[test]
    fn a_failed_check_is_failed_never_up_to_date() {
        for (reply, want) in [
            (
                Reply::Fail(HttpError::Offline("dns".into())),
                CheckFailure::Offline,
            ),
            (Reply::Fail(HttpError::Timeout), CheckFailure::Timeout),
            (Reply::Limited, CheckFailure::RateLimited),
            (Reply::Body(404, Vec::new()), CheckFailure::NotFound),
            (
                Reply::Body(500, b"oops".to_vec()),
                CheckFailure::Server(500),
            ),
            (Reply::Body(403, b"{}".to_vec()), CheckFailure::RateLimited),
        ] {
            let r = rig(UpdateMode::Notify);
            r.http.route(LIST_URL, reply);
            let out = r.engine.check();
            assert_eq!(out, CheckOutcome::Failed(want), "{out:?}");
            assert_eq!(out.code(), "failed");
            assert_ne!(out.code(), "up_to_date");
        }
        // 200 with something that is not a release list.
        let r = rig(UpdateMode::Notify);
        r.http
            .route(LIST_URL, Reply::Body(200, br#"{"message":"hi"}"#.to_vec()));
        assert!(matches!(
            r.engine.check(),
            CheckOutcome::Failed(CheckFailure::BadAnswer(_))
        ));
    }

    #[test]
    fn a_release_without_a_file_for_this_platform_or_checksums_is_reported_as_such() {
        let r = rig(UpdateMode::Notify);
        r.http.route(
            LIST_URL,
            Reply::Body(
                200,
                br#"[{"tag_name":"v0.4.0","assets":[{"name":"Miasma-macOS.zip","browser_download_url":"https://x/m","size":1}]}]"#
                    .to_vec(),
            ),
        );
        assert_eq!(
            r.engine.check(),
            CheckOutcome::NoAsset {
                version: "0.4.0".into()
            }
        );

        let r = rig(UpdateMode::Notify);
        r.http.route(
            LIST_URL,
            Reply::Body(200, release_list("v0.4.0", false, false)),
        );
        assert_eq!(
            r.engine.check(),
            CheckOutcome::Unverifiable {
                version: "0.4.0".into()
            }
        );
    }

    #[test]
    fn a_skipped_version_is_still_reported_but_flagged() {
        let r = rig(UpdateMode::Notify);
        serve_release(&r, "miasma 0.4.0 (new000000)\n");
        assert!(!offer_of(r.engine.check()).skipped);
        r.engine.skip("0.4.0");
        assert!(offer_of(r.engine.check()).skipped);
    }

    // ── prepare and apply, end to end over the fake network ──

    #[test]
    fn check_download_verify_apply_end_to_end() {
        let r = rig(UpdateMode::Notify);
        serve_release(&r, "miasma 0.4.0 (new000000)\n");
        let offer = offer_of(r.engine.check());
        let mut seen = 0u64;
        let mut j = r
            .engine
            .prepare(&offer, &mut |done, _| {
                seen = done;
            })
            .unwrap();
        assert!(seen > 0);
        assert_eq!(j.phase, Phase::Downloaded);
        // Nothing in the install folder changed yet.
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe")).unwrap(),
            OLD
        );
        // The download is inside the data directory.
        assert!(j.work_dir.starts_with(&r.data));
        let applied = r.engine.apply(&mut j).unwrap();
        assert_eq!(applied.version, "0.4.0");
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe")).unwrap(),
            "miasma 0.4.0 (new000000)\n"
        );
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe.prev")).unwrap(),
            OLD
        );
    }

    #[test]
    fn a_missing_sha256sums_refuses_the_release() {
        let r = rig(UpdateMode::Notify);
        serve_release(&r, "miasma 0.4.0 (new000000)\n");
        let offer = offer_of(r.engine.check());
        r.http.route(SUMS_URL, Reply::Body(404, Vec::new()));
        assert_eq!(
            r.engine.prepare(&offer, &mut |_, _| {}).unwrap_err(),
            UpdateError::Unverifiable
        );
        // Nothing is left behind.
        assert!(
            !crate::paths::update_dir(&r.data).exists()
                || fs::read_dir(crate::paths::update_dir(&r.data))
                    .unwrap()
                    .count()
                    == 0
        );
    }

    #[test]
    fn a_hash_mismatch_refuses_the_download_and_deletes_it() {
        let r = rig(UpdateMode::Notify);
        serve_release(&r, "miasma 0.4.0 (new000000)\n");
        let offer = offer_of(r.engine.check());
        let bad = format!("{}  {ZIP_NAME}\n", "0".repeat(64));
        r.http.route(SUMS_URL, Reply::Body(200, bad.into_bytes()));
        let e = r.engine.prepare(&offer, &mut |_, _| {}).unwrap_err();
        assert!(matches!(
            e,
            UpdateError::Verify(super::super::verify::VerifyError::Mismatch { .. })
        ));
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe")).unwrap(),
            OLD
        );
        let left = fs::read_dir(crate::paths::update_dir(&r.data))
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(left, 0, "the rejected download is deleted");
    }

    #[test]
    fn sums_that_do_not_list_the_archive_refuse_the_release() {
        let r = rig(UpdateMode::Notify);
        serve_release(&r, "miasma 0.4.0 (new000000)\n");
        let offer = offer_of(r.engine.check());
        let other = format!("{}  something-else.zip\n", "a".repeat(64));
        r.http.route(SUMS_URL, Reply::Body(200, other.into_bytes()));
        assert!(matches!(
            r.engine.prepare(&offer, &mut |_, _| {}).unwrap_err(),
            UpdateError::Verify(super::super::verify::VerifyError::NotListed(_))
        ));
    }

    #[test]
    fn with_a_pinned_key_a_valid_signature_is_required() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let mut r = rig(UpdateMode::Notify);
        r.engine.keys = vec![sk.verifying_key().to_bytes()];
        let sums = serve_release(&r, "miasma 0.4.0 (new000000)\n");
        let offer = offer_of(r.engine.check());

        // Missing signature file.
        r.http.route(SIG_URL, Reply::Body(404, Vec::new()));
        assert_eq!(
            r.engine.prepare(&offer, &mut |_, _| {}).unwrap_err(),
            UpdateError::Verify(super::super::verify::VerifyError::SignatureMissing)
        );
        // Signature over different bytes (tampered checksum file).
        let mut tampered = sums.clone();
        tampered[0] = b'f';
        r.http.route(
            SIG_URL,
            Reply::Body(200, sk.sign(&tampered).to_bytes().to_vec()),
        );
        assert_eq!(
            r.engine.prepare(&offer, &mut |_, _| {}).unwrap_err(),
            UpdateError::Verify(super::super::verify::VerifyError::SignatureInvalid)
        );
        // The right signature.
        r.http.route(
            SIG_URL,
            Reply::Body(200, sk.sign(&sums).to_bytes().to_vec()),
        );
        let mut j = r.engine.prepare(&offer, &mut |_, _| {}).unwrap();
        r.engine.apply(&mut j).unwrap();
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe")).unwrap(),
            "miasma 0.4.0 (new000000)\n"
        );
    }

    #[test]
    fn without_pinned_keys_the_signature_file_is_not_even_fetched() {
        let r = rig(UpdateMode::Notify);
        serve_release(&r, "miasma 0.4.0 (new000000)\n");
        let offer = offer_of(r.engine.check());
        r.engine.prepare(&offer, &mut |_, _| {}).unwrap();
        let reqs = r.http.requests.lock().unwrap();
        assert!(!reqs.iter().any(|u| u == SIG_URL), "{reqs:?}");
    }

    #[test]
    fn a_new_version_that_does_not_start_is_rolled_back_and_not_retried_automatically() {
        let r = rig(UpdateMode::Auto);
        serve_release(&r, "BROKEN");
        let offer = offer_of(r.engine.check());
        assert!(!r.engine.failed_before(&offer));
        let mut j = r.engine.prepare(&offer, &mut |_, _| {}).unwrap();
        assert!(matches!(
            r.engine.apply(&mut j),
            Err(UpdateError::HealthCheck(_))
        ));
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe")).unwrap(),
            OLD
        );
        assert!(r.engine.failed_before(&offer));
    }

    #[test]
    fn a_busy_daemon_blocks_the_apply_but_not_the_download() {
        let mut r = rig(UpdateMode::Auto);
        r.engine.activity = Box::new(FixedActivity(Busy::Active("a transfer is running".into())));
        serve_release(&r, "miasma 0.4.0 (new000000)\n");
        let offer = offer_of(r.engine.check());
        let mut j = r.engine.prepare(&offer, &mut |_, _| {}).unwrap();
        assert!(matches!(r.engine.apply(&mut j), Err(UpdateError::Busy(_))));
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe")).unwrap(),
            OLD
        );
        // The verified download is kept for the next try (and for a restart).
        assert!(matches!(r.engine.resume().unwrap(), Resumed::Pending(_)));
    }

    // ── local build source ──

    fn local_rig() -> (Rig, PathBuf) {
        let mut r = rig(UpdateMode::Notify);
        let dir = r._t.path().join("target-release");
        fs::create_dir_all(&dir).unwrap();
        r.engine.cfg.local_build_dir = Some(dir.to_string_lossy().into_owned());
        (r, dir)
    }

    fn set_mtime(p: &Path, ahead: bool) {
        let f = fs::File::options().write(true).open(p).unwrap();
        let t = std::time::SystemTime::now();
        let t = if ahead {
            t + Duration::from_secs(3600)
        } else {
            t - Duration::from_secs(3600)
        };
        f.set_modified(t).unwrap();
    }

    #[test]
    fn a_newer_local_build_with_another_id_is_offered_without_any_network() {
        let (r, dir) = local_rig();
        fs::write(dir.join("miasma.exe"), version_text("0.3.2", "dev111111")).unwrap();
        fs::write(dir.join("miasma-desktop.exe"), "dev desktop").unwrap();
        set_mtime(&dir.join("miasma.exe"), true);
        let o = offer_of(r.engine.check());
        assert_eq!(o.source, Source::Local);
        assert_eq!(o.build_id.as_deref(), Some("dev111111"));
        assert_eq!(r.http.count(), 0);

        let mut j = r.engine.prepare(&o, &mut |_, _| {}).unwrap();
        r.engine.apply(&mut j).unwrap();
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe")).unwrap(),
            version_text("0.3.2", "dev111111")
        );
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe.prev")).unwrap(),
            OLD
        );
    }

    #[test]
    fn a_local_build_with_the_same_id_or_an_older_file_is_not_offered() {
        let (r, dir) = local_rig();
        fs::write(dir.join("miasma.exe"), version_text("0.3.2", "old000000")).unwrap();
        set_mtime(&dir.join("miasma.exe"), true);
        // Same build id as the running program: nothing to do (falls through to the release check).
        r.http.route(
            LIST_URL,
            Reply::Body(200, release_list("v0.3.2", true, false)),
        );
        assert!(matches!(r.engine.check(), CheckOutcome::UpToDate { .. }));

        // Older file, different id.
        fs::write(dir.join("miasma.exe"), version_text("0.3.2", "dev111111")).unwrap();
        set_mtime(&dir.join("miasma.exe"), false);
        assert!(matches!(r.engine.check(), CheckOutcome::UpToDate { .. }));
    }

    #[test]
    fn the_local_check_never_starts_the_desktop_program() {
        let (r, dir) = local_rig();
        fs::write(dir.join("miasma.exe"), version_text("0.3.2", "dev111111")).unwrap();
        fs::write(
            dir.join("miasma-desktop.exe"),
            version_text("0.3.2", "dev111111"),
        )
        .unwrap();
        set_mtime(&dir.join("miasma.exe"), true);
        let _ = r.engine.check();
        // FileProber records every program it was asked to start.
        let calls = r.prober.calls.lock().unwrap();
        assert!(!calls.is_empty());
        assert!(
            calls.iter().all(|c| c.file_name().unwrap() == "miasma.exe"),
            "{calls:?}"
        );
    }

    #[test]
    fn an_incomplete_local_build_folder_is_refused_not_half_installed() {
        let (r, dir) = local_rig();
        fs::write(dir.join("miasma.exe"), version_text("0.3.2", "dev111111")).unwrap();
        set_mtime(&dir.join("miasma.exe"), true);
        // miasma-desktop.exe is installed but missing from the build folder.
        let o = offer_of(r.engine.check());
        assert!(matches!(
            r.engine.prepare(&o, &mut |_, _| {}).unwrap_err(),
            UpdateError::NoTarget(_)
        ));
        assert_eq!(
            fs::read_to_string(r.install.join("miasma.exe")).unwrap(),
            OLD
        );
    }

    // ── target detection ──

    #[test]
    fn target_detection_for_folders_and_bundles() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("miasma.exe"), "x").unwrap();
        fs::write(d.path().join("miasma-desktop.exe"), "x").unwrap();
        let t = detect_target(&d.path().join("miasma-desktop.exe"), Os::Windows).unwrap();
        assert_eq!(t.kind, TargetKind::Files);
        assert_eq!(t.names, ["miasma.exe", "miasma-desktop.exe"]);

        // No command line program next to the exe: not updatable in place.
        let e = tempfile::tempdir().unwrap();
        fs::write(e.path().join("miasma-desktop.exe"), "x").unwrap();
        assert!(matches!(
            detect_target(&e.path().join("miasma-desktop.exe"), Os::Windows),
            Err(UpdateError::NoTarget(_))
        ));

        let app_exe = Path::new("/Applications/Miasma.app/Contents/MacOS/miasma-desktop");
        let t = detect_target(app_exe, Os::MacOs).unwrap();
        assert_eq!(t.kind, TargetKind::Bundle);
        assert_eq!(t.bundle.as_deref(), Some("Miasma.app"));
        assert_eq!(t.dir, PathBuf::from("/Applications"));
        assert_eq!(bundle_root(Path::new("/usr/local/bin/miasma")), None);
    }
}
