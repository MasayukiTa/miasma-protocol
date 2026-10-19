//! Updates in the window: the Settings section, the banner, and the glue to
//! `miasma_core::update`.
//!
//! Everything that touches the network or the disk runs on a short-lived
//! thread (`update-worker`); the window only reads messages from it. Nothing
//! resident: no timer, no buffer. The one automatic check happens once, after
//! the start delay of `update::schedule` (60 s plus up to 60 s of jitter), and
//! only when `update.mode` is not `off`.
//!
//! A failed automatic check is silent (the window keeps working, nothing is
//! shown but the line in Settings). A failed check is never shown as "up to
//! date".

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use miasma_core::config::NodeConfig;
use miasma_core::update::apply::{load_journal, Applied, Journal, Resumed};
use miasma_core::update::engine::{auto_install_allowed, running_install_dir};
use miasma_core::update::schedule::{startup_delay, Throttle};
use miasma_core::update::verify::UPDATE_PUBKEYS;
use miasma_core::update::{
    CheckFailure, CheckOutcome, Engine, UpdateConfig, UpdateError, UpdateMode, UpdateOffer,
};

use crate::buildinfo::BUILD_ID;
use crate::errors::{ErrorKind, UiError};
use crate::locale::{self, Locale, UpdateStrings};
use crate::ui_kit::{self as kit, Level};

/// Set on the program started after an automatic or requested restart, so the
/// new window does not start another update (no loops).
pub const RELAUNCH_GUARD_ENV: &str = "MIASMA_UPDATE_RELAUNCHED";

/// How often an update that waits for an idle moment tries again.
const IDLE_RETRY: Duration = Duration::from_secs(30);
/// A restart request older than this is forgotten (the person cancelled the close).
const RELAUNCH_WINDOW: Duration = Duration::from_secs(120);

static RELAUNCH: Mutex<Option<Instant>> = Mutex::new(None);

/// Ask for the program to be started again once this window has closed.
pub fn request_relaunch() {
    if let Ok(mut g) = RELAUNCH.lock() {
        *g = Some(Instant::now());
    }
}

/// True once if a restart was asked for shortly before. Called by `main` after
/// the window is gone.
pub fn take_relaunch() -> bool {
    RELAUNCH
        .lock()
        .ok()
        .and_then(|mut g| g.take())
        .is_some_and(|at| at.elapsed() < RELAUNCH_WINDOW)
}

/// Start the (now updated) program again with the same arguments.
pub fn spawn_relaunch() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let _ = std::process::Command::new(exe)
        .args(args)
        .env(RELAUNCH_GUARD_ENV, "1")
        .spawn();
}

enum Msg {
    Checked { outcome: CheckOutcome, auto: bool },
    Prepared(Result<Box<Journal>, UpdateError>),
    Applied(Result<Applied, UpdateError>, Box<Journal>),
    Resumed(Result<Resumed, UpdateError>),
    ConfigSaved(Result<(), String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Idle,
    Checking,
    Downloading,
    /// Downloaded and verified; waiting to be installed.
    Ready,
    Applying,
    Installed(String),
    RolledBack,
}

/// What the last check found, for the Settings line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Summary {
    UpToDate,
    Available(String),
    Local,
    NoAsset(String),
    Unverifiable(String),
    Failed,
    Disabled,
}

pub struct UpdatesUi {
    data_dir: PathBuf,
    cfg: UpdateConfig,
    /// `transport.iroh_extra_ca_pem`: an extra CA for the GitHub requests.
    extra_ca: Option<String>,
    throttle: Throttle,
    phase: Phase,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    ctx: Option<egui::Context>,
    last_check: Option<(Instant, Summary)>,
    offer: Option<UpdateOffer>,
    journal: Option<Box<Journal>>,
    /// "Later" was pressed for the offer on screen.
    dismissed: bool,
    error: Option<UiError>,
    save_failed: bool,
    wait_note: Option<(u64, Instant)>,
    percent: Arc<AtomicU64>,
    /// The person asked for the install (so it is not held back as in notify mode).
    install_wanted: bool,
    waiting_idle: bool,
    last_apply_try: Option<Instant>,
    guard: bool,
    resume_started: bool,
    /// The public keys this build verifies releases with. With none, nothing is
    /// installed without the person asking (see `auto_install`).
    signing_keys: Vec<[u8; 32]>,
}

impl UpdatesUi {
    /// Whether `update.mode = auto` may really install by itself: only when this
    /// build can verify a signature. Without pinned keys the setting is treated
    /// like `notify` and the person has to press the install button.
    fn auto_install(&self) -> bool {
        auto_install_allowed(self.cfg.mode, &self.signing_keys)
    }

    pub fn new(data_dir: PathBuf) -> Self {
        let node = NodeConfig::load(&data_dir).ok();
        let cfg = node.as_ref().map(|c| c.update.clone()).unwrap_or_default();
        let extra_ca = node.and_then(|c| c.transport.iroh_extra_ca_pem.clone());
        let (tx, rx) = channel();
        Self {
            data_dir,
            cfg,
            extra_ca,
            throttle: Throttle::new(Instant::now(), startup_delay()),
            phase: Phase::Idle,
            tx,
            rx,
            ctx: None,
            last_check: None,
            offer: None,
            journal: None,
            dismissed: false,
            error: None,
            save_failed: false,
            wait_note: None,
            percent: Arc::new(AtomicU64::new(0)),
            install_wanted: false,
            waiting_idle: false,
            last_apply_try: None,
            guard: std::env::var_os(RELAUNCH_GUARD_ENV).is_some(),
            resume_started: false,
            signing_keys: UPDATE_PUBKEYS.to_vec(),
        }
    }

    // ── worker plumbing ─────────────────────────────────────────────────────

    fn engine(&self) -> Result<Engine, UpdateError> {
        Engine::new(
            &self.data_dir,
            self.cfg.clone(),
            env!("MIASMA_VERSION"),
            BUILD_ID,
        )
        .map(|e| e.with_extra_ca_file(self.extra_ca.clone()))
    }

    fn run(
        &self,
        f: impl FnOnce(Engine, &Sender<Msg>) + Send + 'static,
        on_fail: fn(UpdateError) -> Msg,
    ) {
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        let eng = self.engine();
        let _ = std::thread::Builder::new()
            .name("update-worker".into())
            .spawn(move || {
                match eng {
                    Ok(e) => f(e, &tx),
                    Err(err) => {
                        let _ = tx.send(on_fail(err));
                    }
                }
                if let Some(c) = ctx {
                    c.request_repaint();
                }
            });
    }

    fn start_check(&mut self, auto: bool) {
        if !self.cfg.is_enabled() || self.phase == Phase::Checking {
            return;
        }
        self.phase = Phase::Checking;
        self.error = None;
        self.run(
            move |e, tx| {
                let _ = tx.send(Msg::Checked {
                    outcome: e.check(),
                    auto,
                });
            },
            |err| Msg::Checked {
                outcome: CheckOutcome::Failed(CheckFailure::Local(err.to_string())),
                auto: true,
            },
        );
    }

    fn start_prepare(&mut self) {
        let Some(offer) = self.offer.clone() else {
            return;
        };
        self.phase = Phase::Downloading;
        self.percent.store(0, Ordering::Relaxed);
        let pct = self.percent.clone();
        self.run(
            move |e, tx| {
                let r = e.prepare(&offer, &mut |done, total| {
                    if let Some(t) = total.filter(|t| *t > 0) {
                        pct.store(done * 100 / t, Ordering::Relaxed);
                    }
                });
                let _ = tx.send(Msg::Prepared(r.map(Box::new)));
            },
            |err| Msg::Prepared(Err(err)),
        );
    }

    fn start_apply(&mut self) {
        let Some(j) = self.journal.take() else {
            return;
        };
        self.phase = Phase::Applying;
        self.waiting_idle = false;
        self.last_apply_try = Some(Instant::now());
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        let eng = self.engine();
        let _ = std::thread::Builder::new()
            .name("update-worker".into())
            .spawn(move || {
                let mut j = j;
                let msg = match eng {
                    Ok(e) => {
                        let r = e.apply(&mut j);
                        Msg::Applied(r, j)
                    }
                    Err(err) => Msg::Applied(Err(err), j),
                };
                let _ = tx.send(msg);
                if let Some(c) = ctx {
                    c.request_repaint();
                }
            });
    }

    fn start_resume(&mut self) {
        self.resume_started = true;
        // Only when an earlier run left a journal; reading it is a local file read.
        let have_journal = match running_install_dir() {
            Ok(dir) => matches!(load_journal(&self.data_dir, &dir), Ok(Some(_)) | Err(_)),
            // Cannot tell where this program lives: let the engine report it.
            Err(_) => miasma_core::paths::update_journal(&self.data_dir).exists(),
        };
        if !have_journal {
            return;
        }
        self.run(
            |e, tx| {
                let _ = tx.send(Msg::Resumed(e.resume()));
            },
            |err| Msg::Resumed(Err(err)),
        );
    }

    fn save_mode(&mut self, mode: UpdateMode) {
        self.cfg.mode = mode;
        self.save_failed = false;
        let dir = self.data_dir.clone();
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        let _ = std::thread::Builder::new()
            .name("update-config".into())
            .spawn(move || {
                let r = NodeConfig::load(&dir)
                    .and_then(|mut c| {
                        c.update.mode = mode;
                        c.save(&dir)
                    })
                    .map_err(|e| e.to_string());
                let _ = tx.send(Msg::ConfigSaved(r));
                if let Some(c) = ctx {
                    c.request_repaint();
                }
            });
    }

    // ── per-frame work ──────────────────────────────────────────────────────

    /// Called once per frame. Cheap: drains messages, decides what is due.
    pub fn tick(&mut self, ctx: &egui::Context) {
        if self.ctx.is_none() {
            self.ctx = Some(ctx.clone());
        }
        if !self.resume_started {
            self.start_resume();
        }
        while let Ok(m) = self.rx.try_recv() {
            self.handle(m);
        }
        let now = Instant::now();
        if self.wait_note.is_some_and(|(_, until)| now >= until) {
            self.wait_note = None;
        }

        // The single automatic check of this run.
        if self.cfg.is_enabled()
            && self.cfg.check_at_start
            && !self.guard
            && self.phase == Phase::Idle
            && self.throttle.take_auto(now)
        {
            self.start_check(true);
        }

        // Automatic mode: install the downloaded update as soon as the program is idle.
        if self.auto_install()
            && self.phase == Phase::Ready
            && self.journal.is_some()
            && self
                .last_apply_try
                .is_none_or(|t| t.elapsed() >= IDLE_RETRY)
        {
            self.start_apply();
        }

        // Automatic mode: restart once the update is in (nothing was running, or it
        // would not have been installed).
        if self.auto_install() && matches!(self.phase, Phase::Installed(_)) {
            request_relaunch();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn handle(&mut self, m: Msg) {
        match m {
            Msg::Checked { outcome, auto } => {
                self.phase = Phase::Idle;
                let summary = match &outcome {
                    CheckOutcome::Disabled => Summary::Disabled,
                    CheckOutcome::UpToDate { .. } => Summary::UpToDate,
                    CheckOutcome::Available(o)
                        if o.source == miasma_core::update::Source::Local =>
                    {
                        Summary::Local
                    }
                    CheckOutcome::Available(o) => Summary::Available(o.version.clone()),
                    CheckOutcome::NoAsset { version } => Summary::NoAsset(version.clone()),
                    CheckOutcome::Unverifiable { version } => {
                        Summary::Unverifiable(version.clone())
                    }
                    CheckOutcome::Failed(_) => Summary::Failed,
                };
                self.last_check = Some((Instant::now(), summary));
                self.dismissed = false;
                match outcome {
                    CheckOutcome::Available(o) => {
                        let skipped = o.skipped;
                        self.offer = Some(o);
                        let failed_before = self
                            .engine()
                            .map(|e| self.offer.as_ref().is_some_and(|o| e.failed_before(o)))
                            .unwrap_or(false);
                        if self.auto_install() && !skipped && !failed_before && auto {
                            self.start_prepare();
                        }
                    }
                    CheckOutcome::Failed(f) => {
                        self.offer = None;
                        // Quiet when it ran by itself; a person who asked is told.
                        if !auto {
                            self.error =
                                Some(UiError::new(ErrorKind::UpdateCheckFailed, f.to_string()));
                        }
                    }
                    _ => self.offer = None,
                }
            }
            Msg::Prepared(Ok(j)) => {
                self.journal = Some(j);
                self.phase = Phase::Ready;
                if self.install_wanted || self.auto_install() {
                    self.start_apply();
                }
            }
            Msg::Prepared(Err(e)) => {
                self.phase = Phase::Idle;
                self.install_wanted = false;
                self.error = Some(ui_error(&e));
            }
            Msg::Applied(Ok(a), _) => {
                self.install_wanted = false;
                self.phase = Phase::Installed(a.version);
                self.offer = None;
            }
            Msg::Applied(Err(e), j) => {
                self.install_wanted = false;
                match &e {
                    UpdateError::Busy(_) => {
                        // Nothing was touched; keep the download and try again later.
                        self.journal = Some(j);
                        self.phase = Phase::Ready;
                        self.waiting_idle = true;
                        if !self.auto_install() {
                            self.error = Some(ui_error(&e));
                        }
                    }
                    UpdateError::HealthCheck(_) => {
                        self.phase = Phase::RolledBack;
                        self.error = Some(ui_error(&e));
                    }
                    UpdateError::RestoreFailed(_) => {
                        // The old version could not be put back. Do not offer the
                        // install again; the next start retries the restore.
                        self.phase = Phase::Idle;
                        self.error = Some(ui_error(&e));
                    }
                    _ => {
                        self.journal = Some(j);
                        self.phase = Phase::Ready;
                        self.error = Some(ui_error(&e));
                    }
                }
            }
            Msg::Resumed(Ok(Resumed::Completed(a))) => self.phase = Phase::Installed(a.version),
            Msg::Resumed(Ok(Resumed::RolledBack(_))) => self.phase = Phase::RolledBack,
            Msg::Resumed(Ok(Resumed::Pending(j))) => {
                self.journal = Some(j);
                self.phase = Phase::Ready;
            }
            Msg::Resumed(Ok(Resumed::Nothing)) => {}
            Msg::Resumed(Err(e)) => self.error = Some(ui_error(&e)),
            Msg::ConfigSaved(Err(_)) => self.save_failed = true,
            Msg::ConfigSaved(Ok(())) => {}
        }
    }

    // ── actions from the buttons ────────────────────────────────────────────

    fn check_now(&mut self) {
        match self.throttle.take_manual(Instant::now()) {
            Ok(()) => self.start_check(false),
            Err(wait) => {
                let secs = wait.as_secs().max(1);
                self.wait_note = Some((secs, Instant::now() + wait));
            }
        }
    }

    fn update_now(&mut self) {
        self.install_wanted = true;
        self.error = None;
        if self.journal.is_some() && self.phase == Phase::Ready {
            self.start_apply();
        } else if self.offer.is_some() && self.phase == Phase::Idle {
            self.start_prepare();
        }
    }

    fn skip_version(&mut self) {
        if let Some(o) = &self.offer {
            if let Ok(e) = self.engine() {
                e.skip(&o.version);
            }
            if let Some(o) = self.offer.as_mut() {
                o.skipped = true;
            }
        }
    }

    // ── drawing ─────────────────────────────────────────────────────────────

    fn ago(&self, at: Instant, u: &UpdateStrings) -> String {
        let s = at.elapsed().as_secs();
        if s < 60 {
            u.ago_seconds.replace("{n}", &s.to_string())
        } else if s < 3600 {
            u.ago_minutes.replace("{n}", &(s / 60).to_string())
        } else {
            u.ago_hours.replace("{n}", &(s / 3600).to_string())
        }
    }

    fn summary_text(&self, s: &Summary, u: &UpdateStrings) -> (Level, String) {
        match s {
            Summary::UpToDate => (Level::Ok, u.result_up_to_date.to_owned()),
            Summary::Available(v) => (Level::Info, u.result_available.replace("{v}", v)),
            Summary::Local => (Level::Info, u.result_local.to_owned()),
            Summary::NoAsset(v) => (Level::Warn, u.result_no_asset.replace("{v}", v)),
            Summary::Unverifiable(v) => (Level::Warn, u.result_unverifiable.replace("{v}", v)),
            Summary::Failed => (Level::Warn, u.result_failed.to_owned()),
            Summary::Disabled => (Level::Muted, u.result_disabled.to_owned()),
        }
    }

    /// The line that says what the updater is doing right now, if anything.
    fn working_text(&self, u: &UpdateStrings) -> Option<(Level, String)> {
        match &self.phase {
            Phase::Checking => Some((Level::Info, u.checking.to_owned())),
            Phase::Downloading => Some((
                Level::Info,
                u.status_downloading
                    .replace("{pct}", &self.percent.load(Ordering::Relaxed).to_string()),
            )),
            Phase::Applying => Some((Level::Info, u.status_applying.to_owned())),
            Phase::Ready if self.waiting_idle => {
                Some((Level::Info, u.status_waiting_idle.to_owned()))
            }
            Phase::Ready => Some((Level::Info, u.status_ready.to_owned())),
            Phase::Installed(v) => Some((Level::Ok, u.status_installed.replace("{v}", v))),
            Phase::RolledBack => Some((Level::Warn, u.status_rolled_back.to_owned())),
            Phase::Idle => None,
        }
    }

    /// The Updates section of Settings.
    pub fn section(&mut self, ui: &mut egui::Ui, locale: Locale, technical: bool) {
        let u = locale::update_strings(locale);
        kit::section(ui, u.heading, |ui| {
            let desc = match self.cfg.mode {
                UpdateMode::Off => u.mode_desc_off,
                UpdateMode::Notify => u.mode_desc_notify,
                UpdateMode::Auto => u.mode_desc_auto,
            };
            kit::form_row(ui, u.mode_label, Some(desc), |ui| {
                let mut mode = self.cfg.mode;
                let options = [
                    (UpdateMode::Off, u.mode_off),
                    (UpdateMode::Notify, u.mode_notify),
                    (UpdateMode::Auto, u.mode_auto),
                ];
                if kit::segmented(ui, &mut mode, &options) && mode != self.cfg.mode {
                    self.save_mode(mode);
                }
            });
            if self.save_failed {
                kit::notice(ui, Level::Error, u.config_save_failed);
            }

            kit::kv_grid(ui, |g| {
                g.mono(u.version_label, &crate::buildinfo::build_row_value());
                let last = match &self.last_check {
                    Some((at, _)) => self.ago(*at, u),
                    None => u.never_checked.to_owned(),
                };
                g.text(u.last_check_label, &last);
            });

            let busy = matches!(
                self.phase,
                Phase::Checking | Phase::Downloading | Phase::Applying
            );
            let can_check = self.cfg.is_enabled() && !busy;
            kit::button_row(ui, |ui| {
                if kit::primary(ui, can_check, u.check_now).clicked() {
                    self.check_now();
                }
                if self.cfg.is_enabled()
                    && self.phase == Phase::Idle
                    && self.offer.as_ref().is_some_and(|o| !o.skipped)
                    && ui.add(kit::secondary_button(u.update_now)).clicked()
                {
                    self.update_now();
                }
                if self.offer.as_ref().is_some_and(|o| !o.skipped)
                    && ui.add(kit::secondary_button(u.skip_version)).clicked()
                {
                    self.skip_version();
                }
            });
            if let Some((secs, _)) = self.wait_note {
                kit::hint(ui, &u.wait_before_recheck.replace("{n}", &secs.to_string()));
            }

            if let Some((level, text)) = self.working_text(u) {
                kit::notice(ui, level, &text);
            } else if let Some((_, s)) = &self.last_check {
                let (level, text) = self.summary_text(s, u);
                kit::notice(ui, level, &text);
            }
            if let Some(o) = self.offer.as_ref().filter(|o| o.skipped) {
                kit::hint(ui, &u.status_skipped.replace("{v}", &o.version));
            }
            if let Some(e) = &self.error {
                kit::notice(ui, Level::Error, &e.text(locale, technical));
            }
            kit::hint(ui, u.backup_note);
        });
    }

    /// The banner above the page: a new version, or an installed update.
    pub fn banner(&mut self, ui: &mut egui::Ui, locale: Locale) {
        if !self.cfg.is_enabled() {
            return;
        }
        let u = locale::update_strings(locale);
        match self.phase.clone() {
            Phase::Installed(v) if !self.auto_install() => {
                kit::notice(ui, Level::Ok, &u.banner_installed.replace("{v}", &v));
                kit::button_row(ui, |ui| {
                    if kit::primary(ui, true, u.restart_now).clicked() {
                        request_relaunch();
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if ui.add(kit::secondary_button(u.later)).clicked() {
                        self.phase = Phase::Idle;
                    }
                });
            }
            Phase::Downloading | Phase::Applying => {
                if self.install_wanted {
                    if let Some((level, text)) = self.working_text(u) {
                        kit::notice(ui, level, &text);
                    }
                }
            }
            Phase::Idle | Phase::Ready => {
                let Some(o) = self.offer.clone() else { return };
                if o.skipped || self.dismissed || self.cfg.mode != UpdateMode::Notify {
                    return;
                }
                kit::notice(
                    ui,
                    Level::Info,
                    &u.banner_available.replace("{v}", &o.version),
                );
                kit::button_row(ui, |ui| {
                    if kit::primary(ui, true, u.update_now).clicked() {
                        self.update_now();
                    }
                    if ui.add(kit::secondary_button(u.later)).clicked() {
                        self.dismissed = true;
                    }
                    if ui.add(kit::secondary_button(u.skip_version)).clicked() {
                        self.skip_version();
                    }
                });
            }
            _ => {}
        }
    }
}

/// The window's error kind for an update error.
pub fn ui_error(e: &UpdateError) -> UiError {
    let kind = match e {
        UpdateError::Busy(_) => ErrorKind::UpdateBusy,
        UpdateError::NotWritable(_) | UpdateError::NoTarget(_) => ErrorKind::UpdateNotWritable,
        UpdateError::Verify(_) | UpdateError::Unverifiable | UpdateError::Archive(_) => {
            ErrorKind::UpdateVerifyFailed
        }
        UpdateError::Network(_) | UpdateError::NoAsset | UpdateError::Disabled => {
            ErrorKind::UpdateCheckFailed
        }
        UpdateError::HealthCheck(_)
        | UpdateError::Io(_)
        | UpdateError::Journal(_)
        | UpdateError::RestoreFailed(_) => ErrorKind::UpdateApplyFailed,
    };
    UiError::new(kind, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::update::apply::Journal;
    use miasma_core::update::verify::VerifyError;

    fn ui() -> (tempfile::TempDir, UpdatesUi) {
        let d = tempfile::tempdir().unwrap();
        let u = UpdatesUi::new(d.path().to_path_buf());
        (d, u)
    }

    #[test]
    fn errors_map_to_their_kinds() {
        use miasma_core::update::http::HttpError;
        assert_eq!(
            ui_error(&UpdateError::Busy("x".into())).kind,
            ErrorKind::UpdateBusy
        );
        assert_eq!(
            ui_error(&UpdateError::Verify(VerifyError::SumsMissing)).kind,
            ErrorKind::UpdateVerifyFailed
        );
        assert_eq!(
            ui_error(&UpdateError::Unverifiable).kind,
            ErrorKind::UpdateVerifyFailed
        );
        assert_eq!(
            ui_error(&UpdateError::Network(HttpError::Timeout)).kind,
            ErrorKind::UpdateCheckFailed
        );
        assert_eq!(
            ui_error(&UpdateError::NotWritable("x".into())).kind,
            ErrorKind::UpdateNotWritable
        );
        assert_eq!(
            ui_error(&UpdateError::HealthCheck("x".into())).kind,
            ErrorKind::UpdateApplyFailed
        );
    }

    #[test]
    fn a_failed_automatic_check_is_quiet_and_never_reads_up_to_date() {
        let (_d, mut u) = ui();
        u.handle(Msg::Checked {
            outcome: CheckOutcome::Failed(CheckFailure::Offline),
            auto: true,
        });
        assert!(u.error.is_none(), "an automatic failure shows no error");
        assert_eq!(u.last_check.as_ref().unwrap().1, Summary::Failed);
        assert_ne!(u.last_check.as_ref().unwrap().1, Summary::UpToDate);
        assert!(u.offer.is_none());
        // A person who pressed Check now is told.
        u.handle(Msg::Checked {
            outcome: CheckOutcome::Failed(CheckFailure::Offline),
            auto: false,
        });
        assert_eq!(u.error.as_ref().unwrap().kind, ErrorKind::UpdateCheckFailed);
    }

    #[test]
    fn the_failed_text_never_claims_the_program_is_up_to_date() {
        let (_d, u) = ui();
        for l in Locale::ALL {
            let s = locale::update_strings(l);
            let (level, text) = u.summary_text(&Summary::Failed, s);
            assert_eq!(level, Level::Warn);
            assert_ne!(text, s.result_up_to_date);
        }
    }

    #[test]
    fn a_busy_apply_keeps_the_download_for_later() {
        let (_d, mut u) = ui();
        let j = Box::new(dummy_journal());
        u.handle(Msg::Applied(
            Err(UpdateError::Busy("a transfer is running".into())),
            j,
        ));
        assert_eq!(u.phase, Phase::Ready);
        assert!(u.journal.is_some());
        assert!(u.waiting_idle);
    }

    #[test]
    fn a_failed_start_check_shows_rolled_back() {
        let (_d, mut u) = ui();
        let j = Box::new(dummy_journal());
        u.handle(Msg::Applied(Err(UpdateError::HealthCheck("x".into())), j));
        assert_eq!(u.phase, Phase::RolledBack);
        assert_eq!(u.error.as_ref().unwrap().kind, ErrorKind::UpdateApplyFailed);
    }

    #[test]
    fn auto_mode_without_signing_keys_does_not_install_by_itself() {
        let (_d, mut u) = ui();
        u.cfg.mode = UpdateMode::Auto;
        u.signing_keys = Vec::new();
        assert!(!u.auto_install());
        // A downloaded update waits for the person instead of being applied.
        u.handle(Msg::Prepared(Ok(Box::new(dummy_journal()))));
        assert_eq!(u.phase, Phase::Ready);
        assert!(u.journal.is_some());
        assert!(!u.waiting_idle);
        assert!(u.last_apply_try.is_none());
        // With a key the same setting is honoured; other modes never are.
        u.signing_keys = vec![[1u8; 32]];
        assert!(u.auto_install());
        u.cfg.mode = UpdateMode::Notify;
        assert!(!u.auto_install());
    }

    #[test]
    fn manual_checks_are_spaced_and_say_so() {
        let (_d, mut u) = ui();
        u.cfg.mode = UpdateMode::Notify;
        u.check_now();
        assert_eq!(u.phase, Phase::Checking);
        u.phase = Phase::Idle;
        u.check_now();
        assert_eq!(
            u.phase,
            Phase::Idle,
            "the second press inside 30 s starts nothing"
        );
        assert!(u.wait_note.is_some());
    }

    #[test]
    fn with_updates_off_nothing_starts() {
        let (_d, mut u) = ui();
        u.cfg.mode = UpdateMode::Off;
        u.start_check(false);
        assert_eq!(u.phase, Phase::Idle);
    }

    #[test]
    fn a_restart_request_is_taken_once() {
        request_relaunch();
        assert!(take_relaunch());
        assert!(!take_relaunch());
    }

    fn dummy_journal() -> Journal {
        use miasma_core::update::apply::{Phase as P, TargetKind};
        Journal {
            id: "x".into(),
            source: "release".into(),
            version: "0.4.0".into(),
            build_id: None,
            phase: P::Downloaded,
            kind: TargetKind::Files,
            dir: PathBuf::new(),
            bundle: None,
            names: Vec::new(),
            hashes: Vec::new(),
            work_dir: PathBuf::new(),
            archive: None,
            archive_name: None,
            archive_sha256: None,
            local_dir: None,
            started_unix: 0,
        }
    }
}
