//! The Network section of Settings and the "Check my network" view.
//!
//! Reading and writing the settings use the same `NodeConfig` load and save the command line
//! tool uses; saving runs on a short-lived thread. The reachability check is
//! `miasma_core::transport::reach::run_matrix`, the code behind `miasma netcheck --matrix`. It
//! runs on its own thread with its own runtime and can be cancelled; the window only reads
//! messages from that thread, so it never waits for the network. What is shown is built by
//! [`crate::network_model`] and the texts come from [`crate::network_strings`].

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};
use miasma_core::config::{IrohMode, NodeConfig};
use miasma_core::transport::iroh_direct::IrohSettings;
use miasma_core::transport::reach::{
    run_matrix, MatrixOptions, MatrixReport, Outcome, TOTAL_BUDGET,
};
use miasma_core::transport::reach_net::SystemNet;
use tokio::sync::Notify;

use crate::locale::Locale;
use crate::network_model::{
    add_relay_url, check_ca_file, file_name_of, load_settings, report_json, save_settings, CaCheck,
    Issue, MatrixView, NetworkSettings, RowState, UrlError, MAX_RETRY_HOURS,
};
use crate::network_strings::{
    advice_text, group_text, net_strings, outcome_text, role_text, NetStrings,
};
use crate::ui_kit::{self as kit, Level};

enum Msg {
    Saved(Result<NetworkSettings, String>),
    Checked(Result<Option<MatrixReport>, String>),
    ReportSaved(Result<Option<PathBuf>, String>),
}

enum SaveState {
    Idle,
    Saving,
    Saved,
    Failed(String),
}

enum Check {
    Idle,
    Running {
        started: Instant,
        cancel: Arc<Notify>,
        cancelling: bool,
    },
    Cancelled,
    Failed(String),
}

pub struct NetworkUi {
    data_dir: PathBuf,
    saved: NetworkSettings,
    edit: NetworkSettings,
    load_failed: bool,
    ca_check: CaCheck,
    new_relay: String,
    relay_error: Option<UrlError>,
    save: SaveState,
    check: Check,
    report: Option<MatrixReport>,
    view: Option<MatrixView>,
    report_note: Option<(Level, String)>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl NetworkUi {
    pub fn new(data_dir: PathBuf) -> Self {
        let (settings, load_failed) = match load_settings(&data_dir) {
            Ok(s) => (s, false),
            Err(_) => (NetworkSettings::default(), true),
        };
        let (tx, rx) = channel();
        let ca_check = check_ca_file(&settings.ca_path);
        Self {
            data_dir,
            saved: settings.clone(),
            edit: settings,
            load_failed,
            ca_check,
            new_relay: String::new(),
            relay_error: None,
            save: SaveState::Idle,
            check: Check::Idle,
            report: None,
            view: None,
            report_note: None,
            tx,
            rx,
        }
    }

    fn dirty(&self) -> bool {
        self.edit != self.saved
    }

    // ── workers ─────────────────────────────────────────────────────────────

    fn start_save(&mut self, ctx: &egui::Context) {
        self.ca_check = check_ca_file(&self.edit.ca_path);
        if !self.edit.issues(&self.ca_check).is_empty() {
            return;
        }
        self.save = SaveState::Saving;
        let dir = self.data_dir.clone();
        let s = self.edit.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let _ = std::thread::Builder::new()
            .name("network-config".into())
            .spawn(move || {
                let r = save_settings(&dir, &s).map(|()| s);
                let _ = tx.send(Msg::Saved(r));
                ctx.request_repaint();
            });
    }

    fn start_check(&mut self, ctx: &egui::Context) {
        if matches!(self.check, Check::Running { .. }) {
            return;
        }
        let cancel = Arc::new(Notify::new());
        self.check = Check::Running {
            started: Instant::now(),
            cancel: cancel.clone(),
            cancelling: false,
        };
        self.report_note = None;
        let dir = self.data_dir.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let _ = std::thread::Builder::new()
            .name("network-check".into())
            .spawn(move || {
                let r = run_check(&dir, cancel);
                let _ = tx.send(Msg::Checked(r));
                ctx.request_repaint();
            });
    }

    fn cancel_check(&mut self) {
        if let Check::Running {
            cancel, cancelling, ..
        } = &mut self.check
        {
            if !*cancelling {
                *cancelling = true;
                cancel.notify_one();
            }
        }
    }

    fn start_save_report(&mut self, ctx: &egui::Context, file_name: &'static str) {
        let Some(report) = &self.report else {
            return;
        };
        let text = match report_json(report) {
            Ok(t) => t,
            Err(e) => {
                self.report_note = Some((Level::Error, e));
                return;
            }
        };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let _ = std::thread::Builder::new()
            .name("network-report".into())
            .spawn(move || {
                let r = match rfd::FileDialog::new()
                    .set_file_name(file_name)
                    .add_filter("JSON", &["json"])
                    .save_file()
                {
                    Some(path) => std::fs::write(&path, text)
                        .map(|()| Some(path))
                        .map_err(|e| e.to_string()),
                    None => Ok(None),
                };
                let _ = tx.send(Msg::ReportSaved(r));
                ctx.request_repaint();
            });
    }

    fn drain(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Saved(Ok(s)) => {
                    self.saved = s;
                    self.save = SaveState::Saved;
                }
                Msg::Saved(Err(e)) => self.save = SaveState::Failed(e),
                Msg::Checked(Ok(Some(report))) => {
                    self.view = Some(MatrixView::from_report(&report));
                    self.report = Some(report);
                    self.check = Check::Idle;
                }
                Msg::Checked(Ok(None)) => self.check = Check::Cancelled,
                Msg::Checked(Err(e)) => self.check = Check::Failed(e),
                Msg::ReportSaved(r) => {
                    self.report_note = match r {
                        Ok(Some(p)) => Some((Level::Ok, p.to_string_lossy().into_owned())),
                        Ok(None) => None,
                        Err(e) => Some((Level::Error, e)),
                    };
                }
            }
        }
    }
}

/// Run the matrix with the saved settings. `Ok(None)` means it was cancelled.
fn run_check(
    data_dir: &std::path::Path,
    cancel: Arc<Notify>,
) -> Result<Option<MatrixReport>, String> {
    let mut config = NodeConfig::load(data_dir).map_err(|e| e.to_string())?;
    let settings = IrohSettings::from_config(&config.transport);
    config.transport.zeroize_secret_copies();
    let opts = MatrixOptions::from_settings(&settings, Vec::new());
    let net = SystemNet::new(settings);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let out = rt.block_on(async {
        tokio::select! {
            r = run_matrix(&net, &opts) => Some(r),
            () = cancel.notified() => None,
        }
    });
    rt.shutdown_timeout(Duration::from_secs(2));
    Ok(out)
}

fn url_error_text<'a>(s: &'a NetStrings, e: UrlError) -> &'a str {
    match e {
        UrlError::Empty => s.err_url_empty,
        UrlError::NotHttps => s.err_url_not_https,
        UrlError::Space => s.err_url_space,
        UrlError::UserInfo => s.err_url_userinfo,
        UrlError::Host => s.err_url_host,
        UrlError::Port => s.err_url_port,
        UrlError::QueryOrFragment => s.err_url_query,
        UrlError::Duplicate => s.err_url_dup,
        UrlError::TooMany => s.err_url_toomany,
    }
}

fn ca_text(s: &NetStrings, path: &str, check: &CaCheck) -> Option<(Level, String)> {
    let name = file_name_of(path);
    match check {
        CaCheck::Empty => None,
        CaCheck::Valid { certs } => Some((
            Level::Ok,
            s.ca_ok
                .replace("{name}", &name)
                .replace("{n}", &certs.to_string()),
        )),
        CaCheck::Missing => Some((Level::Error, s.ca_missing.replace("{name}", &name))),
        CaCheck::Unreadable => Some((Level::Error, s.ca_unreadable.replace("{name}", &name))),
        CaCheck::TooLarge => Some((Level::Error, s.ca_too_large.replace("{name}", &name))),
        CaCheck::Invalid => Some((Level::Error, s.ca_invalid.replace("{name}", &name))),
    }
}

impl NetworkUi {
    /// Draw the two sections: the settings, then the reachability check.
    pub fn section(&mut self, ui: &mut egui::Ui, locale: Locale) {
        self.drain();
        let s = net_strings(locale);
        let ctx = ui.ctx().clone();
        self.settings_section(ui, s, &ctx);
        self.check_section(ui, locale, s, &ctx);
    }

    fn settings_section(&mut self, ui: &mut egui::Ui, s: &'static NetStrings, ctx: &egui::Context) {
        kit::section(ui, s.heading, |ui| {
            kit::paragraph_muted(ui, s.intro);
            if self.load_failed {
                kit::notice(ui, Level::Warn, s.load_failed);
            }

            // Connection mode.
            let desc = match self.edit.mode {
                IrohMode::N0 => s.mode_desc_public,
                IrohMode::Custom => s.mode_desc_own,
                IrohMode::Off => s.mode_desc_direct,
            };
            let mut mode = self.edit.mode;
            kit::form_row(ui, s.mode_label, Some(desc), |ui| {
                kit::segmented(
                    ui,
                    &mut mode,
                    &[
                        (IrohMode::N0, s.mode_public),
                        (IrohMode::Custom, s.mode_own),
                        (IrohMode::Off, s.mode_direct),
                    ],
                );
                kit::status_dot(ui, Level::Warn, s.restart_tag);
            });
            self.edit.mode = mode;

            // Relay addresses.
            let mut remove: Option<usize> = None;
            let mut add = false;
            kit::form_row(ui, s.relays_label, Some(s.relays_desc), |ui| {
                if self.edit.relay_urls.is_empty() {
                    kit::hint(ui, s.relay_none);
                }
                for (i, url) in self.edit.relay_urls.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.add(kit::compact_button(s.relay_remove)).clicked() {
                            remove = Some(i);
                        }
                        kit::mono(ui, url);
                    });
                }
                ui.horizontal(|ui| {
                    let w = kit::input_width_beside_button(ui);
                    let r = ui.add(
                        kit::input(&mut self.new_relay)
                            .hint_text(s.relay_placeholder)
                            .desired_width(w),
                    );
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.add(kit::secondary_button(s.relay_add)).clicked() || enter {
                        add = true;
                    }
                });
                if let Some(e) = self.relay_error {
                    kit::notice(ui, Level::Error, url_error_text(s, e));
                }
                kit::status_dot(ui, Level::Warn, s.restart_tag);
            });
            if let Some(i) = remove {
                self.edit.relay_urls.remove(i);
                self.relay_error = None;
            }
            if add {
                match add_relay_url(&mut self.edit.relay_urls, &self.new_relay) {
                    Ok(_) => {
                        self.new_relay.clear();
                        self.relay_error = None;
                    }
                    Err(e) => self.relay_error = Some(e),
                }
            }

            // Same-network discovery.
            let mut lan = self.edit.lan_discovery;
            kit::form_row(ui, s.lan_label, Some(s.lan_desc), |ui| {
                kit::segmented(ui, &mut lan, &[(true, s.lan_on), (false, s.lan_off)]);
                kit::status_dot(ui, Level::Warn, s.restart_tag);
            });
            self.edit.lan_discovery = lan;

            // Extra certificate.
            let mut choose = false;
            let mut clear = false;
            kit::form_row(ui, s.ca_label, Some(s.ca_desc), |ui| {
                ui.horizontal(|ui| {
                    choose = ui.add(kit::secondary_button(s.ca_choose)).clicked();
                    if !self.edit.ca_path.trim().is_empty() {
                        clear = ui.add(kit::secondary_button(s.ca_clear)).clicked();
                    }
                });
                if self.edit.ca_path.trim().is_empty() {
                    kit::hint(ui, s.ca_none);
                } else if let Some((level, text)) = ca_text(s, &self.edit.ca_path, &self.ca_check) {
                    kit::status_dot(ui, level, &text);
                }
                kit::status_dot(ui, Level::Warn, s.restart_tag);
            });
            if choose {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("Certificate", &["pem", "crt", "cer", "der"])
                    .pick_file()
                {
                    self.edit.ca_path = p.to_string_lossy().into_owned();
                    self.ca_check = check_ca_file(&self.edit.ca_path);
                }
            }
            if clear {
                self.edit.ca_path.clear();
                self.ca_check = CaCheck::Empty;
            }

            // Retry window.
            let mut hours = self.edit.retry_hours;
            kit::form_row(ui, s.retry_label, Some(s.retry_desc), |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::DragValue::new(&mut hours)
                            .clamp_range(0..=MAX_RETRY_HOURS)
                            .speed(1.0),
                    );
                    ui.label(RichText::new(s.retry_unit).color(kit::pal().text));
                });
                kit::status_dot(ui, Level::Warn, s.restart_tag);
            });
            self.edit.retry_hours = hours;

            // Problems, then Save / Discard.
            let issues = self.edit.issues(&self.ca_check);
            for i in &issues {
                match i {
                    Issue::OwnRelayNeedsUrl => kit::notice(ui, Level::Warn, s.issue_own_needs_url),
                    Issue::RetryRange => kit::notice(ui, Level::Error, s.issue_retry_range),
                    Issue::CertificateUnusable => {}
                }
            }
            let dirty = self.dirty();
            if dirty {
                // Editing again hides the result of the earlier save.
                if matches!(self.save, SaveState::Saved) {
                    self.save = SaveState::Idle;
                }
                kit::hint(ui, s.unsaved);
            }
            let saving = matches!(self.save, SaveState::Saving);
            let mut do_save = false;
            let mut discard = false;
            kit::button_row(ui, |ui| {
                do_save = kit::primary(ui, dirty && issues.is_empty() && !saving, s.save).clicked();
                discard = ui
                    .add_enabled(dirty && !saving, kit::secondary_button(s.discard))
                    .clicked();
            });
            if do_save {
                self.start_save(ctx);
            }
            if discard {
                self.edit = self.saved.clone();
                self.ca_check = check_ca_file(&self.edit.ca_path);
                self.relay_error = None;
                self.new_relay.clear();
                self.save = SaveState::Idle;
            }
            match &self.save {
                SaveState::Saved if !dirty => kit::notice(ui, Level::Ok, s.saved_notice),
                SaveState::Failed(e) => {
                    kit::notice(ui, Level::Error, &s.save_failed.replace("{err}", e))
                }
                _ => {}
            }
        });
    }

    fn check_section(
        &mut self,
        ui: &mut egui::Ui,
        locale: Locale,
        s: &'static NetStrings,
        ctx: &egui::Context,
    ) {
        kit::section(ui, s.check_heading, |ui| {
            kit::paragraph_muted(ui, s.check_desc);
            let running = matches!(self.check, Check::Running { .. });
            let mut start = false;
            let mut cancel = false;
            kit::button_row(ui, |ui| {
                start = kit::primary(ui, !running, s.check_button).clicked();
                if let Check::Running { cancelling, .. } = &self.check {
                    cancel = ui
                        .add_enabled(!*cancelling, kit::secondary_button(s.check_cancel))
                        .clicked();
                }
            });
            if start {
                self.start_check(ctx);
            }
            if cancel {
                self.cancel_check();
            }
            match &self.check {
                Check::Running { started, .. } => {
                    let elapsed = started.elapsed();
                    let fraction =
                        (elapsed.as_secs_f32() / TOTAL_BUDGET.as_secs_f32()).clamp(0.0, 0.97);
                    kit::progress(ui, s.check_button, fraction, false);
                    kit::hint(
                        ui,
                        &s.check_running
                            .replace("{s}", &elapsed.as_secs().to_string()),
                    );
                    ctx.request_repaint_after(Duration::from_millis(250));
                }
                Check::Cancelled => kit::notice(ui, Level::Info, s.check_cancelled),
                Check::Failed(e) => {
                    kit::notice(ui, Level::Error, &s.check_failed.replace("{err}", e))
                }
                Check::Idle => {}
            }

            if let Some(view) = self.view.clone() {
                result_view(ui, locale, s, &view);
                let mut save_report = false;
                kit::button_row(ui, |ui| {
                    save_report = ui.add(kit::secondary_button(s.save_report)).clicked();
                });
                if save_report {
                    self.start_save_report(ctx, "network-report.json");
                }
                if let Some((level, text)) = &self.report_note {
                    let shown = match level {
                        Level::Ok => s.report_saved.replace("{path}", text),
                        _ => s.report_failed.replace("{err}", text),
                    };
                    kit::notice(ui, *level, &shown);
                }
            }
        });
    }
}

/// The table, the counts and the suggested setup of one finished check.
fn result_view(ui: &mut egui::Ui, locale: Locale, s: &NetStrings, view: &MatrixView) {
    let summary = s
        .summary
        .replace("{ok}", &view.works.to_string())
        .replace("{bad}", &view.failed.to_string())
        .replace("{skip}", &view.skipped.to_string())
        .replace("{s}", &view.elapsed_secs.to_string());
    let level = if view.works == 0 {
        Level::Error
    } else if view.failed > 0 {
        Level::Warn
    } else {
        Level::Ok
    };
    kit::notice(ui, level, &summary);

    if view.rows.is_empty() {
        kit::hint(ui, s.no_rows);
    } else {
        let table = kit::table(ui, &[0.18, 0.30, 0.13, 0.39]);
        table.header(ui, &[s.col_path, s.col_target, s.col_result, s.col_reason]);
        for (i, row) in view.rows.iter().enumerate() {
            table.row(ui, i > 0, |cells| {
                cells.text(group_text(row.group, locale));
                cells.text(&format!("{} ({})", row.target, role_text(row.role, locale)));
                match row.state {
                    RowState::Works => cells.status(Level::Ok, s.result_works),
                    RowState::Failed => cells.status(Level::Error, s.result_failed),
                    RowState::Skipped => cells.status(Level::Muted, s.result_skipped),
                }
                let reason = reason_text(s, locale, row);
                cells.add(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(reason).color(kit::pal().text)).wrap(true),
                    );
                });
            });
        }
    }

    kit::section_heading(ui, s.suggest_heading);
    if view.advice.is_empty() {
        kit::paragraph_muted(ui, s.suggest_none);
    } else {
        let text = view
            .advice
            .iter()
            .map(|a| advice_text(*a, locale))
            .collect::<Vec<_>>()
            .join(" ");
        kit::paragraph(ui, &text);
    }
}

/// The "reason" cell: for a working path what was measured, for the others why it failed.
fn reason_text(s: &NetStrings, locale: Locale, row: &crate::network_model::RowView) -> String {
    if row.state == RowState::Works {
        let mut parts = Vec::new();
        if let Some(ms) = row.rtt_ms {
            parts.push(s.measured_rtt.replace("{ms}", &ms.to_string()));
        }
        if let Some(kib) = row.kib_per_s {
            parts.push(s.measured_speed.replace("{kib}", &kib.to_string()));
        }
        if parts.is_empty() {
            return outcome_text(Outcome::Ok, locale).to_owned();
        }
        return parts.join(", ");
    }
    let mut t = outcome_text(row.outcome, locale).to_owned();
    if let Some(d) = row.detail.as_deref().filter(|d| !d.is_empty()) {
        t.push_str(" (");
        t.push_str(d);
        t.push(')');
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_model::RowView;
    use miasma_core::transport::reach::{Group, Role};

    fn row(state: RowState, outcome: Outcome) -> RowView {
        RowView {
            group: Group::Tls,
            role: Role::Relay,
            target: "relay.example.org".into(),
            state,
            outcome,
            detail: None,
            rtt_ms: None,
            kib_per_s: None,
        }
    }

    #[test]
    fn a_failed_row_shows_its_classified_reason_in_every_language() {
        for l in Locale::ALL {
            let s = net_strings(l);
            let r = row(RowState::Failed, Outcome::Timeout);
            assert_eq!(reason_text(s, l, &r), outcome_text(Outcome::Timeout, l));
        }
    }

    #[test]
    fn a_non_public_authority_row_names_the_authority() {
        let mut r = row(RowState::Failed, Outcome::NonPublicCa);
        r.detail = Some("Example Inspection CA".into());
        let t = reason_text(net_strings(Locale::En), Locale::En, &r);
        assert!(t.ends_with("(Example Inspection CA)"), "{t}");
    }

    #[test]
    fn a_working_row_shows_what_was_measured() {
        let mut r = row(RowState::Works, Outcome::Ok);
        r.rtt_ms = Some(87);
        r.kib_per_s = Some(512);
        let t = reason_text(net_strings(Locale::En), Locale::En, &r);
        assert_eq!(t, "round trip 87 ms, 512 KiB/s");
        let plain = row(RowState::Works, Outcome::Ok);
        assert_eq!(
            reason_text(net_strings(Locale::En), Locale::En, &plain),
            "Works."
        );
    }

    #[test]
    fn certificate_status_lines_follow_the_check() {
        let s = net_strings(Locale::En);
        assert!(ca_text(s, "", &CaCheck::Empty).is_none());
        let (lv, t) = ca_text(s, "/x/corp.pem", &CaCheck::Valid { certs: 2 }).unwrap();
        assert_eq!(lv, Level::Ok);
        assert_eq!(t, "corp.pem: 2 certificate(s) found.");
        for c in [
            CaCheck::Missing,
            CaCheck::Unreadable,
            CaCheck::TooLarge,
            CaCheck::Invalid,
        ] {
            let (lv, t) = ca_text(s, "/x/corp.pem", &c).unwrap();
            assert_eq!(lv, Level::Error);
            assert!(t.starts_with("corp.pem:"), "{t}");
        }
    }

    #[test]
    fn every_url_error_has_text() {
        for l in Locale::ALL {
            let s = net_strings(l);
            for e in [
                UrlError::Empty,
                UrlError::NotHttps,
                UrlError::Space,
                UrlError::UserInfo,
                UrlError::Host,
                UrlError::Port,
                UrlError::QueryOrFragment,
                UrlError::Duplicate,
                UrlError::TooMany,
            ] {
                assert!(!url_error_text(s, e).is_empty(), "{l:?} {e:?}");
            }
        }
    }

    #[test]
    fn the_screen_state_follows_messages_from_the_workers() {
        let dir = tempfile::tempdir().unwrap();
        let mut ui = NetworkUi::new(dir.path().to_path_buf());
        assert!(!ui.dirty() && !ui.load_failed);

        // A finished check fills the view and ends the running state.
        let report = MatrixReport {
            schema: 1,
            iroh_mode: "n0".into(),
            elapsed_ms: 3000,
            probes: Vec::new(),
            advice: Vec::new(),
        };
        ui.check = Check::Running {
            started: Instant::now(),
            cancel: Arc::new(Notify::new()),
            cancelling: false,
        };
        ui.tx.send(Msg::Checked(Ok(Some(report)))).unwrap();
        ui.drain();
        assert!(matches!(ui.check, Check::Idle));
        assert_eq!(ui.view.as_ref().unwrap().rows.len(), 0);
        assert!(ui.report.is_some());

        // A cancelled check keeps the earlier result.
        ui.tx.send(Msg::Checked(Ok(None))).unwrap();
        ui.drain();
        assert!(matches!(ui.check, Check::Cancelled));
        assert!(ui.view.is_some());

        // A failed check says why.
        ui.tx.send(Msg::Checked(Err("boom".into()))).unwrap();
        ui.drain();
        assert!(matches!(&ui.check, Check::Failed(e) if e == "boom"));

        // A save moves the saved copy, so the screen is clean again.
        ui.edit.retry_hours = 5;
        assert!(ui.dirty());
        ui.tx.send(Msg::Saved(Ok(ui.edit.clone()))).unwrap();
        ui.drain();
        assert!(!ui.dirty());
        assert!(matches!(ui.save, SaveState::Saved));
    }

    #[test]
    fn cancelling_a_check_wakes_the_runner() {
        let cancel = Arc::new(Notify::new());
        let mut ui = NetworkUi::new(tempfile::tempdir().unwrap().path().to_path_buf());
        ui.check = Check::Running {
            started: Instant::now(),
            cancel: cancel.clone(),
            cancelling: false,
        };
        ui.cancel_check();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let woke = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), cancel.notified())
                .await
                .is_ok()
        });
        assert!(woke, "the stored permit must wake the runner");
        assert!(matches!(
            ui.check,
            Check::Running {
                cancelling: true,
                ..
            }
        ));
    }
}
