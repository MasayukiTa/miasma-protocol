//! Developer-only "UI tour" (cargo feature `ui-tour`, not part of any release build).
//!
//! With `MIASMA_UI_TOUR=<dir>` set, the running app walks through theme x language x tab
//! (plus a few connection states), asks egui for a screenshot of its own window after each step
//! and writes it to `<dir>/<name>.ppm`. This exists because a GL window cannot be captured with
//! `PrintWindow` from a private desktop; the app renders the frame itself, so what is saved is
//! exactly what egui drew (fonts, colours, clipping).

use std::path::PathBuf;

use eframe::egui;

use miasma_core::transfer::{Phase, TransferKind, TransferState, TransferStatus};

use super::{MiasmaApp, Tab};
use crate::locale::Locale;
use crate::theme::ThemeMode;
use crate::transfers::{transfer_id, NewForm};
use crate::worker::DaemonState;

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

/// What to arrange on the Transfers tab for one step.
#[derive(Clone)]
struct TransfersView {
    /// Which mock job to select (a fragment of its path).
    select: &'static str,
    form: NewForm,
    resume_prompt: bool,
    /// No jobs at all.
    empty: bool,
}

fn view(select: &'static str, form: NewForm, resume_prompt: bool, empty: bool) -> TransfersView {
    TransfersView {
        select,
        form,
        resume_prompt,
        empty,
    }
}

fn mock(kind: TransferKind, mid: &str, name: &str, state: TransferState) -> TransferStatus {
    TransferStatus {
        mid: mid.to_owned(),
        kind,
        name: name.to_owned(),
        phase: Phase::Transferring,
        state,
        segments_done: 0,
        segments_total: 0,
        bytes_done: 0,
        bytes_total: 0,
        rate_bps: 0.0,
        eta_secs: None,
        elapsed_secs: 0.0,
        fetch_ms: 0,
        decode_ms: 0,
        write_ms: 0,
        pieces_fetched: 0,
        pieces_rejected: 0,
        segment_retries: 0,
        resumed_from_segment: 0,
        last_error: None,
        resumable: false,
    }
}

/// One job per state, plus a 100 GiB receive at 37 % with a 1600-segment strip that was resumed
/// part-way (so the resume marker shows).
fn mock_jobs() -> Vec<TransferStatus> {
    let mut big = mock(
        TransferKind::Receive,
        "miasma:3vQk9TzWc1nXbR7uYhE4sJmAfPdLgN2oKxVe8CiUyH",
        r"\\?\D:\Downloads\backup-100GiB.img",
        TransferState::Running,
    );
    big.segments_total = 1600;
    big.segments_done = 592;
    big.bytes_total = 100 * GIB;
    big.bytes_done = 37 * GIB;
    big.rate_bps = 48.3 * MIB as f64;
    big.eta_secs = Some(((100 - 37) * GIB) / (48 * MIB));
    big.elapsed_secs = 5_820.0;
    big.fetch_ms = 4_100_000;
    big.decode_ms = 1_300_000;
    big.write_ms = 90_000;
    big.pieces_fetched = 5_920;
    big.pieces_rejected = 3;
    big.segment_retries = 2;
    big.resumed_from_segment = 412;

    let mut send = mock(
        TransferKind::Send,
        "miasma:8HcTn2WqYv5LbXe7RkAuJ3dMzPfN9oGsVi4KxCyUeB",
        "/Users/owner/Movies/wedding-4K.mov",
        TransferState::Running,
    );
    send.segments_total = 68;
    send.segments_done = 21;
    send.bytes_total = 4 * GIB + 300 * MIB;
    send.bytes_done = 1_400 * MIB;
    send.rate_bps = 11.2 * MIB as f64;
    send.eta_secs = Some(3 * 3600 + 5 * 60 + 9);
    send.elapsed_secs = 133.0;
    send.fetch_ms = 90_000;
    send.decode_ms = 38_000;
    send.write_ms = 5_000;

    let mut paused = mock(
        TransferKind::Receive,
        "miasma:6Fd2MwPq8ZxRt4YcHnLbV9sKgJeAuC7oXiTk3Ey5Nv",
        r"D:\Downloads\lecture-archive.zip",
        TransferState::Paused,
    );
    paused.segments_total = 384;
    paused.segments_done = 200;
    paused.bytes_total = 24 * GIB;
    paused.bytes_done = 12_500 * MIB;
    paused.resumed_from_segment = 200;
    paused.resumable = true;
    paused.last_error =
        Some("segment 201: only 7 of 10 pieces could be fetched; will retry".to_owned());

    let mut failed = mock(
        TransferKind::Receive,
        "miasma:2Yb7KcNwXq5RtLzHvPeMd9AgUsJfC3oVxTi8Ek4nWh",
        r"D:\Downloads\contract-scan.pdf",
        TransferState::Failed,
    );
    failed.phase = Phase::Preparing;
    failed.last_error = Some("wrong password: this transfer is password-protected".to_owned());

    let mut cancelled = mock(
        TransferKind::Send,
        "miasma:9Ns4XcQbT7WkLeRyHvPdM2AgUzJfC5oVxTi3Ek8nYh",
        "/Users/owner/Documents/photos-2025.tar",
        TransferState::Cancelled,
    );
    cancelled.segments_total = 12;
    cancelled.segments_done = 5;
    cancelled.bytes_total = 700 * MIB;
    cancelled.bytes_done = 292 * MIB;
    cancelled.resumed_from_segment = 5;
    cancelled.resumable = true;

    let mut done = mock(
        TransferKind::Send,
        "miasma:4Rw8TcNbQ2XkLeYvHzPdM7AgUsJfC5oVxTi3Ek9nWh",
        "/Users/owner/Documents/thesis-final.pdf",
        TransferState::Complete,
    );
    done.phase = Phase::Done;
    done.segments_total = 1;
    done.segments_done = 1;
    done.bytes_total = 38 * MIB;
    done.bytes_done = 38 * MIB;
    done.rate_bps = 6.4 * MIB as f64;
    done.elapsed_secs = 11.0;
    done.fetch_ms = 6_000;
    done.decode_ms = 2_100;
    done.write_ms = 300;

    vec![big, send, paused, failed, cancelled, done]
}

struct Step {
    name: String,
    theme: ThemeMode,
    locale: Locale,
    tab: Tab,
    daemon: Option<DaemonState>,
    transfers: Option<TransfersView>,
}

pub struct Tour {
    out: PathBuf,
    steps: Vec<Step>,
    idx: usize,
    frames_in_step: u32,
    requested: bool,
}

impl Tour {
    pub fn from_env() -> Option<Self> {
        let out = PathBuf::from(std::env::var_os("MIASMA_UI_TOUR")?);
        let _ = std::fs::create_dir_all(&out);
        let mut steps = Vec::new();
        let tabs = [
            (Tab::Store, "store"),
            (Tab::Retrieve, "retrieve"),
            (Tab::Send, "send"),
            (Tab::Inbox, "inbox"),
            (Tab::Outbox, "outbox"),
            (Tab::Status, "status"),
            (Tab::Settings, "settings"),
        ];
        steps.push(Step {
            name: "system_en_store".to_owned(),
            theme: ThemeMode::System,
            locale: Locale::En,
            tab: Tab::Store,
            daemon: None,
            transfers: None,
        });
        for (theme, tname) in [(ThemeMode::Dark, "dark"), (ThemeMode::Light, "light")] {
            for (locale, lname) in [(Locale::En, "en"), (Locale::Ja, "ja")] {
                for (tab, name) in tabs {
                    steps.push(Step {
                        name: format!("{tname}_{lname}_{name}"),
                        theme,
                        locale,
                        tab,
                        daemon: None,
                        transfers: None,
                    });
                }
                // The Transfers tab, one step per situation worth looking at. The daemon is
                // shown as connected so the forms are enabled.
                let views = [
                    ("big", view("backup-100GiB", NewForm::Receive, false, false)),
                    ("send", view("wedding-4K", NewForm::Send, false, false)),
                    ("paused", view("lecture-archive", NewForm::Receive, true, false)),
                    ("failed", view("contract-scan", NewForm::Send, false, false)),
                    ("stopped", view("photos-2025", NewForm::Receive, false, false)),
                    ("complete", view("thesis-final", NewForm::Receive, false, false)),
                    ("empty", view("", NewForm::Receive, false, true)),
                ];
                for (vname, v) in views {
                    steps.push(Step {
                        name: format!("{tname}_{lname}_transfers_{vname}"),
                        theme,
                        locale,
                        tab: Tab::Transfers,
                        daemon: Some(DaemonState::Connected),
                        transfers: Some(v),
                    });
                }
                for (d, dname) in [
                    (DaemonState::Stopped, "stopped"),
                    (DaemonState::Starting, "starting"),
                    (DaemonState::NeedsInit, "needsinit"),
                ] {
                    steps.push(Step {
                        name: format!("{tname}_{lname}_store_{dname}"),
                        theme,
                        locale,
                        tab: Tab::Store,
                        daemon: Some(d),
                        transfers: None,
                    });
                }
            }
        }
        // MIASMA_UI_TOUR_FILTER=<text> keeps only the steps whose name contains it.
        if let Ok(f) = std::env::var("MIASMA_UI_TOUR_FILTER") {
            steps.retain(|s| s.name.contains(&f));
        }
        Some(Self {
            out,
            steps,
            idx: 0,
            frames_in_step: 0,
            requested: false,
        })
    }

    /// Call once per frame before drawing. Returns true when the tour is finished.
    pub fn drive(&mut self, app: &mut MiasmaApp, ctx: &egui::Context) -> bool {
        let Some(step) = self.steps.get(self.idx) else {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return true;
        };
        ctx.request_repaint();
        if self.frames_in_step == 0 {
            app.theme_mode = step.theme;
            app.locale = step.locale;
            app.tab = step.tab;
            if let Some(d) = &step.daemon {
                app.daemon_state = d.clone();
            }
            if let Some(v) = &step.transfers {
                // Tall enough that the list, the detail pane and the form are all on screen.
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1000.0, 1400.0)));
                app.transfers
                    .set_mock(if v.empty { Vec::new() } else { mock_jobs() });
                let id = app
                    .transfers
                    .jobs
                    .iter()
                    .find(|j| !v.select.is_empty() && j.name.contains(v.select))
                    .map(transfer_id);
                app.transfers.select_job(id);
                app.transfers.set_form(v.form);
                if v.resume_prompt {
                    app.transfers.open_resume_prompt();
                }
            }
        } else if let Some(d) = &step.daemon {
            // The worker may report its own state meanwhile; keep the one being shown.
            app.daemon_state = d.clone();
        }
        self.frames_in_step += 1;
        if !self.requested && self.frames_in_step >= 8 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            self.requested = true;
        }
        if self.requested {
            let shot = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(img) = shot {
                let path = self.out.join(format!("{}.ppm", step.name));
                let [w, h] = img.size;
                let mut data = format!("P6\n{w} {h}\n255\n").into_bytes();
                for p in &img.pixels {
                    data.extend_from_slice(&[p.r(), p.g(), p.b()]);
                }
                let _ = std::fs::write(&path, data);
                self.idx += 1;
                self.frames_in_step = 0;
                self.requested = false;
            }
        }
        false
    }
}
