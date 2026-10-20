//! Developer-only "UI tour" (cargo feature `ui-tour`, not part of any release build).
//!
//! With `MIASMA_UI_TOUR=<dir>` set, the running app walks through theme x language x tab
//! (plus a few connection states), asks egui for a screenshot of its own window after each step
//! and writes it to `<dir>/<name>.ppm`. This exists because a GL window cannot be captured with
//! `PrintWindow` from a private desktop; the app renders the frame itself, so what is saved is
//! exactly what egui drew (fonts, colours, clipping).

mod raster;

use std::path::PathBuf;

use eframe::egui;

use miasma_core::transfer::{Phase, TransferKind, TransferState, TransferStatus};

use super::{InboxItem, MiasmaApp, Tab};
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
        share_id: None,
        share_id_checked: false,
        publisher_authenticated: false,
        path: None,
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

/// Fill the status fields the daemon would report, so Status/Send/Inbox/Outbox/Store show data.
fn mock_app(app: &mut MiasmaApp) {
    use crate::worker::TransportStatusInfo;
    use std::sync::Arc;
    use zeroize::Zeroizing;
    app.peer_id = "12D3KooWHbnkB6HD2o5drAChZZVNg53AWHDFKbDtuDPpwX3ZtS62".to_owned();
    app.peer_count = 3;
    app.share_count = 295;
    app.used_mb = 1130.6;
    app.quota_mb = 10240;
    app.replicated_count = 12;
    app.pending_replication = 2;
    app.listen_addrs = vec![
        "/ip4/10.238.5.182/udp/56485/quic-v1".to_owned(),
        "/ip4/127.0.0.1/udp/56485/quic-v1".to_owned(),
    ];
    app.wss_port = 61745;
    app.wss_tls_enabled = false;
    app.obfs_quic_port = 61746;
    app.transport_statuses = vec![
        TransportStatusInfo {
            name: "direct-libp2p".to_owned(),
            available: true,
            selected: true,
            success_count: 14,
            failure_count: 0,
            session_failures: 0,
            data_failures: 0,
            last_error: None,
        },
        TransportStatusInfo {
            name: "tcp-direct".to_owned(),
            available: true,
            selected: false,
            success_count: 2,
            failure_count: 3,
            session_failures: 1,
            data_failures: 2,
            last_error: None,
        },
        TransportStatusInfo {
            name: "wss-tunnel".to_owned(),
            available: false,
            selected: false,
            success_count: 0,
            failure_count: 4,
            session_failures: 0,
            data_failures: 0,
            last_error: Some(
                "connection refused (os error 111) while dialing the relay".to_owned(),
            ),
        },
    ];
    app.sharing_contact =
        Some("miasma-contact:3vQk9TzWc1nXbR7uYhE4sJmAfPdLgN2oKxVe8CiUyH".to_owned());
    app.last_mid = Some("miasma:3vQk9TzWc1nXbR7uYhE4sJmAfPdLgN2oKxVe8CiUyH".to_owned());
    app.retrieved_summary = Some("Retrieved 38.0 MiB (thesis-final.pdf)".to_owned());
    app.save_data = Some(vec![0u8; 4]);
    let item = |id: &str, state: &str, code: bool, name: Option<&str>| InboxItem {
        envelope_id: id.to_owned(),
        sender: "12D3KooWHbnkB6HD2o5drAChZZVNg53AWHDFKbDtuDPpwX3ZtS62".to_owned(),
        recipient: "12D3KooWQ9fPzKx2TnYw5Rb7uLhE4sJmAfPdLgN2oKxVe8CiUyH".to_owned(),
        state: state.to_owned(),
        challenge_code: code.then(|| Arc::new(Zeroizing::new("482-913".to_owned()))),
        created_at: "2026-10-12 09:41".to_owned(),
        expires_at: "2026-10-19 09:41".to_owned(),
        filename: name.map(str::to_owned),
        file_size: if name.is_some() { 38 * MIB } else { 0 },
    };
    app.inbox_items = vec![
        item(
            "a1b2c3d4e5f60718293a",
            "Confirmed",
            true,
            Some("thesis-final.pdf"),
        ),
        item(
            "b2c3d4e5f6071829a3b4",
            "Pending",
            false,
            Some("photos-2025.tar"),
        ),
        item("c3d4e5f6071829a3b4c5", "Expired", false, None),
    ];
    app.outbox_items = vec![
        item(
            "d4e5f6071829a3b4c5d6",
            "ChallengeIssued",
            false,
            Some("wedding-4K.mov"),
        ),
        item(
            "e5f6071829a3b4c5d6e7",
            "Retrieved",
            false,
            Some("thesis-final.pdf"),
        ),
    ];
}

struct Step {
    name: String,
    theme: ThemeMode,
    locale: Locale,
    tab: Tab,
    daemon: Option<DaemonState>,
    transfers: Option<TransfersView>,
    /// A `ContactsUi::fixture` name (Contacts tab with fake data).
    contacts: Option<&'static str>,
    /// A `ChatUi::fixture` name (Chat tab with fake data).
    chat: Option<&'static str>,
    /// Window size to render at.
    size: Option<(f32, f32)>,
    /// Product mode to show (None: leave as the app has it).
    mode: Option<crate::variant::ProductMode>,
    /// A `SendFlow::fixture` name: the send flow is open over this screen.
    flow: Option<&'static str>,
    /// Files are being dragged over the window (the "Drop files to send" veil).
    hover: bool,
}

/// `MIASMA_UI_SNAP=<dir>`: leave the app alone and only save what it draws, every
/// `MIASMA_UI_SNAP_SECS` seconds (default 5), as `<dir>/snap_<n>.ppm`. Used to look at a real
/// session (real daemon, real clicks) that cannot be screenshotted from outside.
/// `MIASMA_UI_SNAP_SIZE=1000x1400` resizes the window once at the start.
struct Snap {
    out: PathBuf,
    every: std::time::Duration,
    size: Option<(f32, f32)>,
    last: std::time::Instant,
    n: u32,
    requested: bool,
    sized: bool,
}

impl Snap {
    fn drive(&mut self, ctx: &egui::Context) {
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
        if !self.sized {
            self.sized = true;
            if let Some((w, h)) = self.size {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(w, h)));
            }
        }
        if !self.requested && self.last.elapsed() >= self.every {
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
                let [w, h] = img.size;
                let mut data = format!("P6\n{w} {h}\n255\n").into_bytes();
                for p in &img.pixels {
                    data.extend_from_slice(&[p.r(), p.g(), p.b()]);
                }
                let _ = std::fs::write(self.out.join(format!("snap_{:04}.ppm", self.n)), data);
                self.n += 1;
                self.last = std::time::Instant::now();
                self.requested = false;
            }
        }
    }
}

pub struct Tour {
    out: PathBuf,
    steps: Vec<Step>,
    idx: usize,
    frames_in_step: u32,
    requested: bool,
    snap: Option<Snap>,
}

impl Tour {
    pub fn from_env() -> Option<Self> {
        if let Some(dir) = std::env::var_os("MIASMA_UI_SNAP") {
            let out = PathBuf::from(dir);
            let _ = std::fs::create_dir_all(&out);
            let secs = std::env::var("MIASMA_UI_SNAP_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5);
            let size = std::env::var("MIASMA_UI_SNAP_SIZE").ok().and_then(|v| {
                let (w, h) = v.split_once('x')?;
                Some((w.parse().ok()?, h.parse().ok()?))
            });
            return Some(Self {
                out: out.clone(),
                steps: Vec::new(),
                idx: 0,
                frames_in_step: 0,
                requested: false,
                snap: Some(Snap {
                    out,
                    every: std::time::Duration::from_secs(secs),
                    size,
                    last: std::time::Instant::now(),
                    n: 0,
                    requested: false,
                    sized: false,
                }),
            });
        }
        let out = PathBuf::from(std::env::var_os("MIASMA_UI_TOUR")?);
        let _ = std::fs::create_dir_all(&out);
        let steps = all_steps();
        Some(Self {
            out,
            steps,
            idx: 0,
            frames_in_step: 0,
            requested: false,
            snap: None,
        })
    }

    /// Call once per frame before drawing. Returns true when the tour is finished.
    pub fn drive(&mut self, app: &mut MiasmaApp, ctx: &egui::Context) -> bool {
        if let Some(snap) = &mut self.snap {
            snap.drive(ctx);
            return false;
        }
        let Some(step) = self.steps.get(self.idx) else {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return true;
        };
        ctx.request_repaint();
        arrange(step, app, ctx, self.frames_in_step == 0);
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

/// Every step of the GL-window tour (and of its filter).
fn all_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    let easy_store_tour = std::env::var_os("MIASMA_UI_TOUR_EASY").is_some();
    let tabs = [
        (Tab::Contacts, "contacts"),
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
        contacts: None,
        chat: None,
        size: None,
        mode: None,
        flow: None,
        hover: false,
    });
    for (theme, tname) in [(ThemeMode::Dark, "dark"), (ThemeMode::Light, "light")] {
        for (locale, lname) in [(Locale::En, "en"), (Locale::Ja, "ja")] {
            if easy_store_tour {
                for (tab, name) in [(Tab::Home, "home"), (Tab::Files, "files")] {
                    steps.push(Step {
                        name: format!("{tname}_{lname}_{name}"),
                        theme,
                        locale,
                        tab,
                        daemon: Some(DaemonState::Connected),
                        transfers: None,
                        contacts: None,
                        chat: None,
                        size: None,
                        mode: None,
                        flow: None,
                        hover: false,
                    });
                }
            }
            for (tab, name) in tabs {
                steps.push(Step {
                    name: format!("{tname}_{lname}_{name}"),
                    theme,
                    locale,
                    tab,
                    daemon: Some(DaemonState::Connected),
                    transfers: None,
                    contacts: None,
                    chat: None,
                    size: None,
                    mode: None,
                    flow: None,
                    hover: false,
                });
            }
            // The Transfers tab, one step per situation worth looking at. The daemon is
            // shown as connected so the forms are enabled.
            let views = [
                ("big", view("backup-100GiB", NewForm::Receive, false, false)),
                ("send", view("wedding-4K", NewForm::Send, false, false)),
                (
                    "paused",
                    view("lecture-archive", NewForm::Receive, true, false),
                ),
                ("failed", view("contract-scan", NewForm::Send, false, false)),
                (
                    "stopped",
                    view("photos-2025", NewForm::Receive, false, false),
                ),
                (
                    "complete",
                    view("thesis-final", NewForm::Receive, false, false),
                ),
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
                    contacts: None,
                    chat: None,
                    size: None,
                    mode: None,
                    flow: None,
                    hover: false,
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
                    contacts: None,
                    chat: None,
                    size: None,
                    mode: None,
                    flow: None,
                    hover: false,
                });
            }
        }
    }
    // The Contacts tab with fake data: every fixture, wide and at the 700 px minimum.
    // MIASMA_UI_TOUR_FILTER=contacts_ keeps just these.
    for fx in crate::contacts::FIXTURES {
        for (w, h, wname) in [(1400.0, 2100.0, "wide"), (700.0, 2700.0, "narrow")] {
            for (theme, tname, locale, lname) in [
                (ThemeMode::Light, "light", Locale::Ja, "ja"),
                (ThemeMode::Dark, "dark", Locale::Ja, "ja"),
                (ThemeMode::Light, "light", Locale::En, "en"),
            ] {
                steps.push(Step {
                    name: format!("contacts_{fx}_{tname}_{lname}_{wname}"),
                    theme,
                    locale,
                    tab: Tab::Contacts,
                    daemon: Some(DaemonState::Connected),
                    transfers: None,
                    contacts: Some(fx),
                    chat: None,
                    size: Some((w, h)),
                    mode: None,
                    flow: None,
                    hover: false,
                });
            }
        }
    }
    // The Chat tab with fake data: every fixture, wide and at the 700 px minimum.
    // MIASMA_UI_TOUR_FILTER=chat_ keeps just these.
    for fx in crate::chat_ui::FIXTURES {
        for (w, h, wname) in [(1400.0, 900.0, "wide"), (700.0, 900.0, "narrow")] {
            for (theme, tname, locale, lname) in [
                (ThemeMode::Light, "light", Locale::Ja, "ja"),
                (ThemeMode::Dark, "dark", Locale::Ja, "ja"),
                (ThemeMode::Light, "light", Locale::En, "en"),
            ] {
                steps.push(Step {
                    name: format!("chat_{fx}_{tname}_{lname}_{wname}"),
                    theme,
                    locale,
                    tab: Tab::Chat,
                    daemon: Some(DaemonState::Connected),
                    transfers: None,
                    contacts: None,
                    chat: Some(fx),
                    size: Some((w, h)),
                    mode: None,
                    flow: None,
                    hover: false,
                });
            }
        }
    }
    // MIASMA_UI_TOUR_FILTER=<a>,<b> keeps only the steps whose name contains one of the parts.
    if let Ok(f) = std::env::var("MIASMA_UI_TOUR_FILTER") {
        steps.retain(|s| f.split(',').any(|part| s.name.contains(part)));
    }
    steps
}

/// Put the app into the state a step shows. Called every frame; `first` on the first one.
fn arrange(step: &Step, app: &mut MiasmaApp, ctx: &egui::Context, first: bool) {
    if first {
        app.theme_mode = step.theme;
        if let Some(m) = step.mode {
            app.mode = m;
        } else if std::env::var_os("MIASMA_UI_TOUR_EASY").is_some() {
            app.mode = crate::variant::ProductMode::Easy;
        }
        if let Some((w, h)) = tour_size() {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(w, h)));
        }
        app.locale = step.locale;
        app.tab = step.tab;
        // The send flow is closed at the start of every step, then opened as the step says.
        app.send_flow = crate::send_flow::SendFlow::default();
        if let Some(d) = &step.daemon {
            app.daemon_state = d.clone();
        }
        if let Some(fx) = step.contacts {
            if let Some((w, h)) = step.size {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(w, h)));
            }
            if let Some(ui) = crate::contacts::ContactsUi::fixture(
                fx,
                crate::locale::contact_strings(step.locale),
            ) {
                app.contacts = ui;
            }
        }
        if step.chat.is_some() {
            // The old-log-files question is not what these screenshots are about.
            app.logs.legacy = None;
        }
        if let Some(fx) = step.chat {
            if let Some((w, h)) = step.size {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(w, h)));
            }
            if let Some(ui) = crate::chat_ui::ChatUi::fixture(fx) {
                app.chat = ui;
            }
            // The registered contacts the chat fixtures refer to (ids a and b).
            let contacts = if fx == "nocontacts" { "empty" } else { "two" };
            if let Some(ui) = crate::contacts::ContactsUi::fixture(
                contacts,
                crate::locale::contact_strings(step.locale),
            ) {
                app.contacts = ui;
            }
        }
        if let Some(name) = step.flow {
            if let Some(ui) = crate::contacts::ContactsUi::fixture(
                "active",
                crate::locale::contact_strings(step.locale),
            ) {
                app.contacts = ui;
            }
            app.transfers.set_mock(mock_jobs());
            app.send_flow = crate::send_flow::SendFlow::fixture(name, app.contacts.contact_list())
                .unwrap_or_default();
        }
        if let Some(v) = &step.transfers {
            // Tall enough that the list, the detail pane and the form are all on screen.
            if std::env::var_os("MIASMA_UI_TOUR_SIZE").is_none() {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1000.0, 1400.0)));
            }
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
    if matches!(step.daemon, Some(DaemonState::Connected)) {
        mock_app(app);
        // The real worker runs in the background of a tour and reports that no service is
        // there; that banner is not what a connected screen shows.
        app.status_msg = None;
        app.last_error = None;
    }
}

/// Smallest and largest window side the tour accepts from `MIASMA_UI_TOUR_SIZE`.
const TOUR_SIDE_MIN: f32 = 320.0;
const TOUR_SIDE_MAX: f32 = 8192.0;

/// Read a size such as `1366x768` (width x height in pixels). Anything else, or a side
/// outside 320..=8192, is not a size.
fn parse_tour_size(text: &str) -> Option<(f32, f32)> {
    let (w, h) = text.trim().split_once(['x', 'X'])?;
    let (w, h) = (w.trim().parse::<f32>().ok()?, h.trim().parse::<f32>().ok()?);
    let ok = |v: f32| v.is_finite() && (TOUR_SIDE_MIN..=TOUR_SIDE_MAX).contains(&v);
    (ok(w) && ok(h)).then_some((w, h))
}

/// `MIASMA_UI_TOUR_SIZE=<w>x<h>`: render every step at this size (for example `1366x768` or
/// `1920x1080` for the Store screenshots). Unset or unreadable: each step uses its own size.
fn tour_size() -> Option<(f32, f32)> {
    std::env::var("MIASMA_UI_TOUR_SIZE")
        .ok()
        .and_then(|v| parse_tour_size(&v))
}

/// The Microsoft Store minimum for a desktop screenshot.
const STORE_SIZE: (f32, f32) = (1366.0, 768.0);

/// Home, Files, Contacts, Chat and Settings at the Store minimum size, in every language,
/// with the tour's sample data only (the connected-service mock, the "two" contacts fixture
/// and the "thread" chat fixture). Names: `store_<en|ja|zh>_<screen>_1366x768`.
fn store_steps() -> Vec<Step> {
    use crate::variant::ProductMode;
    let mut steps = Vec::new();
    let locales = [(Locale::En, "en"), (Locale::Ja, "ja"), (Locale::ZhCn, "zh")];
    for (locale, lname) in locales {
        let base = |screen: &str, tab: Tab| Step {
            name: format!("store_{lname}_{screen}_1366x768"),
            theme: ThemeMode::Light,
            locale,
            tab,
            daemon: Some(DaemonState::Connected),
            transfers: None,
            contacts: None,
            chat: None,
            size: Some(STORE_SIZE),
            flow: None,
            hover: false,
            mode: Some(ProductMode::Easy),
        };
        steps.push(base("home", Tab::Home));
        steps.push(base("files", Tab::Files));
        let mut contacts = base("contacts", Tab::Contacts);
        contacts.contacts = Some("two");
        steps.push(contacts);
        let mut chat = base("chat", Tab::Chat);
        chat.chat = Some("thread");
        steps.push(chat);
        steps.push(base("settings", Tab::Settings));
    }
    steps
}

/// The Easy-mode Store-facing tour: the five top-level screens, the file screens behind
/// Files, and the error/connection states, in every language, wide and at the 700 px minimum.
fn easy_steps() -> Vec<Step> {
    use crate::variant::ProductMode;
    let mut steps = Vec::new();
    let sizes = [(1200.0, 900.0, "wide"), (700.0, 1200.0, "narrow")];
    let locales = [(Locale::En, "en"), (Locale::Ja, "ja"), (Locale::ZhCn, "zh")];
    // Easy mode has no Send screen: sending is the shared flow (see the "flow" steps below).
    let screens: [(Tab, &str); 7] = [
        (Tab::Home, "home"),
        (Tab::Files, "files"),
        (Tab::Settings, "settings"),
        (Tab::Inbox, "inbox"),
        (Tab::Store, "store"),
        (Tab::Retrieve, "retrieve"),
        (Tab::Outbox, "outbox"),
    ];
    for (locale, lname) in locales {
        for (w, h, wname) in sizes {
            let base = |name: String, tab: Tab, daemon: DaemonState| Step {
                name,
                theme: ThemeMode::Light,
                locale,
                tab,
                daemon: Some(daemon),
                transfers: None,
                contacts: None,
                chat: None,
                // Long pages get a taller window so what is below the fold is seen too.
                size: Some((
                    w,
                    if matches!(tab, Tab::Settings | Tab::Transfers) {
                        h * 2.0
                    } else {
                        h
                    },
                )),
                mode: Some(ProductMode::Easy),
                flow: None,
                hover: false,
            };
            for (tab, tname) in screens {
                steps.push(base(
                    format!("easy_{lname}_{tname}_{wname}"),
                    tab,
                    DaemonState::Connected,
                ));
            }
            for (d, dname) in [
                (DaemonState::Stopped, "stopped"),
                (DaemonState::Starting, "starting"),
                (DaemonState::NeedsInit, "needsinit"),
            ] {
                steps.push(base(
                    format!("easy_{lname}_home_{dname}_{wname}"),
                    Tab::Home,
                    d.clone(),
                ));
                steps.push(base(
                    format!("easy_{lname}_files_{dname}_{wname}"),
                    Tab::Store,
                    d,
                ));
            }
            for (vname, v) in [
                ("big", view("backup-100GiB", NewForm::Receive, false, false)),
                ("failed", view("contract-scan", NewForm::Send, false, false)),
                ("empty", view("", NewForm::Receive, false, true)),
            ] {
                let mut s = base(
                    format!("easy_{lname}_transfers_{vname}_{wname}"),
                    Tab::Transfers,
                    DaemonState::Connected,
                );
                s.transfers = Some(v);
                steps.push(s);
            }
            for fx in ["empty", "two", "failed", "adderror"] {
                let mut s = base(
                    format!("easy_{lname}_contacts_{fx}_{wname}"),
                    Tab::Contacts,
                    DaemonState::Connected,
                );
                s.contacts = Some(fx);
                steps.push(s);
            }
            for fx in [
                "nocontacts",
                "list",
                "thread",
                "failed",
                "notsupported",
                "menu",
                "verify",
                "grouplist",
                "group",
                "groupinfo",
            ] {
                let mut s = base(
                    format!("easy_{lname}_chat_{fx}_{wname}"),
                    Tab::Chat,
                    DaemonState::Connected,
                );
                s.chat = Some(fx);
                steps.push(s);
            }
            // The one send flow, over Home, in every state; and the veil shown while files are
            // dragged over the window.
            for fx in crate::send_flow::FIXTURES.iter().copied() {
                let mut s = base(
                    format!("easy_{lname}_flow_{fx}_{wname}"),
                    Tab::Home,
                    DaemonState::Connected,
                );
                s.flow = Some(fx);
                steps.push(s);
            }
            let mut s = base(
                format!("easy_{lname}_drop_{wname}"),
                Tab::Home,
                DaemonState::Connected,
            );
            s.hover = true;
            steps.push(s);
        }
    }
    steps.extend(store_steps());
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tour_sizes_are_read_from_width_x_height() {
        assert_eq!(parse_tour_size("1366x768"), Some((1366.0, 768.0)));
        assert_eq!(parse_tour_size("1920X1080"), Some((1920.0, 1080.0)));
        assert_eq!(parse_tour_size(" 1200 x 900 "), Some((1200.0, 900.0)));
        for bad in [
            "",
            "1366",
            "x768",
            "1366x",
            "axb",
            "100x100",
            "1366x9999",
            "-5x700",
            "1366x768x2",
            "NaNx768",
        ] {
            assert_eq!(parse_tour_size(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_store_steps_cover_the_five_screens_at_the_store_minimum_in_every_language() {
        let steps = store_steps();
        assert_eq!(steps.len(), 15);
        for s in &steps {
            assert_eq!(s.size, Some((1366.0, 768.0)), "{}", s.name);
            assert!(s.name.starts_with("store_") && s.name.ends_with("_1366x768"));
        }
        for lang in ["en", "ja", "zh"] {
            for screen in ["home", "files", "contacts", "chat", "settings"] {
                let name = format!("store_{lang}_{screen}_1366x768");
                assert!(steps.iter().any(|s| s.name == name), "missing {name}");
            }
        }
        // Sample data only: the fixtures the tour already uses.
        let chat = steps
            .iter()
            .find(|s| s.name == "store_en_chat_1366x768")
            .unwrap();
        assert_eq!(chat.chat, Some("thread"));
        let contacts = steps
            .iter()
            .find(|s| s.name == "store_en_contacts_1366x768")
            .unwrap();
        assert_eq!(contacts.contacts, Some("two"));
        // They are part of the default headless tour.
        let all = easy_steps();
        assert!(steps.iter().all(|s| all.iter().any(|a| a.name == s.name)));
    }

    /// Window-less tour: renders every step of the Easy tour (or, with `MIASMA_UI_TOUR_ALL`, the
    /// whole GL tour) on the CPU and writes PNG files. Output folder: `MIASMA_UI_TOUR_OUT`, or
    /// `<temp dir>/miasma-ui-tour`. `MIASMA_UI_TOUR_FILTER` keeps only matching step names.
    /// Run with `--features ui-tour`; it also runs as a plain smoke test of every screen.
    #[test]
    fn headless_tour_renders_every_step() {
        let out = std::env::var_os("MIASMA_UI_TOUR_OUT")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("miasma-ui-tour"));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        let mut steps = if std::env::var_os("MIASMA_UI_TOUR_ALL").is_some() {
            all_steps()
        } else {
            easy_steps()
        };
        if let Ok(f) = std::env::var("MIASMA_UI_TOUR_FILTER") {
            steps.retain(|s| f.split(',').any(|part| s.name.contains(part)));
        }
        assert!(!steps.is_empty());

        let data = tempfile::tempdir().unwrap();
        let ctx = egui::Context::default();
        let mut app = MiasmaApp::new_with_ctx(
            &ctx,
            None,
            crate::variant::ProductMode::Easy,
            Locale::En,
            ThemeMode::Light,
            data.path().to_path_buf(),
            crate::LaunchIntent::Normal,
        );
        let mut raster = raster::Renderer::default();
        let mut clock = 0.0f64;
        let mut written = 0usize;
        for step in &steps {
            // MIASMA_UI_TOUR_SIZE wins over the size a step carries.
            let (w, h) = tour_size()
                .or(step.size)
                .unwrap_or(if step.transfers.is_some() {
                    (1000.0, 1400.0)
                } else {
                    (1000.0, 700.0)
                });
            let mut last = None;
            for frame in 0..8 {
                arrange(step, &mut app, &ctx, frame == 0);
                let mut raw = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(w, h),
                    )),
                    time: Some(clock),
                    predicted_dt: 1.0 / 60.0,
                    ..Default::default()
                };
                if step.hover {
                    raw.hovered_files.push(egui::HoveredFile::default());
                }
                raw.viewports
                    .entry(egui::ViewportId::ROOT)
                    .or_default()
                    .native_pixels_per_point = Some(1.0);
                clock += 1.0 / 60.0;
                let full = ctx.run(raw, |ctx| app.update_frame(ctx, None));
                raster.apply(&full.textures_delta);
                last = Some(full.shapes);
            }
            let prims = ctx.tessellate(last.unwrap(), 1.0);
            let bg = ctx.style().visuals.panel_fill;
            let rgb = raster.paint(&prims, w as usize, h as usize, [bg.r(), bg.g(), bg.b()]);
            let bmp = raster::bmp(&rgb, w as usize, h as usize);
            std::fs::write(out.join(format!("{}.bmp", step.name)), bmp).unwrap();
            written += 1;
        }
        // BMP -> PNG with the .NET imaging classes (always present on Windows PowerShell).
        #[cfg(windows)]
        {
            let script = format!(
                "Add-Type -AssemblyName System.Drawing; Get-ChildItem -LiteralPath '{}' -Filter *.bmp | ForEach-Object {{ $i = [System.Drawing.Image]::FromFile($_.FullName); $i.Save([IO.Path]::ChangeExtension($_.FullName,'png'), [System.Drawing.Imaging.ImageFormat]::Png); $i.Dispose(); Remove-Item -LiteralPath $_.FullName }}",
                out.display()
            );
            let st = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .status();
            eprintln!("png conversion: {st:?}");
        }
        eprintln!("UI_TOUR_DONE {} images in {}", written, out.display());
    }
}
