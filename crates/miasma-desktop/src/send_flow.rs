//! The one send flow.
//!
//! Every way to start sending something in the desktop app ends here: Home "Send a file", the
//! per-person "Send files" button in Contacts, the paperclip of a conversation, and dropping files
//! on the window. The flow asks for three things only: who (a contact, or "anyone, with an
//! invitation code"), which files (a picker, or what was dropped; several at once), and, behind
//! "More options" and only for the invitation route, a password and how much redundancy.
//!
//! Two existing ways carry the files and both keep working unchanged:
//!
//! * a **contact**: a direct push to a registered contact (`contacts.rs`, `PushRequest::Send`),
//!   which needs no password and no Share ID;
//! * an **invitation code**: a resumable transfer in the daemon (`WorkerCmd::TransferStartPublish`,
//!   shown in Files), whose Share ID the sender hands over together with the optional password.
//!
//! This file holds the state machine and its drawing. It never touches the network: it hands
//! requests to the app (`next_command`) and to `ContactsUi::queue_files`, and reads progress back
//! from the lists those screens already keep.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};
use miasma_core::push::ContactInfo;
use miasma_core::transfer::{password_policy, TransferState, TransferStatus};
use zeroize::Zeroize;

use crate::a11y::CollapsingExt as _;
use crate::chat::{elide, NAME_CHARS};
use crate::contacts::{base_name, ContactsUi, FileStatus, SentFile};
use crate::locale::{ComposeStrings, ContactStrings, TransferStrings};
use crate::theme::{self, Palette};
use crate::transfers::{
    fill, format_permille, permille, send_password_state, transfer_id, violation_codes,
    weak_password_text, EasyChoice, SendPassword, DEFAULT_PRESET, PRESETS,
};
use crate::ui_kit::{self as kit, Level};
use crate::worker::WorkerCmd;

fn pal() -> Palette {
    theme::palette()
}

/// Longest file name shown in a row before it is cut in the middle.
const FILE_NAME_CHARS: usize = 44;

// ─── Pure state ─────────────────────────────────────────────────────────────

/// Who the files go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// Not chosen yet.
    None,
    /// A registered contact (its id in the Contacts list).
    Contact(String),
    /// Anyone who is given the invitation code.
    Code,
}

/// Why Send is not available yet. The first one in this order is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// The background service is not connected.
    Offline,
    Recipient,
    Files,
    /// The chosen contact has sending turned off (the name is for the message).
    ContactOff(String),
    /// The two password fields differ.
    Mismatch,
    /// The password breaks the rules the daemon enforces.
    WeakPassword,
}

/// What pressing Send does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Contact {
        id: String,
        paths: Vec<PathBuf>,
    },
    Code {
        paths: Vec<PathBuf>,
        password: Option<String>,
        preset: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Contact,
    Code,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Asking who, what and how.
    Form,
    /// Sent: the files and where each one stands.
    Result,
}

/// Where the app should go when a result button is pressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowNav {
    Files,
    Contacts,
}

/// What a frame of the flow asks of the app.
#[derive(Default)]
pub struct FlowOutput {
    /// Files queued for a contact: the conversation with that contact notes them.
    pub noted: Option<(String, Vec<SentFile>)>,
    pub nav: Option<FlowNav>,
}

/// A request for the worker, with whether it carries a password.
pub struct Outgoing {
    pub cmd: WorkerCmd,
    pub protected: bool,
}

/// One file of an invitation-code send that has not been started yet, with its own password and
/// protection level (a second send opened while the first is still being handed over must not
/// change them).
struct Pending {
    path: PathBuf,
    password: Option<String>,
    preset: usize,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub struct SendFlow {
    open: bool,
    phase: Phase,
    recipient: Recipient,
    files: Vec<PathBuf>,
    /// A folder was dropped or picked and left out.
    folder_refused: bool,
    more_open: bool,
    /// Changes whenever the flow is opened afresh, so "More options" starts collapsed again.
    generation: u32,
    password: String,
    confirm: String,
    /// The password the Generate button just made, shown once in clear.
    generated: Option<String>,
    preset: usize,

    // The result.
    route: Route,
    result_contact: Option<(String, String)>,
    result_files: Vec<PathBuf>,
    queue: VecDeque<Pending>,
    in_flight: Option<Pending>,
    started: HashMap<PathBuf, String>,
    failed: HashMap<PathBuf, String>,
    since_ms: u64,
    copied: Option<(PathBuf, Instant)>,
}

impl Default for SendFlow {
    fn default() -> Self {
        Self {
            open: false,
            phase: Phase::Form,
            recipient: Recipient::None,
            files: Vec::new(),
            folder_refused: false,
            more_open: false,
            generation: 0,
            password: String::new(),
            confirm: String::new(),
            generated: None,
            preset: DEFAULT_PRESET,
            route: Route::Contact,
            result_contact: None,
            result_files: Vec::new(),
            queue: VecDeque::new(),
            in_flight: None,
            started: HashMap::new(),
            failed: HashMap::new(),
            since_ms: 0,
            copied: None,
        }
    }
}

impl Drop for SendFlow {
    fn drop(&mut self) {
        self.zeroize_passwords();
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl SendFlow {
    fn zeroize_passwords(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
        self.generated.zeroize();
        self.generated = None;
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    #[cfg(test)]
    pub fn recipient(&self) -> &Recipient {
        &self.recipient
    }

    #[cfg(test)]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Back to a blank form (a flow still working on an earlier send keeps going; only what is
    /// shown is replaced).
    fn reset(&mut self) {
        self.zeroize_passwords();
        let mut fresh = Self::default();
        fresh.generation = self.generation.wrapping_add(1);
        // Files of an earlier send that were not started yet are still sent, each with its own
        // password and protection level; the flow just no longer shows them.
        fresh.queue = std::mem::take(&mut self.queue);
        fresh.in_flight = self.in_flight.take();
        *self = fresh;
    }

    /// Open with nothing chosen. With no contact to send to, the invitation code is preselected.
    pub fn open_empty(&mut self, contacts: &[ContactInfo]) {
        self.reset();
        self.open = true;
        if !contacts.iter().any(|c| c.allow_send) {
            self.recipient = Recipient::Code;
        }
    }

    /// Open with this contact chosen (Contacts "Send files", a conversation's paperclip).
    pub fn open_for_contact(&mut self, id: &str) {
        self.reset();
        self.open = true;
        self.recipient = Recipient::Contact(id.to_owned());
    }

    /// Open with files already chosen (dropped on the window). `contact` is the person the drop
    /// is meant for, when the screen it landed on says so. A flow that is already asking keeps
    /// what it has and gets the files added.
    pub fn open_with_files(
        &mut self,
        paths: Vec<PathBuf>,
        contact: Option<String>,
        contacts: &[ContactInfo],
    ) {
        if !(self.open && self.phase == Phase::Form) {
            match &contact {
                Some(id) => self.open_for_contact(id),
                None => self.open_empty(contacts),
            }
        } else if self.recipient == Recipient::None {
            if let Some(id) = contact {
                self.recipient = Recipient::Contact(id);
            }
        }
        self.add_files(paths);
    }

    /// Add files to the list: a file already there is not added twice, a folder is left out (and
    /// remembered, so the form can say so). Returns how many were added.
    pub fn add_files(&mut self, paths: Vec<PathBuf>) -> usize {
        let mut added = 0;
        for p in paths {
            if p.is_dir() {
                self.folder_refused = true;
                continue;
            }
            if !self.files.contains(&p) {
                self.files.push(p);
                added += 1;
            }
        }
        added
    }

    pub fn remove_file(&mut self, index: usize) {
        if index < self.files.len() {
            self.files.remove(index);
        }
    }

    pub fn close(&mut self) {
        self.open = false;
        self.password.zeroize();
        self.confirm.zeroize();
        self.generated.zeroize();
        self.generated = None;
    }

    fn label_of<'a>(contacts: &'a [ContactInfo], id: &str) -> Option<&'a ContactInfo> {
        contacts.iter().find(|c| c.id == id)
    }

    /// The first reason Send cannot be pressed, if any.
    pub fn blocker(&self, connected: bool, contacts: &[ContactInfo]) -> Option<Blocker> {
        if !connected {
            return Some(Blocker::Offline);
        }
        match &self.recipient {
            Recipient::None => return Some(Blocker::Recipient),
            Recipient::Contact(id) => match Self::label_of(contacts, id) {
                None => return Some(Blocker::Recipient),
                Some(c) if !c.allow_send && !self.files.is_empty() => {
                    return Some(Blocker::ContactOff(c.label.clone()))
                }
                Some(_) => {}
            },
            Recipient::Code => {}
        }
        if self.files.is_empty() {
            return Some(Blocker::Files);
        }
        if let Recipient::Contact(id) = &self.recipient {
            if let Some(c) = Self::label_of(contacts, id) {
                if !c.allow_send {
                    return Some(Blocker::ContactOff(c.label.clone()));
                }
            }
        }
        if self.recipient == Recipient::Code {
            if self.password != self.confirm {
                return Some(Blocker::Mismatch);
            }
            if matches!(send_password_state(&self.password), SendPassword::Weak(_)) {
                return Some(Blocker::WeakPassword);
            }
        }
        None
    }

    /// What Send would do, or why it cannot.
    pub fn plan(&self, connected: bool, contacts: &[ContactInfo]) -> Result<Plan, Blocker> {
        if let Some(b) = self.blocker(connected, contacts) {
            return Err(b);
        }
        Ok(match &self.recipient {
            Recipient::Contact(id) => Plan::Contact {
                id: id.clone(),
                paths: self.files.clone(),
            },
            _ => Plan::Code {
                paths: self.files.clone(),
                password: (!self.password.is_empty()).then(|| self.password.clone()),
                preset: self.preset,
            },
        })
    }

    /// Press Send. A contact's files are queued with the Contacts screen at once (returned, so
    /// the conversation can note them); an invitation-code send is queued here and handed out one
    /// file at a time by [`Self::next_command`].
    pub fn start(
        &mut self,
        connected: bool,
        contacts: &mut ContactsUi,
        ct: &ContactStrings,
    ) -> Result<Option<(String, Vec<SentFile>)>, Blocker> {
        let list = contacts.contact_list().to_vec();
        let plan = self.plan(connected, &list)?;
        self.phase = Phase::Result;
        self.since_ms = unix_ms();
        self.copied = None;
        self.started.clear();
        self.failed.clear();
        match plan {
            Plan::Contact { id, paths } => {
                self.route = Route::Contact;
                self.result_files = paths.clone();
                let label = Self::label_of(&list, &id)
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                self.result_contact = Some((id.clone(), label));
                let sent = contacts.queue_files(ct, &id, paths);
                Ok(Some((id, sent)))
            }
            Plan::Code {
                paths,
                mut password,
                preset,
            } => {
                self.route = Route::Code;
                self.result_contact = None;
                self.result_files = paths.clone();
                self.queue.extend(paths.into_iter().map(|path| Pending {
                    path,
                    password: password.clone(),
                    preset,
                }));
                password.zeroize();
                self.password.zeroize();
                self.confirm.zeroize();
                self.generated.zeroize();
                self.generated = None;
                Ok(None)
            }
        }
    }

    /// The next invitation-code send to hand to the worker, if one is due: one at a time, the next
    /// only after the daemon answered the one before. `None` when nothing is waiting.
    pub fn next_command(&mut self) -> Option<Outgoing> {
        if self.in_flight.is_some() {
            return None;
        }
        let p = self.queue.pop_front()?;
        let preset = PRESETS[p.preset.min(PRESETS.len() - 1)];
        let out = Outgoing {
            cmd: WorkerCmd::TransferStartPublish {
                file_path: p.path.clone(),
                password: p.password.clone(),
                data_shards: preset.k,
                total_shards: preset.n,
                restart: false,
            },
            protected: p.password.is_some(),
        };
        self.in_flight = Some(p);
        Some(out)
    }

    /// The worker's channel did not take the command: it goes back to the front of the queue.
    pub fn put_back(&mut self) {
        if let Some(p) = self.in_flight.take() {
            self.queue.push_front(p);
        }
    }

    /// The daemon accepted the send in flight; `id` is the transfer's id. False when the flow
    /// had none in flight (the answer belongs to something else).
    pub fn on_started(&mut self, id: String) -> bool {
        match self.in_flight.take() {
            Some(p) => {
                self.started.insert(p.path.clone(), id);
                true
            }
            None => false,
        }
    }

    /// The daemon refused the send in flight. False when the flow had none in flight.
    pub fn on_failed(&mut self, why: String) -> bool {
        match self.in_flight.take() {
            Some(p) => {
                self.failed.insert(p.path.clone(), why);
                true
            }
            None => false,
        }
    }

    /// Something is still being handed to the daemon (the window keeps redrawing).
    pub fn is_busy(&self) -> bool {
        self.in_flight.is_some() || !self.queue.is_empty()
    }

    fn generate_password(&mut self) {
        let pw = password_policy::generate(password_policy::GENERATE_DEFAULT_LEN);
        self.password.zeroize();
        self.confirm.zeroize();
        self.generated.zeroize();
        self.password = pw.as_str().to_owned();
        self.confirm = pw.as_str().to_owned();
        self.generated = Some(pw.as_str().to_owned());
    }

    /// Back to the form for more files to the same place.
    fn send_more(&mut self) {
        let recipient = self.recipient.clone();
        self.reset();
        self.open = true;
        self.recipient = recipient;
    }
}

/// How one job of an invitation-code send stands, in words and level.
pub(crate) fn job_status(k: &ComposeStrings, job: &TransferStatus) -> (String, Level) {
    match job.state {
        TransferState::Running => (
            fill(
                k.st_sending,
                &[(
                    "pct",
                    &format_permille(permille(job.bytes_done, job.bytes_total, job.state)),
                )],
            ),
            Level::Info,
        ),
        TransferState::Paused => (k.st_waiting.to_owned(), Level::Muted),
        TransferState::Complete => (k.st_done.to_owned(), Level::Ok),
        TransferState::Failed | TransferState::Cancelled => (k.st_failed.to_owned(), Level::Error),
    }
}

/// How one file sent to a contact stands.
pub(crate) fn file_status_text(k: &ComposeStrings, s: &FileStatus) -> (String, Level) {
    match s {
        FileStatus::Waiting => (k.st_waiting.to_owned(), Level::Muted),
        FileStatus::Sending { percent } => (
            fill(k.st_sending, &[("pct", &format!("{percent}%"))]),
            Level::Info,
        ),
        FileStatus::Done => (k.st_done.to_owned(), Level::Ok),
        FileStatus::Failed { reason } => (
            fill(k.st_failed_why, &[("why", reason.as_str())]),
            Level::Error,
        ),
    }
}

/// The sentence for a blocker (what to do next).
fn blocker_text(k: &ComposeStrings, t: &TransferStrings, b: &Blocker, flow: &SendFlow) -> String {
    match b {
        Blocker::Offline => t.forms_offline.to_owned(),
        Blocker::Recipient => k.err_recipient.to_owned(),
        Blocker::Files => k.err_files.to_owned(),
        Blocker::ContactOff(name) => fill(k.err_contact_off, &[("name", name)]),
        Blocker::Mismatch => t.mismatch.to_owned(),
        Blocker::WeakPassword => match send_password_state(&flow.password) {
            SendPassword::Weak(v) => weak_password_text(t, &violation_codes(&v)),
            _ => String::new(),
        },
    }
}

// ─── Drawing ────────────────────────────────────────────────────────────────

enum FormAction {
    None,
    Send,
    Cancel,
}

impl SendFlow {
    /// Draw the flow as a dialog over the window (nothing when it is closed).
    #[allow(clippy::too_many_arguments)]
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        k: &ComposeStrings,
        t: &TransferStrings,
        ct: &ContactStrings,
        contacts: &mut ContactsUi,
        transfers: &crate::transfers::TransfersUi,
        connected: bool,
    ) -> FlowOutput {
        let mut out = FlowOutput::default();
        if !self.open {
            return out;
        }
        crate::a11y::dialog_enter(ctx, "send_flow");
        if crate::a11y::esc_pressed(ctx) {
            self.close();
            crate::a11y::dialog_leave(ctx, "send_flow");
            return out;
        }
        let list = contacts.contact_list().to_vec();
        let screen = ctx.screen_rect();
        let width = (screen.width() - 48.0).clamp(280.0, 520.0);
        let max_h = (screen.height() - 72.0 - 72.0).max(220.0);
        let mut action = FormAction::None;
        let mut close = false;
        let mut nav = None;
        crate::a11y::dialog_title(ctx, k.flow_title);
        egui::Window::new(k.flow_title)
            .id(egui::Id::new("send_flow_window"))
            .collapsible(false)
            .resizable(false)
            // Anchored at the top so that the room below (the scroll area's limit) does not
            // shrink as the dialog grows.
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 72.0))
            .show(ctx, |ui| {
                ui.set_width(width);
                egui::ScrollArea::vertical()
                    .id_source("send_flow_scroll")
                    .max_height(max_h)
                    .auto_shrink([false, true])
                    .show(ui, |ui| match self.phase {
                        Phase::Form => {
                            action = self.form_ui(ui, k, t, ct, &list, connected);
                        }
                        Phase::Result => {
                            let (n, c) = self.result_ui(ui, k, t, ct, contacts, transfers);
                            nav = n;
                            close = c;
                        }
                    });
            });
        match action {
            FormAction::None => {}
            FormAction::Cancel => close = true,
            FormAction::Send => {
                if let Ok(noted) = self.start(connected, contacts, ct) {
                    out.noted = noted;
                }
            }
        }
        if nav.is_some() {
            out.nav = nav;
            close = true;
        }
        if close {
            self.close();
            crate::a11y::dialog_leave(ctx, "send_flow");
        }
        out
    }

    fn form_ui(
        &mut self,
        ui: &mut egui::Ui,
        k: &ComposeStrings,
        t: &TransferStrings,
        ct: &ContactStrings,
        list: &[ContactInfo],
        connected: bool,
    ) -> FormAction {
        ui.spacing_mut().item_spacing.y = kit::SP_2;

        // Who.
        ui.label(kit::muted_text(k.to_label));
        let shown = match &self.recipient {
            Recipient::None => k.to_placeholder.to_owned(),
            Recipient::Code => k.to_code.to_owned(),
            Recipient::Contact(id) => Self::label_of(list, id)
                .map(|c| elide(&c.label, NAME_CHARS))
                .unwrap_or_else(|| k.to_placeholder.to_owned()),
        };
        let combo = egui::ComboBox::from_id_source("send_flow_to")
            .selected_text(shown)
            .width(ui.available_width() - kit::SP_4)
            .show_ui(ui, |ui| {
                for c in list {
                    let label = if c.allow_send {
                        elide(&c.label, NAME_CHARS)
                    } else {
                        fill(k.to_off, &[("name", &elide(&c.label, NAME_CHARS))])
                    };
                    let selected = matches!(&self.recipient, Recipient::Contact(id) if *id == c.id);
                    let r = crate::form_check::add_enabled(
                        ui,
                        c.allow_send,
                        egui::SelectableLabel::new(selected, label),
                    );
                    if r.clicked() {
                        self.recipient = Recipient::Contact(c.id.clone());
                    }
                }
                let r = ui.selectable_label(self.recipient == Recipient::Code, k.to_code);
                if r.clicked() {
                    self.recipient = Recipient::Code;
                }
            });
        combo
            .response
            .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, k.a11y_to));
        if self.recipient == Recipient::Code {
            kit::hint(ui, k.to_code_hint);
        }
        if list.is_empty() {
            kit::hint(ui, k.to_none_contacts);
        }
        ui.add_space(kit::SP_1);

        // Which files.
        ui.label(kit::muted_text(k.files_label));
        if self.files.is_empty() {
            kit::hint(ui, k.files_none);
        }
        let mut remove: Option<usize> = None;
        for (i, p) in self.files.iter().enumerate() {
            let name = base_name(&p.to_string_lossy());
            ui.horizontal(|ui| {
                let r = ui.add(kit::compact_button(k.file_remove));
                let a11y = fill(k.a11y_file_remove, &[("name", &name)]);
                r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, a11y.clone()));
                if r.clicked() {
                    remove = Some(i);
                }
                ui.add(
                    egui::Label::new(
                        RichText::new(elide(&name, FILE_NAME_CHARS)).color(pal().text),
                    )
                    .truncate(true),
                )
                .on_hover_text(p.to_string_lossy().into_owned());
            });
        }
        if let Some(i) = remove {
            self.remove_file(i);
        }
        if self.folder_refused {
            kit::notice(ui, Level::Warn, k.err_folder);
        }
        let choose = if self.files.is_empty() {
            k.files_choose
        } else {
            k.files_add
        };
        if ui.add(kit::secondary_button(choose)).clicked() {
            if let Some(p) = rfd::FileDialog::new().set_title(ct.pick_title).pick_files() {
                self.add_files(p);
            }
        }
        kit::hint(ui, k.files_drop);

        // More options: only the invitation route has a password and a protection level.
        if self.recipient == Recipient::Code {
            ui.add_space(kit::SP_1);
            egui::CollapsingHeader::new(RichText::new(k.more_options).color(pal().muted))
                .id_source(("send_flow_more", self.generation))
                .default_open(self.more_open)
                .show_a11y(ui, |ui| self.more_ui(ui, t));
        }

        // The one action.
        ui.add_space(kit::SP_2);
        let blocker = self.blocker(connected, list);
        if let Some(b) = &blocker {
            let text = blocker_text(k, t, b, self);
            if !text.is_empty() {
                if *b == Blocker::Offline {
                    kit::notice(ui, Level::Warn, &text);
                } else {
                    kit::hint(ui, &text);
                }
            }
        }
        let mut action = FormAction::None;
        kit::button_row(ui, |ui| {
            if kit::primary(ui, blocker.is_none(), k.send).clicked() {
                action = FormAction::Send;
            }
            if ui.add(kit::secondary_button(k.cancel)).clicked() {
                action = FormAction::Cancel;
            }
        });
        action
    }

    fn more_ui(&mut self, ui: &mut egui::Ui, t: &TransferStrings) {
        ui.spacing_mut().item_spacing.y = kit::SP_2;
        ui.label(kit::muted_text(t.password_label));
        let mut generate = false;
        // The password field and its repeat are one pair: the same width.
        let field_w = kit::input_width_beside_button(ui);
        let au = crate::locale::audit_strings(t.locale);
        ui.horizontal(|ui| {
            let r = ui.add(
                kit::input(&mut self.password)
                    .password(true)
                    .desired_width(field_w),
            );
            crate::form_check::name(&r, au.a11y_password);
            if ui.add(kit::secondary_button(t.pw_generate)).clicked() {
                generate = true;
            }
        });
        if generate {
            self.generate_password();
        }
        kit::hint(ui, t.pw_policy_note_easy);
        if self.generated.as_deref() != Some(self.password.as_str()) {
            self.generated.zeroize();
            self.generated = None;
        }
        if let Some(pw) = self.generated.clone() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(pw.as_str()).monospace().color(pal().text));
                if ui.add(kit::compact_button(t.copy)).clicked() {
                    ui.output_mut(|o| o.copied_text = pw.clone());
                }
            });
            kit::hint(ui, t.pw_generated_note);
        }
        ui.label(kit::muted_text(t.confirm_label));
        let r = ui.add(
            kit::input(&mut self.confirm)
                .password(true)
                .desired_width(field_w),
        );
        crate::form_check::name(&r, au.a11y_password_repeat);
        if self.password != self.confirm && !self.confirm.is_empty() {
            kit::notice(ui, Level::Error, t.mismatch);
        }
        match send_password_state(&self.password) {
            SendPassword::Weak(v) => {
                kit::notice(
                    ui,
                    Level::Error,
                    &weak_password_text(t, &violation_codes(&v)),
                );
            }
            SendPassword::Short => {
                kit::hint(ui, t.pw_short_warning);
            }
            SendPassword::Unprotected | SendPassword::Good => {}
        }
        ui.add_space(kit::SP_1);
        ui.label(kit::muted_text(t.red_label_easy));
        let current = EasyChoice::from_preset_index(self.preset);
        for choice in EasyChoice::ALL {
            let (label, desc) = match choice {
                EasyChoice::Fastest => (t.easy_fast, t.easy_fast_desc),
                EasyChoice::Balanced => (t.easy_bal, t.easy_bal_desc),
                EasyChoice::Safest => (t.easy_safe, t.easy_safe_desc),
            };
            ui.vertical(|ui| {
                if ui.radio(current == Some(choice), label).clicked() {
                    self.preset = choice.preset_index();
                }
                ui.horizontal(|ui| {
                    ui.add_space(kit::SP_5);
                    ui.add(
                        egui::Label::new(RichText::new(desc).small().color(pal().muted)).wrap(true),
                    );
                });
            });
        }
    }

    /// The files and where each one stands. Returns where to go (if a button asked) and whether
    /// to close.
    fn result_ui(
        &mut self,
        ui: &mut egui::Ui,
        k: &ComposeStrings,
        t: &TransferStrings,
        ct: &ContactStrings,
        contacts: &ContactsUi,
        transfers: &crate::transfers::TransfersUi,
    ) -> (Option<FlowNav>, bool) {
        ui.spacing_mut().item_spacing.y = kit::SP_2;
        match (&self.route, &self.result_contact) {
            (Route::Contact, Some((_, name))) => {
                kit::paragraph(
                    ui,
                    &fill(k.result_contact, &[("name", &elide(name, NAME_CHARS))]),
                );
            }
            _ => {
                kit::paragraph(ui, k.result_code);
            }
        }
        // One line per file: name, and how it stands.
        let files = self.result_files.clone();
        for p in &files {
            let name = base_name(&p.to_string_lossy());
            let (text, level) = match (&self.route, &self.result_contact) {
                (Route::Contact, Some((id, _))) => {
                    let st = contacts.file_status(ct, id, &p.to_string_lossy(), self.since_ms);
                    file_status_text(k, &st)
                }
                _ => {
                    if let Some(why) = self.failed.get(p) {
                        (
                            fill(k.st_failed_why, &[("why", why.as_str())]),
                            Level::Error,
                        )
                    } else if let Some(job) = self
                        .started
                        .get(p)
                        .and_then(|id| transfers.jobs.iter().find(|j| &transfer_id(j) == id))
                    {
                        job_status(k, job)
                    } else {
                        (k.st_waiting.to_owned(), Level::Muted)
                    }
                }
            };
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(elide(&name, FILE_NAME_CHARS)).color(pal().text));
                ui.label(RichText::new(text).color(kit::level_color(level)));
                // The invitation of a send that is under way: what the person is handed.
                if self.route == Route::Code {
                    let share = self
                        .started
                        .get(p)
                        .and_then(|id| transfers.jobs.iter().find(|j| &transfer_id(j) == id))
                        .and_then(|j| j.share_id.clone())
                        .filter(|s| !s.is_empty());
                    if let Some(share_id) = share {
                        let copied = self.copied.as_ref().is_some_and(|(cp, at)| {
                            cp == p && at.elapsed() < Duration::from_secs(2)
                        });
                        let label = if copied { t.copied } else { t.copy_invitation };
                        if ui.add(kit::compact_button(label)).clicked() {
                            ui.output_mut(|o| {
                                o.copied_text =
                                    miasma_core::transfer::invitation_text(&share_id, t.invite_lang)
                            });
                            self.copied = Some((p.clone(), Instant::now()));
                        }
                    }
                }
            });
        }
        ui.add_space(kit::SP_2);
        let mut nav = None;
        let mut close = false;
        kit::button_row(ui, |ui| {
            let (label, dest) = match self.route {
                Route::Contact => (k.show_in_contacts, FlowNav::Contacts),
                Route::Code => (k.show_in_files, FlowNav::Files),
            };
            if kit::primary(ui, true, label).clicked() {
                nav = Some(dest);
            }
            if ui.add(kit::secondary_button(k.send_more)).clicked() {
                self.send_more();
            }
            if ui.add(kit::secondary_button(k.close)).clicked() {
                close = true;
            }
        });
        (nav, close)
    }
}

// ─── Dropping files on the window ───────────────────────────────────────────

/// What the window was given this frame: whether files are being dragged over it, the paths that
/// were dropped, and where the pointer is.
pub struct DropInput {
    pub hovering: bool,
    pub paths: Vec<PathBuf>,
    pub pos: Option<egui::Pos2>,
}

pub fn read_drops(ctx: &egui::Context) -> DropInput {
    ctx.input(|i| DropInput {
        hovering: !i.raw.hovered_files.is_empty(),
        paths: i
            .raw
            .dropped_files
            .iter()
            .filter_map(|f| f.path.clone())
            .collect(),
        pos: i.pointer.hover_pos().or(i.pointer.latest_pos()),
    })
}

/// While files are dragged over the window: a veil over everything with "Drop files to send".
pub fn paint_drop_overlay(ctx: &egui::Context, text: &str) {
    let p = pal();
    let screen = ctx.screen_rect();
    egui::Area::new(egui::Id::new("send_drop_overlay"))
        .order(egui::Order::Foreground)
        .fixed_pos(screen.min)
        .interactable(false)
        .show(ctx, |ui| {
            let painter = ui.painter();
            painter.rect_filled(screen, 0.0, p.bg.gamma_multiply(0.86));
            let inner = screen.shrink(kit::SP_4);
            painter.rect_stroke(inner, 12.0, egui::Stroke::new(2.0, p.accent));
            painter.text(
                screen.center(),
                egui::Align2::CENTER_CENTER,
                text,
                egui::FontId::proportional(20.0),
                p.accent,
            );
        });
}

// ─── Dev-only screenshot fixtures ───────────────────────────────────────────

/// Fixture names for the `ui-tour` screenshots.
#[cfg(any(test, feature = "ui-tour"))]
pub const FIXTURES: &[&str] = &["empty", "contact", "code", "sent", "codesent"];

#[cfg(any(test, feature = "ui-tour"))]
impl SendFlow {
    /// A flow in a state worth looking at. `contacts` are the ones of `ContactsUi::fixture("two")`
    /// (ids a and b); the result of "sent" reads the rows of `ContactsUi::fixture("active")`.
    pub fn fixture(name: &str, contacts: &[ContactInfo]) -> Option<Self> {
        let mut f = SendFlow::default();
        let docs = |n: &str| PathBuf::from(format!("/Users/owner/Documents/{n}"));
        match name {
            "empty" => f.open_empty(contacts),
            "contact" => {
                f.open_for_contact("a");
                f.add_files(vec![
                    docs("thesis-final.pdf"),
                    docs("meeting-notes.txt"),
                    docs("photos-2025.zip"),
                ]);
            }
            "code" => {
                f.open_empty(contacts);
                f.recipient = Recipient::Code;
                f.add_files(vec![docs("contract-scan.pdf")]);
                f.more_open = true;
            }
            "sent" => {
                f.open_for_contact("b");
                f.add_files(vec![
                    docs("ミーティング資料_最終版_修正反映済み_営業部確認用_v12.pdf"),
                    docs("memo.txt"),
                ]);
                f.phase = Phase::Result;
                f.route = Route::Contact;
                f.result_contact = Some(("b".into(), "山田".into()));
                f.result_files = f.files.clone();
            }
            "codesent" => {
                f.open_empty(contacts);
                f.recipient = Recipient::Code;
                f.add_files(vec![
                    PathBuf::from("/Users/owner/Movies/wedding-4K.mov"),
                    docs("thesis-final.pdf"),
                ]);
                f.phase = Phase::Result;
                f.route = Route::Code;
                f.result_files = f.files.clone();
                f.started.insert(
                    f.files[0].clone(),
                    miasma_core::transfer::jobs::send_id(&f.files[0]),
                );
            }
            _ => return None,
        }
        Some(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(id: &str, label: &str, send: bool) -> ContactInfo {
        ContactInfo {
            id: id.into(),
            label: label.into(),
            endpoint_id: "e".repeat(64),
            fingerprint: "AAAAA-BBBBB-CCCCC-DDDDD".into(),
            added_at: 0,
            allow_send: send,
            allow_receive: true,
            max_file_size: None,
            default_max_file_size: 1 << 30,
            inbox_dir: String::new(),
        }
    }

    fn two() -> Vec<ContactInfo> {
        vec![contact("a", "Alice", true), contact("b", "Bob", false)]
    }

    /// A real file, so the "is it a folder" check has something to look at.
    fn file(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, b"x").unwrap();
        p
    }

    /// A password of the right shape, made here so no fixed secret sits in the source.
    fn good_password() -> String {
        password_policy::generate(password_policy::GENERATE_DEFAULT_LEN)
            .as_str()
            .to_owned()
    }

    #[test]
    fn a_closed_flow_is_not_open_and_opening_needs_no_files() {
        let mut f = SendFlow::default();
        assert!(!f.is_open());
        f.open_empty(&two());
        assert!(f.is_open());
        assert!(f.files().is_empty());
        assert_eq!(f.recipient(), &Recipient::None);
    }

    #[test]
    fn with_no_one_to_send_to_the_invitation_code_is_preselected() {
        let mut f = SendFlow::default();
        f.open_empty(&[]);
        assert_eq!(f.recipient(), &Recipient::Code);
        // A contact that may not be sent to does not count.
        f.open_empty(&[contact("b", "Bob", false)]);
        assert_eq!(f.recipient(), &Recipient::Code);
        f.open_empty(&two());
        assert_eq!(f.recipient(), &Recipient::None);
    }

    #[test]
    fn a_recipient_is_required() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = SendFlow::default();
        f.open_empty(&two());
        f.add_files(vec![file(&dir, "a.txt")]);
        assert_eq!(f.blocker(true, &two()), Some(Blocker::Recipient));
        assert_eq!(f.plan(true, &two()), Err(Blocker::Recipient));
        f.recipient = Recipient::Contact("a".into());
        assert_eq!(f.blocker(true, &two()), None);
    }

    #[test]
    fn an_empty_file_list_is_blocked() {
        let mut f = SendFlow::default();
        f.open_for_contact("a");
        assert_eq!(f.blocker(true, &two()), Some(Blocker::Files));
        assert_eq!(f.plan(true, &two()), Err(Blocker::Files));
        // Also for the invitation code.
        f.open_empty(&[]);
        assert_eq!(f.blocker(true, &[]), Some(Blocker::Files));
    }

    #[test]
    fn nothing_is_sent_while_the_service_is_not_connected() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = SendFlow::default();
        f.open_for_contact("a");
        f.add_files(vec![file(&dir, "a.txt")]);
        assert_eq!(f.blocker(false, &two()), Some(Blocker::Offline));
    }

    #[test]
    fn starting_from_a_contact_prefills_it() {
        let mut f = SendFlow::default();
        f.open_for_contact("a");
        assert!(f.is_open());
        assert_eq!(f.recipient(), &Recipient::Contact("a".into()));
        // Opening again for someone else replaces it, and clears the files.
        let dir = tempfile::tempdir().unwrap();
        f.add_files(vec![file(&dir, "a.txt")]);
        f.open_for_contact("b");
        assert_eq!(f.recipient(), &Recipient::Contact("b".into()));
        assert!(f.files().is_empty());
    }

    #[test]
    fn a_contact_who_may_not_be_sent_to_blocks_with_their_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = SendFlow::default();
        f.open_for_contact("b");
        f.add_files(vec![file(&dir, "a.txt")]);
        assert_eq!(
            f.blocker(true, &two()),
            Some(Blocker::ContactOff("Bob".into()))
        );
        // A contact that is gone is the same as none chosen.
        f.open_for_contact("zz");
        f.add_files(vec![file(&dir, "a.txt")]);
        assert_eq!(f.blocker(true, &two()), Some(Blocker::Recipient));
    }

    #[test]
    fn several_files_queue_without_duplicates_and_can_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (file(&dir, "a.txt"), file(&dir, "b.txt"));
        let mut f = SendFlow::default();
        f.open_for_contact("a");
        assert_eq!(f.add_files(vec![a.clone(), b.clone()]), 2);
        assert_eq!(f.add_files(vec![a.clone()]), 0, "the same file twice");
        assert_eq!(f.files(), &[a.clone(), b.clone()]);
        f.remove_file(0);
        assert_eq!(f.files(), &[b]);
        f.remove_file(9);
        assert_eq!(f.files().len(), 1);
    }

    #[test]
    fn a_folder_is_left_out_and_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let a = file(&dir, "a.txt");
        let mut f = SendFlow::default();
        f.open_for_contact("a");
        assert_eq!(f.add_files(vec![sub, a.clone()]), 1);
        assert_eq!(f.files(), &[a]);
        assert!(f.folder_refused);
        // Only a folder: nothing to send.
        f.open_for_contact("a");
        assert_eq!(f.add_files(vec![dir.path().join("sub")]), 0);
        assert_eq!(f.blocker(true, &two()), Some(Blocker::Files));
    }

    #[test]
    fn a_password_that_does_not_match_blocks_the_invitation_route() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = SendFlow::default();
        f.open_empty(&[]);
        f.add_files(vec![file(&dir, "a.txt")]);
        assert_eq!(f.blocker(true, &[]), None, "no password is allowed");
        f.password = good_password();
        assert_eq!(f.blocker(true, &[]), Some(Blocker::Mismatch));
        f.confirm = f.password.clone();
        assert_eq!(f.blocker(true, &[]), None);
        // The rules of the daemon: too short a password is refused here too.
        f.password = f.password.chars().take(2).collect();
        f.confirm = f.password.clone();
        assert_eq!(f.blocker(true, &[]), Some(Blocker::WeakPassword));
    }

    #[test]
    fn a_contact_route_ignores_the_password_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = SendFlow::default();
        f.open_for_contact("a");
        f.add_files(vec![file(&dir, "a.txt")]);
        f.password = good_password();
        f.confirm = good_password();
        assert_ne!(f.password, f.confirm);
        assert_eq!(f.blocker(true, &two()), None);
        match f.plan(true, &two()) {
            Ok(Plan::Contact { id, paths }) => {
                assert_eq!(id, "a");
                assert_eq!(paths.len(), 1);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_invitation_route_hands_files_to_the_worker_one_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (file(&dir, "a.txt"), file(&dir, "b.txt"));
        let mut f = SendFlow::default();
        f.open_empty(&[]);
        f.add_files(vec![a.clone(), b.clone()]);
        let pw = good_password();
        f.password = pw.clone();
        f.confirm = pw.clone();
        let mut contacts = ContactsUi::default();
        let ct = crate::locale::contact_strings(crate::locale::Locale::En);
        assert!(matches!(f.start(true, &mut contacts, ct), Ok(None)));
        assert!(
            f.password.is_empty() && f.confirm.is_empty(),
            "wiped at once"
        );
        assert!(f.is_busy());

        let first = f.next_command().expect("the first file is due");
        assert!(first.protected);
        match first.cmd {
            WorkerCmd::TransferStartPublish {
                file_path,
                password,
                restart,
                ..
            } => {
                assert_eq!(file_path, a);
                assert_eq!(password.as_deref(), Some(pw.as_str()));
                assert!(!restart);
            }
            _ => panic!("not a publish"),
        }
        // The second waits for the answer to the first.
        assert!(f.next_command().is_none());
        f.on_started("id-a".into());
        let second = f.next_command().expect("the second file is due");
        assert!(second.protected);
        f.on_failed("refused".into());
        assert!(f.next_command().is_none());
        assert!(!f.is_busy());
        assert_eq!(f.started.get(&a).map(String::as_str), Some("id-a"));
        assert_eq!(f.failed.get(&b).map(String::as_str), Some("refused"));
        assert!(f.in_flight.is_none() && f.queue.is_empty());
    }

    #[test]
    fn a_second_send_does_not_change_the_password_of_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (file(&dir, "a.txt"), file(&dir, "b.txt"));
        let mut contacts = ContactsUi::default();
        let ct = crate::locale::contact_strings(crate::locale::Locale::En);
        let mut f = SendFlow::default();
        f.open_empty(&[]);
        f.add_files(vec![a.clone()]);
        let pw = good_password();
        f.password = pw.clone();
        f.confirm = pw.clone();
        f.start(true, &mut contacts, ct).unwrap();
        // Before the worker took it, another send is opened, without a password.
        f.open_empty(&[]);
        f.add_files(vec![b.clone()]);
        f.start(true, &mut contacts, ct).unwrap();
        let first = f.next_command().unwrap();
        assert!(first.protected);
        match first.cmd {
            WorkerCmd::TransferStartPublish {
                file_path,
                password,
                ..
            } => {
                assert_eq!(file_path, a);
                assert_eq!(password.as_deref(), Some(pw.as_str()));
            }
            _ => panic!("not a publish"),
        }
        f.on_started("one".into());
        let second = f.next_command().unwrap();
        assert!(!second.protected);
    }

    #[test]
    fn a_command_the_channel_did_not_take_goes_back_to_the_front() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (file(&dir, "a.txt"), file(&dir, "b.txt"));
        let mut f = SendFlow::default();
        f.open_empty(&[]);
        f.add_files(vec![a.clone(), b]);
        let mut contacts = ContactsUi::default();
        let ct = crate::locale::contact_strings(crate::locale::Locale::En);
        f.start(true, &mut contacts, ct).unwrap();
        let first = f.next_command().unwrap();
        assert!(!first.protected);
        f.put_back();
        match f.next_command().unwrap().cmd {
            WorkerCmd::TransferStartPublish { file_path, .. } => assert_eq!(file_path, a),
            _ => panic!("not a publish"),
        }
    }

    #[test]
    fn an_answer_with_nothing_in_flight_is_ignored() {
        let mut f = SendFlow::default();
        assert!(!f.on_started("x".into()));
        assert!(!f.on_failed("y".into()));
        assert!(f.started.is_empty() && f.failed.is_empty());
    }

    #[test]
    fn dropping_files_opens_the_flow_with_them() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (file(&dir, "a.txt"), file(&dir, "b.txt"));
        let mut f = SendFlow::default();
        f.open_with_files(vec![a.clone()], None, &two());
        assert!(f.is_open());
        assert_eq!(f.files(), &[a.clone()]);
        assert_eq!(f.recipient(), &Recipient::None);
        // A second drop while it is open adds to the list and keeps what was chosen.
        f.recipient = Recipient::Code;
        f.open_with_files(vec![b.clone(), a.clone()], Some("a".into()), &two());
        assert_eq!(f.files(), &[a, b]);
        assert_eq!(f.recipient(), &Recipient::Code);
    }

    #[test]
    fn a_drop_on_a_contact_prefills_that_contact() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = SendFlow::default();
        f.open_with_files(vec![file(&dir, "a.txt")], Some("a".into()), &two());
        assert_eq!(f.recipient(), &Recipient::Contact("a".into()));
        // Open but nobody chosen: the drop's contact fills the gap.
        let mut g = SendFlow::default();
        g.open_empty(&two());
        g.open_with_files(vec![file(&dir, "b.txt")], Some("a".into()), &two());
        assert_eq!(g.recipient(), &Recipient::Contact("a".into()));
    }

    #[test]
    fn a_drop_after_a_send_starts_a_new_form() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = SendFlow::default();
        f.open_for_contact("a");
        f.add_files(vec![file(&dir, "a.txt")]);
        let mut contacts = ContactsUi::default();
        let ct = crate::locale::contact_strings(crate::locale::Locale::En);
        // No such contact in this (empty) list: the plan is refused, nothing moves on.
        assert!(f.start(true, &mut contacts, ct).is_err());
        assert_eq!(f.phase, Phase::Form);
        f.phase = Phase::Result;
        f.open_with_files(vec![file(&dir, "b.txt")], None, &two());
        assert_eq!(f.phase, Phase::Form);
        assert_eq!(f.files().len(), 1);
    }

    #[test]
    fn send_more_keeps_the_recipient_and_drops_the_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = SendFlow::default();
        f.open_for_contact("a");
        f.add_files(vec![file(&dir, "a.txt")]);
        f.phase = Phase::Result;
        f.send_more();
        assert_eq!(f.phase, Phase::Form);
        assert_eq!(f.recipient(), &Recipient::Contact("a".into()));
        assert!(f.files().is_empty());
    }

    #[test]
    fn closing_wipes_the_password_fields() {
        let mut f = SendFlow::default();
        f.open_empty(&[]);
        f.generate_password();
        assert!(!f.password.is_empty());
        assert_eq!(f.password, f.confirm);
        assert_eq!(f.generated.as_deref(), Some(f.password.as_str()));
        f.close();
        assert!(!f.is_open());
        assert!(f.password.is_empty() && f.confirm.is_empty() && f.generated.is_none());
    }

    #[test]
    fn statuses_read_in_every_language() {
        for lang in crate::locale::Locale::ALL {
            let k = crate::locale::compose_strings(lang);
            let (waiting, _) = file_status_text(k, &FileStatus::Waiting);
            let (sending, _) = file_status_text(k, &FileStatus::Sending { percent: 37 });
            let (done, _) = file_status_text(k, &FileStatus::Done);
            let (failed, level) = file_status_text(
                k,
                &FileStatus::Failed {
                    reason: "no route".into(),
                },
            );
            assert!(sending.contains("37%"));
            assert!(failed.contains("no route"));
            assert_eq!(level, Level::Error);
            assert_ne!(waiting, done);
        }
    }

    /// The dialog fits a 700 px window, in every state and every language, and draws without
    /// panicking (default fonts: this checks the box, not the look).
    #[test]
    fn every_fixture_draws_inside_a_narrow_window() {
        for lang in crate::locale::Locale::ALL {
            let k = crate::locale::compose_strings(lang);
            let t = crate::locale::transfer_strings(lang);
            let ct = crate::locale::contact_strings(lang);
            for name in FIXTURES {
                let mut contacts = ContactsUi::fixture("active", ct).unwrap();
                let list = contacts.contact_list().to_vec();
                let mut flow = SendFlow::fixture(name, &list).unwrap();
                let transfers = crate::transfers::TransfersUi::default();
                let ctx = egui::Context::default();
                let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(700.0, 900.0));
                for _ in 0..3 {
                    let input = egui::RawInput {
                        screen_rect: Some(screen),
                        ..Default::default()
                    };
                    let _ = ctx.run(input, |ctx| {
                        flow.show(ctx, k, t, ct, &mut contacts, &transfers, true);
                    });
                }
                let used = ctx.used_rect();
                assert!(
                    used.right() <= 700.5 && used.bottom() <= 900.5,
                    "{lang:?} {name}: {used:?}"
                );
            }
        }
    }
}
