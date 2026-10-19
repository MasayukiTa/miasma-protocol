//! Group conversations in the Chat area: the rows in the conversation list, the "New group" form,
//! the conversation view (sender above each incoming message, the unverified-member badge, how
//! far each of my messages got), the group information panel and the confirmations.
//!
//! Like `chat_ui.rs` this file never touches the network or the disk: every request is queued in
//! `out` and goes to the background service through `WorkerCmd::Chat(ChatRequest::Group(..))`
//! (the chat screen drains it). The decisions are in `group.rs`.
//!
//! Group rules the screen follows: being added to a group never makes anyone a contact (a member
//! who is not a contact is marked as unverified, and "Add as contact" only opens the ordinary
//! add-contact form with the code filled in and permissions off); there are no read receipts; the
//! history is kept by the service; the creator and admins add and remove members.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use eframe::egui::{self, vec2, Align, Layout, RichText, Sense, Stroke};
use miasma_core::chat::group::ipc::{
    GroupDetailInfo, GroupMessageInfo, GroupRequest, GroupResponse,
};
use miasma_core::chat::{ChatRequest, ChatResponse};
use miasma_core::push::ContactInfo;

use crate::chat::{
    cap_text, composer_cap, counter, counter_text, elide, prepare_send, when_list, when_message,
    Clock, CounterLevel, SendBlock, MAX_PREVIEWS,
};
use crate::chat_ui::ChatAction;
use crate::group::*;
use crate::locale::{chat_strings, group_strings, ChatStrings, GroupStrings, Locale};
use crate::theme::{self, Palette};
use crate::transfers::fill;
use crate::ui_kit::{self as kit, Level};
use crate::ux::{confirm, Answer};
use crate::worker::ChatFail;

fn pal() -> Palette {
    theme::palette()
}

const LIST_OPEN: Duration = Duration::from_secs(3);
const LIST_CLOSED: Duration = Duration::from_secs(10);
const HISTORY_EVERY: Duration = Duration::from_secs(2);
const HISTORY_BUSY: Duration = Duration::from_secs(1);
const DETAIL_EVERY: Duration = Duration::from_secs(10);
/// A service that does not do groups is asked again this rarely.
const RETRY_UNSUPPORTED: Duration = Duration::from_secs(30);
/// An answer that has not come back after this long is asked for again.
const STALE: Duration = Duration::from_secs(20);
/// Height of a row of the conversation list (the same as a one-to-one row).
const ROW_H: f32 = 62.0;
/// Room kept under the message list for the composer and its hints.
const COMPOSER_RESERVE: f32 = 190.0;
/// Drafts remembered while another group is open.
const MAX_DRAFTS: usize = 20;

fn stale(t: Option<Instant>) -> Option<Instant> {
    t.filter(|t| t.elapsed() <= STALE)
}

/// Whether the background service does groups, as far as the last answers say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Support {
    Unknown,
    Yes,
    /// An older service, or one that runs without group chat. Asked again now and then; the
    /// rest of the Chat area is not affected.
    No,
}

#[derive(Debug, Clone)]
struct Open {
    id: String,
    name: String,
}

/// What a confirmation dialog is about.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Confirm {
    Leave,
    DeleteHistory,
    Remove { endpoint_id: String, who: String },
}

/// The one action waiting for the service's answer; its words are used when the answer is "done".
#[derive(Debug, Clone, PartialEq, Eq)]
enum Acting {
    Leave { name: String },
    Delete { name: String },
    Remove { who: String, name: String },
    Add { name: String },
    Accept { name: String },
    Decline { name: String },
}

#[derive(Debug, Clone)]
struct Preview {
    key: (u64, u64, GroupStatus),
    last: GroupLast,
}

pub struct GroupUi {
    locale: Locale,
    support: Support,
    area_open: bool,

    rows: Vec<GroupRow>,
    loaded: bool,
    unread: GroupUnread,
    previews: HashMap<String, Preview>,
    preview_inflight: HashSet<String>,

    open: Option<Open>,
    detail: Option<GroupDetailInfo>,
    messages: Vec<GroupMessageInfo>,
    thread_loaded: bool,
    limit: u32,
    info_open: bool,

    composer: String,
    drafts: HashMap<String, String>,
    focus_composer: bool,
    ime_composing: bool,

    form: Option<NewGroupForm>,
    form_msg: Option<String>,
    focus_form: bool,
    creating: bool,
    add: Option<Picks>,
    add_msg: Option<String>,
    confirm: Option<Confirm>,
    acting: Option<Acting>,
    page_msg: Option<String>,
    notices: Vec<String>,
    action: Option<ChatAction>,

    out: VecDeque<ChatRequest>,
    sends_in_flight: u32,
    list_inflight: Option<Instant>,
    history_inflight: Option<Instant>,
    detail_inflight: Option<Instant>,
    last_list: Instant,
    last_history: Instant,
    last_detail: Instant,
    list_dirty: bool,
    thread_dirty: bool,
    detail_dirty: bool,
}

impl Default for GroupUi {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            locale: Locale::default(),
            support: Support::Unknown,
            area_open: false,
            rows: Vec::new(),
            loaded: false,
            unread: GroupUnread::default(),
            previews: HashMap::new(),
            preview_inflight: HashSet::new(),
            open: None,
            detail: None,
            messages: Vec::new(),
            thread_loaded: false,
            limit: PAGE,
            info_open: false,
            composer: String::new(),
            drafts: HashMap::new(),
            focus_composer: false,
            ime_composing: false,
            form: None,
            form_msg: None,
            focus_form: false,
            creating: false,
            add: None,
            add_msg: None,
            confirm: None,
            acting: None,
            page_msg: None,
            notices: Vec::new(),
            action: None,
            out: VecDeque::new(),
            sends_in_flight: 0,
            list_inflight: None,
            history_inflight: None,
            detail_inflight: None,
            last_list: now,
            last_history: now,
            last_detail: now,
            list_dirty: false,
            thread_dirty: false,
            detail_dirty: false,
        }
    }
}

impl GroupUi {
    fn gs(&self) -> &'static GroupStrings {
        group_strings(self.locale)
    }

    fn cs(&self) -> &'static ChatStrings {
        chat_strings(self.locale)
    }

    fn push(&mut self, r: GroupRequest) {
        self.out.push_back(ChatRequest::Group(r));
    }

    // ─── Seen from the chat screen ──────────────────────────────────────────

    pub fn set_locale(&mut self, locale: Locale) {
        self.locale = locale;
    }

    pub fn rows(&self) -> &[GroupRow] {
        &self.rows
    }

    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// The groups can be created (the service does groups).
    pub fn can_create(&self) -> bool {
        self.support != Support::No
    }

    pub fn unseen(&self) -> u32 {
        self.unread.unseen()
    }

    pub fn mark_seen(&mut self) {
        self.unread.mark_seen();
    }

    pub fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
    }

    /// Hand queued requests to the worker; stops at the first one the channel does not take.
    pub fn drain(&mut self, try_send: &mut impl FnMut(ChatRequest) -> bool) {
        while let Some(req) = self.out.front().cloned() {
            if try_send(req) {
                self.out.pop_front();
            } else {
                break;
            }
        }
    }

    /// The Chat area was opened: the list of groups is due at once.
    pub fn on_area_opened(&mut self) {
        self.list_dirty = true;
    }

    /// The connection came back: read everything again.
    pub fn on_reconnect(&mut self) {
        self.support = Support::Unknown;
        self.list_inflight = None;
        self.history_inflight = None;
        self.detail_inflight = None;
        self.preview_inflight.clear();
        self.list_dirty = true;
    }

    /// The tab was left: let go of the messages (they are read again when the tab comes back).
    pub fn on_area_closed(&mut self) {
        self.messages.clear();
        self.thread_loaded = false;
        self.previews.clear();
        self.preview_inflight.clear();
        self.page_msg = None;
        self.form = None;
        self.add = None;
        self.confirm = None;
    }

    pub fn open_index(&mut self, index: usize) {
        if let Some(r) = self.rows.get(index).cloned() {
            self.open_group(&r.id, &r.name);
        }
    }

    pub fn open_new_group(&mut self) {
        self.form = Some(NewGroupForm::default());
        self.form_msg = None;
        self.creating = false;
        self.focus_form = true;
    }

    fn open_group(&mut self, id: &str, name: &str) {
        self.stash_draft();
        let messages = self
            .rows
            .iter()
            .find(|r| r.id == id)
            .map_or(0, |r| r.messages);
        self.unread.open(id, messages);
        self.open = Some(Open {
            id: id.to_owned(),
            name: name.to_owned(),
        });
        self.messages.clear();
        self.detail = None;
        self.thread_loaded = false;
        self.limit = PAGE;
        self.info_open = false;
        self.composer = self.drafts.remove(id).unwrap_or_default();
        self.focus_composer = true;
        self.page_msg = None;
        self.add = None;
        self.add_msg = None;
        self.confirm = None;
        self.history_inflight = None;
        self.detail_inflight = None;
        self.thread_dirty = true;
        self.detail_dirty = true;
    }

    fn close(&mut self) {
        self.stash_draft();
        self.open = None;
        self.messages.clear();
        self.detail = None;
        self.thread_loaded = false;
        self.info_open = false;
        self.add = None;
        self.confirm = None;
        self.page_msg = None;
        self.list_dirty = true;
    }

    /// Keep what was typed for the group being left (a few of them, in memory only).
    fn stash_draft(&mut self) {
        let Some(o) = &self.open else {
            return;
        };
        let id = o.id.clone();
        if self.composer.trim().is_empty() {
            self.drafts.remove(&id);
        } else {
            if self.drafts.len() >= MAX_DRAFTS && !self.drafts.contains_key(&id) {
                self.drafts.clear();
            }
            let text = std::mem::take(&mut self.composer);
            self.drafts.insert(id, text);
        }
        self.composer.clear();
    }

    fn open_row(&self) -> Option<&GroupRow> {
        let o = self.open.as_ref()?;
        self.rows.iter().find(|r| r.id == o.id)
    }

    /// My status in the open group.
    fn status(&self) -> GroupStatus {
        if let Some(r) = self.open_row() {
            return r.status;
        }
        self.detail
            .as_ref()
            .map_or(GroupStatus::Other, |d| GroupStatus::parse(&d.group.status))
    }

    fn open_name(&self) -> String {
        match (self.open_row(), &self.open) {
            (Some(r), _) => r.name.clone(),
            (None, Some(o)) => o.name.clone(),
            _ => String::new(),
        }
    }

    // ─── Asking ─────────────────────────────────────────────────────────────

    /// Ask for more data when it is due. Cheap: the list of groups every 3 s while the Chat area
    /// is open (every 10 s otherwise, so arrivals are counted); the open group's messages every
    /// 2 s (every second while something is on its way) and its members every 10 s.
    pub fn tick(&mut self, area_open: bool) {
        self.area_open = area_open;
        let now = Instant::now();
        self.list_inflight = stale(self.list_inflight);
        self.history_inflight = stale(self.history_inflight);
        self.detail_inflight = stale(self.detail_inflight);
        let since_list = now.duration_since(self.last_list);
        if self.support == Support::No {
            if self.list_inflight.is_none() && since_list >= RETRY_UNSUPPORTED {
                self.ask_list(now);
            }
            return;
        }
        let every = if area_open { LIST_OPEN } else { LIST_CLOSED };
        if self.list_inflight.is_none() && (self.list_dirty || since_list >= every) {
            self.ask_list(now);
        }
        if !area_open || self.support != Support::Yes {
            return;
        }
        let Some(o) = self.open.clone() else {
            return;
        };
        let status = self.status();
        if status != GroupStatus::Invited && self.history_inflight.is_none() {
            let busy = self.sends_in_flight > 0
                || self.messages.iter().any(|m| {
                    matches!(
                        delivery_of(m),
                        GroupDelivery::Waiting { .. } | GroupDelivery::Partial { .. }
                    )
                });
            let every = if busy { HISTORY_BUSY } else { HISTORY_EVERY };
            if !self.thread_loaded
                || self.thread_dirty
                || now.duration_since(self.last_history) >= every
            {
                self.thread_dirty = false;
                self.last_history = now;
                self.history_inflight = Some(now);
                let limit = self.limit;
                self.push(GroupRequest::History {
                    group: o.id.clone(),
                    before: None,
                    limit: Some(limit),
                });
            }
        }
        if self.detail_inflight.is_none()
            && (self.detail.is_none()
                || self.detail_dirty
                || now.duration_since(self.last_detail) >= DETAIL_EVERY)
        {
            self.detail_dirty = false;
            self.last_detail = now;
            self.detail_inflight = Some(now);
            self.push(GroupRequest::Show { group: o.id });
        }
    }

    fn ask_list(&mut self, now: Instant) {
        self.list_dirty = false;
        self.last_list = now;
        self.list_inflight = Some(now);
        self.push(GroupRequest::List {});
    }

    // ─── Answers ────────────────────────────────────────────────────────────

    /// Process the service's answer to a group request made by this screen.
    pub fn on_reply(&mut self, req: &GroupRequest, reply: Result<ChatResponse, ChatFail>) {
        match req {
            GroupRequest::List {} => self.list_inflight = None,
            GroupRequest::History {
                group,
                limit: Some(1),
                ..
            } => {
                self.preview_inflight.remove(group);
            }
            GroupRequest::History { .. } => self.history_inflight = None,
            GroupRequest::Show { .. } => self.detail_inflight = None,
            _ => {}
        }
        match reply {
            Ok(ChatResponse::Group(resp)) => self.on_group(req, resp),
            Ok(ChatResponse::Error { kind, .. }) => self.on_error(req, &kind),
            Ok(_) => {}
            Err(ChatFail::NotSupported) => {
                if matches!(req, GroupRequest::List {}) {
                    self.support = Support::No;
                } else {
                    self.fail(req, self.cs().err_other.to_owned());
                }
            }
            Err(_) => {
                let why = self.cs().err_other.to_owned();
                self.fail(req, why);
            }
        }
    }

    fn on_error(&mut self, req: &GroupRequest, kind: &str) {
        if kind == "unavailable" {
            self.support = Support::No;
        }
        let why = error_text(self.gs(), self.cs(), kind);
        let gone = kind == "unknown_group"
            && self
                .open
                .as_ref()
                .is_some_and(|o| group_of(req) == Some(o.id.as_str()));
        self.fail(req, why);
        if gone {
            self.close();
        }
    }

    /// A request got an error or no answer. Reads are silent (they are asked again); an action
    /// says what went wrong and gives back what it took (a message's text).
    fn fail(&mut self, req: &GroupRequest, why: String) {
        match req {
            GroupRequest::Send { text, .. } => {
                self.sends_in_flight = self.sends_in_flight.saturating_sub(1);
                if self.composer.trim().is_empty() {
                    self.composer = text.clone();
                }
                self.page_msg = Some(why);
            }
            GroupRequest::Create { .. } => {
                self.creating = false;
                self.form_msg = Some(why);
            }
            GroupRequest::Add { .. } => {
                self.acting = None;
                self.add_msg = Some(why);
            }
            GroupRequest::Remove { .. }
            | GroupRequest::Leave { .. }
            | GroupRequest::Accept { .. }
            | GroupRequest::Decline { .. } => {
                self.acting = None;
                self.page_msg = Some(why);
            }
            GroupRequest::List {}
            | GroupRequest::History { .. }
            | GroupRequest::Show { .. }
            | GroupRequest::Settings { .. } => {}
        }
    }

    fn is_open_id(&self, id: &str) -> bool {
        self.open.as_ref().is_some_and(|o| o.id == id)
    }

    fn on_group(&mut self, req: &GroupRequest, resp: GroupResponse) {
        match resp {
            GroupResponse::Error { kind, .. } => self.on_error(req, &kind),
            GroupResponse::Groups(list) => {
                self.support = Support::Yes;
                let known: HashSet<String> = invitations(&self.rows)
                    .iter()
                    .map(|r| r.id.clone())
                    .collect();
                self.rows = group_rows(&list);
                self.loaded = true;
                // A new invitation waiting for an answer is announced once.
                for r in invitations(&self.rows) {
                    if !known.contains(&r.id) {
                        let gs = self.gs();
                        self.notices.push(fill(
                            gs.invite_toast,
                            &[("name", &elide(&r.name, NAME_CHARS))],
                        ));
                    }
                }
                let viewing = self.open.as_ref().map(|o| o.id.clone());
                self.unread
                    .on_list(&self.rows, viewing.as_deref(), self.area_open);
                let keep: HashSet<&str> = self.rows.iter().map(|r| r.id.as_str()).collect();
                self.previews.retain(|k, _| keep.contains(k.as_str()));
                if let Some(id) = viewing {
                    if !keep.contains(id.as_str()) {
                        self.close();
                    } else if let Some(r) = self.rows.iter().find(|r| r.id == id) {
                        // The members or my own status changed: read the member list again.
                        let changed = self.detail.as_ref().is_some_and(|d| {
                            d.group.members != r.members
                                || GroupStatus::parse(&d.group.status) != r.status
                        });
                        if changed {
                            self.detail_dirty = true;
                            self.thread_dirty = true;
                        }
                    }
                }
                self.ask_previews();
            }
            GroupResponse::Detail(d) => {
                if self.is_open_id(&d.group.id) {
                    self.detail = Some(d);
                }
            }
            GroupResponse::History { group, messages } => {
                let row = GroupRow::from(&group);
                if matches!(req, GroupRequest::History { limit: Some(1), .. }) {
                    let key = (row.messages, row.last_ms, row.status);
                    let last = last_of(self.gs(), &messages);
                    self.previews.insert(row.id.clone(), Preview { key, last });
                } else if self.is_open_id(&row.id) {
                    if self.area_open {
                        self.unread.open(&row.id, row.messages);
                    }
                    self.messages = messages;
                    self.thread_loaded = true;
                    if let Some(slot) = self.rows.iter_mut().find(|r| r.id == row.id) {
                        *slot = row;
                    }
                }
            }
            GroupResponse::Created { id, .. } => {
                let name = self
                    .form
                    .as_ref()
                    .map(|f| f.name.trim().to_owned())
                    .unwrap_or_default();
                self.form = None;
                self.creating = false;
                self.form_msg = None;
                self.notices.push(fill(
                    self.gs().ng_created,
                    &[("name", &elide(&name, NAME_CHARS))],
                ));
                self.list_dirty = true;
                self.open_group(&id, &name);
            }
            GroupResponse::Queued { .. } => {
                self.sends_in_flight = self.sends_in_flight.saturating_sub(1);
                self.thread_dirty = true;
                self.list_dirty = true;
            }
            GroupResponse::Done {} => self.on_done(),
            // The change was made in the service; the saved setting is the screen's own.
            GroupResponse::Settings { .. } => {}
        }
    }

    fn on_done(&mut self) {
        let gs = self.gs();
        let said = |s: &str, name: &str| fill(s, &[("name", &elide(name, NAME_CHARS))]);
        self.list_dirty = true;
        self.detail_dirty = true;
        self.thread_dirty = true;
        match self.acting.take() {
            Some(Acting::Leave { name }) => self.notices.push(said(gs.left_done, &name)),
            Some(Acting::Accept { name }) => self.notices.push(said(gs.accepted_done, &name)),
            Some(Acting::Add { name }) => {
                self.add = None;
                self.add_msg = None;
                self.notices.push(said(gs.added_done, &name));
            }
            Some(Acting::Remove { who, name }) => self.notices.push(fill(
                gs.removed_done,
                &[
                    ("who", &elide(&who, NAME_CHARS)),
                    ("name", &elide(&name, NAME_CHARS)),
                ],
            )),
            Some(Acting::Delete { name }) => {
                self.notices.push(said(gs.deleted_done, &name));
                self.close();
            }
            Some(Acting::Decline { name }) => {
                self.notices.push(said(gs.declined_done, &name));
                self.close();
            }
            None => {}
        }
    }

    /// The last message of each group that changed (the first screenful only).
    fn ask_previews(&mut self) {
        let mut wanted = Vec::new();
        for r in self.rows.iter().take(MAX_PREVIEWS) {
            if r.messages == 0 || r.status == GroupStatus::Invited {
                continue;
            }
            let fresh = self
                .previews
                .get(&r.id)
                .is_some_and(|p| p.key == (r.messages, r.last_ms, r.status));
            if !fresh && !self.preview_inflight.contains(&r.id) {
                wanted.push(r.id.clone());
            }
        }
        if !self.area_open {
            return;
        }
        for id in wanted {
            self.preview_inflight.insert(id.clone());
            self.push(GroupRequest::History {
                group: id,
                before: None,
                limit: Some(1),
            });
        }
    }

    // ─── Actions ────────────────────────────────────────────────────────────

    fn submit(&mut self, max_bytes: usize) {
        let Some(o) = self.open.clone() else {
            return;
        };
        if !can_send(self.status()) {
            return;
        }
        match prepare_send(&self.composer, max_bytes) {
            Err(SendBlock::Empty) => {}
            Err(SendBlock::TooLong) => self.page_msg = Some(self.cs().too_long_note.to_owned()),
            Ok(text) => {
                self.page_msg = None;
                self.composer.clear();
                self.sends_in_flight += 1;
                self.push(GroupRequest::Send { group: o.id, text });
            }
        }
    }

    fn start_create(&mut self) {
        let Some(form) = self.form.as_mut() else {
            return;
        };
        match form.check() {
            Err(e) => form.error = Some(e),
            Ok((name, members)) => {
                form.error = None;
                self.creating = true;
                self.form_msg = None;
                self.push(GroupRequest::Create { name, members });
            }
        }
    }

    fn start_add(&mut self) {
        let (Some(o), Some(p)) = (self.open.clone(), self.add.clone()) else {
            return;
        };
        if p.is_empty() || self.acting.is_some() {
            return;
        }
        self.acting = Some(Acting::Add {
            name: self.open_name(),
        });
        self.add_msg = None;
        self.push(GroupRequest::Add {
            group: o.id,
            members: p.ids().to_vec(),
            admin: false,
        });
    }

    fn start_confirmed(&mut self, c: Confirm) {
        let Some(o) = self.open.clone() else {
            return;
        };
        if self.acting.is_some() {
            return;
        }
        let name = self.open_name();
        match c {
            Confirm::Leave => {
                self.acting = Some(Acting::Leave { name });
                self.push(GroupRequest::Leave { group: o.id });
            }
            Confirm::DeleteHistory => {
                self.acting = Some(Acting::Delete { name });
                self.push(GroupRequest::Decline { group: o.id });
            }
            Confirm::Remove { endpoint_id, who } => {
                self.acting = Some(Acting::Remove { who, name });
                self.push(GroupRequest::Remove {
                    group: o.id,
                    member: endpoint_id,
                });
            }
        }
    }

    fn start_invitation(&mut self, accept: bool) {
        let Some(o) = self.open.clone() else {
            return;
        };
        let name = self.open_name();
        self.answer_invitation(&o.id, &name, accept);
    }

    /// Say yes or no to the invitation to group `id` (from the open group or from a card).
    fn answer_invitation(&mut self, id: &str, name: &str, accept: bool) {
        if self.acting.is_some() {
            return;
        }
        let name = name.to_owned();
        self.page_msg = None;
        if accept {
            self.acting = Some(Acting::Accept { name });
            self.push(GroupRequest::Accept {
                group: id.to_owned(),
            });
        } else {
            self.acting = Some(Acting::Decline { name });
            self.push(GroupRequest::Decline {
                group: id.to_owned(),
            });
        }
    }

    /// Change `chat.group_auto_join` in the running service (the caller saves it in the
    /// configuration file). A service that predates it answers with an error, which is dropped.
    pub fn set_auto_join(&mut self, on: bool) {
        self.push(GroupRequest::Settings {
            auto_join: Some(on),
        });
    }

    /// The invitations waiting for an answer, as cards at the top of the Chat area: who added me,
    /// what it means to not have answered, and Accept / Decline. Draws nothing when there are none.
    pub fn invitation_cards(&mut self, ui: &mut egui::Ui, contacts: &[ContactInfo]) {
        let gs = self.gs();
        let waiting: Vec<GroupRow> = invitations(&self.rows).into_iter().cloned().collect();
        if waiting.is_empty() {
            return;
        }
        let busy = self.acting.is_some();
        let mut answer: Option<(String, String, bool)> = None;
        kit::notice(
            ui,
            Level::Warn,
            &fill(gs.invites_waiting, &[("n", &waiting.len().to_string())]),
        );
        ui.add_space(kit::SP_2);
        let dismiss = self.cs().dismiss;
        if let Some(msg) = self.page_msg.clone() {
            ui.horizontal_wrapped(|ui| {
                kit::notice(ui, Level::Error, &msg);
                if ui.add(kit::compact_button(dismiss)).clicked() {
                    self.page_msg = None;
                }
            });
        }
        for row in &waiting {
            let name = elide(&row.name, NAME_CHARS);
            let who = inviter_name(gs, contacts, row);
            egui::Frame::none()
                .stroke(Stroke::new(2.0, pal().accent))
                .fill(pal().surface)
                .rounding(8.0)
                .inner_margin(egui::Margin::same(kit::SP_4))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        RichText::new(fill(gs.invite_title, &[("name", &name)]))
                            .strong()
                            .color(pal().text),
                    );
                    kit::paragraph(ui, &fill(gs.invite_body, &[("who", &who)]));
                    ui.add_space(kit::SP_2);
                    kit::button_row(ui, |ui| {
                        let label = fill(gs.a11y_accept_named, &[("name", &name)]);
                        let r = kit::primary(ui, !busy, gs.accept);
                        r.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, label.clone())
                        });
                        if r.clicked() {
                            answer = Some((row.id.clone(), row.name.clone(), true));
                        }
                        let label = fill(gs.a11y_decline_named, &[("name", &name)]);
                        let r = ui.add_enabled(!busy, kit::secondary_button(gs.decline));
                        r.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, label.clone())
                        });
                        if r.clicked() {
                            answer = Some((row.id.clone(), row.name.clone(), false));
                        }
                    });
                });
            ui.add_space(kit::SP_2);
        }
        if let Some((id, name, accept)) = answer {
            self.answer_invitation(&id, &name, accept);
        }
    }

    // ─── Drawing: the list ──────────────────────────────────────────────────

    /// The "New group" button of the list's heading.
    pub fn new_group_button(&mut self, ui: &mut egui::Ui, has_contacts: bool) {
        let gs = self.gs();
        let enabled = has_contacts && self.can_create();
        let resp = ui.add_enabled(enabled, kit::secondary_button(gs.new_group));
        resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.a11y_new_group));
        let resp = if !self.can_create() {
            resp.on_disabled_hover_text(gs.unsupported)
        } else {
            resp
        };
        if resp.clicked() {
            self.open_new_group();
        }
    }

    /// One group row of the conversation list. True when it was pressed.
    pub fn row(&self, ui: &mut egui::Ui, index: usize, clock: Clock) -> bool {
        let (gs, cs) = (self.gs(), self.cs());
        let Some(row) = self.rows.get(index) else {
            return false;
        };
        let last = self
            .previews
            .get(&row.id)
            .map_or(GroupLast::None, |p| p.last.clone());
        let preview = preview_line(gs, cs, row, &last);
        let when = when_list(cs, row.last_ms, clock);
        let unread = self.unread.of(row);
        group_row(ui, gs, cs, row, &preview, &when, unread).clicked()
    }

    // ─── Drawing: the conversation ──────────────────────────────────────────

    /// Draw the open group. The action is for the app (open the add-contact form).
    pub fn conversation_view(
        &mut self,
        ui: &mut egui::Ui,
        clock: Clock,
        max_bytes: usize,
    ) -> Option<ChatAction> {
        let o = self.open.clone()?;
        let (gs, cs) = (self.gs(), self.cs());
        let status = self.status();
        let name = self.open_name();

        let mut back = false;
        ui.horizontal_wrapped(|ui| {
            let r = ui.add(kit::secondary_button(cs.back));
            r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, cs.a11y_back));
            if r.clicked() {
                back = true;
            }
            ui.label(
                RichText::new(elide(&name, NAME_CHARS))
                    .text_style(egui::TextStyle::Heading)
                    .color(pal().text),
            )
            .on_hover_text(&name);
        });
        if back {
            self.close();
            return None;
        }
        if status != GroupStatus::Invited {
            let (label, a11y) = if self.info_open {
                (gs.back_to_messages, gs.a11y_back_to_messages)
            } else {
                (gs.info_button, gs.a11y_info)
            };
            ui.horizontal_wrapped(|ui| {
                let r = ui.add(kit::secondary_button(label));
                r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, a11y));
                if r.clicked() {
                    self.info_open = !self.info_open;
                }
            });
        }
        ui.add_space(kit::SP_1);
        if let Some(d) = &self.detail {
            let n = unverified_count(&d.members);
            if n > 0 && !self.info_open && status != GroupStatus::Invited {
                kit::notice(
                    ui,
                    Level::Warn,
                    &fill(gs.unverified_header, &[("n", &n.to_string())]),
                );
                ui.add_space(kit::SP_2);
            }
        }
        if let Some(msg) = self.page_msg.clone() {
            ui.horizontal_wrapped(|ui| {
                kit::notice(ui, Level::Error, &msg);
                if ui.add(kit::compact_button(cs.dismiss)).clicked() {
                    self.page_msg = None;
                }
            });
        }
        if status == GroupStatus::Invited {
            self.invitation_view(ui);
        } else if self.info_open {
            self.info_view(ui);
        } else {
            if can_send(status) {
                if let Some(d) = &self.detail {
                    for (warn, text) in waiting_notices(gs, &waiting_of(gs, d)) {
                        kit::notice(ui, if warn { Level::Warn } else { Level::Info }, &text);
                        ui.add_space(kit::SP_2);
                    }
                }
            }
            self.thread_view(ui, &o, clock);
            if can_send(status) {
                self.composer_view(ui, max_bytes);
            } else {
                kit::notice(ui, Level::Warn, gs.not_joined_note);
            }
        }
        self.action.take()
    }

    fn invitation_view(&mut self, ui: &mut egui::Ui) {
        let gs = self.gs();
        let busy = self.acting.is_some();
        let mut accept = false;
        let mut decline = false;
        kit::surface(ui, |ui| {
            kit::paragraph(ui, gs.invited_note);
            ui.add_space(kit::SP_2);
            kit::button_row(ui, |ui| {
                let r = kit::primary(ui, !busy, gs.accept);
                r.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.a11y_accept)
                });
                accept = r.clicked();
                let r = ui.add_enabled(!busy, kit::secondary_button(gs.decline));
                r.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.a11y_decline)
                });
                decline = r.clicked();
            });
        });
        if accept {
            self.start_invitation(true);
        } else if decline {
            self.start_invitation(false);
        }
    }

    fn thread_view(&mut self, ui: &mut egui::Ui, o: &Open, clock: Clock) {
        let (gs, cs) = (self.gs(), self.cs());
        let width = ui.available_width();
        let bubble_w = (width * 0.78).clamp(220.0, 640.0);
        if !self.thread_loaded {
            ui.label(RichText::new(cs.loading).color(pal().muted));
        }
        let height = (ui.available_height() - COMPOSER_RESERVE).max(140.0);
        let can_more = self.thread_loaded
            && self.messages.len() as u32 >= self.limit
            && self.limit < MAX_WINDOW;
        let mut older = false;
        let mut add_code: Option<String> = None;
        let detail = self.detail.as_ref();
        let added_line = detail.and_then(|d| added_by_line(gs, d));
        let messages = &self.messages;
        let loaded = self.thread_loaded;
        egui::ScrollArea::vertical()
            .id_source(("group_thread", o.id.as_str()))
            .max_height(height)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = kit::SP_2;
                if can_more {
                    let r = ui.add(kit::secondary_button(gs.older_button));
                    r.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.older_button)
                    });
                    older = r.clicked();
                }
                // The system line: the first thing of the group, shown once the oldest messages are.
                if let Some(line) = &added_line {
                    if !can_more {
                        kit::paragraph_muted(ui, line);
                    }
                }
                if messages.is_empty() && loaded {
                    kit::paragraph_muted(ui, cs.empty_thread);
                }
                for m in messages {
                    let sender = sender_of(gs, m);
                    let code = detail.and_then(|d| contact_code_of(d, &m.sender));
                    if message_row(ui, gs, cs, m, &sender, code.is_some(), clock, bubble_w) {
                        add_code = code.map(str::to_owned);
                    }
                }
            });
        if older {
            self.limit = (self.limit + PAGE).min(MAX_WINDOW);
            self.thread_dirty = true;
        }
        if let Some(code) = add_code {
            self.action = Some(ChatAction::AddContact(code));
        }
    }

    fn composer_view(&mut self, ui: &mut egui::Ui, max_bytes: usize) {
        let (gs, cs) = (self.gs(), self.cs());
        ui.add_space(kit::SP_1);
        // Japanese input: Enter that confirms a conversion must not send.
        let composing = ui.input(|i| {
            i.events.iter().fold(self.ime_composing, |now, e| match e {
                egui::Event::CompositionStart => true,
                egui::Event::CompositionUpdate(s) => !s.is_empty(),
                egui::Event::CompositionEnd(_) => false,
                _ => now,
            })
        });
        self.ime_composing = composing;
        let id = egui::Id::new("group_composer");
        let focused = ui.memory(|m| m.has_focus(id));
        let mut submit = false;
        if focused
            && !self.ime_composing
            && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
        {
            submit = true;
        }
        let resp = ui.add(
            kit::input_multiline(&mut self.composer)
                .id(id)
                .desired_rows(3)
                .hint_text(cs.composer_hint),
        );
        resp.widget_info(|| {
            egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, gs.a11y_composer)
        });
        if resp.changed() && cap_text(&mut self.composer, composer_cap(max_bytes)) {
            self.page_msg = Some(cs.too_long_note.to_owned());
        }
        if self.focus_composer {
            resp.request_focus();
            self.focus_composer = false;
        }
        let ctr = counter(&self.composer, max_bytes);
        let can_send = !matches!(ctr.level, CounterLevel::Empty | CounterLevel::Over);
        ui.horizontal_wrapped(|ui| {
            let btn = kit::primary(ui, can_send, cs.send);
            btn.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.a11y_send));
            let btn = if can_send {
                btn
            } else if ctr.level == CounterLevel::Over {
                btn.on_disabled_hover_text(cs.too_long_note)
            } else {
                btn.on_disabled_hover_text(cs.send_empty_hint)
            };
            if btn.clicked() {
                submit = true;
            }
            let color = match ctr.level {
                CounterLevel::Over => pal().danger,
                CounterLevel::Near => pal().warning,
                _ => pal().muted,
            };
            ui.label(RichText::new(counter_text(cs, &ctr)).small().color(color));
            ui.label(RichText::new(cs.composer_keys).small().color(pal().faint));
        });
        if submit && can_send {
            self.submit(max_bytes);
            self.focus_composer = true;
        } else if submit && ctr.level == CounterLevel::Over {
            self.page_msg = Some(cs.too_long_note.to_owned());
        }
    }

    // ─── Drawing: the information panel ─────────────────────────────────────

    fn info_view(&mut self, ui: &mut egui::Ui) {
        let (gs, cs) = (self.gs(), self.cs());
        let status = self.status();
        let busy = self.acting.is_some();
        let mut ask_add = false;
        let mut ask_leave = false;
        let mut ask_delete = false;
        let mut ask_remove: Option<(String, String)> = None;
        let mut add_contact: Option<String> = None;
        let Some(d) = self.detail.clone() else {
            ui.label(RichText::new(cs.loading).color(pal().muted));
            return;
        };
        kit::section(ui, gs.info_title, |_| {});
        egui::ScrollArea::vertical()
            .id_source("group_info")
            .auto_shrink([false, false])
            .max_height((ui.available_height() - 20.0).max(160.0))
            .show(ui, |ui| {
                kit::section(
                    ui,
                    &fill(gs.members_title, &[("n", &d.members.len().to_string())]),
                    |ui| {
                        for m in &d.members {
                            let name = member_name(gs, m);
                            kit::surface(ui, |ui| {
                                let r = ui.add(
                                    egui::Label::new(
                                        RichText::new(elide(&name, NAME_CHARS))
                                            .strong()
                                            .color(pal().text),
                                    )
                                    .wrap(true),
                                );
                                r.widget_info(|| {
                                    egui::WidgetInfo::labeled(
                                        egui::WidgetType::Label,
                                        member_summary(gs, m),
                                    )
                                });
                                ui.horizontal_wrapped(|ui| {
                                    let role = if m.role == "admin" {
                                        gs.role_admin
                                    } else {
                                        gs.role_member
                                    };
                                    ui.label(kit::meta_text(role, pal().muted));
                                    if m.you {
                                        ui.label(kit::meta_text(gs.you_tag, pal().muted));
                                    } else if m.verified {
                                        ui.label(kit::meta_text(gs.marker_verified, pal().success));
                                    } else {
                                        egui::Frame::none()
                                            .stroke(Stroke::new(1.0, pal().warning))
                                            .rounding(4.0)
                                            .inner_margin(egui::Margin::symmetric(4.0, 0.0))
                                            .show(ui, |ui| {
                                                ui.label(kit::meta_text(
                                                    gs.marker_unverified,
                                                    pal().warning,
                                                ))
                                                .on_hover_text(gs.unverified_tip);
                                            });
                                    }
                                });
                                let standing = standing_of(m);
                                if let Some(t) = standing_text(gs, &standing) {
                                    let color = match standing {
                                        Standing::Joined => pal().success,
                                        Standing::Invited => pal().muted,
                                        _ => pal().warning,
                                    };
                                    ui.label(kit::meta_text(t, color));
                                }
                                if !m.you {
                                    ui.label(kit::meta_text(
                                        format!("{}: {}", gs.code_label, m.fingerprint),
                                        pal().muted,
                                    ));
                                    kit::button_row(ui, |ui| {
                                        if !m.verified {
                                            let r =
                                                ui.add(kit::secondary_button(gs.add_as_contact));
                                            let label =
                                                fill(gs.a11y_add_contact, &[("name", &name)]);
                                            r.widget_info(|| {
                                                egui::WidgetInfo::labeled(
                                                    egui::WidgetType::Button,
                                                    label.clone(),
                                                )
                                            });
                                            if r.clicked() {
                                                add_contact = Some(m.contact_code.clone());
                                            }
                                        }
                                        if can_remove(&d, m) {
                                            let r = ui
                                                .add_enabled(!busy, kit::danger_button(gs.remove));
                                            let label = fill(gs.a11y_remove, &[("name", &name)]);
                                            r.widget_info(|| {
                                                egui::WidgetInfo::labeled(
                                                    egui::WidgetType::Button,
                                                    label.clone(),
                                                )
                                            });
                                            if r.clicked() {
                                                ask_remove =
                                                    Some((m.endpoint_id.clone(), name.clone()));
                                            }
                                        }
                                    });
                                }
                            });
                            ui.add_space(kit::SP_1);
                        }
                    },
                );
                // Add member: for the creator and admins.
                let check = add_check(&d);
                kit::button_row(ui, |ui| {
                    let enabled = matches!(check, AddCheck::Allowed { .. }) && !busy;
                    let r = ui.add_enabled(enabled, kit::secondary_button(gs.add_member));
                    r.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.a11y_add_member)
                    });
                    let r = match check {
                        AddCheck::NotAdmin => r.on_disabled_hover_text(gs.admin_only_hint),
                        AddCheck::Full => r.on_disabled_hover_text(fill(
                            gs.full_hint,
                            &[(
                                "max",
                                &miasma_core::chat::group::membership::MAX_MEMBERS.to_string(),
                            )],
                        )),
                        AddCheck::NotJoined => r.on_disabled_hover_text(gs.not_joined_note),
                        AddCheck::Allowed { .. } => r,
                    };
                    if r.clicked() {
                        ask_add = true;
                    }
                });
                match check {
                    AddCheck::NotAdmin => kit::hint(ui, gs.admin_only_hint).clone(),
                    AddCheck::Full => kit::hint(
                        ui,
                        &fill(
                            gs.full_hint,
                            &[(
                                "max",
                                &miasma_core::chat::group::membership::MAX_MEMBERS.to_string(),
                            )],
                        ),
                    )
                    .clone(),
                    _ => ui.label(""),
                };
                ui.add_space(kit::SP_3);
                kit::divider(ui);
                ui.add_space(kit::SP_2);
                kit::button_row(ui, |ui| {
                    let r =
                        ui.add_enabled(can_leave(status) && !busy, kit::danger_button(gs.leave));
                    r.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.a11y_leave)
                    });
                    if r.clicked() {
                        ask_leave = true;
                    }
                    let allowed = can_delete_history(status) && !busy;
                    let r = ui.add_enabled(allowed, kit::danger_button(gs.delete_history));
                    r.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.a11y_delete_history)
                    });
                    let r = if can_delete_history(status) {
                        r
                    } else {
                        r.on_disabled_hover_text(gs.delete_history_hint)
                    };
                    if r.clicked() {
                        ask_delete = true;
                    }
                });
                if !can_delete_history(status) {
                    kit::hint(ui, gs.delete_history_hint);
                }
            });
        if ask_add {
            self.add = Some(Picks::default());
            self.add_msg = None;
        }
        if ask_leave {
            self.confirm = Some(Confirm::Leave);
        }
        if ask_delete {
            self.confirm = Some(Confirm::DeleteHistory);
        }
        if let Some((endpoint_id, who)) = ask_remove {
            self.confirm = Some(Confirm::Remove { endpoint_id, who });
        }
        if let Some(code) = add_contact {
            self.action = Some(ChatAction::AddContact(code));
        }
    }

    // ─── Drawing: dialogs ───────────────────────────────────────────────────

    /// The dialogs: new group, add members, and the confirmations. Esc closes the open one.
    pub fn dialogs(&mut self, ctx: &egui::Context, contacts: &[ContactInfo]) {
        self.confirm_dialog(ctx);
        self.form_dialog(ctx, contacts);
        self.add_dialog(ctx, contacts);
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(conf) = self.confirm.clone() else {
            return;
        };
        if self.open.is_none() {
            self.confirm = None;
            return;
        }
        let gs = self.gs();
        let name = elide(&self.open_name(), NAME_CHARS);
        let (id, title, body, ok, cancel) = match &conf {
            Confirm::Leave => (
                "group_leave_confirm",
                gs.leave_title,
                fill(gs.leave_body, &[("name", &name)]),
                gs.leave_confirm,
                gs.leave_cancel,
            ),
            Confirm::DeleteHistory => (
                "group_delete_confirm",
                gs.delete_title,
                fill(gs.delete_body, &[("name", &name)]),
                gs.delete_confirm,
                gs.delete_cancel,
            ),
            Confirm::Remove { who, .. } => (
                "group_remove_confirm",
                gs.remove_title,
                fill(
                    gs.remove_body,
                    &[("who", &elide(who, NAME_CHARS)), ("name", &name)],
                ),
                gs.remove_confirm,
                gs.remove_cancel,
            ),
        };
        let answer = confirm::show(ctx, id, title, ok, cancel, |ui| {
            kit::paragraph(ui, &body);
        });
        match answer {
            Answer::Confirm => {
                self.confirm = None;
                self.start_confirmed(conf);
            }
            Answer::Cancel => self.confirm = None,
            Answer::Pending => {}
        }
    }

    fn form_dialog(&mut self, ctx: &egui::Context, contacts: &[ContactInfo]) {
        if self.form.is_none() {
            return;
        }
        if self.confirm.is_none()
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.form = None;
            self.creating = false;
            return;
        }
        let (gs, cs) = (self.gs(), self.cs());
        let creating = self.creating;
        let focus = std::mem::take(&mut self.focus_form);
        let form_msg = self.form_msg.clone();
        let offered = selectable(contacts);
        let mut create = false;
        let mut cancel = false;
        if let Some(form) = self.form.as_mut() {
            form.picks.retain_offered(&offered);
            egui::Window::new(gs.ng_title)
                .id(egui::Id::new("group_new"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .max_width(460.0)
                .show(ctx, |ui| {
                    ui.set_max_width(440.0);
                    ui.label(kit::meta_text(gs.ng_name_label, pal().muted));
                    let r = ui.add(kit::input(&mut form.name).hint_text(gs.ng_name_hint));
                    r.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, gs.a11y_ng_name)
                    });
                    if r.changed() {
                        form.edit_name();
                    }
                    if focus {
                        r.request_focus();
                    }
                    ui.add_space(kit::SP_2);
                    ui.label(kit::meta_text(gs.ng_members_label, pal().muted));
                    if offered.is_empty() {
                        kit::paragraph(ui, gs.ng_none);
                    }
                    egui::ScrollArea::vertical()
                        .id_source("group_new_members")
                        .max_height(240.0)
                        .show(ui, |ui| {
                            for ct in &offered {
                                let mut on = form.picks.contains(&ct.id);
                                let label = elide(&ct.label, NAME_CHARS);
                                let r = ui.checkbox(&mut on, label.clone());
                                let named = fill(gs.a11y_ng_member, &[("name", &label)]);
                                r.widget_info(|| {
                                    egui::WidgetInfo::selected(
                                        egui::WidgetType::Checkbox,
                                        on,
                                        named.clone(),
                                    )
                                });
                                if r.changed() {
                                    form.tick(&ct.id, on);
                                }
                            }
                        });
                    ui.add_space(kit::SP_1);
                    ui.label(kit::meta_text(
                        fill(
                            gs.ng_count,
                            &[
                                ("n", &form.total().to_string()),
                                (
                                    "max",
                                    &miasma_core::chat::group::membership::MAX_MEMBERS.to_string(),
                                ),
                            ],
                        ),
                        pal().muted,
                    ));
                    ui.add(egui::Label::new(kit::meta_text(gs.ng_note, pal().muted)).wrap(true));
                    if let Some(e) = form.error {
                        kit::notice(ui, Level::Error, &form_error_text(gs, e));
                    }
                    if let Some(msg) = &form_msg {
                        kit::notice(ui, Level::Error, msg);
                    }
                    ui.add_space(kit::SP_1);
                    kit::button_row(ui, |ui| {
                        let ready = !form.name.trim().is_empty() && !form.picks.is_empty();
                        let r = kit::primary(ui, ready && !creating, gs.ng_create);
                        r.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.ng_create)
                        });
                        if r.clicked() {
                            create = true;
                        }
                        let r = ui.add(kit::secondary_button(gs.ng_cancel));
                        r.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.ng_cancel)
                        });
                        if r.clicked() {
                            cancel = true;
                        }
                    });
                });
        }
        let _ = cs;
        if cancel {
            self.form = None;
            self.creating = false;
        } else if create {
            self.start_create();
        }
    }

    fn add_dialog(&mut self, ctx: &egui::Context, contacts: &[ContactInfo]) {
        if self.add.is_none() {
            return;
        }
        if self.confirm.is_none()
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.add = None;
            return;
        }
        let Some(d) = self.detail.clone() else {
            self.add = None;
            return;
        };
        let gs = self.gs();
        let busy = self.acting.is_some();
        let msg = self.add_msg.clone();
        let offered = addable(contacts, &d.members);
        let free = free_slots(d.members.len());
        let mut confirm_add = false;
        let mut cancel = false;
        if let Some(p) = self.add.as_mut() {
            p.retain_offered(&offered);
            egui::Window::new(gs.add_title)
                .id(egui::Id::new("group_add"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .max_width(460.0)
                .show(ctx, |ui| {
                    ui.set_max_width(440.0);
                    if offered.is_empty() {
                        kit::paragraph(ui, gs.add_none);
                    }
                    egui::ScrollArea::vertical()
                        .id_source("group_add_members")
                        .max_height(240.0)
                        .show(ui, |ui| {
                            for ct in &offered {
                                let mut on = p.contains(&ct.id);
                                let label = elide(&ct.label, NAME_CHARS);
                                let r = ui.checkbox(&mut on, label.clone());
                                let named = fill(gs.a11y_add_pick, &[("name", &label)]);
                                r.widget_info(|| {
                                    egui::WidgetInfo::selected(
                                        egui::WidgetType::Checkbox,
                                        on,
                                        named.clone(),
                                    )
                                });
                                if r.changed() {
                                    // Refused past the free places; the count below says why.
                                    p.set(&ct.id, on, free);
                                }
                            }
                        });
                    ui.add_space(kit::SP_1);
                    ui.label(kit::meta_text(
                        fill(
                            gs.add_count,
                            &[
                                ("n", &(d.members.len() + p.len()).to_string()),
                                (
                                    "max",
                                    &miasma_core::chat::group::membership::MAX_MEMBERS.to_string(),
                                ),
                            ],
                        ),
                        pal().muted,
                    ));
                    if let Some(m) = &msg {
                        kit::notice(ui, Level::Error, m);
                    }
                    ui.add_space(kit::SP_1);
                    kit::button_row(ui, |ui| {
                        let r = kit::primary(ui, !p.is_empty() && !busy, gs.add_confirm);
                        r.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.add_confirm)
                        });
                        if r.clicked() {
                            confirm_add = true;
                        }
                        let r = ui.add(kit::secondary_button(gs.add_cancel));
                        r.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, gs.add_cancel)
                        });
                        if r.clicked() {
                            cancel = true;
                        }
                    });
                });
        }
        if cancel {
            self.add = None;
        } else if confirm_add {
            self.start_add();
        }
    }
}

fn group_of(req: &GroupRequest) -> Option<&str> {
    match req {
        GroupRequest::Show { group }
        | GroupRequest::Add { group, .. }
        | GroupRequest::Remove { group, .. }
        | GroupRequest::Leave { group }
        | GroupRequest::Send { group, .. }
        | GroupRequest::History { group, .. }
        | GroupRequest::Accept { group }
        | GroupRequest::Decline { group } => Some(group),
        GroupRequest::Create { .. } | GroupRequest::List {} | GroupRequest::Settings { .. } => None,
    }
}

// ─── Rows ───────────────────────────────────────────────────────────────────

fn single_line(
    ui: &egui::Ui,
    text: &str,
    size: f32,
    color: egui::Color32,
    max_width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::single_section(
        text.to_owned(),
        egui::TextFormat::simple(egui::FontId::proportional(size), color),
    );
    job.wrap = egui::text::TextWrapping {
        max_width: max_width.max(16.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    ui.fonts(|f| f.layout_job(job))
}

/// One group in the conversation list, drawn like a one-to-one row: name and time, then the
/// member count with the last message, and the unread badge.
fn group_row(
    ui: &mut egui::Ui,
    gs: &GroupStrings,
    cs: &ChatStrings,
    row: &GroupRow,
    preview: &str,
    when: &str,
    unread: u32,
) -> egui::Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(w, ROW_H), Sense::click());
    let name = elide(&row.name, NAME_CHARS);
    let label = {
        let mut s = row_label(gs, row);
        if unread > 0 {
            s.push_str(", ");
            s.push_str(&fill(
                cs.a11y_unread,
                &[("n", &crate::chat::badge_text(unread))],
            ));
        }
        if !preview.is_empty() {
            s.push_str(", ");
            s.push_str(preview);
        }
        s
    };
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, label.clone()));
    if !ui.is_rect_visible(rect) {
        return resp;
    }
    let p = pal();
    let painter = ui.painter();
    if resp.hovered() || resp.has_focus() {
        painter.rect_filled(rect, 6.0, p.text.gamma_multiply(0.06));
    }
    if resp.has_focus() {
        painter.rect_stroke(rect, 6.0, Stroke::new(1.5, p.accent));
    }
    painter.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, p.border),
    );
    let inner = rect.shrink2(vec2(kit::SP_3, kit::SP_2));
    let when_galley = single_line(ui, when, kit::META_PX, p.muted, inner.width() * 0.4);
    let name_galley = single_line(
        ui,
        &name,
        15.0,
        p.text,
        inner.width() - when_galley.size().x - kit::SP_2,
    );
    let mut badge: Option<(egui::Rect, std::sync::Arc<egui::Galley>)> = None;
    let mut right_pad = 0.0;
    if unread > 0 {
        let text = crate::chat::badge_text(unread);
        let g = single_line(ui, &text, 12.5, p.on_accent(), 60.0);
        let size = vec2((g.size().x + 12.0).max(20.0), 20.0);
        let r = egui::Rect::from_min_size(
            egui::pos2(inner.right() - size.x, inner.bottom() - size.y),
            size,
        );
        right_pad = size.x + kit::SP_2;
        badge = Some((r, g));
    }
    let prev_galley = single_line(ui, preview, 13.5, p.muted, inner.width() - right_pad);
    let painter = ui.painter();
    painter.galley(inner.min, name_galley.clone(), p.text);
    painter.galley(
        egui::pos2(inner.right() - when_galley.size().x, inner.top() + 2.0),
        when_galley,
        p.muted,
    );
    painter.galley(
        egui::pos2(inner.left(), inner.top() + name_galley.size().y + 4.0),
        prev_galley,
        p.muted,
    );
    if let Some((r, g)) = badge {
        painter.rect_filled(r, 10.0, p.accent_fill);
        painter.galley(
            egui::pos2(
                r.center().x - g.size().x * 0.5,
                r.center().y - g.size().y * 0.5,
            ),
            g,
            p.on_accent(),
        );
    }
    resp
}

/// One message of a group as an aligned bubble: for an incoming one the sender above it (with the
/// unverified badge and, when the code is known, "Add as contact"), under it the time and how far
/// my own message got. Returns true when "Add as contact" was pressed.
#[allow(clippy::too_many_arguments)]
fn message_row(
    ui: &mut egui::Ui,
    gs: &GroupStrings,
    cs: &ChatStrings,
    m: &GroupMessageInfo,
    sender: &Sender,
    can_add: bool,
    clock: Clock,
    bubble_w: f32,
) -> bool {
    let p = pal();
    let own = m.outgoing;
    let layout = if own {
        Layout::right_to_left(Align::Min)
    } else {
        Layout::left_to_right(Align::Min)
    };
    let unverified = sender.is_unverified();
    let (fill_color, stroke) = if own {
        (p.selected, Stroke::new(1.0, p.border_strong))
    } else if unverified {
        (p.surface, Stroke::new(1.5, p.warning))
    } else {
        (p.surface, Stroke::new(1.0, p.border))
    };
    let mut add = false;
    if let Some(name) = sender.name() {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(name).strong().color(p.text));
            if unverified {
                egui::Frame::none()
                    .stroke(Stroke::new(1.0, p.warning))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::symmetric(4.0, 0.0))
                    .show(ui, |ui| {
                        ui.label(kit::meta_text(gs.unverified_badge, p.warning))
                            .on_hover_text(gs.unverified_tip);
                    });
                if can_add {
                    let r = ui.add(kit::compact_button(gs.add_as_contact));
                    let label = fill(gs.a11y_add_contact, &[("name", name)]);
                    r.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Button, label.clone())
                    });
                    if r.clicked() {
                        add = true;
                    }
                }
            }
        });
    }
    ui.with_layout(layout, |ui| {
        egui::Frame::none()
            .fill(fill_color)
            .stroke(stroke)
            .rounding(10.0)
            .inner_margin(egui::Margin::symmetric(kit::SP_3, kit::SP_2))
            .show(ui, |ui| {
                ui.set_max_width(bubble_w);
                ui.add(egui::Label::new(RichText::new(&m.text).color(p.text)).wrap(true));
            });
    });
    let when = when_message(cs, m.at_ms, clock);
    let delivery = delivery_of(m);
    let state = delivery_text(gs, delivery);
    let state_color = match delivery {
        GroupDelivery::All { .. } => p.success,
        GroupDelivery::Partial { .. } | GroupDelivery::FailedAll { .. } => p.danger,
        _ => p.muted,
    };
    ui.with_layout(layout, |ui| {
        if let Some(s) = state {
            ui.add(egui::Label::new(kit::meta_text(s, state_color)).wrap(true));
        }
        if !when.is_empty() {
            ui.label(kit::meta_text(when, p.muted));
        }
    });
    if m.gap_before > 0 {
        ui.with_layout(layout, |ui| {
            ui.add(
                egui::Label::new(kit::meta_text(
                    fill(gs.gap_note, &[("n", &m.gap_before.to_string())]),
                    p.muted,
                ))
                .wrap(true),
            );
        });
    }
    add
}

/// The most groups the service keeps (shown by the "too many groups" sentence).

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::chat::group::ipc::{GroupInfo, MemberInfo};

    fn info(id: &str, status: &str, members: u32, messages: u64, last_ms: u64) -> GroupInfo {
        GroupInfo {
            id: id.into(),
            name: format!("Team {id}"),
            epoch: 1,
            status: status.into(),
            members,
            messages,
            last_ms,
            pending: 0,
            invited_by: None,
        }
    }

    fn member(ep: &str, you: bool, verified: bool, admin: bool) -> MemberInfo {
        MemberInfo {
            endpoint_id: ep.into(),
            fingerprint: format!("{ep}ABCD-EFGH-IJKL-MNOP"),
            contact_code: format!("miasma-contact:{ep}"),
            role: if admin { "admin" } else { "member" }.into(),
            hint: (!verified && !you).then(|| format!("hint {ep}")),
            label: verified.then(|| format!("label {ep}")),
            verified,
            you,
            status: Some(if you { "you" } else { "joined" }.into()),
            reason: None,
        }
    }

    fn detail(status: &str, admin: bool) -> GroupDetailInfo {
        let members = vec![
            member("me", true, false, admin),
            member("amy", false, true, !admin),
            member("bob", false, false, false),
        ];
        GroupDetailInfo {
            group: info("g1", status, members.len() as u32, 2, 1_792_074_000_000),
            members,
            is_admin: admin,
            added_by: None,
        }
    }

    fn message(ord: u64, outgoing: bool, verified: bool) -> GroupMessageInfo {
        GroupMessageInfo {
            ord,
            id: format!("m{ord}"),
            outgoing,
            sender: if outgoing { "me".into() } else { "bob".into() },
            sender_label: verified.then(|| "Amy".into()),
            sender_hint: Some("Bob".into()),
            sender_fingerprint: "BOBB-1234-5678-9ABC".into(),
            verified,
            counter: ord,
            epoch: 1,
            text: format!("text {ord}"),
            sent_ms: 1_792_074_000_000,
            at_ms: 1_792_074_000_000,
            total: outgoing.then_some(2),
            delivered: outgoing.then_some(1),
            failed: outgoing.then_some(0),
            gap_before: if ord == 3 { 2 } else { 0 },
        }
    }

    /// A screen with a list read, as after the first answer.
    fn ready() -> GroupUi {
        let mut ui = GroupUi {
            support: Support::Yes,
            list_dirty: false,
            area_open: true,
            ..Default::default()
        };
        ui.rows = group_rows(&[
            info("g1", "joined", 3, 2, 1_792_074_000_000),
            info("g2", "invited", 2, 0, 1_792_070_000_000),
            info("g3", "left", 4, 9, 1_792_000_000_000),
        ]);
        ui.loaded = true;
        ui
    }

    fn opened(admin: bool) -> GroupUi {
        let mut ui = ready();
        ui.open_group("g1", "Team g1");
        ui.detail = Some(detail("joined", admin));
        ui.messages = vec![
            message(1, false, false),
            message(2, false, true),
            message(3, true, false),
        ];
        ui.thread_loaded = true;
        ui.thread_dirty = false;
        ui.detail_dirty = false;
        ui
    }

    fn requests(ui: &mut GroupUi) -> Vec<GroupRequest> {
        let mut v = Vec::new();
        ui.drain(&mut |r| {
            if let ChatRequest::Group(g) = r {
                v.push(g);
            }
            true
        });
        v
    }

    fn reply(ui: &mut GroupUi, req: GroupRequest, resp: GroupResponse) {
        ui.on_reply(&req, Ok(ChatResponse::Group(resp)));
    }

    #[test]
    fn the_list_of_groups_is_asked_for_once_and_then_every_few_seconds() {
        let mut ui = GroupUi::default();
        ui.on_area_opened();
        ui.tick(true);
        let r = requests(&mut ui);
        assert!(matches!(r.as_slice(), [GroupRequest::List {}]), "{r:?}");
        // Not again while the answer is awaited, nor right after it.
        ui.tick(true);
        assert!(requests(&mut ui).is_empty());
        reply(
            &mut ui,
            GroupRequest::List {},
            GroupResponse::Groups(vec![info("g1", "joined", 2, 0, 0)]),
        );
        ui.tick(true);
        assert!(requests(&mut ui).is_empty());
        assert_eq!(ui.rows().len(), 1);
        ui.list_dirty = true;
        ui.tick(true);
        assert!(matches!(
            requests(&mut ui).as_slice(),
            [GroupRequest::List {}]
        ));
    }

    #[test]
    fn an_open_group_asks_for_its_messages_and_members_only_while_the_tab_is_open() {
        let mut ui = ready();
        ui.open_group("g1", "Team g1");
        ui.tick(false);
        assert!(
            requests(&mut ui).is_empty(),
            "tab closed: nothing for the group"
        );
        ui.tick(true);
        let r = requests(&mut ui);
        assert!(r.iter().any(|x| matches!(
            x,
            GroupRequest::History { group, before: None, limit: Some(50) } if group == "g1"
        )));
        assert!(r
            .iter()
            .any(|x| matches!(x, GroupRequest::Show { group } if group == "g1")));
        // Not again until answered.
        ui.tick(true);
        assert!(requests(&mut ui).is_empty());
    }

    #[test]
    fn an_invitation_is_not_asked_for_messages() {
        let mut ui = ready();
        ui.open_group("g2", "Team g2");
        ui.tick(true);
        let r = requests(&mut ui);
        assert!(!r.iter().any(|x| matches!(x, GroupRequest::History { .. })));
    }

    #[test]
    fn a_service_without_groups_is_not_taken_for_an_old_chat_service() {
        let mut ui = GroupUi::default();
        ui.on_area_opened();
        ui.tick(true);
        let _ = requests(&mut ui);
        ui.on_reply(&GroupRequest::List {}, Err(ChatFail::NotSupported));
        assert!(!ui.can_create());
        // Quiet: no request every frame; asked again only after a long while.
        ui.tick(true);
        assert!(requests(&mut ui).is_empty());
        ui.last_list = Instant::now() - RETRY_UNSUPPORTED - Duration::from_secs(1);
        ui.tick(true);
        assert!(matches!(
            requests(&mut ui).as_slice(),
            [GroupRequest::List {}]
        ));
        // The same for a chat service that runs without group chat.
        ui.on_reply(
            &GroupRequest::List {},
            Ok(ChatResponse::Error {
                kind: "unavailable".into(),
                message: String::new(),
            }),
        );
        assert!(!ui.can_create());
        // Reconnecting asks again at once.
        ui.on_reconnect();
        assert!(ui.can_create());
        ui.tick(true);
        assert!(matches!(
            requests(&mut ui).as_slice(),
            [GroupRequest::List {}]
        ));
    }

    #[test]
    fn the_last_message_of_a_changed_group_is_asked_for_once() {
        let mut ui = GroupUi {
            area_open: true,
            support: Support::Yes,
            list_dirty: false,
            ..Default::default()
        };
        reply(
            &mut ui,
            GroupRequest::List {},
            GroupResponse::Groups(vec![
                info("g1", "joined", 3, 2, 10),
                info("g2", "joined", 3, 0, 5),
                info("g3", "invited", 2, 0, 5),
            ]),
        );
        let r = requests(&mut ui);
        assert_eq!(r.len(), 1, "only the group that has messages: {r:?}");
        assert!(matches!(
            &r[0],
            GroupRequest::History { group, limit: Some(1), .. } if group == "g1"
        ));
        // Not again while in flight.
        reply(
            &mut ui,
            GroupRequest::List {},
            GroupResponse::Groups(vec![info("g1", "joined", 3, 2, 10)]),
        );
        assert!(requests(&mut ui).is_empty());
        // The answer fills the row's preview; an unchanged group is not asked again.
        reply(
            &mut ui,
            GroupRequest::History {
                group: "g1".into(),
                before: None,
                limit: Some(1),
            },
            GroupResponse::History {
                group: info("g1", "joined", 3, 2, 10),
                messages: vec![message(2, false, true)],
            },
        );
        reply(
            &mut ui,
            GroupRequest::List {},
            GroupResponse::Groups(vec![info("g1", "joined", 3, 2, 10)]),
        );
        assert!(requests(&mut ui).is_empty());
        let preview = &ui.previews["g1"].last;
        assert!(matches!(
            preview,
            GroupLast::Message { sender: Sender::Contact { name }, .. } if name == "Amy"
        ));
        // A new message changes the key: asked again.
        reply(
            &mut ui,
            GroupRequest::List {},
            GroupResponse::Groups(vec![info("g1", "joined", 3, 3, 20)]),
        );
        assert_eq!(requests(&mut ui).len(), 1);
    }

    #[test]
    fn arrivals_in_a_group_off_screen_count_as_unread_and_for_the_navigation() {
        let mut ui = GroupUi {
            area_open: true,
            support: Support::Yes,
            list_dirty: false,
            ..Default::default()
        };
        let list = |n| GroupResponse::Groups(vec![info("g1", "joined", 3, n, 10)]);
        reply(&mut ui, GroupRequest::List {}, list(2));
        assert_eq!(ui.unseen(), 0);
        reply(&mut ui, GroupRequest::List {}, list(5));
        assert_eq!(ui.unread.of(&ui.rows[0]), 3);
        assert_eq!(ui.unseen(), 3);
        ui.mark_seen();
        assert_eq!(ui.unseen(), 0);
        // Opening the group clears its badge.
        ui.open_index(0);
        assert_eq!(ui.unread.of(&ui.rows[0]), 0);
    }

    #[test]
    fn creating_a_group_sends_the_contacts_and_opens_it() {
        let mut ui = ready();
        ui.open_new_group();
        let form = ui.form.as_mut().unwrap();
        form.name = "Lunch".into();
        form.tick("c1", true);
        form.tick("c2", true);
        ui.start_create();
        let r = requests(&mut ui);
        assert!(matches!(
            r.as_slice(),
            [GroupRequest::Create { name, members }]
                if name == "Lunch" && members == &vec!["c1".to_string(), "c2".to_string()]
        ));
        assert!(ui.creating);
        reply(
            &mut ui,
            r[0].clone(),
            GroupResponse::Created {
                id: "g9".into(),
                recipients: 2,
            },
        );
        assert!(ui.form.is_none() && !ui.creating);
        assert!(ui.is_open());
        assert_eq!(ui.open.as_ref().unwrap().id, "g9");
        assert_eq!(ui.take_notices().len(), 1);
    }

    #[test]
    fn a_form_without_a_name_or_members_sends_nothing() {
        let mut ui = ready();
        ui.open_new_group();
        ui.start_create();
        assert!(requests(&mut ui).is_empty());
        assert_eq!(ui.form.as_ref().unwrap().error, Some(FormError::Name));
        ui.form.as_mut().unwrap().name = "x".into();
        ui.start_create();
        assert!(requests(&mut ui).is_empty());
        assert_eq!(ui.form.as_ref().unwrap().error, Some(FormError::NoMembers));
    }

    #[test]
    fn a_refused_create_keeps_the_form_and_says_why() {
        let mut ui = ready();
        ui.open_new_group();
        let form = ui.form.as_mut().unwrap();
        form.name = "Lunch".into();
        form.tick("c1", true);
        ui.start_create();
        let r = requests(&mut ui);
        reply(
            &mut ui,
            r[0].clone(),
            GroupResponse::Error {
                kind: "too_many_groups".into(),
                message: "x".into(),
            },
        );
        assert!(ui.form.is_some() && !ui.creating);
        let msg = ui.form_msg.clone().unwrap();
        assert!(msg.contains("32"), "{msg}");
        // No answer at all: the generic sentence, the form stays.
        ui.start_create();
        let r = requests(&mut ui);
        ui.on_reply(&r[0], Err(ChatFail::Other));
        assert_eq!(ui.form_msg.as_deref(), Some(ui.cs().err_other));
    }

    #[test]
    fn a_message_is_sent_to_the_group_and_comes_back_when_it_fails() {
        let mut ui = opened(true);
        ui.composer = "hello all \n".into();
        ui.submit(4096);
        let r = requests(&mut ui);
        assert!(matches!(
            r.as_slice(),
            [GroupRequest::Send { group, text }] if group == "g1" && text == "hello all"
        ));
        assert!(ui.composer.is_empty());
        assert_eq!(ui.sends_in_flight, 1);
        reply(
            &mut ui,
            r[0].clone(),
            GroupResponse::Error {
                kind: "queue_full".into(),
                message: String::new(),
            },
        );
        assert_eq!(ui.sends_in_flight, 0);
        assert_eq!(ui.composer, "hello all", "nothing is lost");
        assert_eq!(ui.page_msg.as_deref(), Some(ui.gs().err_queue_full));
        // Sent: the next messages are asked for soon.
        ui.submit(4096);
        ui.composer = "again".into();
        ui.submit(4096);
        let r = requests(&mut ui);
        reply(
            &mut ui,
            r.last().unwrap().clone(),
            GroupResponse::Queued {
                id: "m".into(),
                recipients: 2,
            },
        );
        assert!(ui.thread_dirty);
    }

    #[test]
    fn nothing_is_sent_from_a_group_i_am_not_in_or_when_empty_or_too_long() {
        let mut ui = opened(true);
        ui.composer = "   ".into();
        ui.submit(4096);
        assert!(requests(&mut ui).is_empty());
        ui.composer = "x".repeat(5000);
        ui.submit(4096);
        assert!(requests(&mut ui).is_empty());
        assert!(ui.page_msg.is_some());
        ui.page_msg = None;
        ui.rows[0].status = GroupStatus::Left;
        ui.composer = "hi".into();
        ui.submit(4096);
        assert!(requests(&mut ui).is_empty());
    }

    #[test]
    fn adding_members_goes_through_the_picker_and_sends_the_chosen_contacts() {
        let mut ui = opened(true);
        ui.add = Some(Picks::default());
        ui.add.as_mut().unwrap().set("c7", true, 5);
        ui.start_add();
        let r = requests(&mut ui);
        assert!(matches!(
            r.as_slice(),
            [GroupRequest::Add { group, members, admin: false }]
                if group == "g1" && members == &vec!["c7".to_string()]
        ));
        // Nothing else is started while this one waits.
        ui.start_confirmed(Confirm::Leave);
        assert!(requests(&mut ui).is_empty());
        reply(&mut ui, r[0].clone(), GroupResponse::Done {});
        assert!(ui.add.is_none());
        assert!(ui.detail_dirty);
        assert_eq!(ui.take_notices().len(), 1);
    }

    #[test]
    fn a_refused_add_keeps_the_picker_and_says_why() {
        let mut ui = opened(true);
        ui.add = Some(Picks::default());
        ui.add.as_mut().unwrap().set("c7", true, 5);
        ui.start_add();
        let r = requests(&mut ui);
        reply(
            &mut ui,
            r[0].clone(),
            GroupResponse::Error {
                kind: "not_admin".into(),
                message: String::new(),
            },
        );
        assert!(ui.add.is_some() && ui.acting.is_none());
        assert_eq!(ui.add_msg.as_deref(), Some(ui.gs().err_not_admin));
    }

    #[test]
    fn removing_a_member_needs_the_confirmation_and_names_the_member() {
        let mut ui = opened(true);
        ui.start_confirmed(Confirm::Remove {
            endpoint_id: "bob".into(),
            who: "Bob".into(),
        });
        let r = requests(&mut ui);
        assert!(matches!(
            r.as_slice(),
            [GroupRequest::Remove { group, member }] if group == "g1" && member == "bob"
        ));
        reply(&mut ui, r[0].clone(), GroupResponse::Done {});
        let n = ui.take_notices();
        assert_eq!(n.len(), 1);
        assert!(n[0].contains("Bob") && n[0].contains("Team g1"), "{n:?}");
    }

    #[test]
    fn leaving_keeps_the_group_on_screen_and_deleting_the_history_removes_it() {
        let mut ui = opened(true);
        ui.start_confirmed(Confirm::Leave);
        let r = requests(&mut ui);
        assert!(matches!(r.as_slice(), [GroupRequest::Leave { group }] if group == "g1"));
        reply(&mut ui, r[0].clone(), GroupResponse::Done {});
        assert!(ui.is_open(), "the history stays until it is deleted");
        // Now out of the group: the history can be deleted (the service forgets the group).
        ui.rows[0].status = GroupStatus::Left;
        ui.start_confirmed(Confirm::DeleteHistory);
        let r = requests(&mut ui);
        assert!(matches!(r.as_slice(), [GroupRequest::Decline { group }] if group == "g1"));
        reply(&mut ui, r[0].clone(), GroupResponse::Done {});
        assert!(!ui.is_open());
        assert_eq!(ui.take_notices().len(), 2);
    }

    #[test]
    fn a_last_admin_who_tries_to_leave_is_told_why() {
        let mut ui = opened(true);
        ui.start_confirmed(Confirm::Leave);
        let r = requests(&mut ui);
        reply(
            &mut ui,
            r[0].clone(),
            GroupResponse::Error {
                kind: "last_admin".into(),
                message: String::new(),
            },
        );
        assert_eq!(ui.page_msg.as_deref(), Some(ui.gs().err_last_admin));
        assert!(ui.acting.is_none(), "free to try something else");
    }

    #[test]
    fn an_invitation_is_accepted_or_declined_and_declining_closes_it() {
        let mut ui = ready();
        ui.open_group("g2", "Team g2");
        ui.start_invitation(true);
        let r = requests(&mut ui);
        assert!(matches!(r.as_slice(), [GroupRequest::Accept { group }] if group == "g2"));
        reply(&mut ui, r[0].clone(), GroupResponse::Done {});
        assert!(ui.is_open());
        ui.start_invitation(false);
        let r = requests(&mut ui);
        assert!(matches!(r.as_slice(), [GroupRequest::Decline { group }] if group == "g2"));
        reply(&mut ui, r[0].clone(), GroupResponse::Done {});
        assert!(!ui.is_open());
    }

    #[test]
    fn an_invitation_card_answers_from_the_list_without_opening_the_group() {
        let mut ui = ready();
        assert!(!ui.is_open());
        ui.answer_invitation("g2", "group g2", true);
        let r = requests(&mut ui);
        assert!(matches!(r.as_slice(), [GroupRequest::Accept { group }] if group == "g2"));
        // A second press while the first is on its way sends nothing.
        ui.answer_invitation("g2", "group g2", false);
        assert!(requests(&mut ui).is_empty());
        reply(&mut ui, r[0].clone(), GroupResponse::Done {});
        assert_eq!(ui.take_notices().len(), 1, "the joined toast");
        assert!(ui.list_dirty, "the list is read again");
        ui.answer_invitation("g2", "group g2", false);
        let r = requests(&mut ui);
        assert!(matches!(r.as_slice(), [GroupRequest::Decline { group }] if group == "g2"));
        // A failure is kept to be shown on the card.
        ui.on_reply(&r[0], Err(ChatFail::NotSupported));
        assert!(ui.page_msg.is_some());
        assert!(ui.acting.is_none(), "the buttons come back");
    }

    #[test]
    fn the_setting_is_sent_to_the_running_service() {
        let mut ui = ready();
        ui.set_auto_join(false);
        let r = requests(&mut ui);
        assert!(matches!(
            r.as_slice(),
            [GroupRequest::Settings {
                auto_join: Some(false)
            }]
        ));
        // The service's answer changes nothing on screen and an old service's error is silent.
        reply(
            &mut ui,
            r[0].clone(),
            GroupResponse::Settings { auto_join: false },
        );
        ui.on_reply(&r[0], Err(ChatFail::NotSupported));
        assert!(ui.page_msg.is_none());
    }

    #[test]
    fn answers_for_a_group_that_was_left_are_dropped() {
        let mut ui = opened(true);
        ui.close();
        reply(
            &mut ui,
            GroupRequest::History {
                group: "g1".into(),
                before: None,
                limit: Some(50),
            },
            GroupResponse::History {
                group: info("g1", "joined", 3, 2, 1),
                messages: vec![message(1, false, false)],
            },
        );
        assert!(ui.messages.is_empty());
        reply(
            &mut ui,
            GroupRequest::Show { group: "g1".into() },
            GroupResponse::Detail(detail("joined", true)),
        );
        assert!(ui.detail.is_none());
    }

    #[test]
    fn a_group_that_no_longer_exists_closes_the_view() {
        let mut ui = opened(true);
        let req = GroupRequest::Show { group: "g1".into() };
        reply(
            &mut ui,
            req,
            GroupResponse::Error {
                kind: "unknown_group".into(),
                message: String::new(),
            },
        );
        assert!(!ui.is_open());
    }

    #[test]
    fn older_messages_widen_the_window_up_to_the_service_page() {
        let mut ui = opened(true);
        ui.limit = PAGE;
        ui.messages = (1..=PAGE as u64).map(|i| message(i, false, true)).collect();
        // The button is shown while a full page came back; pressing it asks for more.
        ui.limit = (ui.limit + PAGE).min(MAX_WINDOW);
        ui.thread_dirty = true;
        ui.tick(true);
        let r = requests(&mut ui);
        assert!(r.iter().any(|x| matches!(
            x,
            GroupRequest::History {
                limit: Some(100),
                before: None,
                ..
            }
        )));
        assert_eq!(MAX_WINDOW, 200);
    }

    #[test]
    fn a_draft_is_kept_per_group_while_another_is_open() {
        let mut ui = opened(true);
        ui.composer = "unsent".into();
        ui.open_group("g3", "Team g3");
        assert!(ui.composer.is_empty());
        ui.open_group("g1", "Team g1");
        assert_eq!(ui.composer, "unsent");
    }

    #[test]
    fn leaving_the_tab_lets_go_of_the_messages() {
        let mut ui = opened(true);
        ui.on_area_closed();
        assert!(ui.messages.is_empty() && !ui.thread_loaded);
        assert!(
            ui.is_open(),
            "the open group is shown again when the tab returns"
        );
    }

    // ── Drawing ──────────────────────────────────────────────────────────

    fn clock() -> Clock {
        Clock {
            now_ms: 1_792_074_600_000,
            utc_offset_secs: 0,
        }
    }

    fn contacts() -> Vec<ContactInfo> {
        ["a", "b", "c"]
            .iter()
            .map(|n| ContactInfo {
                id: (*n).into(),
                label: format!("Contact {n}"),
                endpoint_id: format!("ep-{n}"),
                fingerprint: String::new(),
                added_at: 0,
                allow_send: *n != "c",
                allow_receive: true,
                max_file_size: None,
                default_max_file_size: 0,
                inbox_dir: String::new(),
            })
            .collect()
    }

    #[test]
    fn every_screen_draws_without_panicking_at_both_widths_in_every_language() {
        for (w, h) in [(700.0, 900.0), (1400.0, 900.0)] {
            for locale in Locale::ALL {
                for screen in [
                    "list",
                    "thread",
                    "info",
                    "info_member",
                    "left",
                    "invited",
                    "form",
                    "add",
                    "confirm",
                    "waiting",
                    "waiting_info",
                ] {
                    let mut ui = match screen {
                        "list" => ready(),
                        "waiting" | "waiting_info" => {
                            let mut u = opened(true);
                            let d = u.detail.as_mut().unwrap();
                            d.added_by = Some("amy".into());
                            d.members[1].status = Some("invited".into());
                            d.members[2].status = Some("unreachable".into());
                            d.members[2].reason = Some("not_allowed".into());
                            let mut extra = member("dee", false, true, false);
                            extra.status = Some("no_group_support".into());
                            d.members.push(extra);
                            u.info_open = screen == "waiting_info";
                            u
                        }
                        "invited" => {
                            let mut u = ready();
                            u.open_group("g2", "Team g2");
                            u
                        }
                        "left" => {
                            let mut u = opened(true);
                            u.rows[0].status = GroupStatus::Left;
                            u.detail = Some(detail("left", true));
                            u.info_open = true;
                            u
                        }
                        "info_member" => {
                            let mut u = opened(false);
                            u.info_open = true;
                            u
                        }
                        "info" => {
                            let mut u = opened(true);
                            u.info_open = true;
                            u
                        }
                        "form" => {
                            let mut u = ready();
                            u.open_new_group();
                            u.form.as_mut().unwrap().tick("a", true);
                            u.form_msg = Some("x".into());
                            u
                        }
                        "add" => {
                            let mut u = opened(true);
                            u.add = Some(Picks::default());
                            u
                        }
                        "confirm" => {
                            let mut u = opened(true);
                            u.confirm = Some(Confirm::Remove {
                                endpoint_id: "bob".into(),
                                who: "Bob".into(),
                            });
                            u
                        }
                        _ => opened(true),
                    };
                    ui.set_locale(locale);
                    let list = contacts();
                    let ctx = egui::Context::default();
                    kit::apply_theme(&ctx, false);
                    for _ in 0..3 {
                        let input = egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::pos2(0.0, 0.0),
                                vec2(w, h),
                            )),
                            ..Default::default()
                        };
                        let _ = ctx.run(input, |ctx| {
                            egui::CentralPanel::default().show(ctx, |panel| {
                                kit::column(panel, |panel| {
                                    if ui.is_open() {
                                        let _ = ui.conversation_view(panel, clock(), 4096);
                                    } else {
                                        ui.invitation_cards(panel, &list);
                                        for i in 0..ui.rows().len() {
                                            let _ = ui.row(panel, i, clock());
                                        }
                                    }
                                });
                            });
                            ui.dialogs(ctx, &list);
                        });
                    }
                    // Drawing asks the service for nothing.
                    assert!(requests(&mut ui).is_empty(), "{screen} {locale:?}");
                }
            }
        }
    }
}
