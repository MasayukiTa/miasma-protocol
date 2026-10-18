//! The Chat area: one-to-one messages between registered contacts.
//!
//! Everything the service knows (conversations, messages, status, events) is read through
//! `WorkerCmd::Chat` on the worker thread; this file never touches the network or the disk. The
//! screen asks only while the Chat tab is open or a send is in flight (a light poll for unread
//! counts otherwise), keeps a bounded window of the open conversation in memory, and lays out
//! only the rows that are on screen. The pure decisions are in `chat.rs`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use eframe::egui::{self, vec2, Align, Layout, RichText, Sense, Stroke};
use miasma_core::chat::ipc::{ConversationInfo, MessageInfo};
use miasma_core::chat::{ChatRequest, ChatResponse};
use miasma_core::push::ContactInfo;

use crate::chat::*;
use crate::contacts::{ContactsUi, FileStatus, SentFile};
use crate::locale::{ChatStrings, ContactStrings};
use crate::theme::{self, Palette};
use crate::transfers::fill;
use crate::ui_kit::{self as kit, Level};
use crate::ux::{confirm, Answer};
use crate::worker::ChatFail;

fn pal() -> Palette {
    theme::palette()
}

const EVENTS_OPEN: Duration = Duration::from_millis(500);
const EVENTS_CLOSED: Duration = Duration::from_secs(5);
const LIST_EVERY: Duration = Duration::from_secs(3);
const NEWEST_BUSY: Duration = Duration::from_secs(1);
const RETRY_OPEN: Duration = Duration::from_secs(5);
const RETRY_CLOSED: Duration = Duration::from_secs(30);
/// An answer that has not come back after this long is asked for again.
const STALE: Duration = Duration::from_secs(20);
/// Height of a conversation row.
const ROW_H: f32 = 62.0;
/// Room kept under the message list for the composer and its hints.
const COMPOSER_RESERVE: f32 = 190.0;
/// A row this far outside the visible part of the list is skipped, not laid out.
const CULL_MARGIN: f32 = 240.0;
/// The service's default limit of one message, until its status says otherwise.
const DEFAULT_MAX_BYTES: usize = 4096;
/// The shortest time between two asks for a read receipt.
const READ_EVERY: Duration = Duration::from_secs(2);
/// Contacts whose read point is remembered (cleared above it).
const MAX_READ_ASKED: usize = 200;
/// Drafts remembered while another conversation is open.
const MAX_DRAFTS: usize = 20;

/// What the app does on behalf of the chat screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatAction {
    /// Go to the Contacts tab.
    OpenContacts,
    /// Pick files and send them to this contact (the Contacts tab's own flow).
    SendFiles(String),
    /// Send this file to this contact again (a file line that did not go through).
    RetryFile { contact_id: String, path: String },
}

#[derive(Debug, Clone)]
struct Open {
    contact_id: String,
    endpoint_id: String,
    label: String,
}

#[derive(Debug, Clone)]
enum View {
    List,
    Conversation(Open),
}

pub struct ChatUi {
    /// Set by the window from the daemon status: the home relay is not connected, so a waiting
    /// message is waiting on this computer, not on the other person.
    pub relay_down: bool,
    availability: Availability,
    was_connected: bool,
    initial_sent: bool,
    area_open: bool,

    history_saved: bool,
    max_bytes: usize,

    conversations: Vec<ConversationInfo>,
    conv_loaded: bool,
    rows: Vec<ListRow>,
    previews: HashMap<String, Preview>,
    preview_inflight: HashSet<String>,

    view: View,
    window: MessageWindow,
    thread_loaded: bool,
    notes: HashMap<String, Vec<FileNote>>,
    /// Where each file note stands (by note id), read from the push rows every frame.
    file_states: HashMap<String, FileStatus>,
    /// A button on a file line was pressed; handed to the app at the end of the frame.
    file_action: Option<ChatAction>,
    timeline: Vec<Entry>,
    timeline_dirty: bool,
    heights: HashMap<String, f32>,
    heights_width: f32,
    wrap_px: f32,
    scroll_to: Option<f32>,
    scroll_offset: f32,

    composer: String,
    drafts: HashMap<String, String>,
    focus_composer: bool,
    ime_composing: bool,
    picker_open: bool,
    delete_target: Option<Open>,
    deleting: Option<(String, String)>,
    page_msg: Option<String>,

    unread: Unread,
    /// Read receipts in effect per contact (endpoint ID), as the service last said.
    receipts: HashMap<String, bool>,
    /// The global read-receipt setting (`chat.read_receipts`); on until the service says otherwise.
    receipts_global: bool,
    /// Per contact: the newest received number a read receipt was already asked for.
    read_asked: HashMap<String, u64>,
    read_inflight: Option<Instant>,
    last_read_ask: Option<Instant>,
    event_cursor: Option<u64>,
    want_newest: bool,
    list_dirty: bool,
    sends_in_flight: u32,
    send_kinds: VecDeque<Option<String>>,

    out: VecDeque<ChatRequest>,
    status_inflight: Option<Instant>,
    events_inflight: Option<Instant>,
    list_inflight: Option<Instant>,
    newest_inflight: Option<Instant>,
    older_inflight: Option<Instant>,
    last_try: Instant,
    last_events: Instant,
    last_list: Instant,
    last_newest: Instant,

    notices: Vec<String>,
    clock_override: Option<Clock>,
    /// Dev-only screenshot fixtures: show what was set up, never ask the service.
    frozen: bool,
}

impl Default for ChatUi {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            relay_down: false,
            availability: Availability::Unknown,
            was_connected: false,
            initial_sent: false,
            area_open: false,
            history_saved: true,
            max_bytes: DEFAULT_MAX_BYTES,
            conversations: Vec::new(),
            conv_loaded: false,
            rows: Vec::new(),
            previews: HashMap::new(),
            preview_inflight: HashSet::new(),
            view: View::List,
            window: MessageWindow::default(),
            thread_loaded: false,
            notes: HashMap::new(),
            file_states: HashMap::new(),
            file_action: None,
            timeline: Vec::new(),
            timeline_dirty: false,
            heights: HashMap::new(),
            heights_width: 0.0,
            wrap_px: 400.0,
            scroll_to: None,
            scroll_offset: 0.0,
            composer: String::new(),
            drafts: HashMap::new(),
            focus_composer: false,
            ime_composing: false,
            picker_open: false,
            delete_target: None,
            deleting: None,
            page_msg: None,
            unread: Unread::default(),
            receipts: HashMap::new(),
            receipts_global: true,
            read_asked: HashMap::new(),
            read_inflight: None,
            last_read_ask: None,
            event_cursor: None,
            want_newest: false,
            list_dirty: false,
            sends_in_flight: 0,
            send_kinds: VecDeque::new(),
            out: VecDeque::new(),
            status_inflight: None,
            events_inflight: None,
            list_inflight: None,
            newest_inflight: None,
            older_inflight: None,
            last_try: now,
            last_events: now,
            last_list: now,
            last_newest: now,
            notices: Vec::new(),
            clock_override: None,
            frozen: false,
        }
    }
}

fn stale(t: Option<Instant>) -> Option<Instant> {
    t.filter(|t| t.elapsed() <= STALE)
}

impl ChatUi {
    // ─── Seen from the app ──────────────────────────────────────────────────

    /// New arrivals the navigation item still announces.
    pub fn unseen(&self) -> u32 {
        self.unread.unseen()
    }

    /// The Chat area is open: the arrivals are seen (the badges of single conversations stay).
    pub fn mark_seen(&mut self) {
        self.unread.mark_seen();
    }

    /// Texts for the app's toast, oldest first.
    pub fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
    }

    /// Hand queued requests to the worker; stops at the first one the channel does not take.
    pub fn drain(&mut self, mut try_send: impl FnMut(ChatRequest) -> bool) {
        while let Some(req) = self.out.front().cloned() {
            if try_send(req) {
                self.out.pop_front();
            } else {
                break;
            }
        }
    }

    /// Files were queued for `contact_id` from this screen: remember them for the conversation
    /// and its preview.
    pub fn note_files_sent(&mut self, contact_id: &str, files: &[SentFile]) {
        if files.is_empty() {
            return;
        }
        if self.notes.len() >= 50 && !self.notes.contains_key(contact_id) {
            self.notes.clear();
        }
        let list = self.notes.entry(contact_id.to_owned()).or_default();
        push_notes(list, files, now_ms());
        self.timeline_dirty = true;
        self.list_dirty = true;
    }

    /// Read where each file line stands from the push rows. A line whose state changed is drawn
    /// again at its new height.
    pub fn refresh_file_states(&mut self, contacts: &ContactsUi, ct: &ContactStrings) {
        let mut live: HashSet<&str> = HashSet::new();
        for (cid, notes) in &self.notes {
            for n in notes {
                live.insert(n.id.as_str());
                if n.path.is_empty() {
                    continue;
                }
                let now = contacts.file_status(ct, cid, &n.path, n.at_ms);
                if self.file_states.get(&n.id) != Some(&now) {
                    self.heights.remove(&n.id);
                    self.file_states.insert(n.id.clone(), now);
                }
            }
        }
        self.file_states.retain(|k, _| live.contains(k.as_str()));
    }

    fn clock(&self) -> Clock {
        self.clock_override.unwrap_or(Clock {
            now_ms: now_ms(),
            utc_offset_secs: local_utc_offset_secs(),
        })
    }

    fn open(&self) -> Option<&Open> {
        match &self.view {
            View::Conversation(o) => Some(o),
            View::List => None,
        }
    }

    fn is_open_endpoint(&self, endpoint: &str) -> bool {
        self.open().is_some_and(|o| o.endpoint_id == endpoint)
    }

    // ─── Asking ─────────────────────────────────────────────────────────────

    /// Ask for more data when it is due. Cheap: with the area closed this is one small request
    /// every 5 s (so arrivals are counted); with it open, every 500 ms for the open
    /// conversation and every 3 s for the list.
    pub fn tick(&mut self, area_open: bool, connected: bool) {
        if self.frozen {
            self.area_open = area_open;
            return;
        }
        let was_open = self.area_open;
        self.area_open = area_open;
        if connected && !self.was_connected {
            // (Re)connected: read everything again.
            self.initial_sent = false;
            self.status_inflight = None;
            self.events_inflight = None;
            self.list_inflight = None;
            self.newest_inflight = None;
            self.older_inflight = None;
            self.preview_inflight.clear();
            self.event_cursor = None;
            self.availability = Availability::Unknown;
        }
        self.was_connected = connected;
        if was_open && !area_open {
            self.on_area_closed();
        }
        if !connected {
            return;
        }
        let now = Instant::now();
        self.status_inflight = stale(self.status_inflight);
        self.events_inflight = stale(self.events_inflight);
        self.list_inflight = stale(self.list_inflight);
        self.newest_inflight = stale(self.newest_inflight);
        self.older_inflight = stale(self.older_inflight);

        if !self.initial_sent {
            self.initial_sent = true;
            self.last_try = now;
            self.ask_status(now);
            self.ask_events(now);
            return;
        }
        if self.availability != Availability::Ok {
            // Not usable: look again now and then (the service may have been started meanwhile).
            let every = if area_open { RETRY_OPEN } else { RETRY_CLOSED };
            if now.duration_since(self.last_try) >= every && self.status_inflight.is_none() {
                self.last_try = now;
                self.ask_status(now);
                if self.event_cursor.is_none() {
                    self.ask_events(now);
                }
            }
            return;
        }
        if !was_open && area_open {
            // Just opened: everything on screen is due at once.
            self.list_dirty = true;
            self.thread_loaded = false;
            if self.status_inflight.is_none() {
                self.ask_status(now);
            }
        }
        let every = if area_open {
            EVENTS_OPEN
        } else {
            EVENTS_CLOSED
        };
        if self.events_inflight.is_none() && now.duration_since(self.last_events) >= every {
            self.ask_events(now);
        }
        if !area_open {
            return;
        }
        match &self.view {
            View::List => {
                if self.list_inflight.is_none()
                    && (self.list_dirty || now.duration_since(self.last_list) >= LIST_EVERY)
                {
                    self.list_dirty = false;
                    self.last_list = now;
                    self.list_inflight = Some(now);
                    self.out.push_back(ChatRequest::Conversations {});
                }
            }
            View::Conversation(o) => {
                if self.newest_inflight.is_none() && !self.window.is_detached() {
                    let busy = self.window.has_unfinished() || self.sends_in_flight > 0;
                    let due = !self.thread_loaded
                        || self.want_newest
                        || (busy && now.duration_since(self.last_newest) >= NEWEST_BUSY);
                    if due {
                        self.want_newest = false;
                        self.last_newest = now;
                        self.newest_inflight = Some(now);
                        self.out.push_back(ChatRequest::History {
                            contact: o.endpoint_id.clone(),
                            before: None,
                            limit: Some(PAGE),
                        });
                    }
                }
            }
        }
    }

    fn ask_status(&mut self, now: Instant) {
        self.status_inflight = Some(now);
        self.out.push_back(ChatRequest::Status {});
    }

    fn ask_events(&mut self, now: Instant) {
        self.events_inflight = Some(now);
        self.last_events = now;
        self.out.push_back(ChatRequest::Events {
            // The first question only learns where the numbers are now.
            since: self.event_cursor.unwrap_or(u64::MAX),
        });
    }

    /// The tab was left: let go of the open conversation's messages (they are read again when
    /// the tab comes back).
    fn on_area_closed(&mut self) {
        self.window.clear();
        self.heights.clear();
        self.timeline.clear();
        self.timeline_dirty = false;
        self.thread_loaded = false;
        self.scroll_to = None;
        self.scroll_offset = 0.0;
        self.rows.clear();
        self.conversations.clear();
        self.conv_loaded = false;
        self.previews.clear();
        self.preview_inflight.clear();
        self.page_msg = None;
        self.picker_open = false;
        self.delete_target = None;
        self.read_inflight = None;
    }

    // ─── Answers ────────────────────────────────────────────────────────────

    /// Process the service's answer to a request this screen made.
    pub fn on_reply(
        &mut self,
        c: &ChatStrings,
        req: ChatRequest,
        reply: Result<ChatResponse, ChatFail>,
    ) {
        if self.frozen {
            return;
        }
        match &req {
            ChatRequest::Events { .. } => self.events_inflight = None,
            ChatRequest::Conversations {} => self.list_inflight = None,
            ChatRequest::Status {} => self.status_inflight = None,
            ChatRequest::MarkRead { .. } => self.read_inflight = None,
            ChatRequest::History {
                contact,
                before,
                limit,
            } => {
                if before.is_none() && *limit == Some(1) {
                    self.preview_inflight.remove(contact);
                } else if before.is_some() {
                    self.older_inflight = None;
                } else {
                    self.newest_inflight = None;
                }
            }
            _ => {}
        }
        match reply {
            Ok(resp) => self.on_answer(c, &req, resp),
            Err(f) => {
                self.availability = match f {
                    ChatFail::DaemonDown => Availability::DaemonDown,
                    ChatFail::NotSupported => Availability::OldDaemon,
                    ChatFail::Other => self.availability,
                };
                if let ChatRequest::Send { text, .. } = &req {
                    self.send_failed(text, c.err_other);
                }
            }
        }
    }

    /// A send got no answer or an error: nothing is lost, the text goes back into the composer.
    fn send_failed(&mut self, text: &str, why: &str) {
        self.sends_in_flight = self.sends_in_flight.saturating_sub(1);
        self.send_kinds.pop_front();
        if self.composer.trim().is_empty() {
            self.composer = text.to_owned();
        }
        self.page_msg = Some(why.to_owned());
    }

    fn on_answer(&mut self, c: &ChatStrings, req: &ChatRequest, resp: ChatResponse) {
        match resp {
            ChatResponse::Error { kind, .. } => {
                if kind == "unavailable" {
                    self.availability = Availability::NoChat;
                }
                match req {
                    ChatRequest::Send { text, .. } => {
                        self.send_failed(text, error_text(c, &kind));
                    }
                    ChatRequest::Events { .. }
                    | ChatRequest::Conversations {}
                    | ChatRequest::MarkRead { .. } => {}
                    _ => {
                        if kind != "unavailable" {
                            self.page_msg = Some(error_text(c, &kind).to_owned());
                        }
                    }
                }
            }
            ChatResponse::Status(s) => {
                self.availability = Availability::Ok;
                self.history_saved = s.history_saved;
                self.max_bytes = (s.max_message_bytes as usize).max(1);
                self.receipts_global = s.read_receipts;
            }
            ChatResponse::ReadMarked { disabled, wait, .. } => {
                // Asked once per advance; "too soon" is asked again later.
                if let ChatRequest::MarkRead { contact, up_to_seq } = req {
                    if !wait {
                        if self.read_asked.len() >= MAX_READ_ASKED {
                            self.read_asked.clear();
                        }
                        self.read_asked.insert(contact.clone(), *up_to_seq);
                    }
                    if disabled {
                        self.receipts.insert(contact.clone(), false);
                    }
                }
            }
            ChatResponse::ReceiptsSet { enabled } => {
                if let ChatRequest::SetReadReceipts { contact, .. } = req {
                    self.receipts.insert(contact.clone(), enabled);
                    // Switched on again: what was seen meanwhile may be reported now.
                    self.read_asked.remove(contact);
                }
                self.list_dirty = true;
                self.want_newest = true;
            }
            ChatResponse::Conversations(list) => {
                self.availability = Availability::Ok;
                self.on_conversations(list);
            }
            ChatResponse::History {
                endpoint_id,
                messages,
                ..
            } => {
                self.availability = Availability::Ok;
                let ChatRequest::History { before, limit, .. } = req else {
                    return;
                };
                if before.is_none() && *limit == Some(1) {
                    let key = self
                        .conversations
                        .iter()
                        .find(|x| x.endpoint_id == endpoint_id)
                        .map(PreviewKey::of);
                    if let Some(key) = key {
                        self.previews.insert(
                            endpoint_id,
                            Preview {
                                key,
                                last: last_of(&messages),
                            },
                        );
                    }
                } else if !self.is_open_endpoint(&endpoint_id) {
                    // The person went elsewhere meanwhile.
                } else if before.is_some() {
                    let added = self.window.apply_older(messages, limit.unwrap_or(PAGE));
                    let spacing = kit::SP_2;
                    let grown: f32 = added.iter().map(|m| self.estimate(m) + spacing).sum();
                    self.scroll_to = Some(self.scroll_offset + grown);
                    self.timeline_dirty = true;
                } else {
                    self.window.apply_newest(messages, limit.unwrap_or(PAGE));
                    self.thread_loaded = true;
                    self.timeline_dirty = true;
                }
            }
            ChatResponse::Queued { .. } => {
                self.sends_in_flight = self.sends_in_flight.saturating_sub(1);
                // A message that replaces a failed one: the failed one goes now it is queued.
                if let (Some(Some(old)), ChatRequest::Send { contact, .. }) =
                    (self.send_kinds.pop_front(), req)
                {
                    self.out.push_back(ChatRequest::DeleteLocal {
                        contact: contact.clone(),
                        message_id: Some(old),
                    });
                }
                self.want_newest = true;
                self.list_dirty = true;
            }
            ChatResponse::Deleted { .. } => {
                if let ChatRequest::DeleteLocal { message_id, .. } = req {
                    if message_id.is_some() {
                        self.want_newest = true;
                    } else if let Some((endpoint, label)) = self.deleting.take() {
                        self.previews.remove(&endpoint);
                        if self.is_open_endpoint(&endpoint) {
                            self.window.clear();
                            self.heights.clear();
                            self.timeline_dirty = true;
                            self.thread_loaded = true;
                        }
                        self.notices
                            .push(fill(c.delete_done, &[("name", &elide(&label, NAME_CHARS))]));
                    }
                }
                self.list_dirty = true;
            }
            ChatResponse::Events { next, events } => {
                self.availability = Availability::Ok;
                let baseline = self.event_cursor.is_none();
                // A restarted service counts from the start again.
                self.event_cursor = Some(next);
                if baseline {
                    return;
                }
                for ev in events {
                    self.list_dirty = true;
                    if ev.kind == "received" {
                        let viewing = self.area_open && self.is_open_endpoint(&ev.endpoint_id);
                        self.unread
                            .on_received(&ev.endpoint_id, viewing, self.area_open);
                    }
                    if self.is_open_endpoint(&ev.endpoint_id) {
                        self.want_newest = true;
                    }
                }
            }
            // Group chat has no screen yet; the command line uses it.
            ChatResponse::Group(_) => {}
        }
    }

    fn on_conversations(&mut self, list: Vec<ConversationInfo>) {
        for c in &list {
            self.receipts.insert(c.endpoint_id.clone(), c.read_receipts);
        }
        self.conversations = list;
        self.conv_loaded = true;
        self.rows = list_rows(&self.conversations);
        let keep: HashSet<&str> = self
            .conversations
            .iter()
            .map(|x| x.endpoint_id.as_str())
            .collect();
        self.previews.retain(|k, _| keep.contains(k.as_str()));
        self.unread.retain_peers(|k| keep.contains(k));
        // The last message of each conversation that changed (the first screenful only).
        let mut wanted = Vec::new();
        for r in self.rows.iter().take(MAX_PREVIEWS) {
            let Some(conv) = self
                .conversations
                .iter()
                .find(|x| x.endpoint_id == r.endpoint_id)
            else {
                continue;
            };
            let fresh = self
                .previews
                .get(&r.endpoint_id)
                .is_some_and(|p| p.key == PreviewKey::of(conv));
            if !fresh && !self.preview_inflight.contains(&r.endpoint_id) {
                wanted.push(r.endpoint_id.clone());
            }
        }
        for ep in wanted {
            self.preview_inflight.insert(ep.clone());
            self.out.push_back(ChatRequest::History {
                contact: ep,
                before: None,
                limit: Some(1),
            });
        }
    }

    fn estimate(&self, m: &MessageInfo) -> f32 {
        estimate_row_height(
            m.text.chars().count(),
            m.text.matches('\n').count(),
            self.wrap_px,
            m.outgoing && m.state == "failed",
        )
    }

    // ─── Read receipts ──────────────────────────────────────────────────────

    /// Receipts are in effect with this contact (the setting and the contact's own switch).
    fn receipts_on(&self, endpoint: &str) -> bool {
        self.receipts_global && self.receipts.get(endpoint).copied().unwrap_or(true)
    }

    /// Switch receipts for one contact now (the answer confirms it).
    fn set_receipts(&mut self, endpoint: &str, enabled: bool) {
        self.receipts.insert(endpoint.to_owned(), enabled);
        self.out.push_back(ChatRequest::SetReadReceipts {
            contact: endpoint.to_owned(),
            enabled,
        });
    }

    /// The open conversation shows received messages up to number `seen` right now. A read receipt
    /// is asked for only when the window is in front, the Chat tab is open, receipts are on, the
    /// number is new and the last ask was a moment ago: never for what merely arrived.
    fn note_seen(&mut self, endpoint: &str, seen: u64, window_focused: bool) {
        if self.frozen || !window_focused || !self.area_open || seen == 0 {
            return;
        }
        if !self.receipts_on(endpoint) {
            return;
        }
        if self.read_asked.get(endpoint).is_some_and(|&n| n >= seen) {
            return;
        }
        self.read_inflight = stale(self.read_inflight);
        if self.read_inflight.is_some() {
            return;
        }
        if self.last_read_ask.is_some_and(|t| t.elapsed() < READ_EVERY) {
            return;
        }
        let now = Instant::now();
        self.read_inflight = Some(now);
        self.last_read_ask = Some(now);
        self.out.push_back(ChatRequest::MarkRead {
            contact: endpoint.to_owned(),
            up_to_seq: seen,
        });
    }

    // ─── Actions ────────────────────────────────────────────────────────────

    fn open_conversation(&mut self, contact_id: &str, endpoint_id: &str, label: &str) {
        self.stash_draft();
        self.view = View::Conversation(Open {
            contact_id: contact_id.to_owned(),
            endpoint_id: endpoint_id.to_owned(),
            label: label.to_owned(),
        });
        self.window.clear();
        self.heights.clear();
        self.timeline.clear();
        self.timeline_dirty = true;
        self.thread_loaded = false;
        self.scroll_to = None;
        self.scroll_offset = 0.0;
        self.newest_inflight = None;
        self.older_inflight = None;
        self.want_newest = true;
        self.composer = self.drafts.remove(contact_id).unwrap_or_default();
        self.focus_composer = true;
        self.page_msg = None;
        self.unread.open(endpoint_id);
    }

    fn close_conversation(&mut self) {
        self.stash_draft();
        self.view = View::List;
        self.window.clear();
        self.heights.clear();
        self.timeline.clear();
        self.thread_loaded = false;
        self.page_msg = None;
        self.list_dirty = true;
    }

    /// Keep what was typed for the conversation being left (a few of them, in memory only).
    fn stash_draft(&mut self) {
        let Some(o) = self.open() else {
            return;
        };
        let id = o.contact_id.clone();
        if self.composer.trim().is_empty() {
            self.drafts.remove(&id);
        } else {
            if self.drafts.len() >= MAX_DRAFTS && !self.drafts.contains_key(&id) {
                self.drafts.clear();
            }
            let mut text = std::mem::take(&mut self.composer);
            cap_text(&mut text, composer_cap(self.max_bytes));
            self.drafts.insert(id, text);
        }
        self.composer.clear();
    }

    fn submit(&mut self, c: &ChatStrings) {
        let Some(o) = self.open().cloned() else {
            return;
        };
        match prepare_send(&self.composer, self.max_bytes) {
            Err(SendBlock::Empty) => {}
            Err(SendBlock::TooLong) => self.page_msg = Some(c.too_long_note.to_owned()),
            Ok(text) => {
                if self.window.is_detached() {
                    // Sending goes to the newest end.
                    self.window.jump_to_latest();
                    self.heights.clear();
                    self.timeline_dirty = true;
                    self.thread_loaded = false;
                }
                self.page_msg = None;
                self.composer.clear();
                self.sends_in_flight += 1;
                self.send_kinds.push_back(None);
                self.out.push_back(ChatRequest::Send {
                    contact: o.contact_id,
                    text,
                });
            }
        }
    }

    /// "Send again" on a failed message: queue its text again; the failed one goes once that is
    /// queued.
    fn retry(&mut self, failed_id: &str, text: &str) {
        let Some(o) = self.open().cloned() else {
            return;
        };
        self.sends_in_flight += 1;
        self.send_kinds.push_back(Some(failed_id.to_owned()));
        self.out.push_back(ChatRequest::Send {
            contact: o.contact_id,
            text: text.to_owned(),
        });
    }

    fn delete_history(&mut self, o: &Open) {
        self.deleting = Some((o.endpoint_id.clone(), o.label.clone()));
        self.out.push_back(ChatRequest::DeleteLocal {
            contact: o.endpoint_id.clone(),
            message_id: None,
        });
    }

    // ─── Drawing ────────────────────────────────────────────────────────────

    /// Draw the whole area. `contacts` is the Contacts tab's list (names, who may be sent to).
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        c: &ChatStrings,
        connected: bool,
        contacts: &[ContactInfo],
    ) -> Option<ChatAction> {
        let mut action = None;
        if !connected || self.availability == Availability::DaemonDown {
            self.heading(ui, c, |_| {});
            self.notice_card(ui, c.daemon_down, Level::Warn, None, c);
            return None;
        }
        match self.availability {
            Availability::NoChat => {
                self.heading(ui, c, |_| {});
                self.notice_card(ui, c.unavailable, Level::Warn, Some(c.retry_now), c);
                return None;
            }
            Availability::OldDaemon => {
                self.heading(ui, c, |_| {});
                self.notice_card(ui, c.old_daemon, Level::Warn, Some(c.retry_now), c);
                return None;
            }
            Availability::Unknown => {
                self.heading(ui, c, |_| {});
                ui.label(RichText::new(c.loading).color(pal().muted));
                return None;
            }
            _ => {}
        }
        match self.view.clone() {
            View::List => self.list_view(ui, c, contacts, &mut action),
            View::Conversation(o) => self.conversation_view(ui, c, contacts, &o, &mut action),
        }
        self.picker_dialog(ui.ctx(), c, contacts);
        self.delete_dialog(ui.ctx(), c);
        if action.is_none() {
            action = self.file_action.take();
        }
        action
    }

    fn heading(&self, ui: &mut egui::Ui, c: &ChatStrings, actions: impl FnOnce(&mut egui::Ui)) {
        kit::page_actions(ui, c.heading, Some(c.desc), actions, |_| {});
    }

    fn notice_card(
        &mut self,
        ui: &mut egui::Ui,
        text: &str,
        level: Level,
        retry: Option<&str>,
        _c: &ChatStrings,
    ) {
        kit::surface(ui, |ui| {
            kit::notice(ui, level, text);
            if let Some(label) = retry {
                ui.add_space(kit::SP_2);
                if ui.add(kit::secondary_button(label)).clicked() {
                    self.initial_sent = false;
                    self.availability = Availability::Unknown;
                }
            }
        });
    }

    fn memory_only_note(&self, ui: &mut egui::Ui, c: &ChatStrings) {
        if !self.history_saved {
            kit::notice(ui, Level::Info, c.memory_only);
            ui.add_space(kit::SP_2);
        }
    }

    // ── The list ─────────────────────────────────────────────────────────

    fn list_view(
        &mut self,
        ui: &mut egui::Ui,
        c: &ChatStrings,
        contacts: &[ContactInfo],
        action: &mut Option<ChatAction>,
    ) {
        let mut new_chat = false;
        kit::page_actions(
            ui,
            c.heading,
            Some(c.desc),
            |ui| {
                let resp = kit::primary(ui, !contacts.is_empty(), c.new_chat);
                resp.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::WidgetType::Button, c.new_chat)
                });
                if resp.clicked() {
                    new_chat = true;
                }
            },
            |_| {},
        );
        if new_chat {
            self.picker_open = true;
        }
        self.memory_only_note(ui, c);
        let clock = self.clock();
        let mut open_row: Option<usize> = None;
        if self.rows.is_empty() {
            if !self.conv_loaded {
                ui.label(RichText::new(c.loading).color(pal().muted));
                return;
            }
            if contacts.is_empty() {
                kit::surface(ui, |ui| {
                    kit::paragraph(ui, c.list_empty_no_contacts);
                    ui.add_space(kit::SP_2);
                    if ui.add(kit::secondary_button(c.open_contacts)).clicked() {
                        *action = Some(ChatAction::OpenContacts);
                    }
                });
            } else {
                kit::surface(ui, |ui| {
                    kit::paragraph(ui, c.list_empty);
                });
            }
            return;
        }
        kit::section(ui, c.list_title, |_| {});
        egui::ScrollArea::vertical()
            .id_source("chat_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for (i, row) in self.rows.iter().enumerate() {
                    let note = self.notes.get(&row.contact_id).and_then(|n| n.last());
                    let stored = self
                        .previews
                        .get(&row.endpoint_id)
                        .map(|p| p.last.clone())
                        .unwrap_or(LastKind::None);
                    let last = effective_last(&stored, row.last_ms, note);
                    let preview = preview_text(c, &last);
                    let when_ms = match (&last, note) {
                        (LastKind::File { .. }, Some(n)) => n.at_ms,
                        _ => row.last_ms,
                    };
                    let when = when_list(c, when_ms, clock);
                    let unread = self.unread.of(&row.endpoint_id);
                    if conversation_row(ui, c, row, &preview, &when, unread).clicked() {
                        open_row = Some(i);
                    }
                }
            });
        if let Some(i) = open_row {
            let r = self.rows[i].clone();
            self.open_conversation(&r.contact_id, &r.endpoint_id, &r.label);
        }
    }

    // ── One conversation ─────────────────────────────────────────────────

    fn conversation_view(
        &mut self,
        ui: &mut egui::Ui,
        c: &ChatStrings,
        contacts: &[ContactInfo],
        o: &Open,
        action: &mut Option<ChatAction>,
    ) {
        let known = contacts.iter().find(|x| x.id == o.contact_id);
        let name = known.map_or(o.label.as_str(), |x| x.label.as_str());
        let send_allowed = known.map(|x| x.allow_send).unwrap_or(true);

        // Header: back, name, and the two things to do with the conversation.
        let mut back = false;
        let mut ask_delete = false;
        let mut send_file = false;
        ui.horizontal_wrapped(|ui| {
            let r = ui.add(kit::secondary_button(c.back));
            r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, c.a11y_back));
            if r.clicked() {
                back = true;
            }
            ui.label(
                RichText::new(elide(name, NAME_CHARS))
                    .text_style(egui::TextStyle::Heading)
                    .color(pal().text),
            )
            .on_hover_text(name);
        });
        let receipts_global = self.receipts_global;
        let receipts_on = self.receipts_on(&o.endpoint_id);
        let mut switch_receipts = false;
        ui.horizontal_wrapped(|ui| {
            let r = ui.add_enabled(send_allowed, kit::secondary_button(c.send_file));
            r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, c.a11y_attach));
            if r.on_hover_text(c.send_file_hint).clicked() {
                send_file = true;
            }
            if receipts_global {
                let label = if receipts_on {
                    c.receipts_on
                } else {
                    c.receipts_off
                };
                let r = ui.add(kit::secondary_button(label));
                r.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::WidgetType::Button, c.a11y_receipts)
                });
                if r.on_hover_text(c.receipts_hint).clicked() {
                    switch_receipts = true;
                }
            }
            if ui.add(kit::danger_button(c.delete_history)).clicked() {
                ask_delete = true;
            }
        });
        if switch_receipts {
            self.set_receipts(&o.endpoint_id, !receipts_on);
        }
        ui.add_space(kit::SP_1);
        if !receipts_global {
            kit::notice(ui, Level::Info, c.receipts_global_off);
            ui.add_space(kit::SP_2);
        }
        self.memory_only_note(ui, c);
        if back {
            self.close_conversation();
            return;
        }
        if send_file {
            *action = Some(ChatAction::SendFiles(o.contact_id.clone()));
        }
        if ask_delete {
            self.delete_target = Some(Open {
                contact_id: o.contact_id.clone(),
                endpoint_id: o.endpoint_id.clone(),
                label: name.to_owned(),
            });
        }

        self.thread_view(ui, c, o);
        if self.window.is_detached() {
            ui.horizontal(|ui| {
                if ui.add(kit::secondary_button(c.jump_latest)).clicked() {
                    self.window.jump_to_latest();
                    self.heights.clear();
                    self.timeline_dirty = true;
                    self.thread_loaded = false;
                    self.scroll_to = Some(f32::MAX);
                }
            });
        }
        if let Some(msg) = self.page_msg.clone() {
            ui.horizontal_wrapped(|ui| {
                kit::notice(ui, Level::Error, &msg);
                if ui.add(kit::compact_button(c.dismiss)).clicked() {
                    self.page_msg = None;
                }
            });
        }
        if send_allowed {
            self.composer_view(ui, c);
        } else {
            kit::notice(ui, Level::Warn, c.send_off_note);
        }
    }

    fn thread_view(&mut self, ui: &mut egui::Ui, c: &ChatStrings, o: &Open) {
        let clock = self.clock();
        let width = ui.available_width();
        if (width - self.heights_width).abs() > 1.0 {
            // A different width wraps differently: measure again as rows come into view.
            self.heights.clear();
            self.heights_width = width;
        }
        let bubble_w = (width * 0.78).clamp(220.0, 640.0);
        self.wrap_px = bubble_w;
        if self.timeline_dirty {
            let notes: &[FileNote] = self
                .notes
                .get(&o.contact_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            self.timeline = merge_timeline(self.window.items(), notes);
            self.timeline_dirty = false;
            // Heights of rows that are gone are forgotten.
            let live: HashSet<&str> = self
                .window
                .items()
                .iter()
                .map(|m| m.id.as_str())
                .chain(notes.iter().map(|n| n.id.as_str()))
                .collect();
            self.heights.retain(|k, _| live.contains(k.as_str()));
        }
        if !self.thread_loaded {
            ui.label(RichText::new(c.loading).color(pal().muted));
        }
        let height = (ui.available_height() - COMPOSER_RESERVE).max(140.0);
        let mut area = egui::ScrollArea::vertical()
            .id_source(("chat_thread", o.endpoint_id.as_str()))
            .max_height(height)
            .auto_shrink([false, false])
            .stick_to_bottom(true);
        if let Some(y) = self.scroll_to.take() {
            area = area.vertical_scroll_offset(y);
        }
        let notes: &[FileNote] = self
            .notes
            .get(&o.contact_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let relay_down = self.relay_down;
        let msgs = self.window.items();
        let timeline = &self.timeline;
        let heights = &mut self.heights;
        let older_loading = self.older_inflight.is_some();
        let has_older = self.window.has_older();
        let thread_loaded = self.thread_loaded;
        let mut retry: Option<(String, String)> = None;
        let mut file_retry: Option<(String, String)> = None;
        let file_states = &self.file_states;
        let contact_id = o.contact_id.clone();
        let mut moved = false;
        // Messages whose rows really overlap the visible part (not the culling margin).
        let mut in_view: Vec<usize> = Vec::new();
        let out = area.show_viewport(ui, |ui, viewport| {
            ui.spacing_mut().item_spacing.y = kit::SP_2;
            let spacing = kit::SP_2;
            if older_loading {
                ui.label(RichText::new(c.loading_older).small().color(pal().muted));
            }
            if timeline.is_empty() && thread_loaded {
                kit::paragraph_muted(ui, c.empty_thread);
            }
            let mut y = 0.0f32;
            for e in timeline {
                let (key, est) = match *e {
                    Entry::Msg(i) => {
                        let m = &msgs[i];
                        (
                            m.id.as_str(),
                            estimate_row_height(
                                m.text.chars().count(),
                                m.text.matches('\n').count(),
                                bubble_w,
                                m.outgoing && m.state == "failed",
                            ),
                        )
                    }
                    Entry::File(i) => (notes[i].id.as_str(), 36.0),
                };
                let h = heights.get(key).copied().unwrap_or(est);
                let visible =
                    y + h >= viewport.min.y - CULL_MARGIN && y <= viewport.max.y + CULL_MARGIN;
                if visible {
                    if let Entry::Msg(i) = *e {
                        if y + h >= viewport.min.y && y <= viewport.max.y {
                            in_view.push(i);
                        }
                    }
                    let r = ui.vertical(|ui| match *e {
                        Entry::Msg(i) => message_row(ui, c, &msgs[i], clock, bubble_w, relay_down),
                        Entry::File(i) => {
                            let st = file_states
                                .get(&notes[i].id)
                                .cloned()
                                .unwrap_or(FileStatus::Waiting);
                            if file_row(ui, c, &notes[i], &st, clock) {
                                file_retry = Some((contact_id.clone(), notes[i].path.clone()));
                            }
                            None
                        }
                    });
                    let measured = r.response.rect.height();
                    if (measured - h).abs() > 1.0 {
                        moved = true;
                    }
                    heights.insert(key.to_owned(), measured);
                    y += measured + spacing;
                    if let (Some(()), Entry::Msg(i)) = (r.inner, *e) {
                        retry = Some((msgs[i].id.clone(), msgs[i].text.clone()));
                    }
                } else {
                    ui.allocate_space(vec2(width, h));
                    y += h + spacing;
                }
            }
        });
        if moved {
            ui.ctx().request_repaint();
        }
        self.scroll_offset = out.state.offset.y;
        // The conversation is on screen with the window in front: what is in view is read.
        if thread_loaded {
            let seen = newest_seen_seq(self.window.items(), &in_view);
            let focused = ui.ctx().input(|i| i.focused);
            self.note_seen(&o.endpoint_id, seen, focused);
        }
        if let Some((id, text)) = retry {
            self.retry(&id, &text);
        }
        if let Some((contact_id, path)) = file_retry {
            self.file_action = Some(ChatAction::RetryFile { contact_id, path });
        }
        // Near the top with more behind it: ask for the next older page.
        if self.thread_loaded
            && self.window.has_older()
            && has_older
            && self.older_inflight.is_none()
            && out.state.offset.y < 80.0
        {
            if let Some(before) = self.window.oldest_ord() {
                self.older_inflight = Some(Instant::now());
                self.out.push_back(ChatRequest::History {
                    contact: o.endpoint_id.clone(),
                    before: Some(before),
                    limit: Some(PAGE),
                });
            }
        }
    }

    fn composer_view(&mut self, ui: &mut egui::Ui, c: &ChatStrings) {
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
        let id = egui::Id::new("chat_composer");
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
                .hint_text(c.composer_hint),
        );
        resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, c.a11y_composer));
        if resp.changed() && cap_text(&mut self.composer, composer_cap(self.max_bytes)) {
            self.page_msg = Some(c.too_long_note.to_owned());
        }
        if self.focus_composer {
            resp.request_focus();
            self.focus_composer = false;
        }
        let ctr = counter(&self.composer, self.max_bytes);
        let can_send = !matches!(ctr.level, CounterLevel::Empty | CounterLevel::Over);
        ui.horizontal_wrapped(|ui| {
            let btn = kit::primary(ui, can_send, c.send);
            btn.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, c.a11y_send));
            let btn = if can_send {
                btn
            } else if ctr.level == CounterLevel::Over {
                btn.on_disabled_hover_text(c.too_long_note)
            } else {
                btn.on_disabled_hover_text(c.send_empty_hint)
            };
            if btn.clicked() {
                submit = true;
            }
            let color = match ctr.level {
                CounterLevel::Over => pal().danger,
                CounterLevel::Near => pal().warning,
                _ => pal().muted,
            };
            ui.label(RichText::new(counter_text(c, &ctr)).small().color(color));
            ui.label(RichText::new(c.composer_keys).small().color(pal().faint));
        });
        if submit && can_send {
            self.submit(c);
            self.focus_composer = true;
        } else if submit && ctr.level == CounterLevel::Over {
            self.page_msg = Some(c.too_long_note.to_owned());
        }
    }

    // ── Dialogs ──────────────────────────────────────────────────────────

    fn delete_dialog(&mut self, ctx: &egui::Context, c: &ChatStrings) {
        let Some(target) = self.delete_target.clone() else {
            return;
        };
        let answer = confirm::show(
            ctx,
            "chat_delete_confirm",
            c.delete_title,
            c.delete_confirm,
            c.delete_cancel,
            |ui| {
                kit::paragraph(
                    ui,
                    &fill(
                        c.delete_body,
                        &[("name", &elide(&target.label, NAME_CHARS))],
                    ),
                );
            },
        );
        match answer {
            Answer::Confirm => {
                self.delete_history(&target);
                self.delete_target = None;
            }
            Answer::Cancel => self.delete_target = None,
            Answer::Pending => {}
        }
    }

    fn picker_dialog(&mut self, ctx: &egui::Context, c: &ChatStrings, contacts: &[ContactInfo]) {
        if !self.picker_open {
            return;
        }
        crate::a11y::dialog_enter(ctx, "chat_picker");
        if crate::a11y::esc_pressed(ctx) {
            self.picker_open = false;
            crate::a11y::dialog_leave(ctx, "chat_picker");
            return;
        }
        let mut chosen: Option<(String, String, String)> = None;
        let mut close = false;
        egui::Window::new(c.pick_title)
            .id(egui::Id::new("chat_picker"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .max_width(440.0)
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                if contacts.is_empty() {
                    kit::paragraph(ui, c.pick_none);
                }
                egui::ScrollArea::vertical()
                    .max_height(320.0)
                    .show(ui, |ui| {
                        for ct in picker_order(contacts) {
                            let r = ui.add_enabled(
                                ct.allow_send,
                                kit::secondary_button(elide(&ct.label, NAME_CHARS)),
                            );
                            let r = if ct.allow_send {
                                r
                            } else {
                                r.on_disabled_hover_text(c.pick_send_off)
                            };
                            if r.clicked() {
                                chosen =
                                    Some((ct.id.clone(), ct.endpoint_id.clone(), ct.label.clone()));
                            }
                        }
                    });
                ui.add_space(kit::SP_1);
                let close_button = ui.add(kit::secondary_button(c.pick_close));
                crate::a11y::dialog_focus_safe_button(ui.ctx(), "chat_picker", &close_button);
                if close_button.clicked() {
                    close = true;
                }
            });
        if let Some((id, endpoint, label)) = chosen {
            self.picker_open = false;
            crate::a11y::dialog_leave(ctx, "chat_picker");
            self.open_conversation(&id, &endpoint, &label);
        } else if close {
            self.picker_open = false;
            crate::a11y::dialog_leave(ctx, "chat_picker");
        }
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

/// One row of the conversation list: name and time, then the last message and the unread badge.
fn conversation_row(
    ui: &mut egui::Ui,
    c: &ChatStrings,
    row: &ListRow,
    preview: &str,
    when: &str,
    unread: u32,
) -> egui::Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(w, ROW_H), Sense::click());
    let name = elide(&row.label, NAME_CHARS);
    let label = {
        let mut s = fill(c.a11y_row, &[("name", &name)]);
        if unread > 0 {
            s.push_str(", ");
            s.push_str(&fill(c.a11y_unread, &[("n", &badge_text(unread))]));
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
        kit::focus_ring(painter, rect.shrink(1.0), 6.0);
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
        let g = single_line(ui, &badge_text(unread), 12.5, p.on_accent(), 60.0);
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

/// One message as an aligned bubble with its time and state. Returns `Some(())` when "send
/// again" was pressed.
fn message_row(
    ui: &mut egui::Ui,
    c: &ChatStrings,
    m: &MessageInfo,
    clock: Clock,
    bubble_w: f32,
    relay_down: bool,
) -> Option<()> {
    let p = pal();
    let own = m.outgoing;
    let delivery = delivery_of(m);
    let layout = if own {
        Layout::right_to_left(Align::Min)
    } else {
        Layout::left_to_right(Align::Min)
    };
    let (fill_color, stroke) = if own {
        (p.selected, Stroke::new(1.0, p.border_strong))
    } else {
        (p.surface, Stroke::new(1.0, p.border))
    };
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
    let when = when_message(c, m.at_ms, clock);
    let state = state_label(c, delivery);
    let state_color = match delivery {
        Delivery::Failed => p.danger,
        Delivery::Delivered | Delivery::Read => p.success,
        _ => p.muted,
    };
    let mut retry = None;
    ui.with_layout(layout, |ui| {
        if let Some(s) = state {
            ui.label(kit::meta_text(s, state_color));
        }
        if !when.is_empty() {
            ui.label(kit::meta_text(when, p.muted));
        }
    });
    match delivery {
        Delivery::Queued => {
            ui.with_layout(layout, |ui| {
                let note = if relay_down {
                    c.queued_note_relay
                } else {
                    c.queued_note
                };
                ui.label(kit::meta_text(note, p.muted));
            });
        }
        Delivery::Failed => {
            ui.with_layout(layout, |ui| {
                ui.set_max_width(bubble_w);
                ui.add(
                    egui::Label::new(kit::meta_text(fail_text(c, m.reason.as_deref()), p.danger))
                        .wrap(true),
                );
            });
            ui.with_layout(layout, |ui| {
                let r = ui.add(kit::secondary_button(c.retry));
                r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, c.retry));
                if r.clicked() {
                    retry = Some(());
                }
            });
        }
        _ => {}
    }
    retry
}

/// A file sent from the chat screen, as a system line: a framed block across the column (not
/// a bubble) that starts with the word "Status", so it is told apart from a message by its
/// shape and its words and not only by colour. It says "sent" only when the push is done.
/// Returns true when "send again" was pressed.
fn file_row(
    ui: &mut egui::Ui,
    c: &ChatStrings,
    note: &FileNote,
    status: &FileStatus,
    clock: Clock,
) -> bool {
    let p = pal();
    let line = format!("{} | {}", c.system_label, file_line(c, &note.name, status));
    let mut retry = false;
    egui::Frame::none()
        .fill(p.surface_subtle)
        .stroke(Stroke::new(1.0, p.border_strong))
        .rounding(6.0)
        .inner_margin(egui::Margin::symmetric(kit::SP_3, kit::SP_2))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(kit::meta_text(line, p.text)).wrap(true));
            if let FileStatus::Failed { reason } = status {
                ui.add(egui::Label::new(kit::meta_text(reason.as_str(), p.danger)).wrap(true));
                if ui.add(kit::secondary_button(c.retry)).clicked() {
                    retry = true;
                }
            }
            let when = when_message(c, note.at_ms, clock);
            if !when.is_empty() {
                ui.label(kit::meta_text(when, p.muted));
            }
        });
    retry
}

// ─── Dev-only screenshot fixtures ───────────────────────────────────────────

/// Fixture names for the `ui-tour` screenshots and the layout unit test.
#[cfg(any(test, feature = "ui-tour"))]
pub const FIXTURES: &[&str] = &[
    "nocontacts",
    "empty",
    "list",
    "thread",
    "long",
    "failed",
    "memory",
    "confirm",
    "picker",
    "notsupported",
];

#[cfg(any(test, feature = "ui-tour"))]
impl ChatUi {
    /// A Chat area filled with fake data (no service). `None` for an unknown name. The contacts
    /// are the ones of `ContactsUi::fixture("two")`: ids `a` and `b`.
    pub fn fixture(name: &str) -> Option<Self> {
        const NOW: u64 = 1_792_074_600_000; // 2026-10-15 14:30 UTC
        const MIN: u64 = 60_000;
        const DAY: u64 = 86_400_000;
        const LONG: &str =
            "株式会社サンプル商事 営業第二部 プロジェクト管理チーム 山田太郎さん（出張中のノートPC）";
        let a_ep = "d9a3f1c07b2e4a58b6c1e0f39a7d5b24c8e61f0a9b3d7c2e5f4a8b1c6d0e3f72";
        let conv = |ep: &str, id: &str, label: &str, last_ms: u64, n: u64, pending: u32| {
            ConversationInfo {
                endpoint_id: ep.into(),
                fingerprint: String::new(),
                label: Some(label.into()),
                contact_id: Some(id.into()),
                messages: n,
                last_ms,
                pending,
                read_receipts: true,
            }
        };
        let msg = |ord: u64, outgoing: bool, state: &str, text: &str, at: u64| MessageInfo {
            ord,
            id: format!("m{ord}-{}", text.len()),
            outgoing,
            seq: ord,
            text: text.into(),
            state: state.into(),
            reason: None,
            sent_ms: at,
            at_ms: at,
        };
        let mut ui = ChatUi {
            frozen: true,
            availability: Availability::Ok,
            conv_loaded: true,
            clock_override: Some(Clock {
                now_ms: NOW,
                utc_offset_secs: 0,
            }),
            ..Default::default()
        };
        let mut convs = Vec::new();
        let mut previews: Vec<(String, LastKind)> = Vec::new();
        let mut thread: Vec<MessageInfo> = Vec::new();
        let mut open = false;
        match name {
            "nocontacts" | "empty" | "notsupported" => {}
            "memory" | "list" | "picker" | "confirm" | "thread" | "long" | "failed" => {
                convs = vec![
                    conv(a_ep, "a", "田中", NOW - 2 * MIN, 12, 0),
                    conv("bb", "b", LONG, NOW - DAY, 40, 1),
                    conv("cc", "c", "Alice", NOW - 5 * DAY, 3, 0),
                ];
                previews = vec![
                    (
                        a_ep.into(),
                        LastKind::Text {
                            text: "明日の会議は10時からです。\n資料は共有フォルダに置きました。"
                                .into(),
                            outgoing: false,
                        },
                    ),
                    (
                        "bb".into(),
                        LastKind::Text {
                            text: "了解です。後で確認して連絡します。".repeat(6),
                            outgoing: true,
                        },
                    ),
                    (
                        "cc".into(),
                        LastKind::Text {
                            text: "See you then!".into(),
                            outgoing: false,
                        },
                    ),
                ];
                ui.unread.on_received(a_ep, false, true);
                ui.unread.on_received(a_ep, false, true);
                ui.unread.on_received("cc", false, true);
            }
            _ => return None,
        }
        match name {
            "thread" | "confirm" | "memory" => {
                open = true;
                thread = vec![
                    msg(1, false, "received", "お疲れさまです。", NOW - DAY),
                    msg(2, true, "delivered", "お疲れさまです。今大丈夫ですか？", NOW - DAY + MIN),
                    msg(
                        3,
                        false,
                        "received",
                        "はい、大丈夫です。\n明日の会議は10時からです。資料は共有フォルダに置きました。",
                        NOW - 3 * MIN,
                    ),
                    msg(4, true, "read", "ありがとうございます。確認します。", NOW - 2 * MIN),
                    msg(0, true, "sending", "確認しました。", NOW - 30_000),
                    msg(0, true, "queued", "あとで電話します。", NOW - 10_000),
                ];
            }
            "long" => {
                open = true;
                thread = vec![
                    msg(
                        1,
                        false,
                        "received",
                        &"これは長いメッセージの例です。折り返して表示されます。".repeat(8),
                        NOW - 3 * MIN,
                    ),
                    msg(
                        2,
                        true,
                        "delivered",
                        &"https://example.com/a/very/long/path/that/has/no/spaces/at/all/"
                            .repeat(4),
                        NOW - 2 * MIN,
                    ),
                    msg(3, false, "received", &"a".repeat(300), NOW - MIN),
                ];
            }
            "failed" => {
                open = true;
                let mut m = msg(
                    5,
                    true,
                    "failed",
                    "資料を送りました。ご確認ください。",
                    NOW - 5 * MIN,
                );
                m.reason = Some("not_allowed".into());
                thread = vec![msg(4, false, "received", "こんにちは", NOW - 9 * MIN), m];
            }
            _ => {}
        }
        for (ep, last) in previews {
            if let Some(cv) = convs.iter().find(|x| x.endpoint_id == ep) {
                ui.previews.insert(
                    ep,
                    Preview {
                        key: PreviewKey::of(cv),
                        last,
                    },
                );
            }
        }
        ui.conversations = convs;
        ui.rows = list_rows(&ui.conversations);
        if name == "memory" {
            ui.history_saved = false;
        }
        if name == "notsupported" {
            ui.availability = Availability::OldDaemon;
        }
        if name == "picker" {
            ui.picker_open = true;
        }
        if open {
            ui.view = View::Conversation(Open {
                contact_id: "a".into(),
                endpoint_id: a_ep.into(),
                label: "田中".into(),
            });
            ui.window.apply_newest(thread, PAGE);
            ui.thread_loaded = true;
            ui.timeline_dirty = true;
        }
        if name == "confirm" {
            ui.delete_target = Some(Open {
                contact_id: "a".into(),
                endpoint_id: a_ep.into(),
                label: "田中".into(),
            });
        }
        if name == "failed" || name == "long" {
            ui.composer = String::new();
        }
        Some(ui)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locale::{chat_strings, Locale};
    use miasma_core::chat::ipc::{EventInfo, StatusInfo};

    fn msg(ord: u64, id: &str, outgoing: bool, state: &str) -> MessageInfo {
        MessageInfo {
            ord,
            id: id.into(),
            outgoing,
            seq: ord,
            text: format!("text {id}"),
            state: state.into(),
            reason: None,
            sent_ms: ord,
            at_ms: ord,
        }
    }

    fn ready() -> ChatUi {
        ChatUi {
            availability: Availability::Ok,
            was_connected: true,
            initial_sent: true,
            event_cursor: Some(0),
            ..Default::default()
        }
    }

    fn requests(ui: &mut ChatUi) -> Vec<ChatRequest> {
        let mut v = Vec::new();
        ui.drain(|r| {
            v.push(r);
            true
        });
        v
    }

    fn c() -> &'static ChatStrings {
        chat_strings(Locale::Ja)
    }

    fn marked(sent: bool, disabled: bool, wait: bool) -> Result<ChatResponse, ChatFail> {
        Ok(ChatResponse::ReadMarked {
            sent,
            disabled,
            wait,
        })
    }

    fn mark(contact: &str, up_to_seq: u64) -> ChatRequest {
        ChatRequest::MarkRead {
            contact: contact.into(),
            up_to_seq,
        }
    }

    #[test]
    fn a_read_receipt_is_asked_only_when_the_window_is_in_front_and_the_tab_is_open() {
        let mut ui = ready();
        // The tab is closed: nothing is read, however much is "in view".
        ui.area_open = false;
        ui.note_seen("ep", 3, true);
        assert!(requests(&mut ui).is_empty());
        ui.area_open = true;
        // The window is behind another one.
        ui.note_seen("ep", 3, false);
        assert!(requests(&mut ui).is_empty());
        // Nothing received is in view.
        ui.note_seen("ep", 0, true);
        assert!(requests(&mut ui).is_empty());
        // In front, with a message in view: asked, once.
        ui.note_seen("ep", 3, true);
        let r = requests(&mut ui);
        assert!(
            matches!(&r[..], [ChatRequest::MarkRead { contact, up_to_seq: 3 }] if contact == "ep")
        );
        ui.note_seen("ep", 4, true);
        assert!(requests(&mut ui).is_empty(), "one ask at a time");
        // Dev fixtures never ask the service.
        let mut frozen = ready();
        frozen.area_open = true;
        frozen.frozen = true;
        frozen.note_seen("ep", 3, true);
        assert!(requests(&mut frozen).is_empty());
    }

    #[test]
    fn the_same_point_is_not_asked_twice_and_a_new_one_is() {
        let mut ui = ready();
        ui.area_open = true;
        ui.note_seen("ep", 3, true);
        requests(&mut ui);
        ui.on_reply(c(), mark("ep", 3), marked(true, false, false));
        ui.last_read_ask = None; // (skip the pause between two asks)
        ui.note_seen("ep", 3, true);
        assert!(requests(&mut ui).is_empty(), "already reported");
        ui.note_seen("ep", 2, true);
        assert!(requests(&mut ui).is_empty(), "never backwards");
        ui.note_seen("ep", 5, true);
        let r = requests(&mut ui);
        assert!(matches!(
            &r[..],
            [ChatRequest::MarkRead { up_to_seq: 5, .. }]
        ));
        // Another contact has its own point.
        ui.on_reply(c(), mark("ep", 5), marked(true, false, false));
        ui.last_read_ask = None;
        ui.note_seen("other", 1, true);
        assert!(matches!(
            &requests(&mut ui)[..],
            [ChatRequest::MarkRead { contact, up_to_seq: 1 }] if contact == "other"
        ));
    }

    #[test]
    fn a_too_soon_answer_is_asked_again_and_a_disabled_one_is_not() {
        let mut ui = ready();
        ui.area_open = true;
        ui.note_seen("ep", 3, true);
        requests(&mut ui);
        ui.on_reply(c(), mark("ep", 3), marked(false, false, true));
        ui.last_read_ask = None;
        ui.note_seen("ep", 3, true);
        assert!(
            matches!(
                &requests(&mut ui)[..],
                [ChatRequest::MarkRead { up_to_seq: 3, .. }]
            ),
            "asked again after 'too soon'"
        );
        // The service says receipts are off for this contact: no more asking.
        ui.on_reply(c(), mark("ep", 3), marked(false, true, false));
        assert!(!ui.receipts_on("ep"));
        ui.last_read_ask = None;
        ui.note_seen("ep", 9, true);
        assert!(requests(&mut ui).is_empty());
    }

    #[test]
    fn with_receipts_off_nothing_is_asked_and_the_switch_asks_the_service() {
        let mut ui = ready();
        ui.area_open = true;
        // Off for the contact (as the list says).
        ui.receipts.insert("ep".into(), false);
        ui.note_seen("ep", 3, true);
        assert!(requests(&mut ui).is_empty());
        // Off for everyone (as the status says).
        ui.receipts.insert("ep".into(), true);
        ui.receipts_global = false;
        ui.note_seen("ep", 3, true);
        assert!(requests(&mut ui).is_empty());
        ui.receipts_global = true;
        // Switching a contact off asks the service; the answer confirms it.
        ui.set_receipts("ep", false);
        assert!(matches!(
            &requests(&mut ui)[..],
            [ChatRequest::SetReadReceipts { contact, enabled: false }] if contact == "ep"
        ));
        assert!(!ui.receipts_on("ep"));
        ui.read_asked.insert("ep".into(), 7);
        ui.on_reply(
            c(),
            ChatRequest::SetReadReceipts {
                contact: "ep".into(),
                enabled: true,
            },
            Ok(ChatResponse::ReceiptsSet { enabled: true }),
        );
        assert!(ui.receipts_on("ep"));
        // Switched on again: what is in view may be reported again.
        assert!(!ui.read_asked.contains_key("ep"));
    }

    #[test]
    fn an_error_answer_to_a_receipt_is_silent() {
        let mut ui = ready();
        ui.area_open = true;
        ui.note_seen("ep", 3, true);
        requests(&mut ui);
        ui.on_reply(
            c(),
            mark("ep", 3),
            Ok(ChatResponse::Error {
                kind: "internal".into(),
                message: "x".into(),
            }),
        );
        assert!(ui.page_msg.is_none());
        assert!(ui.read_inflight.is_none());
    }

    #[test]
    fn the_first_questions_learn_the_status_and_where_the_events_are() {
        let mut ui = ChatUi::default();
        ui.tick(false, true);
        let r = requests(&mut ui);
        assert!(matches!(r[0], ChatRequest::Status {}));
        assert!(matches!(r[1], ChatRequest::Events { since: u64::MAX }));
        // Nothing more is asked while those two are out.
        ui.tick(false, true);
        assert!(requests(&mut ui).is_empty());
    }

    #[test]
    fn nothing_is_asked_without_a_connection() {
        let mut ui = ChatUi::default();
        ui.tick(true, false);
        assert!(requests(&mut ui).is_empty());
    }

    #[test]
    fn with_the_tab_closed_only_the_events_are_polled_and_slowly() {
        let mut ui = ready();
        ui.last_events = Instant::now();
        ui.tick(false, true);
        assert!(requests(&mut ui).is_empty(), "not due yet");
        ui.last_events = Instant::now() - Duration::from_secs(6);
        ui.tick(false, true);
        let r = requests(&mut ui);
        assert_eq!(r.len(), 1);
        assert!(matches!(r[0], ChatRequest::Events { since: 0 }));
        // Never the list or a history while the tab is closed.
        ui.events_inflight = None;
        ui.list_dirty = true;
        ui.last_events = Instant::now() - Duration::from_secs(6);
        ui.tick(false, true);
        assert!(requests(&mut ui)
            .iter()
            .all(|r| matches!(r, ChatRequest::Events { .. })));
    }

    #[test]
    fn with_the_tab_open_the_list_is_asked_for_and_then_every_three_seconds() {
        let mut ui = ready();
        ui.area_open = true;
        ui.last_events = Instant::now();
        ui.last_list = Instant::now();
        ui.tick(true, true);
        assert!(requests(&mut ui).is_empty());
        ui.last_list = Instant::now() - Duration::from_secs(4);
        ui.tick(true, true);
        assert!(requests(&mut ui)
            .iter()
            .any(|r| matches!(r, ChatRequest::Conversations {})));
        // Not again while that one is out.
        ui.last_list = Instant::now() - Duration::from_secs(4);
        ui.tick(true, true);
        assert!(!requests(&mut ui)
            .iter()
            .any(|r| matches!(r, ChatRequest::Conversations {})));
    }

    #[test]
    fn an_open_conversation_is_polled_quickly_only_while_something_is_in_flight() {
        let mut ui = ready();
        ui.area_open = true;
        ui.open_conversation("a", "ep", "A");
        ui.tick(true, true);
        let first = requests(&mut ui);
        assert!(first.iter().any(|r| matches!(
            r,
            ChatRequest::History {
                before: None,
                limit: Some(PAGE),
                ..
            }
        )));
        // The newest page arrives, all delivered: quiet.
        ui.on_reply(
            c(),
            ChatRequest::History {
                contact: "ep".into(),
                before: None,
                limit: Some(PAGE),
            },
            Ok(ChatResponse::History {
                endpoint_id: "ep".into(),
                label: None,
                messages: vec![msg(1, "a", true, "delivered")],
            }),
        );
        ui.last_newest = Instant::now() - Duration::from_secs(5);
        ui.last_events = Instant::now();
        ui.tick(true, true);
        assert!(!requests(&mut ui)
            .iter()
            .any(|r| matches!(r, ChatRequest::History { .. })));
        // A message waiting: asked again after a second.
        ui.on_reply(
            c(),
            ChatRequest::Send {
                contact: "a".into(),
                text: "x".into(),
            },
            Ok(ChatResponse::Queued { id: "q".into() }),
        );
        ui.tick(true, true);
        assert!(requests(&mut ui)
            .iter()
            .any(|r| matches!(r, ChatRequest::History { before: None, .. })));
    }

    #[test]
    fn events_count_unread_for_other_conversations_and_nav_arrivals() {
        let mut ui = ready();
        let ev = |ep: &str, kind: &str| EventInfo {
            seq: 1,
            endpoint_id: ep.into(),
            label: None,
            kind: kind.into(),
            message: msg(1, "x", false, "received"),
        };
        // First answer only sets the cursor.
        ui.event_cursor = None;
        ui.on_reply(
            c(),
            ChatRequest::Events { since: u64::MAX },
            Ok(ChatResponse::Events {
                next: 7,
                events: vec![ev("a", "received")],
            }),
        );
        assert_eq!(ui.event_cursor, Some(7));
        assert_eq!(ui.unread.total(), 0, "old events are not news");
        // Tab closed.
        ui.area_open = false;
        ui.on_reply(
            c(),
            ChatRequest::Events { since: 7 },
            Ok(ChatResponse::Events {
                next: 9,
                events: vec![
                    ev("a", "received"),
                    ev("b", "delivered"),
                    ev("a", "received"),
                ],
            }),
        );
        assert_eq!(ui.unread.of("a"), 2);
        assert_eq!(ui.unread.of("b"), 0);
        assert_eq!(ui.unseen(), 2);
        // Tab open on conversation a: its arrivals are read at once.
        ui.area_open = true;
        ui.open_conversation("ca", "a", "A");
        assert_eq!(ui.unread.of("a"), 0, "opening reads it");
        ui.on_reply(
            c(),
            ChatRequest::Events { since: 9 },
            Ok(ChatResponse::Events {
                next: 10,
                events: vec![ev("a", "received")],
            }),
        );
        assert_eq!(ui.unread.of("a"), 0);
        assert!(ui.want_newest, "the open conversation is refreshed");
    }

    #[test]
    fn a_failed_send_gives_the_text_back() {
        let mut ui = ready();
        ui.open_conversation("a", "ep", "A");
        ui.composer = "こんにちは".into();
        ui.submit(c());
        let sent = requests(&mut ui);
        assert!(matches!(&sent[0], ChatRequest::Send { text, .. } if text == "こんにちは"));
        assert!(ui.composer.is_empty());
        assert_eq!(ui.sends_in_flight, 1);
        ui.on_reply(
            c(),
            sent[0].clone(),
            Ok(ChatResponse::Error {
                kind: "outbox_full".into(),
                message: "x".into(),
            }),
        );
        assert_eq!(ui.composer, "こんにちは");
        assert_eq!(ui.sends_in_flight, 0);
        assert_eq!(ui.page_msg.as_deref(), Some(c().err_outbox_full));
        // No answer at all: the same.
        ui.composer = "こんにちは".into();
        ui.submit(c());
        assert!(ui.composer.is_empty());
        let again = requests(&mut ui).remove(0);
        ui.on_reply(c(), again, Err(ChatFail::Other));
        assert_eq!(ui.composer, "こんにちは");
    }

    #[test]
    fn an_empty_or_too_long_message_is_not_sent() {
        let mut ui = ready();
        ui.max_bytes = 30;
        ui.open_conversation("a", "ep", "A");
        ui.composer = "  \n".into();
        ui.submit(c());
        assert!(requests(&mut ui).is_empty());
        ui.composer = "あ".repeat(11);
        ui.submit(c());
        assert!(requests(&mut ui).is_empty());
        assert_eq!(ui.page_msg.as_deref(), Some(c().too_long_note));
        assert!(!ui.composer.is_empty(), "the text stays for editing");
    }

    #[test]
    fn send_again_queues_the_text_and_then_removes_the_failed_one() {
        let mut ui = ready();
        ui.open_conversation("a", "ep", "A");
        ui.retry("failed-id", "もう一度");
        let r = requests(&mut ui);
        assert!(matches!(&r[0], ChatRequest::Send { text, .. } if text == "もう一度"));
        ui.on_reply(
            c(),
            r[0].clone(),
            Ok(ChatResponse::Queued { id: "n".into() }),
        );
        let r = requests(&mut ui);
        assert!(matches!(
            &r[0],
            ChatRequest::DeleteLocal { message_id: Some(id), .. } if id == "failed-id"
        ));
        // A plain send does not delete anything.
        ui.composer = "x".into();
        ui.submit(c());
        let s = requests(&mut ui).remove(0);
        ui.on_reply(c(), s, Ok(ChatResponse::Queued { id: "m".into() }));
        assert!(requests(&mut ui).is_empty());
    }

    #[test]
    fn deleting_a_conversation_clears_it_and_says_so() {
        let mut ui = ready();
        ui.open_conversation("a", "ep", "田中");
        ui.window
            .apply_newest(vec![msg(1, "a", false, "received")], 50);
        ui.delete_history(&Open {
            contact_id: "a".into(),
            endpoint_id: "ep".into(),
            label: "田中".into(),
        });
        let r = requests(&mut ui).remove(0);
        assert!(
            matches!(&r, ChatRequest::DeleteLocal { message_id: None, contact } if contact == "ep")
        );
        ui.on_reply(c(), r, Ok(ChatResponse::Deleted { count: 1 }));
        assert!(ui.window.is_empty());
        assert_eq!(ui.take_notices(), ["田中 との会話の履歴を削除しました"]);
    }

    #[test]
    fn the_answers_for_a_conversation_that_was_left_are_dropped() {
        let mut ui = ready();
        ui.open_conversation("a", "ep-a", "A");
        ui.open_conversation("b", "ep-b", "B");
        ui.on_reply(
            c(),
            ChatRequest::History {
                contact: "ep-a".into(),
                before: None,
                limit: Some(PAGE),
            },
            Ok(ChatResponse::History {
                endpoint_id: "ep-a".into(),
                label: None,
                messages: vec![msg(1, "x", false, "received")],
            }),
        );
        assert!(ui.window.is_empty());
    }

    #[test]
    fn switching_conversations_drops_the_old_window_and_keeps_the_draft() {
        let mut ui = ready();
        ui.open_conversation("a", "ep-a", "A");
        ui.window.apply_newest(
            (1..=60)
                .map(|o| msg(o, &format!("m{o}"), false, "received"))
                .collect(),
            50,
        );
        ui.composer = "書きかけ".into();
        ui.open_conversation("b", "ep-b", "B");
        assert!(ui.window.is_empty());
        assert!(ui.composer.is_empty());
        ui.open_conversation("a", "ep-a", "A");
        assert_eq!(ui.composer, "書きかけ");
        for i in 0..MAX_DRAFTS + 5 {
            ui.composer = "x".into();
            ui.open_conversation(&format!("c{i}"), "e", "C");
            ui.composer = "y".into();
            ui.close_conversation();
        }
        assert!(ui.drafts.len() <= MAX_DRAFTS);
    }

    #[test]
    fn leaving_the_tab_lets_go_of_the_messages() {
        let mut ui = ready();
        ui.area_open = true;
        ui.open_conversation("a", "ep", "A");
        ui.window.apply_newest(
            (1..=50)
                .map(|o| msg(o, &format!("m{o}"), false, "received"))
                .collect(),
            50,
        );
        ui.thread_loaded = true;
        ui.tick(false, true);
        assert!(ui.window.is_empty());
        assert!(!ui.thread_loaded);
        assert!(ui.rows.is_empty());
    }

    #[test]
    fn the_list_asks_for_the_last_message_of_changed_conversations_only() {
        let mut ui = ready();
        let conv = |ep: &str, last: u64| ConversationInfo {
            endpoint_id: ep.into(),
            fingerprint: String::new(),
            label: Some(ep.into()),
            contact_id: Some(ep.into()),
            messages: 2,
            last_ms: last,
            pending: 0,
            read_receipts: true,
        };
        ui.on_reply(
            c(),
            ChatRequest::Conversations {},
            Ok(ChatResponse::Conversations(vec![
                conv("a", 5),
                conv("b", 4),
            ])),
        );
        let r = requests(&mut ui);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|r| matches!(
            r,
            ChatRequest::History {
                before: None,
                limit: Some(1),
                ..
            }
        )));
        // The answers fill the previews.
        for ep in ["a", "b"] {
            ui.on_reply(
                c(),
                ChatRequest::History {
                    contact: ep.into(),
                    before: None,
                    limit: Some(1),
                },
                Ok(ChatResponse::History {
                    endpoint_id: ep.into(),
                    label: None,
                    messages: vec![msg(1, ep, true, "delivered")],
                }),
            );
        }
        assert_eq!(ui.previews.len(), 2);
        // Same list again: nothing to ask. One changed: just that one.
        ui.on_reply(
            c(),
            ChatRequest::Conversations {},
            Ok(ChatResponse::Conversations(vec![
                conv("a", 5),
                conv("b", 4),
            ])),
        );
        assert!(requests(&mut ui).is_empty());
        ui.on_reply(
            c(),
            ChatRequest::Conversations {},
            Ok(ChatResponse::Conversations(vec![
                conv("a", 9),
                conv("b", 4),
            ])),
        );
        let r = requests(&mut ui);
        assert_eq!(r.len(), 1);
        assert!(matches!(&r[0], ChatRequest::History { contact, .. } if contact == "a"));
        // Conversations that vanished lose their preview.
        ui.on_reply(
            c(),
            ChatRequest::Conversations {},
            Ok(ChatResponse::Conversations(vec![conv("b", 4)])),
        );
        assert!(!ui.previews.contains_key("a"));
    }

    #[test]
    fn older_pages_are_asked_with_the_oldest_position_and_never_twice_at_once() {
        let mut ui = ready();
        ui.area_open = true;
        ui.open_conversation("a", "ep", "A");
        ui.on_reply(
            c(),
            ChatRequest::History {
                contact: "ep".into(),
                before: None,
                limit: Some(PAGE),
            },
            Ok(ChatResponse::History {
                endpoint_id: "ep".into(),
                label: None,
                messages: (101..=150)
                    .map(|o| msg(o, &format!("m{o}"), false, "received"))
                    .collect(),
            }),
        );
        assert!(ui.window.has_older());
        assert_eq!(ui.window.oldest_ord(), Some(101));
        ui.scroll_offset = 400.0;
        ui.on_reply(
            c(),
            ChatRequest::History {
                contact: "ep".into(),
                before: Some(101),
                limit: Some(PAGE),
            },
            Ok(ChatResponse::History {
                endpoint_id: "ep".into(),
                label: None,
                messages: (51..=100)
                    .map(|o| msg(o, &format!("m{o}"), false, "received"))
                    .collect(),
            }),
        );
        assert_eq!(ui.window.len(), 100);
        let keep = ui.scroll_to.expect("the view is kept where it was");
        assert!(keep > 400.0, "the new rows are above: {keep}");
    }

    #[test]
    fn errors_of_the_service_are_worded_by_kind() {
        let mut ui = ready();
        ui.on_reply(c(), ChatRequest::Status {}, Err(ChatFail::NotSupported));
        assert_eq!(ui.availability, Availability::OldDaemon);
        ui.on_reply(c(), ChatRequest::Status {}, Err(ChatFail::DaemonDown));
        assert_eq!(ui.availability, Availability::DaemonDown);
        ui.on_reply(
            c(),
            ChatRequest::Status {},
            Ok(ChatResponse::Error {
                kind: "unavailable".into(),
                message: String::new(),
            }),
        );
        assert_eq!(ui.availability, Availability::NoChat);
        ui.on_reply(
            c(),
            ChatRequest::Status {},
            Ok(ChatResponse::Status(StatusInfo {
                history_saved: false,
                conversations: 0,
                outbox: 0,
                outbox_max: 10,
                max_message_bytes: 2000,
                read_receipts: true,
            })),
        );
        assert_eq!(ui.availability, Availability::Ok);
        assert!(!ui.history_saved);
        assert_eq!(ui.max_bytes, 2000);
        // Any other failure keeps what was known.
        ui.on_reply(c(), ChatRequest::Status {}, Err(ChatFail::Other));
        assert_eq!(ui.availability, Availability::Ok);
    }

    #[test]
    fn a_stopped_service_is_asked_again_now_and_then_not_every_frame() {
        let mut ui = ChatUi::default();
        ui.tick(true, true);
        let _ = requests(&mut ui);
        ui.on_reply(c(), ChatRequest::Status {}, Err(ChatFail::NotSupported));
        ui.on_reply(
            c(),
            ChatRequest::Events { since: u64::MAX },
            Err(ChatFail::NotSupported),
        );
        ui.tick(true, true);
        assert!(requests(&mut ui).is_empty(), "not yet");
        ui.last_try = Instant::now() - Duration::from_secs(6);
        ui.tick(true, true);
        let r = requests(&mut ui);
        assert!(matches!(r[0], ChatRequest::Status {}));
        // Reconnecting starts over.
        ui.tick(true, false);
        ui.tick(true, true);
        assert!(!requests(&mut ui).is_empty());
    }

    #[test]
    fn every_fixture_draws_without_panicking_at_both_widths() {
        for name in FIXTURES {
            for (w, h) in [(700.0, 900.0), (1400.0, 900.0)] {
                for locale in Locale::ALL {
                    let strings = chat_strings(locale);
                    let mut chat = ChatUi::fixture(name).expect(name);
                    let contacts = crate::contacts::ContactsUi::fixture(
                        if *name == "nocontacts" {
                            "empty"
                        } else {
                            "two"
                        },
                        crate::locale::contact_strings(locale),
                    )
                    .unwrap();
                    let list = contacts.contact_list().to_vec();
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
                            egui::CentralPanel::default().show(ctx, |ui| {
                                kit::column(ui, |ui| {
                                    let _ = chat.show(ui, strings, true, &list);
                                });
                            });
                        });
                    }
                    // Drawing a fixture asks the service for nothing.
                    assert!(requests(&mut chat).is_empty(), "{name}");
                }
            }
        }
    }
}
