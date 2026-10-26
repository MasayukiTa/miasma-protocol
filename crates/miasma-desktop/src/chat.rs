//! The Chat area, pure part: everything that can be decided without a window.
//!
//! Times and their words, the one-line preview of a conversation, unread counting, the bounded
//! window of messages kept in memory, the order of messages and file notes, the words for a
//! message's state, and the limits of the composer. `chat_ui.rs` holds the state of the screen
//! and draws it; this file is unit-tested headless.

use std::collections::HashMap;

use miasma_core::chat::ipc::{ConversationInfo, MessageInfo};
use miasma_core::push::ContactInfo;

use crate::contacts::{FileStatus, SentFile};
use crate::locale::ChatStrings;
use crate::transfers::fill;

// ─── Limits ─────────────────────────────────────────────────────────────────

/// Messages asked for at a time. The service never returns more than 200 in one answer.
pub const PAGE: u32 = 50;
/// Most messages of one conversation kept in memory. Older pages are dropped from the far end.
pub const MAX_WINDOW: usize = 300;
/// A preview is cut to this many characters before the screen elides it to the row's width.
pub const PREVIEW_CHARS: usize = 120;
/// Conversations whose last message is fetched for the list.
pub const MAX_PREVIEWS: usize = 40;
/// Largest unread number shown as a number; above it the badge says "99+".
pub const BADGE_MAX: u32 = 99;
/// File notes remembered per contact (this session only).
pub const MAX_NOTES_PER_CONTACT: usize = 20;
/// Longest a name is shown in a header or a row before it is elided.
pub const NAME_CHARS: usize = 40;

// ─── Time ───────────────────────────────────────────────────────────────────

/// "Now" and the offset of the local time zone from UTC, passed in so the words for a time are
/// a pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    pub now_ms: u64,
    pub utc_offset_secs: i64,
}

/// Year, month and day of a day number counted from 1970-01-01 (proleptic Gregorian).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn local_secs(ms: u64, offset: i64) -> i64 {
    (ms / 1000) as i64 + offset
}

/// Day number (since 1970-01-01) of a moment in the local time zone.
pub fn day_index(ms: u64, offset: i64) -> i64 {
    local_secs(ms, offset).div_euclid(86_400)
}

/// `HH:MM`, 24-hour, local.
pub fn hhmm(ms: u64, offset: i64) -> String {
    let s = local_secs(ms, offset).rem_euclid(86_400);
    format!("{:02}:{:02}", s / 3600, (s % 3600) / 60)
}

/// The time of a conversation row: "Today 14:05", "Yesterday" or "10/14". Empty for no time.
pub fn when_list(c: &ChatStrings, at_ms: u64, clock: Clock) -> String {
    if at_ms == 0 {
        return String::new();
    }
    let day = day_index(at_ms, clock.utc_offset_secs);
    let today = day_index(clock.now_ms, clock.utc_offset_secs);
    if day == today {
        fill(
            c.time_today,
            &[("time", &hhmm(at_ms, clock.utc_offset_secs))],
        )
    } else if day == today - 1 {
        c.time_yesterday.to_owned()
    } else {
        date_text(c, day)
    }
}

/// The time under a message: "14:05", "Yesterday 14:05" or "10/14 14:05".
pub fn when_message(c: &ChatStrings, at_ms: u64, clock: Clock) -> String {
    if at_ms == 0 {
        return String::new();
    }
    let day = day_index(at_ms, clock.utc_offset_secs);
    let today = day_index(clock.now_ms, clock.utc_offset_secs);
    let hm = hhmm(at_ms, clock.utc_offset_secs);
    if day == today {
        hm
    } else if day == today - 1 {
        format!("{} {hm}", c.time_yesterday)
    } else {
        format!("{} {hm}", date_text(c, day))
    }
}

fn date_text(c: &ChatStrings, day: i64) -> String {
    let (_, m, d) = civil_from_days(day);
    fill(c.time_date, &[("m", &m.to_string()), ("d", &d.to_string())])
}

#[cfg(windows)]
mod win {
    /// `TIME_ZONE_INFORMATION` of the Windows API.
    #[repr(C)]
    pub struct TimeZoneInformation {
        pub bias: i32,
        pub standard_name: [u16; 32],
        pub standard_date: [u16; 8],
        pub standard_bias: i32,
        pub daylight_name: [u16; 32],
        pub daylight_date: [u16; 8],
        pub daylight_bias: i32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetTimeZoneInformation(info: *mut TimeZoneInformation) -> u32;
    }
}

#[cfg(unix)]
mod unix {
    /// The leading fields of `struct tm` (glibc, musl and the BSDs/macOS share this layout).
    #[repr(C)]
    pub struct Tm {
        pub tm_sec: i32,
        pub tm_min: i32,
        pub tm_hour: i32,
        pub tm_mday: i32,
        pub tm_mon: i32,
        pub tm_year: i32,
        pub tm_wday: i32,
        pub tm_yday: i32,
        pub tm_isdst: i32,
        pub tm_gmtoff: std::os::raw::c_long,
        pub tm_zone: *const std::os::raw::c_char,
    }

    extern "C" {
        pub fn localtime_r(time: *const i64, out: *mut Tm) -> *mut Tm;
    }
}

/// Seconds the local time zone is ahead of UTC right now (negative to the west). Zero when the
/// system cannot say.
pub fn local_utc_offset_secs() -> i64 {
    #[cfg(windows)]
    {
        // SAFETY: the structure is plain data that the call fills; nothing is kept.
        let mut info: win::TimeZoneInformation = unsafe { std::mem::zeroed() };
        let id = unsafe { win::GetTimeZoneInformation(&mut info) };
        let extra = match id {
            1 => info.standard_bias,
            2 => info.daylight_bias,
            0 => 0,
            _ => return 0,
        };
        -((info.bias + extra) as i64) * 60
    }
    #[cfg(unix)]
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        // SAFETY: `localtime_r` writes only into the zeroed structure given to it.
        let mut tm: unix::Tm = unsafe { std::mem::zeroed() };
        let ok = unsafe { !unix::localtime_r(&now, &mut tm).is_null() };
        if ok {
            tm.tm_gmtoff as i64
        } else {
            0
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        0
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─── Names and one-line text ────────────────────────────────────────────────

/// `text` cut to `max` characters with an ellipsis. Cuts on a character boundary.
pub fn elide(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// The text on one line: every run of line breaks, tabs and spaces becomes one space, then it is
/// cut to `max` characters.
pub fn one_line(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max * 4));
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() || ch.is_control() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
        // Far more than will ever be shown: stop reading a huge message.
        if out.len() > max * 8 {
            break;
        }
    }
    elide(&out, max)
}

// ─── The last message of a conversation ─────────────────────────────────────

/// What the list shows as the last thing in a conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LastKind {
    /// A message; `outgoing` ones get the "You: " prefix.
    Text {
        text: String,
        outgoing: bool,
    },
    /// A file this person sent from the chat screen.
    File {
        name: String,
    },
    None,
}

/// The one-line preview of `last`, prefix included.
pub fn preview_text(c: &ChatStrings, last: &LastKind) -> String {
    match last {
        LastKind::Text { text, outgoing } => {
            let line = one_line(text, PREVIEW_CHARS);
            if *outgoing {
                fill(c.preview_you, &[("text", &line)])
            } else {
                line
            }
        }
        LastKind::File { name } => fill(
            c.preview_file,
            &[("name", &elide(&one_line(name, PREVIEW_CHARS), 60))],
        ),
        LastKind::None => String::new(),
    }
}

/// What makes a stored preview stale: the conversation's last activity, size and waiting messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviewKey {
    pub last_ms: u64,
    pub messages: u64,
    pub pending: u32,
}

impl PreviewKey {
    pub fn of(c: &ConversationInfo) -> Self {
        Self {
            last_ms: c.last_ms,
            messages: c.messages,
            pending: c.pending,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub key: PreviewKey,
    pub last: LastKind,
}

/// The last message in an answer to a history request (the newest is last).
pub fn last_of(messages: &[MessageInfo]) -> LastKind {
    match messages.last() {
        Some(m) => LastKind::Text {
            text: m.text.clone(),
            outgoing: m.outgoing,
        },
        None => LastKind::None,
    }
}

/// A file note counts as the last thing only when it is newer than the last message.
pub fn effective_last(stored: &LastKind, last_ms: u64, note: Option<&FileNote>) -> LastKind {
    match note {
        Some(n) if n.at_ms > last_ms => LastKind::File {
            name: n.name.clone(),
        },
        _ => stored.clone(),
    }
}

// ─── Conversation rows ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRow {
    pub endpoint_id: String,
    pub contact_id: String,
    pub label: String,
    pub last_ms: u64,
    pub messages: u64,
    pub pending: u32,
}

/// One row per conversation of a registered contact, newest first. A conversation whose contact
/// was removed has no row: the list is for the contacts the person has.
pub fn list_rows(convs: &[ConversationInfo]) -> Vec<ListRow> {
    let mut rows: Vec<ListRow> = convs
        .iter()
        .filter_map(|c| {
            Some(ListRow {
                endpoint_id: c.endpoint_id.clone(),
                contact_id: c.contact_id.clone()?,
                label: c.label.clone()?,
                last_ms: c.last_ms,
                messages: c.messages,
                pending: c.pending,
            })
        })
        .collect();
    rows.sort_by(|a, b| b.last_ms.cmp(&a.last_ms));
    rows
}

/// The contacts the "new conversation" picker offers: every registered contact, the ones that may
/// not be sent to last (they are shown but not selectable).
pub fn picker_order(contacts: &[ContactInfo]) -> Vec<&ContactInfo> {
    let mut v: Vec<&ContactInfo> = contacts.iter().collect();
    v.sort_by_key(|c| (!c.allow_send, c.label.to_lowercase()));
    v
}

// ─── Unread ─────────────────────────────────────────────────────────────────

/// Unread messages per conversation, and the arrivals the navigation item still announces.
#[derive(Debug, Default, Clone)]
pub struct Unread {
    per_peer: HashMap<String, u32>,
    unseen: u32,
}

impl Unread {
    /// A message arrived from `peer`. It is unread unless that conversation is on screen; it
    /// is announced on the navigation item unless the Chat area is open.
    pub fn on_received(&mut self, peer: &str, viewing_it: bool, area_open: bool) {
        if !viewing_it {
            let n = self.per_peer.entry(peer.to_owned()).or_insert(0);
            *n = n.saturating_add(1);
        }
        if !area_open {
            self.unseen = self.unseen.saturating_add(1);
        }
    }

    /// The conversation with `peer` was opened: its messages are read.
    pub fn open(&mut self, peer: &str) {
        self.per_peer.remove(peer);
    }

    /// The Chat area was opened: the navigation item stops announcing.
    pub fn mark_seen(&mut self) {
        self.unseen = 0;
    }

    pub fn of(&self, peer: &str) -> u32 {
        self.per_peer.get(peer).copied().unwrap_or(0)
    }

    #[cfg(test)]
    pub fn total(&self) -> u32 {
        self.per_peer
            .values()
            .fold(0u32, |a, b| a.saturating_add(*b))
    }

    pub fn unseen(&self) -> u32 {
        self.unseen
    }

    /// Forget peers that are not in the list any more.
    pub fn retain_peers(&mut self, keep: impl Fn(&str) -> bool) {
        self.per_peer.retain(|k, _| keep(k));
    }
}

/// The number on a badge: "7", or "99+" above [`BADGE_MAX`].
pub fn badge_text(n: u32) -> String {
    if n > BADGE_MAX {
        format!("{BADGE_MAX}+")
    } else {
        n.to_string()
    }
}

/// The navigation item: the tab name, with the number of new arrivals while there are some.
pub fn nav_label(c: &ChatStrings, unseen: u32) -> String {
    match unseen {
        0 => c.tab.to_owned(),
        n => format!("{} ({} {})", c.tab, badge_text(n), c.nav_new),
    }
}

// ─── The bounded window of messages ─────────────────────────────────────────

/// The messages of the open conversation that are in memory: at most [`MAX_WINDOW`], oldest
/// first, queued ones (`ord` 0) at the end. It grows toward older messages as the person scrolls
/// up; past the limit the newest end is let go ("detached") and a button brings it back.
#[derive(Debug, Default, Clone)]
pub struct MessageWindow {
    items: Vec<MessageInfo>,
    has_older: bool,
    detached: bool,
}

impl MessageWindow {
    pub fn items(&self) -> &[MessageInfo] {
        &self.items
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Older messages may exist than the ones held.
    pub fn has_older(&self) -> bool {
        self.has_older
    }

    /// The newest messages are not held (the window ran past its limit going up).
    pub fn is_detached(&self) -> bool {
        self.detached
    }

    /// The `before` for the next page of older messages: the smallest position held.
    pub fn oldest_ord(&self) -> Option<u64> {
        self.items.iter().map(|m| m.ord).filter(|o| *o > 0).min()
    }

    /// Something is still on its way: the polling of this conversation stays quick.
    pub fn has_unfinished(&self) -> bool {
        self.items
            .iter()
            .any(|m| m.outgoing && matches!(m.state.as_str(), "queued" | "sending"))
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Back to the newest end: forget everything held, the caller asks for the newest page.
    pub fn jump_to_latest(&mut self) {
        self.clear();
    }

    /// Merge the newest page (what a request without `before` returns). `limit` is what was
    /// asked for. Returns false when nothing was done (the window is detached).
    pub fn apply_newest(&mut self, page: Vec<MessageInfo>, limit: u32) -> bool {
        if self.detached {
            return false;
        }
        let persisted = page.iter().filter(|m| m.ord > 0).count();
        let first_ord = page.iter().map(|m| m.ord).filter(|o| *o > 0).min();
        let mut items: Vec<MessageInfo> = Vec::with_capacity(page.len() + self.items.len().min(64));
        match first_ord {
            Some(first) if persisted as u32 >= limit => {
                // The page may not reach the start: keep what is older than it.
                items.extend(
                    self.items
                        .iter()
                        .filter(|m| m.ord > 0 && m.ord < first)
                        .cloned(),
                );
                self.has_older = true;
            }
            _ => {
                // The page reached the oldest message there is.
                self.has_older = false;
            }
        }
        items.extend(page);
        self.items = items;
        self.trim_oldest();
        true
    }

    /// Put an older page (a request with `before`) in front. Returns the messages that were new.
    pub fn apply_older(&mut self, page: Vec<MessageInfo>, limit: u32) -> Vec<MessageInfo> {
        self.has_older = page.len() as u32 >= limit;
        let held: std::collections::HashSet<&str> =
            self.items.iter().map(|m| m.id.as_str()).collect();
        let fresh: Vec<MessageInfo> = page
            .into_iter()
            .filter(|m| !held.contains(m.id.as_str()))
            .collect();
        let mut items = fresh.clone();
        items.append(&mut self.items);
        self.items = items;
        if self.items.len() > MAX_WINDOW {
            self.items.truncate(MAX_WINDOW);
            self.detached = true;
        }
        fresh
    }

    fn trim_oldest(&mut self) {
        if self.items.len() > MAX_WINDOW {
            let drop = self.items.len() - MAX_WINDOW;
            self.items.drain(..drop);
            self.has_older = true;
        }
    }
}

// ─── File notes and the order of what is shown ──────────────────────────────

/// A file this person sent from the chat screen: the chat itself carries text only, so the file
/// is remembered here (this session) and shown in the conversation and its preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNote {
    pub id: String,
    pub name: String,
    /// The file on this computer, which ties the note to its push row.
    pub path: String,
    pub at_ms: u64,
}

/// Add `names` to the notes of one contact, keeping the newest [`MAX_NOTES_PER_CONTACT`].
pub fn push_notes(notes: &mut Vec<FileNote>, files: &[SentFile], at_ms: u64) {
    for (i, f) in files.iter().enumerate() {
        notes.push(FileNote {
            id: format!("file-{at_ms}-{i}-{}", notes.len()),
            name: f.name.clone(),
            path: f.path.clone(),
            at_ms,
        });
    }
    if notes.len() > MAX_NOTES_PER_CONTACT {
        let drop = notes.len() - MAX_NOTES_PER_CONTACT;
        notes.drain(..drop);
    }
}

/// The text of a file line. "Sent" is said only when the push has finished.
pub fn file_line(c: &ChatStrings, name: &str, status: &FileStatus) -> String {
    let name = elide(&one_line(name, PREVIEW_CHARS), 80);
    match status {
        FileStatus::Waiting => fill(c.file_waiting, &[("name", &name)]),
        FileStatus::Sending { percent } => fill(
            c.file_sending,
            &[("name", &name), ("pct", &percent.to_string())],
        ),
        FileStatus::Done => fill(c.file_done, &[("name", &name)]),
        FileStatus::Failed { .. } => fill(c.file_failed, &[("name", &name)]),
    }
}

/// One line of the conversation: a message or a file note, by position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    Msg(usize),
    File(usize),
}

/// Messages in their order with the file notes placed by time: a note goes before the first
/// message that is newer than it, the rest at the end.
pub fn merge_timeline(msgs: &[MessageInfo], notes: &[FileNote]) -> Vec<Entry> {
    let mut out = Vec::with_capacity(msgs.len() + notes.len());
    let mut n = 0;
    for (i, m) in msgs.iter().enumerate() {
        while n < notes.len() && notes[n].at_ms <= m.at_ms {
            out.push(Entry::File(n));
            n += 1;
        }
        out.push(Entry::Msg(i));
    }
    while n < notes.len() {
        out.push(Entry::File(n));
        n += 1;
    }
    out
}

/// Approximate height of a row before it has been laid out, so rows that are not on screen can
/// be skipped without measuring them.
pub fn estimate_row_height(chars: usize, line_breaks: usize, wrap_px: f32, failed: bool) -> f32 {
    const CHAR_PX: f32 = 11.0;
    const LINE_PX: f32 = 22.0;
    let per_line = (wrap_px / CHAR_PX).max(8.0);
    let wrapped = (chars as f32 / per_line).ceil().max(1.0);
    let lines = wrapped + line_breaks as f32;
    // Bubble padding, the meta line, and for a failed message the guidance and the button.
    lines * LINE_PX + 16.0 + 24.0 + if failed { 56.0 } else { 0.0 }
}

// ─── Message state ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Sending,
    /// Waiting on this device for the other side.
    Queued,
    Delivered,
    /// Delivered and the other person has read it (both sides have receipts on).
    Read,
    Failed,
    /// An incoming message.
    Received,
    Unknown,
}

pub fn delivery_of(m: &MessageInfo) -> Delivery {
    match (m.outgoing, m.state.as_str()) {
        (false, _) => Delivery::Received,
        (true, "sending") => Delivery::Sending,
        (true, "queued") => Delivery::Queued,
        (true, "delivered") => Delivery::Delivered,
        (true, "read") => Delivery::Read,
        (true, "failed") => Delivery::Failed,
        (true, _) => Delivery::Unknown,
    }
}

/// The words for the state of one of my messages; none for an incoming one.
pub fn state_label(c: &ChatStrings, d: Delivery) -> Option<&'static str> {
    match d {
        Delivery::Sending => Some(c.state_sending),
        Delivery::Queued => Some(c.state_queued),
        Delivery::Delivered => Some(c.state_delivered),
        Delivery::Read => Some(c.state_read),
        Delivery::Failed => Some(c.state_failed),
        Delivery::Received | Delivery::Unknown => None,
    }
}

/// The one muted line under the contact's name in a conversation header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderStatus {
    /// Nothing to say: no line is shown.
    Quiet,
    /// Messages of mine are waiting for the other person to come online.
    Waiting,
    /// Messages of mine are waiting because this computer is not connected to the relay.
    RelayDown,
}

/// What the header says: only what is true and useful (there is no "online" light, because the
/// service does not know whether the other person is there until a message goes through).
pub fn header_status(relay_down: bool, has_queued: bool) -> HeaderStatus {
    match (has_queued, relay_down) {
        (false, _) => HeaderStatus::Quiet,
        (true, true) => HeaderStatus::RelayDown,
        (true, false) => HeaderStatus::Waiting,
    }
}

/// The highest sequence number among the received messages at `visible` positions of `items`
/// (the rows really on screen), or 0 when there is none. This is what a read receipt reports:
/// never a message the person has not had in view.
pub fn newest_seen_seq(items: &[MessageInfo], visible: &[usize]) -> u64 {
    visible
        .iter()
        .filter_map(|&i| items.get(i))
        .filter(|m| !m.outgoing && m.ord > 0)
        .map(|m| m.seq)
        .max()
        .unwrap_or(0)
}

/// The sentence for why a message failed, from the service's stable reason.
pub fn fail_text(c: &ChatStrings, reason: Option<&str>) -> &'static str {
    match reason {
        Some("not_allowed") => c.fail_not_allowed,
        Some("too_big") => c.fail_too_big,
        Some("rejected") => c.fail_rejected,
        Some("unsupported") => c.fail_unsupported,
        Some("contact_removed") => c.fail_contact_removed,
        Some("send_disabled") => c.fail_send_disabled,
        Some("expired") => c.fail_expired,
        Some("session") => c.fail_session,
        Some("pqc_peer_no_hybrid") => c.fail_pqc_peer_no_hybrid,
        Some("pqc_failed") => c.fail_pqc_failed,
        _ => c.fail_other,
    }
}

/// The line about the hybrid post-quantum upgrade of a conversation, from the
/// service's state word. `None` when nothing is to be shown (the setting is
/// off and nothing was negotiated, or the service does not report it).
pub fn pqc_text(c: &ChatStrings, state: Option<&str>) -> Option<&'static str> {
    match state {
        Some("hybrid") => Some(c.pqc_hybrid),
        Some("classical") => Some(c.pqc_classical),
        Some("pending") => Some(c.pqc_pending),
        Some("failed") => Some(c.pqc_failed),
        _ => None,
    }
}

/// The sentence for an error answer of the service, from its stable kind.
pub fn error_text(c: &ChatStrings, kind: &str) -> &'static str {
    match kind {
        "empty" => c.err_empty,
        "too_big" => c.err_too_big,
        "outbox_full" => c.err_outbox_full,
        "send_disabled" => c.err_send_disabled,
        "unknown_contact" => c.err_unknown_contact,
        "unavailable" => c.unavailable,
        "internal" => c.err_internal,
        _ => c.err_other,
    }
}

// ─── The composer ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterLevel {
    Empty,
    Ok,
    /// 90% of the limit or more.
    Near,
    Over,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter {
    pub chars: usize,
    pub bytes: usize,
    pub max_bytes: usize,
    pub level: CounterLevel,
    /// Characters left, estimated from the average size of the characters typed so far.
    pub approx_left: usize,
    /// Characters over the limit, estimated the same way.
    pub approx_over: usize,
}

/// The limit of a message is in bytes (a Japanese character takes three), so the counter works
/// out characters from the average size of what was typed.
pub fn counter(text: &str, max_bytes: usize) -> Counter {
    let chars = text.chars().count();
    let bytes = text.len();
    let avg = if chars == 0 {
        1.0
    } else {
        (bytes as f64 / chars as f64).max(1.0)
    };
    let level = if text.trim().is_empty() {
        if bytes > max_bytes {
            CounterLevel::Over
        } else {
            CounterLevel::Empty
        }
    } else if bytes > max_bytes {
        CounterLevel::Over
    } else if bytes.saturating_mul(10) >= max_bytes.saturating_mul(9) {
        CounterLevel::Near
    } else {
        CounterLevel::Ok
    };
    Counter {
        chars,
        bytes,
        max_bytes,
        level,
        approx_left: (max_bytes.saturating_sub(bytes) as f64 / avg).floor() as usize,
        approx_over: (bytes.saturating_sub(max_bytes) as f64 / avg).ceil() as usize,
    }
}

pub fn counter_text(c: &ChatStrings, ctr: &Counter) -> String {
    match ctr.level {
        CounterLevel::Over => fill(c.counter_over, &[("n", &ctr.approx_over.to_string())]),
        CounterLevel::Near => fill(c.counter_near, &[("n", &ctr.approx_left.to_string())]),
        _ => fill(c.counter_chars, &[("n", &ctr.chars.to_string())]),
    }
}

/// Why the text cannot be sent now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendBlock {
    Empty,
    TooLong,
}

/// The text to send (trailing blanks and breaks removed), or why it cannot be sent.
pub fn prepare_send(text: &str, max_bytes: usize) -> Result<String, SendBlock> {
    let t = text.trim_end();
    if t.trim().is_empty() {
        return Err(SendBlock::Empty);
    }
    if t.len() > max_bytes {
        return Err(SendBlock::TooLong);
    }
    Ok(t.to_owned())
}

/// Longest text the composer keeps in memory (far above any limit; a paste is cut here).
pub fn composer_cap(max_bytes: usize) -> usize {
    max_bytes.saturating_mul(4).max(1024)
}

/// Cut `text` to at most `cap` bytes on a character boundary. True when something was cut.
pub fn cap_text(text: &mut String, cap: usize) -> bool {
    if text.len() <= cap {
        return false;
    }
    let mut cut = cap;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    true
}

// ─── Availability ───────────────────────────────────────────────────────────

/// Whether the service can do chat, as far as the last answers say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Unknown,
    Ok,
    DaemonDown,
    /// The service runs but chat is off or has no transport.
    NoChat,
    /// The service does not know chat requests (older version).
    OldDaemon,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locale::{chat_strings, Locale};

    fn ja() -> &'static ChatStrings {
        chat_strings(Locale::Ja)
    }

    fn msg(ord: u64, id: &str, outgoing: bool, state: &str) -> MessageInfo {
        MessageInfo {
            ord,
            id: id.into(),
            outgoing,
            seq: ord,
            text: format!("text {id}"),
            state: state.into(),
            reason: None,
            sent_ms: ord * 1000,
            at_ms: ord * 1000,
            tried_ms: 0,
        }
    }

    fn conv(label: Option<&str>, last_ms: u64) -> ConversationInfo {
        ConversationInfo {
            endpoint_id: format!("e{last_ms}"),
            fingerprint: "F".into(),
            label: label.map(str::to_owned),
            contact_id: label.map(|l| format!("id-{l}")),
            messages: 3,
            last_ms,
            pending: 0,
            read_receipts: true,
            pending_reason: None,
            pending_tried_ms: 0,
            pqc: None,
            pqc_reason: None,
        }
    }

    #[test]
    fn a_receipt_reports_only_received_messages_that_were_in_view() {
        let items = vec![
            msg(1, "a", false, "received"),
            msg(2, "b", true, "delivered"),
            msg(3, "c", false, "received"),
            msg(4, "d", false, "received"),
            msg(0, "q", true, "queued"),
        ];
        // Nothing in view, nothing to report.
        assert_eq!(newest_seen_seq(&items, &[]), 0);
        // Only the rows in view count, whatever is newer below them.
        assert_eq!(newest_seen_seq(&items, &[0, 1, 2]), 3);
        assert_eq!(newest_seen_seq(&items, &[0, 1, 2, 3]), 4);
        // My own messages and queued ones are never reported, and a bad index is ignored.
        assert_eq!(newest_seen_seq(&items, &[1, 4, 99]), 0);
    }

    // 2026-10-15 14:30:00 UTC.
    const NOON: u64 = 1_792_074_600_000;
    const JST: i64 = 9 * 3600;

    #[test]
    fn civil_dates_are_right() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn times_are_today_yesterday_or_a_date() {
        let c = ja();
        let clock = Clock {
            now_ms: NOON,
            utc_offset_secs: 0,
        };
        assert_eq!(when_list(c, NOON - 60_000, clock), "今日 14:29");
        assert_eq!(when_list(c, NOON - 86_400_000, clock), "昨日");
        assert_eq!(when_list(c, NOON - 3 * 86_400_000, clock), "10月12日");
        assert_eq!(when_list(c, 0, clock), "");
        assert_eq!(when_message(c, NOON - 60_000, clock), "14:29");
        assert_eq!(when_message(c, NOON - 86_400_000, clock), "昨日 14:30");
        assert_eq!(
            when_message(c, NOON - 3 * 86_400_000, clock),
            "10月12日 14:30"
        );
    }

    #[test]
    fn the_local_zone_moves_the_day_boundary() {
        let c = ja();
        // 23:30 UTC is 08:30 the next day in Japan.
        let late = NOON + 9 * 3_600_000;
        let clock = Clock {
            now_ms: late,
            utc_offset_secs: JST,
        };
        assert_eq!(when_list(c, NOON, clock), "昨日");
        assert_eq!(hhmm(NOON, JST), "23:30");
        let utc = Clock {
            now_ms: late,
            utc_offset_secs: 0,
        };
        assert!(when_list(c, NOON, utc).starts_with("今日"));
        // The English and Chinese tables fill the same holes.
        let en = chat_strings(Locale::En);
        assert_eq!(when_list(en, NOON - 3 * 86_400_000, utc), "10/12");
        assert_eq!(when_list(en, NOON, utc), "Today 14:30");
    }

    #[test]
    fn the_local_offset_is_a_sane_number() {
        let off = local_utc_offset_secs();
        assert!((-14 * 3600..=14 * 3600).contains(&off), "{off}");
    }

    #[test]
    fn previews_are_one_line_with_the_you_prefix() {
        let c = ja();
        let mine = LastKind::Text {
            text: "こんにちは\n\n  元気ですか\t？".into(),
            outgoing: true,
        };
        assert_eq!(preview_text(c, &mine), "あなた：こんにちは 元気ですか ？");
        let theirs = LastKind::Text {
            text: "はい".into(),
            outgoing: false,
        };
        assert_eq!(preview_text(c, &theirs), "はい");
        assert_eq!(preview_text(c, &LastKind::None), "");
    }

    #[test]
    fn long_previews_are_elided_on_a_character_boundary() {
        let c = ja();
        let long = "あ".repeat(500);
        let p = preview_text(
            c,
            &LastKind::Text {
                text: long,
                outgoing: false,
            },
        );
        assert_eq!(p.chars().count(), PREVIEW_CHARS);
        assert!(p.ends_with('…'));
        // A message of nothing but blanks shows nothing rather than a gap.
        assert_eq!(one_line(" \n\t ", 10), "");
        assert_eq!(elide("abc", 3), "abc");
        assert_eq!(elide("abcd", 3), "ab…");
    }

    #[test]
    fn a_file_is_previewed_as_sent_with_its_name_elided() {
        let c = ja();
        let p = preview_text(
            c,
            &LastKind::File {
                name: "報告書.pdf".into(),
            },
        );
        assert_eq!(p, "ファイル：報告書.pdf");
        let long = preview_text(
            c,
            &LastKind::File {
                name: format!("{}.pdf", "長".repeat(200)),
            },
        );
        assert!(long.chars().count() < 100, "{long}");
        // The note wins only over an older message.
        let stored = LastKind::Text {
            text: "x".into(),
            outgoing: true,
        };
        let note = FileNote {
            id: "f".into(),
            name: "a.txt".into(),
            path: "/a.txt".into(),
            at_ms: 5_000,
        };
        assert!(matches!(
            effective_last(&stored, 4_000, Some(&note)),
            LastKind::File { .. }
        ));
        assert_eq!(effective_last(&stored, 6_000, Some(&note)), stored);
        assert_eq!(effective_last(&stored, 6_000, None), stored);
    }

    #[test]
    fn rows_are_only_for_registered_contacts_newest_first() {
        let convs = vec![conv(Some("old"), 10), conv(None, 99), conv(Some("new"), 50)];
        let rows = list_rows(&convs);
        let names: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(names, ["new", "old"]);
        assert_eq!(rows[0].contact_id, "id-new");
    }

    #[test]
    fn unread_counts_per_conversation_and_announces_on_the_nav_item() {
        let mut u = Unread::default();
        // Chat area closed: both count.
        u.on_received("a", false, false);
        u.on_received("a", false, false);
        u.on_received("b", false, false);
        assert_eq!((u.of("a"), u.of("b"), u.total(), u.unseen()), (2, 1, 3, 3));
        // Opening the area clears the nav announcement, not the badges.
        u.mark_seen();
        assert_eq!((u.unseen(), u.total()), (0, 3));
        // The conversation on screen does not collect unread.
        u.on_received("a", true, true);
        assert_eq!((u.of("a"), u.unseen()), (2, 0));
        // Area open on the list: unread grows, the nav item stays quiet.
        u.on_received("b", false, true);
        assert_eq!((u.of("b"), u.unseen()), (2, 0));
        u.open("a");
        assert_eq!(u.of("a"), 0);
        assert_eq!(u.total(), 2);
        u.retain_peers(|p| p == "a");
        assert_eq!(u.total(), 0);
    }

    #[test]
    fn badges_cap_at_99_plus_and_the_nav_label_names_arrivals() {
        assert_eq!(badge_text(1), "1");
        assert_eq!(badge_text(99), "99");
        assert_eq!(badge_text(100), "99+");
        assert_eq!(nav_label(ja(), 0), "チャット");
        assert_eq!(nav_label(ja(), 3), "チャット (3 新着)");
        assert_eq!(nav_label(ja(), 500), "チャット (99+ 新着)");
    }

    #[test]
    fn the_window_merges_the_newest_page_and_keeps_older_pages() {
        let mut w = MessageWindow::default();
        let page: Vec<_> = (11..=20)
            .map(|o| msg(o, &format!("m{o}"), false, "received"))
            .collect();
        assert!(w.apply_newest(page, 10));
        assert!(w.has_older(), "a full page may have more behind it");
        assert_eq!(w.oldest_ord(), Some(11));
        // Older page of 10 arrives.
        let older: Vec<_> = (1..=10)
            .map(|o| msg(o, &format!("m{o}"), false, "received"))
            .collect();
        let added = w.apply_older(older, 10);
        assert_eq!(added.len(), 10);
        assert_eq!(w.len(), 20);
        assert!(w.has_older());
        // The next newest poll (page 10, ords 11..=20 plus a new 21) keeps the older part.
        let again: Vec<_> = (12..=21)
            .map(|o| msg(o, &format!("m{o}"), false, "received"))
            .collect();
        assert!(w.apply_newest(again, 10));
        assert_eq!(w.len(), 21);
        assert_eq!(w.items()[0].ord, 1);
        assert_eq!(w.items().last().unwrap().ord, 21);
        // An older page shorter than asked is the start of the conversation.
        let mut w2 = MessageWindow::default();
        w2.apply_newest(vec![msg(5, "a", false, "received")], 10);
        assert!(!w2.has_older());
    }

    #[test]
    fn queued_messages_follow_the_persisted_ones_and_are_replaced_by_their_final_form() {
        let mut w = MessageWindow::default();
        w.apply_newest(
            vec![msg(1, "a", false, "received"), msg(0, "q", true, "queued")],
            50,
        );
        assert!(w.has_unfinished());
        assert_eq!(w.oldest_ord(), Some(1));
        // The queued one was delivered and got a position.
        w.apply_newest(
            vec![
                msg(1, "a", false, "received"),
                msg(2, "q", true, "delivered"),
            ],
            50,
        );
        assert!(!w.has_unfinished());
        assert_eq!(w.len(), 2);
        assert_eq!(w.items()[1].state, "delivered");
    }

    #[test]
    fn the_window_never_holds_more_than_the_limit() {
        // Going up past the limit lets go of the newest end.
        let mut w = MessageWindow::default();
        let mut next = MAX_WINDOW as u64 + 1_000;
        let first: Vec<_> = (0..50)
            .map(|i| msg(next - 49 + i, &format!("n{i}"), false, "received"))
            .collect();
        w.apply_newest(first, 50);
        next -= 50;
        for _ in 0..10 {
            let page: Vec<_> = (0..50)
                .map(|i| msg(next - 49 + i, &format!("o{next}-{i}"), false, "received"))
                .collect();
            w.apply_older(page, 50);
            next -= 50;
            assert!(w.len() <= MAX_WINDOW);
        }
        assert_eq!(w.len(), MAX_WINDOW);
        assert!(w.is_detached());
        // A detached window ignores polls of the newest page.
        assert!(!w.apply_newest(vec![msg(5000, "x", false, "received")], 50));
        w.jump_to_latest();
        assert!(w.is_empty() && !w.is_detached());
        // Growing at the newest end drops the oldest and remembers there is more.
        let mut w = MessageWindow::default();
        for round in 0..8u64 {
            let page: Vec<_> = (0..50)
                .map(|i| {
                    msg(
                        round * 50 + i + 1,
                        &format!("k{round}-{i}"),
                        false,
                        "received",
                    )
                })
                .collect();
            w.apply_newest(page, 50);
            assert!(w.len() <= MAX_WINDOW);
        }
        assert_eq!(w.len(), MAX_WINDOW);
        assert!(w.has_older());
    }

    #[test]
    fn file_notes_are_placed_by_time_and_bounded() {
        let msgs = vec![
            msg(1, "a", true, "delivered"),
            msg(3, "b", false, "received"),
        ];
        let mut notes = Vec::new();
        let sf = |n: &str| SentFile {
            name: n.into(),
            path: format!("/tmp/{n}"),
        };
        push_notes(&mut notes, &[sf("x.txt")], 2_000);
        push_notes(&mut notes, &[sf("y.txt")], 9_000);
        let order = merge_timeline(&msgs, &notes);
        assert_eq!(
            order,
            [Entry::Msg(0), Entry::File(0), Entry::Msg(1), Entry::File(1)]
        );
        for i in 0..50 {
            push_notes(&mut notes, &[sf(&format!("f{i}"))], 10_000 + i);
        }
        assert_eq!(notes.len(), MAX_NOTES_PER_CONTACT);
        assert!(notes.last().unwrap().name == "f49");
        let ids: std::collections::HashSet<_> = notes.iter().map(|n| n.id.clone()).collect();
        assert_eq!(ids.len(), notes.len(), "ids are unique");
    }

    #[test]
    fn row_height_estimates_grow_with_text() {
        let short = estimate_row_height(5, 0, 400.0, false);
        let long = estimate_row_height(2000, 0, 400.0, false);
        let breaks = estimate_row_height(5, 6, 400.0, false);
        let failed = estimate_row_height(5, 0, 400.0, true);
        assert!(long > short * 3.0);
        assert!(breaks > short);
        assert!(failed > short);
    }

    #[test]
    fn message_states_have_the_agreed_words() {
        let c = ja();
        let w = |m: &MessageInfo| state_label(c, delivery_of(m));
        assert_eq!(w(&msg(1, "a", true, "sending")), Some("送信中"));
        assert_eq!(
            w(&msg(0, "a", true, "queued")),
            Some("送信済み（相手に届くのを待っています）")
        );
        assert_eq!(w(&msg(1, "a", true, "delivered")), Some("届きました"));
        assert_eq!(w(&msg(1, "a", true, "read")), Some("既読"));
        // Only my own messages carry a state; a received one never reads "read".
        assert_eq!(w(&msg(1, "a", false, "read")), None);
        assert_eq!(w(&msg(1, "a", true, "failed")), Some("送信に失敗しました"));
        assert_eq!(w(&msg(1, "a", false, "received")), None);
        assert_eq!(w(&msg(1, "a", true, "something-new")), None);
        // Every reason the service can give has its own sentence, and an unknown one a general one.
        for reason in [
            "not_allowed",
            "too_big",
            "rejected",
            "unsupported",
            "contact_removed",
            "send_disabled",
            "expired",
            "session",
        ] {
            assert_ne!(fail_text(c, Some(reason)), c.fail_other, "{reason}");
        }
        assert_eq!(fail_text(c, Some("brand-new")), c.fail_other);
        assert_eq!(fail_text(c, None), c.fail_other);
        for kind in [
            "empty",
            "too_big",
            "outbox_full",
            "send_disabled",
            "unknown_contact",
        ] {
            assert_ne!(error_text(c, kind), c.err_other, "{kind}");
        }
    }

    #[test]
    fn pqc_fail_reasons_have_their_own_sentence_in_every_language() {
        // The two `require` refusals the service gives map to their own
        // sentences (not the catch-all), in every language.
        for lang in Locale::ALL {
            let c = chat_strings(lang);
            for reason in ["pqc_peer_no_hybrid", "pqc_failed"] {
                assert_ne!(
                    fail_text(c, Some(reason)),
                    c.fail_other,
                    "{lang:?} {reason}"
                );
            }
        }
    }

    #[test]
    fn the_unsupported_peer_message_asks_for_an_update() {
        // When the contact's app does not offer the advanced encryption the
        // setting requires, the message tells the person to ask for an update.
        let update_word = |lang: Locale| -> &'static str {
            match lang {
                Locale::En => "update",
                Locale::Ja => "\u{6700}\u{65b0}\u{7248}",
                Locale::ZhCn => "\u{66f4}\u{65b0}",
            }
        };
        for lang in Locale::ALL {
            let c = chat_strings(lang);
            let s = fail_text(c, Some("pqc_peer_no_hybrid"));
            assert!(
                s.contains(update_word(lang)),
                "{lang:?} does not ask for an update: {s}"
            );
        }
    }

    #[test]
    fn the_counter_follows_the_limit_in_bytes() {
        assert_eq!(counter("", 4096).level, CounterLevel::Empty);
        assert_eq!(counter("  \n", 4096).level, CounterLevel::Empty);
        let ok = counter("こんにちは", 4096);
        assert_eq!((ok.chars, ok.bytes, ok.level), (5, 15, CounterLevel::Ok));
        // 1300 Japanese characters are 3900 bytes: near the limit of 4096.
        let near = counter(&"あ".repeat(1300), 4096);
        assert_eq!(near.level, CounterLevel::Near);
        assert_eq!(near.approx_left, (4096 - 3900) / 3);
        let over = counter(&"あ".repeat(1400), 4096);
        assert_eq!(over.level, CounterLevel::Over);
        assert_eq!(over.approx_over, (4200usize - 4096).div_ceil(3));
        // ASCII counts one byte each.
        assert_eq!(counter(&"a".repeat(4096), 4096).level, CounterLevel::Near);
        assert_eq!(counter(&"a".repeat(4097), 4096).level, CounterLevel::Over);
        let c = ja();
        assert_eq!(counter_text(c, &ok), "5文字");
        assert!(counter_text(c, &near).starts_with("あと約"));
        assert!(counter_text(c, &over).contains("長すぎます"));
    }

    #[test]
    fn sending_needs_text_within_the_limit() {
        assert_eq!(prepare_send("", 100), Err(SendBlock::Empty));
        assert_eq!(prepare_send(" \n ", 100), Err(SendBlock::Empty));
        assert_eq!(prepare_send("hi \n\n", 100), Ok("hi".to_owned()));
        assert_eq!(prepare_send("  hi", 100), Ok("  hi".to_owned()));
        assert_eq!(prepare_send(&"a".repeat(101), 100), Err(SendBlock::TooLong));
        assert!(prepare_send(&"a".repeat(100), 100).is_ok());
        // Three bytes per character count as bytes.
        assert_eq!(prepare_send(&"あ".repeat(34), 100), Err(SendBlock::TooLong));
    }

    #[test]
    fn a_pasted_text_is_cut_on_a_character_boundary() {
        let mut t = "あ".repeat(10);
        assert!(cap_text(&mut t, 10));
        assert_eq!(t, "あ".repeat(3));
        let mut s = "abc".to_owned();
        assert!(!cap_text(&mut s, 3));
        assert!(composer_cap(4096) >= 4096 * 2);
        assert!(composer_cap(1) >= 1024);
    }

    #[test]
    fn the_picker_lists_everyone_and_puts_blocked_contacts_last() {
        let c = |id: &str, label: &str, send: bool| ContactInfo {
            id: id.into(),
            label: label.into(),
            endpoint_id: String::new(),
            fingerprint: String::new(),
            added_at: 0,
            allow_send: send,
            allow_receive: true,
            max_file_size: None,
            default_max_file_size: 0,
            inbox_dir: String::new(),
        };
        let list = vec![
            c("1", "Zed", true),
            c("2", "alice", false),
            c("3", "Bob", true),
        ];
        let order: Vec<&str> = picker_order(&list).iter().map(|x| x.id.as_str()).collect();
        assert_eq!(order, ["3", "1", "2"]);
    }

    #[test]
    fn a_file_line_says_sent_only_when_the_push_is_done() {
        use crate::locale::{chat_strings, Locale};
        for l in [Locale::En, Locale::Ja, Locale::ZhCn] {
            let c = chat_strings(l);
            let waiting = file_line(c, "a.mp4", &FileStatus::Waiting);
            let sending = file_line(c, "a.mp4", &FileStatus::Sending { percent: 42 });
            let done = file_line(c, "a.mp4", &FileStatus::Done);
            let failed = file_line(c, "a.mp4", &FileStatus::Failed { reason: "x".into() });
            for t in [&waiting, &sending, &done, &failed] {
                assert!(t.contains("a.mp4"), "{l:?}: {t}");
                assert!(!t.contains('{'), "{l:?}: {t}");
            }
            assert!(sending.contains("42"), "{l:?}: {sending}");
            assert_eq!(done, fill(c.file_done, &[("name", "a.mp4")]));
            // Three different sentences, none of them the "sent" one.
            assert!(waiting != done && sending != done && failed != done);
            assert!(waiting != failed && sending != failed);
        }
    }
}
